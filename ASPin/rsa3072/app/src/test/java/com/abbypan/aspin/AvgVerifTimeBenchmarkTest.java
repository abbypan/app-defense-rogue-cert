package com.abbypan.aspin;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Benchmark test suite for table:avgveriftime in tex for algorithm rsa3072.
 * Executes in the App environment (JVM / Android test runner).
 */
public class AvgVerifTimeBenchmarkTest {

    @Test
    public void testTableAvgVerifTimeBenchmark() throws Exception {
        String iterProp = System.getProperty("benchmark.iterations");
        if (iterProp == null || iterProp.isEmpty()) {
            iterProp = System.getProperty("iterations");
        }
        int iterations = (iterProp != null && !iterProp.isEmpty()) ? Integer.parseInt(iterProp) : 2000;

        String alg = "rsa3072";
        String host = alg + ".idouzi.top";

        String appCertPem = null, tkJwt = null, tcJwt = null, dcpPublicKeyPem = null, dcpJson = null;

        try {
            tkJwt = fetchHttpUrl("http://" + host + "/.well-known/ClaimSigningKey.jwt");
            tcJwt = fetchHttpUrl("http://" + host + "/.well-known/ServerCertClaim.jwt");
            dcpJson = fetchHttpUrl("http://dcp.idouzi.top/.well-known/DCPServerCertPin-" + alg + ".json");
        } catch (Exception httpEx) {
            System.out.println("HTTP fetch failed for " + alg + ", falling back to local resources: " + httpEx.getMessage());
        }

        if (tkJwt == null) {
            tkJwt = JsonUtils.read_file("src/main/resources/ClaimSigningKey.jwt");
        }
        if (tcJwt == null) {
            tcJwt = JsonUtils.read_file("src/main/resources/ServerCertClaim.jwt");
        }
        if (dcpJson == null) {
            dcpJson = JsonUtils.read_file("src/main/resources/DCPServerCertPin.json");
        }

        dcpPublicKeyPem = JsonUtils.read_file("src/main/resources/my-dcp-pubkey.pem");
        appCertPem = extractCertFromTkJwt(tkJwt);

        String csVerifyRes = JwtVerifier.verifyJwtWithCert(tkJwt, appCertPem);
        String csJwkJson = JwtVerifier.extractConfirmationJwk(csVerifyRes);

        double tkTimeMs = BenchmarkVerifier.benchmarkTkMs(tkJwt, appCertPem, iterations);
        double tcTimeMs = BenchmarkVerifier.benchmarkTcMs(tcJwt, csJwkJson, iterations);
        double dcpTimeMs = BenchmarkVerifier.benchmarkDcpMs(dcpJson, dcpPublicKeyPem, iterations);

        System.out.printf("Completed %-10s (%d iterations): Tk = %.2f ms | Tc = %.2f ms | DCP = %.2f ms\n",
                alg, iterations, tkTimeMs, tcTimeMs, dcpTimeMs);

        assertTrue(tkTimeMs >= 0);
        assertTrue(tcTimeMs >= 0);
        assertTrue(dcpTimeMs >= 0);
    }

    private static String fetchHttpUrl(String urlString) throws Exception {
        java.net.URL url = new java.net.URL(urlString);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        try (java.io.InputStream in = conn.getInputStream()) {
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private static String extractCertFromTkJwt(String tkJwt) {
        try {
            com.nimbusds.jwt.SignedJWT signedJwt = com.nimbusds.jwt.SignedJWT.parse(tkJwt);
            var chain = signedJwt.getHeader().getX509CertChain();
            if (chain != null && !chain.isEmpty()) {
                return chain.get(0).toString();
            }
        } catch (Exception ignored) {}
        try {
            return JsonUtils.read_file("../../signing/rsa3072/my-app-cert.pem");
        } catch (Exception ignored) {}
        return null;
    }
}
