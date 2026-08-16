package com.cert.aspin;

import org.junit.Test;
import org.json.JSONObject;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class CertificateValidationTest {
    private static final long FUTURE_EXPIRATION_MILLIS = 4_102_444_800_000L;

    @Test
    public void aspinRequiresClaimedSubjectAndSan() {
        assertThrows(IllegalArgumentException.class, () -> ASPinVerifier.parseVerifiedClaim(
                "api.example", "{\"issuer\":[\"aW52YWxpZA\"]}",
                FUTURE_EXPIRATION_MILLIS));
    }

    @Test
    public void aspinSupportsTransitionalIssuerAndSanLists() throws Exception {
        String oldIssuer = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        String newIssuer = "sha384:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        ASPinVerifier.CertificateClaim claim = ASPinVerifier.parseVerifiedClaim(
                "api.example", "{\"subject\":\"CN=api.example\","
                        + "\"san\":[\"api.example\",\"backup.example\"],"
                        + "\"issuer\":[\"" + oldIssuer + "\",\"" + newIssuer + "\"]}",
                FUTURE_EXPIRATION_MILLIS);

        assertEquals("api.example", claim.getHost());
        assertEquals(List.of("api.example", "backup.example"),
                claim.getSubjectAlternativeNames());
        assertEquals(List.of(oldIssuer, newIssuer), claim.getIssuerIdentifiers());
    }

    @Test
    public void connectionHostnameMustEqualClaimLookupHostname() {
        assertTrue(ASPinVerifier.sameHostname("API.Example", "api.example"));
        assertThrows(IllegalArgumentException.class,
                () -> ASPinVerifier.sameHostname("api.example.", "api.example"));
        assertTrue(ASPinVerifier.sameHostname("[2001:db8::1]", "2001:0db8::1"));
        assertFalse(ASPinVerifier.sameHostname("api.example", "other.example"));
        assertThrows(IllegalArgumentException.class,
                () -> ASPinVerifier.sameHostname("https://api.example", "api.example"));
    }

    @Test
    public void issuerIdentifierHashesCompleteCaCertificateDer() throws Exception {
        byte[] caDer = "complete DER CA certificate".getBytes(StandardCharsets.UTF_8);
        assertEquals("sha256:xrJpLmtHsCeQvLRwRQ-6faX5RWeSXknChuIQjJhjAmY",
                ASPinVerifier.issuerIdentifier(caDer, "sha256"));
        assertEquals("sha384:9kTLAN-PmnbnNffBieFNsRVJpI0gpr0p88mi5d6erQ6USw_ccb8PX0Dmp7LcfukQ",
                ASPinVerifier.issuerIdentifier(caDer, "sha384"));
    }

    @Test
    public void unsupportedIssuerHashFailsClosed() {
        assertThrows(java.security.cert.CertificateException.class,
                () -> ASPinVerifier.issuerIdentifier(new byte[] {1}, "md5"));
        assertThrows(IllegalArgumentException.class, () -> ASPinVerifier.parseVerifiedClaim(
                "api.example", "{\"subject\":\"CN=api.example\","
                        + "\"san\":[\"api.example\"],\"issuer\":[\"md5:AA\"]}",
                FUTURE_EXPIRATION_MILLIS));
    }

    @Test
    public void nativeValidatedPathIsPreservedForCertClaimCheck() throws Exception {
        Path repoRoot = repositoryRoot();
        String variant = currentVariant(repoRoot);
        Path certDirectory = repoRoot.resolve("realserver/etc/cert").resolve(variant);
        X509Certificate leaf = readFirstCertificate(certDirectory.resolve("real-cert.pem"));
        X509Certificate directIssuer = readFirstCertificate(
                certDirectory.resolve("real-chain.pem"));

        assertArrayEquals(new X509Certificate[] {leaf, directIssuer},
                HttpsConn.requireValidatedPath(List.of(leaf, directIssuer)));
        assertThrows(java.security.cert.CertificateException.class,
                () -> HttpsConn.requireValidatedPath(List.of()));
    }

    @Test
    public void generatedClaimMatchesDirectIssuerCertificateAndChainCheck() throws Exception {
        Path repoRoot = repositoryRoot();
        String variant = currentVariant(repoRoot);
        Path certDirectory = repoRoot.resolve("realserver/etc/cert").resolve(variant);
        X509Certificate leaf = readFirstCertificate(certDirectory.resolve("real-cert.pem"));
        X509Certificate directIssuer = readFirstCertificate(
                certDirectory.resolve("real-chain.pem"));

        JSONObject jws = new JSONObject(new String(Files.readAllBytes(
                repoRoot.resolve("signing").resolve(variant).resolve("ServerCertClaim.jws")),
                StandardCharsets.UTF_8));
        JSONObject payload = new JSONObject(new String(
                Base64.getUrlDecoder().decode(jws.getString("payload")),
                StandardCharsets.UTF_8));
        String claimedIssuer = payload.getJSONArray("issuer").getString(0);
        assertEquals(ASPinVerifier.issuerIdentifier(directIssuer.getEncoded(), "sha256"),
                claimedIssuer);

        ASPinVerifier.CertificateClaim claim = new ASPinVerifier.CertificateClaim(
                "api.example", "CN=api.example", List.of("api.example"),
                List.of(claimedIssuer), FUTURE_EXPIRATION_MILLIS);
        ASPinVerifier.verifyCertificate(
                "api.example", claim, new X509Certificate[] {leaf, directIssuer});
        ASPinVerifier.verifyCertificate(
                "api.example", claim, new X509Certificate[] {leaf, directIssuer},
                FUTURE_EXPIRATION_MILLIS - 1);
        assertThrows(java.security.cert.CertificateException.class,
                () -> ASPinVerifier.verifyCertificate(
                        "api.example", claim,
                        new X509Certificate[] {leaf, directIssuer},
                        FUTURE_EXPIRATION_MILLIS));

        String sha384Issuer = ASPinVerifier.issuerIdentifier(
                directIssuer.getEncoded(), "sha384");
        ASPinVerifier.CertificateClaim sha384Claim = new ASPinVerifier.CertificateClaim(
                "api.example", "CN=api.example", List.of("api.example"),
                List.of(sha384Issuer), FUTURE_EXPIRATION_MILLIS);
        ASPinVerifier.verifyCertificate(
                "api.example", sha384Claim, new X509Certificate[] {leaf, directIssuer});

        int digestStart = claimedIssuer.indexOf(':') + 1;
        char replacement = claimedIssuer.charAt(digestStart) == 'A' ? 'B' : 'A';
        String wrongIssuer = claimedIssuer.substring(0, digestStart) + replacement
                + claimedIssuer.substring(digestStart + 1);
        ASPinVerifier.CertificateClaim wrongClaim = new ASPinVerifier.CertificateClaim(
                "api.example", "CN=api.example", List.of("api.example"),
                List.of(wrongIssuer), FUTURE_EXPIRATION_MILLIS);
        assertThrows(java.security.cert.CertificateException.class,
                () -> ASPinVerifier.verifyCertificate(
                        "api.example", wrongClaim,
                        new X509Certificate[] {leaf, directIssuer}));
    }

    private static X509Certificate readFirstCertificate(Path path) throws Exception {
        try (InputStream input = Files.newInputStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
    }

    private static Path repositoryRoot() {
        Path candidate = Path.of("").toAbsolutePath();
        while (candidate != null && !Files.isDirectory(candidate.resolve("realserver"))) {
            candidate = candidate.getParent();
        }
        if (candidate == null) {
            throw new IllegalStateException("Cannot locate repository root");
        }
        return candidate;
    }

    private static String currentVariant(Path repoRoot) {
        Path current = Path.of("").toAbsolutePath();
        for (String variant : List.of("es256", "es384", "rsa3072", "rsa4096")) {
            if (current.startsWith(repoRoot.resolve("ASPin").resolve(variant))) {
                return variant;
            }
        }
        throw new IllegalStateException("Cannot determine ASPin algorithm variant");
    }
}
