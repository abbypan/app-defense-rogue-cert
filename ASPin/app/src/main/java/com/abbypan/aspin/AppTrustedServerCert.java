package com.abbypan.aspin;

import android.content.Context;
import android.util.Log;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import java.net.HttpURLConnection;
import java.net.URI;

import org.json.JSONObject;

/**
 * Class for managing trusted server certificates for the app
 * Provides functionality to store, retrieve, and validate server certificates
 */
public class AppTrustedServerCert {
    
    private static final String TAG = "AppTrustedServerCert";

    public static void main(String[] args) throws Exception {
        String host = args[0];
        // Note: This main method is for testing only - Context is not available in main
        //Log.d(TAG, "Testing with host: " + host);
    }  
    
    public static ASPinVerifier.CertificateClaim getValidatedServerCertClaim(
            Context ts, String host) throws Exception {
        String appcert = AppInfo.getPrimarySigningCert(ts);
        if (appcert == null) {
            throw new IllegalStateException("Installed app signing certificate is unavailable");
        }

        // The paper intentionally authenticates these HTTP responses cryptographically
        // rather than relying on the TLS/PKI path that ASPin is meant to supplement.
        String csjwt = getPlaintextWellKnown(host, "ClaimSigningKey.jwt");
        String certclaim = getPlaintextWellKnown(host, "ServerCertClaim.jwt");
        String csverifyres = JwtVerifier.verifyJwtWithCert(csjwt, appcert);
        String cs_jwk = new JSONObject(csverifyres).getString("cs_jwk");
        String claimres = JwtVerifier.verifyJwtWithJwk(certclaim, cs_jwk);
        ASPinVerifier.CertificateClaim claim = ASPinVerifier.parseVerifiedClaim(claimres);
        if (!host.equalsIgnoreCase(claim.getHost())) {
            throw new Exception("Host mismatch: " + host + " != " + claim.getHost());
        }
        return claim;
    }

    /** Backwards-compatible helper used by the existing UI. */
    public static String getServerCertClaim(Context ts, String host) throws Exception {
        ASPinVerifier.CertificateClaim claim = getValidatedServerCertClaim(ts, host);
        return String.join(" | ", claim.getIssuers());
    }

    public static HttpsURLConnection createValidatedASPinConnection(Context context, String host)
            throws Exception {
        return HttpsConn.createASPinConnection(host, getValidatedServerCertClaim(context, host));
    }

    private static String getPlaintextWellKnown(String host, String fileName) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) URI.create(
                "http://" + host + "/.well-known/" + fileName).toURL().openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(10_000);
        try {
            return readContent(connection);
        } finally {
            connection.disconnect();
        }
    }

    private static String readContent(HttpURLConnection connection) throws Exception {
        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(
                        connection.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
            return result.toString();
        }
    }
}
