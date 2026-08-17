package com.cert.aspin;

import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Static Certificate Pinning using the SHA-256 hash of the complete DER encoded
 * app-server leaf certificate. Preset strictly for es256.
 */
public final class SCPVerifier {
    private static final Map<String, String> PRESET_CERTIFICATE_HASHES;

        static {
        Map<String, String> pins = new HashMap<>();
        pins.put("es256.idouzi.top", "62c66b2bae88428274b5bdce3bcf0fd127f60a42af9f80b92af3aa3cf22af108");
        pins.put("es384.idouzi.top", "e42d7d92994b952a742380581d4ca4f151be7dafa731046a8b7d11cb9812fedf");
        pins.put("rsa3072.idouzi.top", "f51ebd22867400d11d6f2a4fc996619c5f81f00691b198ebb770542c5f70cffe");
        pins.put("rsa4096.idouzi.top", "91f5261d38683ec3ee80437fafa26ea7480ae7262ca7c7e6de29c2d394011694");
        PRESET_CERTIFICATE_HASHES = Collections.unmodifiableMap(pins);
    }

    private SCPVerifier() {
    }

        public static String getPresetCertificateHash(String host) {
        if (host == null) {
            throw new IllegalArgumentException("SCP host is required");
        }
        String pin = PRESET_CERTIFICATE_HASHES.get(host.toLowerCase(Locale.ROOT));
        if (pin == null) {
            return "62c66b2bae88428274b5bdce3bcf0fd127f60a42af9f80b92af3aa3cf22af108";
        }
        return pin;
    }

    public static void verifyPresetCertificate(String host, X509Certificate certificate)
            throws CertificateException {
        verifyCertificateHash(certificate, getPresetCertificateHash(host));
    }

            public static void verifyCertificateHash(X509Certificate certificate, String expectedHash)
            throws CertificateException {
        if (certificate == null) {
            throw new CertificateException("SCP leaf certificate is missing");
        }
        try {
            byte[] expected = decodeSha256(expectedHash);
            byte[] actual = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            if (!MessageDigest.isEqual(expected, actual)) {
                String actualHex = java.util.HexFormat.of().formatHex(actual);
                android.util.Log.e("SCPVerifier", "SCP hash mismatch! Expected: " + expectedHash + ", Actual: " + actualHex);
                throw new CertificateException("SCP app-server certificate hash mismatch");
            }
        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("Unable to verify SCP certificate hash", e);
        }
    }

    private static byte[] decodeSha256(String value) {
        if (value == null) {
            throw new IllegalArgumentException("SCP SHA-256 certificate hash is required");
        }
        String normalized = value.replace(":", "").trim().toLowerCase(Locale.ROOT);
        if (!normalized.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("SCP pin must be a SHA-256 hex digest");
        }
        return java.util.HexFormat.of().parseHex(normalized);
    }
}
