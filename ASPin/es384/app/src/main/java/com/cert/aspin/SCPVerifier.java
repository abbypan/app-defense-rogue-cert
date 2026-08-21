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
 * app-server leaf certificate. Preset strictly for es384.
 */
public final class SCPVerifier {
    private static final Map<String, String> PRESET_CERTIFICATE_HASHES;

        static {
        Map<String, String> pins = new HashMap<>();
        pins.put("es256.idouzi.top", "2b66df42a8eba359d942dba05e693e43c8a67f7dd19a9b002d84db6fac5b33b5");
        pins.put("es384.idouzi.top", "05f4e3e3c639ff646393f3b8096ba07bc60b466e71ebf6091a71c9127c33b8db");
        pins.put("rsa3072.idouzi.top", "5886898d9cc5922ff29cc7727ea8ececd90e376bf532dca2fbd9cc729abcd28f");
        pins.put("rsa4096.idouzi.top", "9e71b695716cb1c383dbda9d97d116d9d274a2f39674a709ce8266d27a0003df");
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
            return "2b66df42a8eba359d942dba05e693e43c8a67f7dd19a9b002d84db6fac5b33b5";
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
