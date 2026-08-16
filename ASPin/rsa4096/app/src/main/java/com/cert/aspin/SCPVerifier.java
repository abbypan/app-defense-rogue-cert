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
 * app-server leaf certificate. Preset strictly for rsa4096.
 */
public final class SCPVerifier {
    private static final Map<String, String> PRESET_CERTIFICATE_HASHES;

        static {
        Map<String, String> pins = new HashMap<>();
        pins.put("es256.idouzi.top", "ca1ec3c2a9ecc27a473c505a3317c02988e035b6605d4491219352b67e25a0dc");
        pins.put("es384.idouzi.top", "69d30ea462fdc15c57bce3d14e8588ab50ec45a739ffba03b0bad944a4159156");
        pins.put("rsa3072.idouzi.top", "73355ddb56bbff4f50730b6e4b70295d0b2d385925d82d7fc7eef24ef4571b2a");
        pins.put("rsa4096.idouzi.top", "7054416ec422b1fc51f8805e11847811c1071f3d50140218e5549c142ad2ffef");
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
            return "ca1ec3c2a9ecc27a473c505a3317c02988e035b6605d4491219352b67e25a0dc";
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
