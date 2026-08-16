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
        pins.put("es256.idouzi.top", "93d6f15964f16503b2f5139acede752a76ea028e97810dc70afcbfbf804b6aa1");
        pins.put("es384.idouzi.top", "780612e02fba2f0c3344fa8b1b59d4c50781bfe73f66688877ad90b055bfe616");
        pins.put("rsa3072.idouzi.top", "4955602784ebf828eecd72da45cbae49f8405be951ad4e6425d3024f8bd940be");
        pins.put("rsa4096.idouzi.top", "70ef20eaafbdefc3dee524a06763708739c445ec9cdd618fe5cb4e11fd258cb2");
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
            return "93d6f15964f16503b2f5139acede752a76ea028e97810dc70afcbfbf804b6aa1";
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
