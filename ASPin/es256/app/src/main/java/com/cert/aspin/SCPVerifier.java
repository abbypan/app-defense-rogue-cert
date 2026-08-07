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
        pins.put("es256.idouzi.top", "ce8525034c4ab2ead778cf84b90c914d694565f1ef929ebd9341d6a072ea8672");
        pins.put("es384.idouzi.top", "7ba0fb371c932c3af188fe46255cb686f937015495714ef5c94ebeb86233a437");
        pins.put("rsa3072.idouzi.top", "c62b670a0b696a44ffbeea466403b86459f64bef37936094c6af51b7556046ff");
        pins.put("rsa4096.idouzi.top", "37aec2e5b92c7c6dfe68f34e92f6ccf42309a242f394762d42699dd9bc708b81");
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
            return "ce8525034c4ab2ead778cf84b90c914d694565f1ef929ebd9341d6a072ea8672";
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
