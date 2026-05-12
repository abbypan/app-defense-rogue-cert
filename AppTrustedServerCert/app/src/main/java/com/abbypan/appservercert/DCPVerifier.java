package com.abbypan.appservercert;

import org.json.JSONObject;

import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Verifies DCP pin JSON produced by signing/*/gen_dcp.py.
 */
public class DCPVerifier {
    public static String verifyDCPWithPublicKeyPem(String dcpJson, String dcpPublicKeyPem) throws Exception {
        PublicKey publicKey = parsePublicKey(dcpPublicKeyPem);
        return verifyDCP(dcpJson, publicKey);
    }

    public static String verifyDCP(String dcpJson, PublicKey publicKey) throws Exception {
        JSONObject json = new JSONObject(dcpJson);
        String pin = json.getString("pin");
        String sig = json.getString("sig");

        byte[] pinBytes = hexToBytes(pin);
        byte[] sigBytes = hexToBytes(sig);

        boolean valid;
        if (publicKey instanceof ECPublicKey) {
            valid = verifyECDSA(pinBytes, sigBytes, publicKey);
        } else if (publicKey instanceof RSAPublicKey) {
            valid = verifyRSA(pinBytes, sigBytes, publicKey);
        } else {
            throw new IllegalArgumentException("Unsupported DCP key type: " + publicKey.getAlgorithm());
        }

        if (!valid) {
            throw new SecurityException("DCP signature verification failed");
        }

        return normalizeHex(pin);
    }

    private static PublicKey parsePublicKey(String dcpPublicKeyPem) throws Exception {
        Object parsed = PemUtils.parsePemString(dcpPublicKeyPem);
        if (parsed instanceof java.security.cert.X509Certificate cert) {
            return cert.getPublicKey();
        }
        if (parsed instanceof PublicKey publicKey) {
            return publicKey;
        }
        throw new IllegalArgumentException("DCP PEM does not contain a public key or certificate");
    }

    private static boolean verifyECDSA(byte[] pinBytes, byte[] sigBytes, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("NONEwithECDSA");
        verifier.initVerify(publicKey);
        verifier.update(pinBytes);
        return verifier.verify(sigBytes);
    }

    private static boolean verifyRSA(byte[] pinBytes, byte[] sigBytes, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(pinBytes);
        return verifier.verify(sigBytes);
    }

    private static byte[] hexToBytes(String hex) {
        String normalized = normalizeHex(hex);
        if (normalized.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string length must be even");
        }

        byte[] bytes = new byte[normalized.length() / 2];
        for (int i = 0; i < normalized.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(normalized.substring(i, i + 2), 16);
        }
        return bytes;
    }

    private static String normalizeHex(String hex) {
        return hex.replace(":", "").toLowerCase();
    }
}
