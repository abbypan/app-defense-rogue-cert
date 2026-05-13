package com.abbypan.appservercert;

import org.json.JSONObject;

import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class DCPVerifier {
    public static String verifyDCPWithPublicKeyPem(String dcpJson, String dcpPublicKeyPem) throws Exception {
        PublicKey publicKey = parsePublicKeyPem(dcpPublicKeyPem);
        return verifyDCP(dcpJson, publicKey);
    }

    public static String verifyDCP(String dcpJson, PublicKey publicKey) throws Exception {
        JSONObject json = new JSONObject(dcpJson);
        String pin = json.getString("pin");
        String signature = getSignature(json);

        byte[] pinBytes = decodeValue(pin);
        byte[] signatureBytes = decodeValue(signature);

        Signature verifier = createVerifier(publicKey);
        verifier.initVerify(publicKey);
        verifier.update(pinBytes);

        if (!verifier.verify(signatureBytes)) {
            throw new RuntimeException("DCP signature verification failed");
        }

        return normalizePin(pin);
    }

    private static PublicKey parsePublicKeyPem(String publicKeyPem) throws Exception {
        Object parsed = PemUtils.parsePemString(publicKeyPem);
        if (parsed instanceof java.security.cert.X509Certificate certificate) {
            return certificate.getPublicKey();
        }
        if (parsed instanceof PublicKey publicKey) {
            return publicKey;
        }
        throw new IllegalArgumentException("DCP PEM does not contain a public key or certificate");
    }

    private static Signature createVerifier(PublicKey publicKey) throws Exception {
        if (publicKey instanceof ECPublicKey) {
            return Signature.getInstance("NONEwithECDSA");
        } else if (publicKey instanceof RSAPublicKey) {
            return Signature.getInstance("SHA256withRSA");
        } else {
            throw new IllegalArgumentException("Unsupported DCP key type: " + publicKey.getAlgorithm());
        }
    }

    private static String getSignature(JSONObject json) {
        String signature = json.optString("sig", "");
        if (signature.isEmpty()) {
            signature = json.optString("signature", "");
        }
        if (signature.isEmpty()) {
            throw new IllegalArgumentException("DCP JSON missing required field (sig)");
        }
        return signature;
    }

    private static byte[] decodeValue(String value) {
        String normalized = value.trim();
        if (isHex(normalized)) {
            return hexToBytes(normalized);
        }
        try {
            return Base64.getUrlDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            return Base64.getDecoder().decode(normalized);
        }
    }

    private static byte[] hexToBytes(String hex) {
        String normalized = normalizePin(hex);
        if (normalized.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string length must be even");
        }

        byte[] bytes = new byte[normalized.length() / 2];
        for (int i = 0; i < normalized.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(normalized.substring(i, i + 2), 16);
        }
        return bytes;
    }

    private static boolean isHex(String value) {
        String normalized = normalizePin(value);
        return !normalized.isEmpty() && normalized.matches("[0-9a-fA-F]+");
    }

    private static String normalizePin(String pin) {
        return pin.replace(":", "").toLowerCase();
    }
}
