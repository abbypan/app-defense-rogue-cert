package com.abbypan.aspin;

import org.json.JSONObject;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

public class DCPVerifier {
    public static final String PRESET_DCP_PUBLIC_KEY_PEM = 
        "-----BEGIN PUBLIC KEY-----\n" +
        "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzPhDW0zuD+38SjfxDmvt\n" +
        "Kuum5CLs8zBi4podRCD4D6+9fX8g1MlsVMhvyaMtnIxRLqk70al9LpJg2IkgODfv\n" +
        "tdov4svoNF1cdRlyPPI+pvrb90oDD+F+8by/16kPMxE1H2vD3pew/DUSqTcPBBLg\n" +
        "Zr3YGONsTGNkrCBmfQ2YapPtTsN7LTvJS7rvz/ZR+ElW3dQMzjNznIQiZLpXsclG\n" +
        "MVPxU5xxwL5yylE0EAzThPYrJWg/dVEPV38BxScTKKPTdIwkBP4aXhCkADi8HgJ+\n" +
        "wHZvZde8xaG6Za4X2fbPmVrAxHDQElYFeZhjlp9RRksNQHHtzm+EtFlNPR3j3YuX\n" +
        "xvtTe3nEEEOfQ3NI+1zbo9akV/SZYFNsAiyQTJXDLEFMCQHsNQ7WhxtInYGe9AH+\n" +
        "f03WhCocUx7MGrIq9B8eh2RBVwZ7P33Me+sII/IzWv4MAotlwHVA9hNqpF4FsVqD\n" +
        "QRSuuLyDitlgxI0a8IsMN9b95kA16naDEvRgK3IwRLt7AgMBAAE=\n" +
        "-----END PUBLIC KEY-----";

    public static String getPresetDcpPublicKeyPem() {
        return PRESET_DCP_PUBLIC_KEY_PEM;
    }

    public static String verifyPresetDCP(String dcpJson) throws Exception {
        return verifyDCPWithPublicKeyPem(dcpJson, PRESET_DCP_PUBLIC_KEY_PEM);
    }

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

        if (!verifySignature(publicKey, pinBytes, signatureBytes)) {
            throw new RuntimeException("DCP signature verification failed");
        }

        return normalizePin(pin);
    }

    /** Checks the authenticated dynamic pin against the leaf certificate SPKI. */
    public static void verifyCertificatePin(X509Certificate certificate, String authenticatedPin)
            throws CertificateException {
        try {
            String normalizedPin = normalizePin(authenticatedPin);
            byte[] expected = decodeValue(normalizedPin);
            String algorithm = expected.length == 32 ? "SHA-256" : "SHA-384";
            byte[] actual = MessageDigest.getInstance(algorithm)
                    .digest(certificate.getPublicKey().getEncoded());
            if (!MessageDigest.isEqual(expected, actual)) {
                throw new CertificateException("DCP subject-public-key pin mismatch");
            }
        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("Unable to verify DCP certificate pin", e);
        }
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

    private static boolean verifySignature(PublicKey publicKey, byte[] pinBytes, byte[] signatureBytes) throws Exception {
        HashAlgorithm hashAlgorithm = hashAlgorithmForPin(pinBytes);
        if (publicKey instanceof ECPublicKey) {
            Signature verifier = Signature.getInstance("NONEwithECDSA");
            verifier.initVerify(publicKey);
            verifier.update(pinBytes);
            return verifier.verify(signatureBytes);
        } else if (publicKey instanceof RSAPublicKey) {
            return verifyRsaPss((RSAPublicKey) publicKey, pinBytes, signatureBytes, hashAlgorithm);
        } else {
            throw new IllegalArgumentException("Unsupported DCP key type: " + publicKey.getAlgorithm());
        }
    }

    private static boolean verifyRsaPss(
            RSAPublicKey publicKey,
            byte[] messageHash,
            byte[] signature,
            HashAlgorithm hashAlgorithm
    ) throws Exception {
        final int hashLength = hashAlgorithm.digestLength;
        final int saltLength = hashLength;

        BigInteger modulus = publicKey.getModulus();
        int modulusBits = modulus.bitLength();
        int emBits = modulusBits - 1;
        int emLen = (emBits + 7) / 8;
        if (emLen < hashLength + saltLength + 2) {
            return false;
        }

        BigInteger signatureInt = new BigInteger(1, signature);
        if (signatureInt.compareTo(modulus) >= 0) {
            return false;
        }

        byte[] em = toFixedLength(signatureInt.modPow(publicKey.getPublicExponent(), modulus), emLen);
        return verifyPssEncoding(messageHash, em, emBits, hashAlgorithm, saltLength);
    }

    private static boolean verifyPssEncoding(
            byte[] messageHash,
            byte[] encodedMessage,
            int emBits,
            HashAlgorithm hashAlgorithm,
            int saltLength
    ) throws Exception {
        int hashLength = hashAlgorithm.digestLength;
        int emLen = encodedMessage.length;
        if (encodedMessage[emLen - 1] != (byte) 0xbc) {
            return false;
        }

        int dbLength = emLen - hashLength - 1;
        byte[] maskedDb = Arrays.copyOfRange(encodedMessage, 0, dbLength);
        byte[] hash = Arrays.copyOfRange(encodedMessage, dbLength, dbLength + hashLength);

        int unusedBits = 8 * emLen - emBits;
        if (unusedBits > 0 && ((maskedDb[0] & 0xff) >>> (8 - unusedBits)) != 0) {
            return false;
        }

        byte[] dbMask = mgf1(hash, dbLength, hashAlgorithm);
        byte[] db = new byte[dbLength];
        for (int i = 0; i < dbLength; i++) {
            db[i] = (byte) (maskedDb[i] ^ dbMask[i]);
        }
        if (unusedBits > 0) {
            db[0] &= (byte) (0xff >>> unusedBits);
        }

        int psLength = emLen - hashLength - saltLength - 2;
        for (int i = 0; i < psLength; i++) {
            if (db[i] != 0) {
                return false;
            }
        }
        if (db[psLength] != 0x01) {
            return false;
        }

        byte[] salt = Arrays.copyOfRange(db, dbLength - saltLength, dbLength);
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm.jcaName);
        digest.update(new byte[8]);
        digest.update(messageHash);
        digest.update(salt);
        return MessageDigest.isEqual(hash, digest.digest());
    }

    private static byte[] mgf1(byte[] seed, int length, HashAlgorithm hashAlgorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm.jcaName);
        byte[] mask = new byte[length];
        byte[] counter = new byte[4];
        int offset = 0;

        for (int i = 0; offset < length; i++) {
            counter[0] = (byte) (i >>> 24);
            counter[1] = (byte) (i >>> 16);
            counter[2] = (byte) (i >>> 8);
            counter[3] = (byte) i;
            digest.update(seed);
            byte[] block = digest.digest(counter);
            int copyLength = Math.min(block.length, length - offset);
            System.arraycopy(block, 0, mask, offset, copyLength);
            offset += copyLength;
        }

        return mask;
    }

    private static HashAlgorithm hashAlgorithmForPin(byte[] pinBytes) {
        if (pinBytes.length == HashAlgorithm.SHA256.digestLength) {
            return HashAlgorithm.SHA256;
        }
        if (pinBytes.length == HashAlgorithm.SHA384.digestLength) {
            return HashAlgorithm.SHA384;
        }
        throw new IllegalArgumentException("DCP pin must be a SHA-256 or SHA-384 digest");
    }

    private enum HashAlgorithm {
        SHA256("SHA-256", 32),
        SHA384("SHA-384", 48);

        private final String jcaName;
        private final int digestLength;

        HashAlgorithm(String jcaName, int digestLength) {
            this.jcaName = jcaName;
            this.digestLength = digestLength;
        }
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        if (bytes.length == length + 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        if (bytes.length > length) {
            throw new IllegalArgumentException("Integer does not fit expected length");
        }
        byte[] fixed = new byte[length];
        System.arraycopy(bytes, 0, fixed, length - bytes.length, bytes.length);
        return fixed;
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
