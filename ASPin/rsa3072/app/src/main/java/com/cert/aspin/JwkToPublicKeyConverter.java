package com.cert.aspin;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;

import org.json.JSONObject;

/**
 * Utility class to convert JWK (JSON Web Key) strings to Java PublicKey objects.
 * Supports RSA, EC (Elliptic Curve), and OKP (Octet Key Pair) key types.
 */
public class JwkToPublicKeyConverter {

    /**
     * Converts a JWK JSON string to a PublicKey object.
     * 
     * @param jwkJsonString The JWK as a JSON string
     * @return PublicKey object
     * @throws Exception if the JWK format is invalid or unsupported
     */
    public static PublicKey convertJwkToPublicKey(String jwkJsonString) throws Exception {
        if (jwkJsonString == null || jwkJsonString.trim().isEmpty()) {
            throw new IllegalArgumentException("JWK JSON string cannot be null or empty");
        }

        try {
            // Parse the JWK using Nimbus JOSE JWT library
            JWK jwk = JWK.parse(jwkJsonString);
            return convertJwkToPublicKey(jwk);
        } catch (Exception e) {
            throw new Exception("Failed to parse JWK: " + e.getMessage(), e);
        }
    }

    /**
     * Converts a JWK object to a PublicKey object.
     * 
     * @param jwk The JWK object
     * @return PublicKey object
     * @throws Exception if the key type is unsupported
     */
    public static PublicKey convertJwkToPublicKey(JWK jwk) throws Exception {
        if (jwk == null) {
            throw new IllegalArgumentException("JWK cannot be null");
        }

        try {
            if (jwk instanceof RSAKey) {
                return convertRsaJwkToPublicKey((RSAKey) jwk);
            } else if (jwk instanceof ECKey) {
                return convertEcJwkToPublicKey((ECKey) jwk);
            } else if (jwk instanceof OctetKeyPair) {
                return convertOkpJwkToPublicKey((OctetKeyPair) jwk);
            } else {
                throw new UnsupportedOperationException("Unsupported key type: " + jwk.getKeyType());
            }
        } catch (Exception e) {
            throw new Exception("Failed to convert JWK to PublicKey: " + e.getMessage(), e);
        }
    }

    /**
     * Converts an RSA JWK to RSAPublicKey.
     */
    private static RSAPublicKey convertRsaJwkToPublicKey(RSAKey rsaKey) throws Exception {
        try {
            // Get the RSA public key directly from the JWK
            return rsaKey.toRSAPublicKey();
        } catch (Exception e) {
            throw new Exception("Failed to convert RSA JWK to PublicKey: " + e.getMessage(), e);
        }
    }

    /**
     * Converts an EC JWK to ECPublicKey.
     */
    private static ECPublicKey convertEcJwkToPublicKey(ECKey ecKey) throws Exception {
        try {
            java.math.BigInteger x = new java.math.BigInteger(1, ecKey.getX().decode());
            java.math.BigInteger y = new java.math.BigInteger(1, ecKey.getY().decode());
            java.security.spec.ECPoint w = new java.security.spec.ECPoint(x, y);
            
            String crv = ecKey.getCurve().getName();
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
            params.init(new java.security.spec.ECGenParameterSpec(crv));
            java.security.spec.ECParameterSpec ecSpec = params.getParameterSpec(java.security.spec.ECParameterSpec.class);
            
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
            return (ECPublicKey) kf.generatePublic(new java.security.spec.ECPublicKeySpec(w, ecSpec));
        } catch (Exception e) {
            return ecKey.toECPublicKey();
        }
    }

    /**
     * Converts an OKP (Octet Key Pair) JWK to PublicKey.
     * This is typically used for Ed25519 and Ed448 keys.
     */
    private static PublicKey convertOkpJwkToPublicKey(OctetKeyPair okpKey) throws Exception {
        try {
            // Get the public key directly from the OKP JWK
            return okpKey.toPublicKey();
        } catch (Exception e) {
            throw new Exception("Failed to convert OKP JWK to PublicKey: " + e.getMessage(), e);
        }
    }

    /**
     * Converts a JWK Set (multiple JWKs) to an array of PublicKey objects.
     * 
     * @param jwkSetJsonString The JWK Set as a JSON string
     * @return Array of PublicKey objects
     * @throws Exception if the JWK Set format is invalid
     */
    public static PublicKey[] convertJwkSetToPublicKeys(String jwkSetJsonString) throws Exception {
        if (jwkSetJsonString == null || jwkSetJsonString.trim().isEmpty()) {
            throw new IllegalArgumentException("JWK Set JSON string cannot be null or empty");
        }

        try {
            JWKSet jwkSet = JWKSet.parse(jwkSetJsonString);
            return jwkSet.getKeys().stream()
                    .map(jwk -> {
                        try {
                            return convertJwkToPublicKey(jwk);
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to convert JWK in set: " + e.getMessage(), e);
                        }
                    })
                    .toArray(PublicKey[]::new);
        } catch (Exception e) {
            throw new Exception("Failed to parse JWK Set: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts JWK from a JWT payload and converts it to PublicKey.
     * This is useful when the JWK is embedded in a JWT token.
     * 
     * @param jwtPayload The JWT payload as a JSON string
     * @return PublicKey object
     * @throws Exception if the JWT payload doesn't contain a valid JWK
     */
    public static PublicKey extractJwkFromJwtPayload(String jwtPayload) throws Exception {
        if (jwtPayload == null || jwtPayload.trim().isEmpty()) {
            throw new IllegalArgumentException("JWT payload cannot be null or empty");
        }

        try {
            JSONObject payload = new JSONObject(jwtPayload);
            
            // Check if the payload contains JWK fields
            if (payload.has("kty") && payload.has("x")) {
                // This looks like a JWK, convert it directly
                return convertJwkToPublicKey(payload.toString());
            } else {
                throw new IllegalArgumentException("JWT payload does not contain a valid JWK");
            }
        } catch (Exception e) {
            throw new Exception("Failed to extract JWK from JWT payload: " + e.getMessage(), e);
        }
    }

    /**
     * Validates if a string contains a valid JWK format.
     * 
     * @param jwkJsonString The potential JWK JSON string
     * @return true if the string contains a valid JWK, false otherwise
     */
    public static boolean isValidJwk(String jwkJsonString) {
        if (jwkJsonString == null || jwkJsonString.trim().isEmpty()) {
            return false;
        }

        try {
            JWK.parse(jwkJsonString);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Gets the key type from a JWK JSON string.
     * 
     * @param jwkJsonString The JWK as a JSON string
     * @return The key type (e.g., "RSA", "EC", "OKP")
     * @throws Exception if the JWK format is invalid
     */
    public static String getKeyType(String jwkJsonString) throws Exception {
        if (jwkJsonString == null || jwkJsonString.trim().isEmpty()) {
            throw new IllegalArgumentException("JWK JSON string cannot be null or empty");
        }

        try {
            JWK jwk = JWK.parse(jwkJsonString);
            return jwk.getKeyType().getValue();
        } catch (Exception e) {
            throw new Exception("Failed to get key type from JWK: " + e.getMessage(), e);
        }
    }
}
