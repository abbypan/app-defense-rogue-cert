package com.abbypan.appservercert;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.JOSEException;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.json.JSONObject;



public class JwtVerifier {
    public static String verifyJwtWithCert(String token, String cert) throws Exception {
        // 3️⃣ Load certificate public key
        PublicKey publicKey = PemUtils.parseX509Certificate(cert).getPublicKey();
    return verifyJwt(token, publicKey);
    }

    /**
     * Verifies a JWT token using a JWK (JSON Web Key) string.
     * 
     * @param token The JWT token to verify
     * @param jwkJsonString The JWK as a JSON string
     * @return The JWT payload as a string
     * @throws Exception if verification fails or JWK is invalid
     */
    public static String verifyJwtWithJwk(String token, String jwkJsonString) throws Exception {
        // Convert JWK to PublicKey
        PublicKey publicKey = JwkToPublicKeyConverter.convertJwkToPublicKey(jwkJsonString);
        return verifyJwt(token, publicKey);
    }
        public static String verifyJwt(String token, PublicKey publicKey) throws Exception {


            // 4️⃣ Create appropriate verifier
        JWSVerifier verifier;
        if (publicKey instanceof ECPublicKey) {
            verifier = new ECDSAVerifier((ECPublicKey) publicKey);
        } else if (publicKey instanceof RSAPublicKey) {
            verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
            throw new IllegalArgumentException("Unsupported key type: " + publicKey.getAlgorithm());
        }

        // Check if token is JSON-serialized or compact format
        if (token.trim().startsWith("{")) {
            // JSON-serialized JWT
            return verifyJsonSerializedJwt(token, verifier);
            } else {
            // Compact JWT format
            return verifyCompactJwt(token, verifier);
        }
    }

    private static String verifyJsonSerializedJwt(String jsonToken, JWSVerifier verifier) throws Exception {
        // Parse the JSON to extract JWT components
        JSONObject jsonObj = new JSONObject(jsonToken);
        
        // Extract header, payload, and signature
        String header = jsonObj.optString("header", "");
        String payload = jsonObj.optString("payload", "");
        String signature = jsonObj.optString("signature", "");
        
        if (header.isEmpty() || payload.isEmpty() || signature.isEmpty()) {
            throw new IllegalArgumentException("JSON JWT missing required fields (header, payload, signature)");
        }
        
        // Construct compact JWT format
        String compactToken = header + "." + payload + "." + signature;
        
        // Verify using compact format
        return verifyCompactJwt(compactToken, verifier);
    }

    private static String verifyCompactJwt(String compactToken, JWSVerifier verifier) throws Exception {
        // Parse compact JWT
        SignedJWT signedJWT = SignedJWT.parse(compactToken);

        // Verify signature
        boolean valid = signedJWT.verify(verifier);
        if (!valid) {
            throw new RuntimeException("JWT signature verification failed ❌");
        }

        String payload = signedJWT.getPayload().toString();
        //System.out.println("JWT verified ✅");
        //System.out.println("Payload JSON: " + payload);
        return payload;
    }
}