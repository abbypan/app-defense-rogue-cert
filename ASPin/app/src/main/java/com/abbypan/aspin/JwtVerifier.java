package com.abbypan.aspin;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.JOSEException;

import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.io.ByteArrayInputStream;
import java.util.Date;
import java.util.List;

import org.json.JSONObject;



public class JwtVerifier {
    public static String verifyJwtWithCert(String token, String cert) throws Exception {
        // Load certificate public key
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


            // Create appropriate verifier
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
            return verifyJsonSerializedJwt(token, verifier, publicKey);
            } else {
            // Compact JWT format
            return verifyCompactJwt(token, verifier, publicKey);
        }
    }

    
    private static String verifyJsonSerializedJwt(
            String jsonToken, JWSVerifier verifier, PublicKey trustedPublicKey) throws Exception {
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
        return verifyCompactJwt(compactToken, verifier, trustedPublicKey);
    }

    private static String verifyCompactJwt(
            String compactToken, JWSVerifier verifier, PublicKey trustedPublicKey) throws Exception {
        // Parse compact JWT
        SignedJWT signedJWT = SignedJWT.parse(compactToken);

        // Verify signature
        boolean valid = signedJWT.verify(verifier);
        if (!valid) {
            throw new RuntimeException("JWT signature verification failed");
        }

        Date expiration = signedJWT.getJWTClaimsSet().getExpirationTime();
        if (expiration == null) {
            throw new RuntimeException("JWT expiration time is required");
        }
        if (!expiration.after(new Date())) {
            throw new RuntimeException("JWT has expired");
        }

        List<com.nimbusds.jose.util.Base64> certificateChain =
                signedJWT.getHeader().getX509CertChain();
        if (certificateChain != null && !certificateChain.isEmpty()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate headerCertificate = (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(certificateChain.get(0).decode()));
            if (!MessageDigest.isEqual(
                    trustedPublicKey.getEncoded(), headerCertificate.getPublicKey().getEncoded())) {
                throw new RuntimeException("JWT x5c key does not match the trusted verification key");
            }
        }

        String payload = signedJWT.getPayload().toString();
        //System.out.println("JWT verified");
        //System.out.println("Payload JSON: " + payload);
        return payload;
    }
}

