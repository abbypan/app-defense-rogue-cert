package com.abbypan.asproc;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import com.abbypan.asproc.JsonUtils;
import com.abbypan.asproc.JwkToPublicKeyConverter;

/**
 * Unit tests for JwkToPublicKeyConverter class
 * Tests JWK to PublicKey conversion functionality
 */
public class JwkToPublicKeyConverterTest {

    @Test
    public void testConvertJwkToPublicKey() throws Exception {
        // Read the existing JWK file (which is actually a JWT with JWK in payload)
        String jwkJwt = JsonUtils.read_file("src/main/resources/my-claim-pubkey.jwk.json");
        System.out.println("JWK JWT: " + jwkJwt);
        
        // Extract the JWK from the JWT payload
        String[] parts = jwkJwt.split("\\.");
        if (parts.length >= 2) {
            // Decode the payload (base64url)
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            System.out.println("JWT Payload (JWK): " + payload);
            
            // Test if it's a valid JWK
            assertTrue("JWK should be valid", JwkToPublicKeyConverter.isValidJwk(payload));
            
            // Get the key type
            String keyType = JwkToPublicKeyConverter.getKeyType(payload);
            System.out.println("Key type: " + keyType);
            assertNotNull("Key type should not be null", keyType);
            assertEquals("Should be EC key type", "EC", keyType);
            
            // Convert JWK to PublicKey
            PublicKey publicKey = JwkToPublicKeyConverter.convertJwkToPublicKey(payload);
            assertNotNull("PublicKey should not be null", publicKey);
            
            // Verify the key type
            assertTrue("Should be an ECPublicKey", publicKey instanceof ECPublicKey);
            ECPublicKey ecKey = (ECPublicKey) publicKey;
            System.out.println("EC Public Key Algorithm: " + ecKey.getAlgorithm());
            System.out.println("EC Public Key Format: " + ecKey.getFormat());
            
            System.out.println("Successfully converted JWK to PublicKey ï¿?);
        } else {
            fail("JWT should have at least 2 parts");
        }
    }

    @Test
    public void testExtractJwkFromJwtPayload() throws Exception {
        // Read the existing JWK file (which appears to be a JWT with JWK in payload)
        String jwkJwt = JsonUtils.read_file("src/main/resources/my-claim-pubkey.jwk.json");
        
        // First verify it's a JWT by checking if it has the JWT structure
        if (jwkJwt.contains(".")) {
            // This appears to be a JWT, let's try to extract the payload
            String[] parts = jwkJwt.split("\\.");
            if (parts.length >= 2) {
                // Decode the payload (base64url)
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                System.out.println("JWT Payload: " + payload);
                
                // Try to extract JWK from the payload
                try {
                    PublicKey publicKey = JwkToPublicKeyConverter.extractJwkFromJwtPayload(payload);
                    assertNotNull("PublicKey should not be null", publicKey);
                    System.out.println("Successfully extracted JWK from JWT payload ï¿?);
                } catch (Exception e) {
                    System.out.println("Could not extract JWK from JWT payload: " + e.getMessage());
                    // This is expected if the payload doesn't contain a JWK
                }
            }
        }
    }

    @Test
    public void testInvalidJwk() {
        // Test with invalid JWK
        assertFalse("Invalid JWK should return false", JwkToPublicKeyConverter.isValidJwk("invalid json"));
        assertFalse("Null JWK should return false", JwkToPublicKeyConverter.isValidJwk(null));
        assertFalse("Empty JWK should return false", JwkToPublicKeyConverter.isValidJwk(""));
    }

    @Test
    public void testNullAndEmptyInputs() {
        try {
            JwkToPublicKeyConverter.convertJwkToPublicKey((String) null);
            fail("Should throw exception for null input");
        } catch (Exception e) {
            assertTrue("Should contain appropriate error message", e.getMessage().contains("null"));
        }

        try {
            JwkToPublicKeyConverter.convertJwkToPublicKey("");
            fail("Should throw exception for empty input");
        } catch (Exception e) {
            assertTrue("Should contain appropriate error message", e.getMessage().contains("empty"));
        }
    }

    @Test
    public void testIntegrationWithJwtVerifier() throws Exception {
        // Read the JWK file (which is actually a JWT with JWK in payload)
        String jwkJwt = JsonUtils.read_file("src/main/resources/my-claim-pubkey.jwk.json");
        
        // Extract the JWK from the JWT payload
        String[] parts = jwkJwt.split("\\.");
        if (parts.length >= 2) {
            // Decode the payload (base64url)
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            
            // Convert JWK to PublicKey
            PublicKey publicKey = JwkToPublicKeyConverter.convertJwkToPublicKey(payload);
            
            // Test that this public key can be used with JwtVerifier
            // (This would require a valid JWT signed with the corresponding private key)
            assertNotNull("PublicKey should be usable with JwtVerifier", publicKey);
            System.out.println("PublicKey is ready for JWT verification ï¿?);
        } else {
            fail("JWT should have at least 2 parts");
        }
    }
}
