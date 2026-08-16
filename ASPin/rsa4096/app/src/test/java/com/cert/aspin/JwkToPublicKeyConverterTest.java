package com.cert.aspin;

import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class JwkToPublicKeyConverterTest {
    @Test
    public void convertsDelegatedKeyFromCurrentTk() throws Exception {
        String variant = new File("..").getCanonicalFile().getName();
        String token = JsonUtils.read_file("src/main/resources/ClaimSigningKey.jws");
        String encodedPayload = new JSONObject(token).getString("payload");
        JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(
                encodedPayload + "=".repeat((4 - encodedPayload.length() % 4) % 4)),
                java.nio.charset.StandardCharsets.UTF_8));
        String delegatedJwk = payload.getJSONObject("cnf").getJSONObject("jwk").toString();

        assertTrue(JwkToPublicKeyConverter.isValidJwk(delegatedJwk));
        PublicKey key = JwkToPublicKeyConverter.convertJwkToPublicKey(delegatedJwk);
        assertNotNull(key);
        if (variant.startsWith("rsa")) {
            assertTrue(key instanceof RSAPublicKey);
        } else {
            assertTrue(key instanceof ECPublicKey);
        }
    }

    @Test
    public void rejectsInvalidJwk() {
        assertFalse(JwkToPublicKeyConverter.isValidJwk("invalid json"));
        assertFalse(JwkToPublicKeyConverter.isValidJwk(null));
        assertFalse(JwkToPublicKeyConverter.isValidJwk(""));
        assertThrows(Exception.class,
                () -> JwkToPublicKeyConverter.convertJwkToPublicKey((String) null));
        assertThrows(Exception.class,
                () -> JwkToPublicKeyConverter.convertJwkToPublicKey(""));
    }
}
