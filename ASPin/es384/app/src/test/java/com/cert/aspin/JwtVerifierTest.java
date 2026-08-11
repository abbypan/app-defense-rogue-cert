package com.cert.aspin;

import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** Checks the auxiliary verifier against the OS-level ASPin token schema. */
public class JwtVerifierTest {
    @Test
    public void verifiesCurrentTkAndTcSchema() throws Exception {
        String variant = new File("..").getCanonicalFile().getName();
        String appCertificate = JsonUtils.read_file(
                "../../../signing/" + variant + "/my-app-cert.pem");
        String tk = JsonUtils.read_file("src/main/resources/ClaimSigningKey.jwt");
        String tc = JsonUtils.read_file("src/main/resources/ServerCertClaim.jwt");

        com.nimbusds.jwt.SignedJWT parsedTk = com.nimbusds.jwt.SignedJWT.parse(tk);
        com.nimbusds.jwt.SignedJWT parsedTc = com.nimbusds.jwt.SignedJWT.parse(tc);
        assertEquals(Set.of("alg", "kid"), parsedTk.getHeader().getIncludedParams());
        assertEquals(Set.of("alg", "kid"), parsedTc.getHeader().getIncludedParams());

        JSONObject tkPayload = new JSONObject(JwtVerifier.verifyJwtWithCertDetails(
                tk, appCertificate,
                parsedTk.getJWTClaimsSet().getIssueTime().getTime()).getPayload());
        assertEquals(Set.of("cnf", "iat", "exp"), keys(tkPayload));
        assertTrue(tkPayload.getJSONObject("cnf").has("jwk"));
        assertTrue(tkPayload.getLong("iat") < tkPayload.getLong("exp"));

        String claimJwk = JwtVerifier.extractConfirmationJwk(tkPayload.toString());
        JSONObject tcPayload = new JSONObject(JwtVerifier.verifyJwtWithJwkDetails(
                tc, claimJwk,
                parsedTc.getJWTClaimsSet().getIssueTime().getTime()).getPayload());
        assertEquals(
                Set.of("subject", "san", "issuer", "iat", "exp"),
                keys(tcPayload));
        assertTrue(tcPayload.getJSONArray("san").length() > 0);
        assertTrue(tcPayload.getJSONArray("issuer").length() > 0);
        assertTrue(tcPayload.getLong("iat") < tcPayload.getLong("exp"));
        assertFalse(tcPayload.has("host"));
        assertFalse(tcPayload.has("scope"));
        assertFalse(tcPayload.has("ttl"));
    }

    private static Set<String> keys(JSONObject object) {
        Set<String> result = new HashSet<>();
        java.util.Iterator<String> iterator = object.keys();
        while (iterator.hasNext()) result.add(iterator.next());
        return result;
    }
}
