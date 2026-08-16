package com.cert.aspin;

import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/** Checks the auxiliary verifier against the OS-level ASPin token schema. */
public class JwsVerifierTest {
    @Test
    public void verifiesCurrentTkAndTcSchema() throws Exception {
        String variant = new File("..").getCanonicalFile().getName();
        String appCertificate = JsonUtils.read_file(
                "../../../signing/" + variant + "/my-app-cert.pem");
        String tk = JsonUtils.read_file("src/main/resources/ClaimSigningKey.jws");
        String tc = JsonUtils.read_file("src/main/resources/ServerCertClaim.jws");

        JSONObject tkGeneral = new JSONObject(tk);
        JSONObject tcGeneral = new JSONObject(tc);
        assertEquals(Set.of("payload", "signatures"), keys(tkGeneral));
        assertEquals(Set.of("payload", "signatures"), keys(tcGeneral));
        assertEquals(1, tkGeneral.getJSONArray("signatures").length());
        assertEquals(1, tcGeneral.getJSONArray("signatures").length());
        com.nimbusds.jose.JWSObject parsedTk = parseSignatureEntry(tkGeneral, 0);
        com.nimbusds.jose.JWSObject parsedTc = parseSignatureEntry(tcGeneral, 0);
        assertEquals(Set.of("alg", "kid"), parsedTk.getHeader().getIncludedParams());
        assertEquals(Set.of("alg", "kid"), parsedTc.getHeader().getIncludedParams());

        JSONObject rawTkPayload = new JSONObject(parsedTk.getPayload().toString());
        JSONObject tkPayload = new JSONObject(JwsVerifier.verifyJwsWithCertDetails(
                tk, appCertificate,
                rawTkPayload.getLong("iat") * 1_000L).getPayload());
        assertEquals(Set.of("cnf", "iat", "exp"), keys(tkPayload));
        assertTrue(tkPayload.getJSONObject("cnf").has("jwk"));
        assertTrue(tkPayload.getLong("iat") < tkPayload.getLong("exp"));

        String claimJwk = JwsVerifier.extractConfirmationJwk(tkPayload.toString());
        JSONObject rawTcPayload = new JSONObject(parsedTc.getPayload().toString());
        JSONObject tcPayload = new JSONObject(JwsVerifier.verifyJwsWithJwkDetails(
                tc, claimJwk,
                rawTcPayload.getLong("iat") * 1_000L).getPayload());
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

    @Test
    public void rejectsNonGeneralSerializations() throws Exception {
        String variant = new File("..").getCanonicalFile().getName();
        String appCertificate = JsonUtils.read_file(
                "../../../signing/" + variant + "/my-app-cert.pem");
        JSONObject general = new JSONObject(
                JsonUtils.read_file("src/main/resources/ClaimSigningKey.jws"));
        JSONObject entry = general.getJSONArray("signatures").getJSONObject(0);
        String compact = entry.getString("protected") + "."
                + general.getString("payload") + "." + entry.getString("signature");
        JSONObject flattened = new JSONObject()
                .put("payload", general.getString("payload"))
                .put("protected", entry.getString("protected"))
                .put("signature", entry.getString("signature"));

        assertThrows(IllegalArgumentException.class,
                () -> JwsVerifier.verifyJwsWithCert(compact, appCertificate));
        assertThrows(IllegalArgumentException.class,
                () -> JwsVerifier.verifyJwsWithCert(flattened.toString(), appCertificate));
    }

    private static Set<String> keys(JSONObject object) {
        Set<String> result = new HashSet<>();
        java.util.Iterator<String> iterator = object.keys();
        while (iterator.hasNext()) result.add(iterator.next());
        return result;
    }

    private static com.nimbusds.jose.JWSObject parseSignatureEntry(JSONObject general, int index)
            throws Exception {
        JSONObject signature = general.getJSONArray("signatures").getJSONObject(index);
        assertEquals(Set.of("protected", "signature"), keys(signature));
        return com.nimbusds.jose.JWSObject.parse(
                signature.getString("protected") + "."
                        + general.getString("payload") + "."
                        + signature.getString("signature"));
    }
}
