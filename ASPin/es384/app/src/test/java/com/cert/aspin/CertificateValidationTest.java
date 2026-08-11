package com.cert.aspin;

import org.junit.Test;

import java.util.List;
import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class CertificateValidationTest {
    @Test
    public void aspinRequiresClaimedSubjectAndSan() {
        assertThrows(IllegalArgumentException.class, () -> ASPinVerifier.parseVerifiedClaim(
                "api.example", "{\"issuer\":[\"sha256:invalid\"]}"));
    }

    @Test
    public void aspinSupportsTransitionalIssuerAndSanLists() throws Exception {
        String oldIssuer = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        String newIssuer = "sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        ASPinVerifier.CertificateClaim claim = ASPinVerifier.parseVerifiedClaim(
                "api.example", "{\"subject\":\"CN=api.example\","
                        + "\"san\":[\"api.example\",\"backup.example\"],"
                        + "\"issuer\":[\"" + oldIssuer + "\",\"" + newIssuer + "\"]}");

        assertEquals("api.example", claim.getHost());
        assertEquals(List.of("api.example", "backup.example"),
                claim.getSubjectAlternativeNames());
        assertEquals(List.of(oldIssuer, newIssuer), claim.getIssuerIdentifiers());
    }

    @Test
    public void claimHostnameUsesSanPrecedenceAndNativeStyleWildcards() {
        assertTrue(ASPinVerifier.hostMatchesClaim(
                "api.example.com", "CN=ignored.example", List.of("*.example.com")));
        assertFalse(ASPinVerifier.hostMatchesClaim(
                "nested.api.example.com", "CN=nested.api.example.com",
                List.of("*.example.com")));
        assertFalse(ASPinVerifier.hostMatchesClaim(
                "subject.example", "CN=subject.example", List.of("other.example")));
        assertTrue(ASPinVerifier.hostMatchesClaim(
                "subject.example", "CN=subject.example", List.of()));
    }

    @Test
    public void claimHostnameDistinguishesDnsAndIpSan() {
        assertTrue(ASPinVerifier.hostMatchesClaim(
                "2001:db8::1", "CN=unused", List.of("2001:0db8:0:0:0:0:0:1")));
        assertFalse(ASPinVerifier.hostMatchesClaim(
                "192.0.2.1", "CN=192.0.2.1", List.of("192.0.2.2")));
    }

    @Test
    public void connectionHostnameMustEqualClaimLookupHostname() {
        assertTrue(ASPinVerifier.sameHostname("API.Example.", "api.example"));
        assertTrue(ASPinVerifier.sameHostname("[2001:db8::1]", "2001:0db8::1"));
        assertFalse(ASPinVerifier.sameHostname("api.example", "other.example"));
        assertThrows(IllegalArgumentException.class,
                () -> ASPinVerifier.sameHostname("https://api.example", "api.example"));
    }

    @Test
    public void issuerIdentifierDoesNotDependOnDisplayFormat() throws Exception {
        X500Principal issuer = new X500Principal("CN=Issuer CA,O=Example,C=US");
        X500Principal reparsed = new X500Principal(issuer.getName(X500Principal.RFC1779));
        assertEquals(ASPinVerifier.issuerIdentifier(issuer),
                ASPinVerifier.issuerIdentifier(reparsed));
    }
}
