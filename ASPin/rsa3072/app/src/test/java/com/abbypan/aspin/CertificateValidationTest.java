package com.abbypan.aspin;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class CertificateValidationTest {
    @Test
    public void scpUsesPresetLeafCertificateHash() {
        assertEquals(
                "ce8525034c4ab2ead778cf84b90c914d694565f1ef929ebd9341d6a072ea8672",
                SCPVerifier.getPresetCertificateHash("ES256.IDOUZI.TOP"));
    }

    @Test
    public void scpRejectsUnknownHost() {
        assertThrows(IllegalArgumentException.class,
                () -> SCPVerifier.getPresetCertificateHash("unknown.example"));
    }

    @Test
    public void aspinRequiresClaimedSubjectAndSan() {
        assertThrows(IllegalArgumentException.class, () -> ASPinVerifier.parseVerifiedClaim(
                "{\"host\":\"api.example\",\"issuer\":\"CN=Example CA\"}"));
    }

    @Test
    public void aspinSupportsTransitionalIssuerAndSanLists() throws Exception {
        ASPinVerifier.CertificateClaim claim = ASPinVerifier.parseVerifiedClaim(
                "{\"host\":\"api.example\",\"subject\":\"CN=api.example\","
                        + "\"san\":[\"api.example\",\"backup.example\"],"
                        + "\"issuer\":[\"CN=Old CA\",\"CN=New CA\"]}");

        assertEquals(List.of("api.example", "backup.example"),
                claim.getSubjectAlternativeNames());
        assertEquals(List.of("CN=Old CA", "CN=New CA"), claim.getIssuers());
    }
}
