package com.cert.aspin;

import org.junit.Test;
import java.net.SocketTimeoutException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLHandshakeException;
import static org.junit.Assert.*;

public class RttBenchmarkChecksTest {
    @Test public void expectedPaths() {
        for (String scheme : new String[] {"TLS", "ASPin", "SCP", "DCP"}) {
            assertEquals("accepted", RttBenchmarkChecks.expectedOutcome(scheme, "real"));
            assertEquals("TLS".equals(scheme) ? "accepted" : "policy_rejected",
                    RttBenchmarkChecks.expectedOutcome(scheme, "rogue"));
        }
    }
    @Test public void unchangedPolicyDuringCertificateChange() {
        for (String scheme : new String[] {"TLS", "ASPin", "ASPin-compatible", "SCP", "DCP"}) {
            assertEquals("accepted", RttBenchmarkChecks.expectedOutcome(scheme, "renewal"));
            assertEquals("SCP".equals(scheme) || "DCP".equals(scheme)
                            ? "policy_rejected" : "accepted",
                    RttBenchmarkChecks.expectedOutcome(scheme, "rekey"));
        }
    }
    @Test public void timeoutIsNotPolicyRejection() {
        assertFalse(RttBenchmarkChecks.isPolicyRejection(new SocketTimeoutException(), "ASPin"));
        assertFalse(RttBenchmarkChecks.isPolicyRejection(
                new CertificateException("Trust anchor for certification path not found"), "DCP"));
        assertFalse(RttBenchmarkChecks.isPolicyRejection(
                new IllegalStateException("Pin verification failed"), "SCP"));
    }
    @Test public void onlyExactCertificatePolicyFailuresCount() {
        SSLHandshakeException error = new SSLHandshakeException("TLS failure");
        error.initCause(new CertificateException("Pin verification failed"));
        assertTrue(RttBenchmarkChecks.isPolicyRejection(error, "SCP"));
        assertFalse(RttBenchmarkChecks.isPolicyRejection(error, "DCP"));
        assertTrue(RttBenchmarkChecks.isPolicyRejection(
                new CertificateException("Dynamic pin verification failed"), "DCP"));
    }
    @Test public void cacheEvidence() {
        RttBenchmarkChecks.requireCacheEvidence("hot", 0, 0);
        RttBenchmarkChecks.requireCacheEvidence("cold-forced-refresh", 1, 2);
    }
    @Test(expected=IllegalStateException.class) public void partialRefreshIsNotCold() {
        RttBenchmarkChecks.requireCacheEvidence("cold-forced-refresh", 0, 2);
    }
    @Test(expected=IllegalStateException.class) public void fetchIsNotHot() {
        RttBenchmarkChecks.requireCacheEvidence("hot", 1, 0);
    }
    @Test(expected=IllegalArgumentException.class) public void scpHasNoDynamicCache() {
        RttBenchmarkChecks.cacheFor("SCP", "hot");
    }
}
