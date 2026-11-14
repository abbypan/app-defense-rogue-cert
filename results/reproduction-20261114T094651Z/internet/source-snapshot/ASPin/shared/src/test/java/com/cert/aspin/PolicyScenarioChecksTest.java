package com.cert.aspin;

import org.junit.Test;
import java.net.SocketTimeoutException;
import java.io.IOException;
import static org.junit.Assert.*;

public class PolicyScenarioChecksTest {
    @Test public void acceptsOnlySpecifiedLookupFailure() {
        assertTrue(PolicyScenarioChecks.matchesLookupFailure(new IllegalStateException("ASPin validation failed: HTTPS 503 retrieving /.well-known/ClaimSigningKey.jws"), "metadata-503"));
        assertFalse(PolicyScenarioChecks.matchesLookupFailure(new IOException("Connection reset"), "metadata-503"));
        assertFalse(PolicyScenarioChecks.matchesLookupFailure(new SocketTimeoutException(), "metadata-503"));
        assertTrue(PolicyScenarioChecks.matchesLookupFailure(new Exception(new SocketTimeoutException()), "metadata-timeout"));
        assertTrue(PolicyScenarioChecks.matchesLookupFailure(new IllegalStateException("ASPin validation failed: Read timed out"), "metadata-timeout"));
        assertFalse(PolicyScenarioChecks.matchesLookupFailure(new IllegalStateException("timeout"), "metadata-timeout"));
    }
    @Test public void rootAndTargetFailuresAreDistinct() {
        assertTrue(PolicyScenarioChecks.matchesLookupFailure(new IllegalStateException("No General JWS signature matches trusted key"), "root-mismatch"));
        assertTrue(PolicyScenarioChecks.matchesLookupFailure(new IllegalStateException("ASPin validation failed: T_k has no valid signature under the installed app or manifest ASPin root"), "root-mismatch"));
        assertFalse(PolicyScenarioChecks.matchesLookupFailure(new IllegalStateException("ASPin anti-rollback rejected lower iat"), "root-mismatch"));
        assertTrue(PolicyScenarioChecks.matchesLookupFailure(new SecurityException("Unable to resolve target package missing"), "target-unavailable"));
        assertFalse(PolicyScenarioChecks.matchesLookupFailure(new IllegalStateException("Unable to resolve target package missing"), "target-unavailable"));
    }
    @Test public void rejectionMustNotSendApplicationRequest() {
        assertTrue(PolicyScenarioChecks.passed("lookup_refused", "lookup_refused", false, false, false));
        assertFalse(PolicyScenarioChecks.passed("lookup_refused", "lookup_refused", true, false, false));
        assertFalse(PolicyScenarioChecks.passed("lookup_refused", "lookup_refused", false, true, false));
        assertFalse(PolicyScenarioChecks.passed("accepted", "unexpected_error", false, false, false));
        assertTrue(PolicyScenarioChecks.passed("policy_rejected", "policy_rejected", true, false, true));
        assertFalse(PolicyScenarioChecks.passed("policy_rejected", "policy_rejected", true, true, true));
    }
}
