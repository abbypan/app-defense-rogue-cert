package com.cert.aspin;

import java.net.SocketTimeoutException;

/** Strict classifications: unrelated transport/parser/state failures never pass. */
public final class PolicyScenarioChecks {
    private PolicyScenarioChecks() { }

    public static boolean matchesLookupFailure(Throwable error, String kind) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            String message = String.valueOf(cause.getMessage());
            if ("metadata-503".equals(kind) && message.contains("HTTPS 503 retrieving /.well-known/")) return true;
            if ("metadata-timeout".equals(kind) && (cause instanceof SocketTimeoutException
                    // Binder preserves the OS exception message, not nested checked causes.
                    || (cause instanceof IllegalStateException
                    && (message.equals("ASPin validation failed: Read timed out")
                    || message.equals("ASPin validation failed: timeout"))))) return true;
            if ("root-mismatch".equals(kind) && (message.contains("No General JWS signature matches trusted key")
                    || message.contains("T_k has no valid signature under the installed app or manifest ASPin root"))) return true;
            if ("target-unavailable".equals(kind) && cause instanceof SecurityException
                    && (message.contains("Target package is not visible to the ASPin caller")
                    || message.contains("Unable to resolve target package"))) return true;
            if ("expired-replay".equals(kind) && message.contains("ASPin token is not fresh")) return true;
            if ("debug-egress-denied".equals(kind)
                    && message.equals("ASPin validation failed: ASPin claim endpoint resolves to a special-use address")) return true;
        }
        return false;
    }

    public static boolean passed(String expected, String outcome, boolean tlsAttempted,
            boolean appRequestSent, boolean lookupSucceeded) {
        if (!expected.equals(outcome)) return false;
        if ("accepted".equals(outcome)) return tlsAttempted && appRequestSent;
        if ("lookup_refused".equals(outcome)) return !tlsAttempted && !appRequestSent && !lookupSucceeded;
        if ("policy_rejected".equals(outcome)) return tlsAttempted && !appRequestSent && lookupSucceeded;
        return false;
    }
}
