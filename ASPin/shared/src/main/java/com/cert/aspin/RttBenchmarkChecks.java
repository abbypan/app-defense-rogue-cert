package com.cert.aspin;

import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

/** Pure-Java validation shared by the RTT runner and its unit tests. */
public final class RttBenchmarkChecks {
    private RttBenchmarkChecks() { }

    public static String expectedOutcome(String scheme, String phase) {
        if (!"real".equals(phase) && !"rogue".equals(phase)) {
            throw new IllegalArgumentException("Unknown server phase");
        }
        if (!Set.of("TLS", "ASPin", "ASPin-compatible", "SCP", "DCP").contains(scheme)) {
            throw new IllegalArgumentException("Unknown scheme");
        }
        return "rogue".equals(phase) && !"TLS".equals(scheme)
                ? "policy_rejected" : "accepted";
    }

    public static boolean isPolicyRejection(Throwable error, String scheme) {
        String message = switch (scheme) {
            case "ASPin", "ASPin-compatible" -> "Direct issuer CA certificate is not authorized by the authenticated ASPin claim";
            case "SCP" -> "Pin verification failed";
            case "DCP" -> "Dynamic pin verification failed";
            default -> "";
        };
        Set<Throwable> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = error; cause != null && visited.add(cause);
                cause = cause.getCause()) {
            if (cause instanceof CertificateException && !message.isEmpty()
                    && message.equals(cause.getMessage())) return true;
        }
        return false;
    }

    public static void requireCacheEvidence(String cache, long tkNanos, long tcNanos) {
        if ("hot".equals(cache) && tkNanos == 0 && tcNanos == 0) return;
        if ("cold-forced-refresh".equals(cache) && tkNanos > 0 && tcNanos > 0) return;
        throw new IllegalStateException("Requested policy-cache regime not observed: " + cache);
    }

    public static String cacheFor(String scheme, String requested) {
        if ("TLS".equals(scheme)) {
            if (!"none".equals(requested)) throw new IllegalArgumentException("TLS has no policy cache");
        } else if ("SCP".equals(scheme)) {
            if (!"static".equals(requested)) throw new IllegalArgumentException("SCP policy is static");
        } else if (!Set.of("hot", "cold-forced-refresh").contains(requested)) {
            throw new IllegalArgumentException("Unknown policy-cache regime");
        }
        return requested;
    }
}
