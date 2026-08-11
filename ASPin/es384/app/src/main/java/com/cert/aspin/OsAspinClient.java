package com.cert.aspin;

import android.content.Context;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** Thin reflection adapter for the Android OS-level ASPin API. */
public final class OsAspinClient {
    private static final String SERVICE_NAME = "aspin";

    private OsAspinClient() {
    }

    public static Result getCertificateClaim(Context context, String hostname) throws Exception {
        return requestCertificateClaim(context, null, hostname, false);
    }

    public static Result getCertificateClaimForApp(
            Context context, String targetAppId, String hostname) throws Exception {
        return requestCertificateClaim(context, targetAppId, hostname, false);
    }

    public static Result refreshCertificateClaim(Context context, String hostname) throws Exception {
        return requestCertificateClaim(context, null, hostname, true);
    }

    public static Result refreshCertificateClaimForApp(
            Context context, String targetAppId, String hostname) throws Exception {
        return requestCertificateClaim(context, targetAppId, hostname, true);
    }

    private static Result requestCertificateClaim(
            Context context, String targetAppId, String hostname, boolean forceRefresh)
            throws Exception {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(hostname, "hostname");
        if (targetAppId != null && targetAppId.trim().isEmpty()) {
            throw new IllegalArgumentException("Target app ID must not be empty");
        }
        Object manager = context.getSystemService(SERVICE_NAME);
        if (manager == null) {
            throw new UnsupportedOperationException(
                    "This Android build does not provide the OS-level ASPin service");
        }
        final Method request;
        final Object platformClaim;
        if (targetAppId == null) {
            request = manager.getClass().getMethod(
                    forceRefresh ? "refreshCertificateClaim" : "getCertificateClaim",
                    String.class);
            platformClaim = invoke(request, manager, hostname);
        } else {
            request = manager.getClass().getMethod(
                    forceRefresh ? "refreshCertificateClaimForApp"
                            : "getCertificateClaimForApp",
                    String.class, String.class);
            platformClaim = invoke(request, manager, targetAppId, hostname);
        }
        if (platformClaim == null) {
            throw new IllegalStateException("The OS-level ASPin service returned no claim");
        }

        Class<?> claimClass = platformClaim.getClass();
        String returnedHostname = (String) invokeNoArgs(
                claimClass, platformClaim, "getHostname");
        if (!ASPinVerifier.sameHostname(hostname, returnedHostname)) {
            throw new IllegalStateException(
                    "The OS-level ASPin response is not bound to the requested hostname");
        }
        ASPinVerifier.CertificateClaim claim = new ASPinVerifier.CertificateClaim(
                hostname,
                (String) invokeNoArgs(claimClass, platformClaim, "getSubject"),
                copyStrings((List<?>) invokeNoArgs(
                        claimClass, platformClaim, "getSubjectAlternativeNames")),
                copyStrings((List<?>) invokeNoArgs(
                        claimClass, platformClaim, "getIssuers")));
        return new Result(
                claim,
                ((Number) invokeNoArgs(
                        claimClass, platformClaim, "getIssuedAtMillis")).longValue(),
                ((Number) invokeNoArgs(
                        claimClass, platformClaim, "getExpiresAtMillis")).longValue(),
                ((Number) invokeNoArgs(
                        claimClass, platformClaim,
                        "getClaimKeyDownloadAndVerificationNanos")).longValue(),
                ((Number) invokeNoArgs(
                        claimClass, platformClaim,
                        "getClaimDownloadAndVerificationNanos")).longValue());
    }

    private static Object invokeNoArgs(Class<?> type, Object receiver, String methodName)
            throws Exception {
        return invoke(type.getMethod(methodName), receiver);
    }

    private static Object invoke(Method method, Object receiver, Object... arguments)
            throws Exception {
        try {
            return method.invoke(receiver, arguments);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new IllegalStateException("OS-level ASPin invocation failed", cause);
        }
    }

    private static List<String> copyStrings(List<?> source) {
        if (source == null) {
            throw new IllegalArgumentException("The OS-level ASPin claim contains a null list");
        }
        List<String> result = new ArrayList<>(source.size());
        for (Object item : source) {
            if (!(item instanceof String) || ((String) item).trim().isEmpty()) {
                throw new IllegalArgumentException(
                        "The OS-level ASPin claim contains an invalid string list");
            }
            result.add((String) item);
        }
        return Collections.unmodifiableList(result);
    }

    public static final class Result {
        private final ASPinVerifier.CertificateClaim claim;
        private final long issuedAtMillis;
        private final long expiresAtMillis;
        private final long claimKeyDownloadAndVerificationNanos;
        private final long claimDownloadAndVerificationNanos;

        private Result(
                ASPinVerifier.CertificateClaim claim,
                long issuedAtMillis,
                long expiresAtMillis,
                long claimKeyDownloadAndVerificationNanos,
                long claimDownloadAndVerificationNanos) {
            this.claim = claim;
            this.issuedAtMillis = issuedAtMillis;
            this.expiresAtMillis = expiresAtMillis;
            this.claimKeyDownloadAndVerificationNanos =
                    claimKeyDownloadAndVerificationNanos;
            this.claimDownloadAndVerificationNanos =
                    claimDownloadAndVerificationNanos;
        }

        public ASPinVerifier.CertificateClaim getClaim() {
            return claim;
        }

        public long getIssuedAtMillis() {
            return issuedAtMillis;
        }

        public long getExpiresAtMillis() {
            return expiresAtMillis;
        }

        public long getClaimKeyDownloadAndVerificationNanos() {
            return claimKeyDownloadAndVerificationNanos;
        }

        public long getClaimDownloadAndVerificationNanos() {
            return claimDownloadAndVerificationNanos;
        }
    }
}
