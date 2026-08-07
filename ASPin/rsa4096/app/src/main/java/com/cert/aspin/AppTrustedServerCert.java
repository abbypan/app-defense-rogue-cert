package com.cert.aspin;

import android.content.Context;

import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.json.JSONObject;

/** Retrieves, authenticates, and caches the ASPin claim chain. */
public final class AppTrustedServerCert {
    private static final Map<String, CachedKey> KEY_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, CachedClaim> CLAIM_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, Long> HIGHEST_SEEN_KEY_IAT = new ConcurrentHashMap<>();
    private static final Map<String, Long> HIGHEST_SEEN_CLAIM_IAT = new ConcurrentHashMap<>();

    private AppTrustedServerCert() {
    }

    public static ASPinVerifier.CertificateClaim getValidatedServerCertClaim(
            Context context, String host) throws Exception {
        String normalizedHost = normalizeHost(host);
        long now = System.currentTimeMillis();
        CachedClaim cached = CLAIM_CACHE.get(normalizedHost);
        if (cached != null && cached.isUsable(now)) {
            return cached.claim;
        }

        try {
            java.security.PublicKey appPublicKey = AppInfo.getPrimarySigningPublicKey(context);
            if (appPublicKey == null) {
                throw new IllegalStateException("Installed app signing public key is unavailable");
            }

            CachedKey key = authenticatedClaimKey(normalizedHost, appPublicKey, now);
            String claimToken = getPlaintextWellKnown(normalizedHost, "ServerCertClaim.jwt");
            JwtVerifier.VerifiedJwt verifiedClaim = JwtVerifier.verifyJwtWithJwkDetails(
                    claimToken, key.jwk, now);

            long iat = verifiedClaim.getIssueTimeMillis();
            if (iat > 0) {
                Long highestSeenIat = HIGHEST_SEEN_CLAIM_IAT.get(normalizedHost);
                if (highestSeenIat != null && iat < highestSeenIat) {
                    throw new IllegalArgumentException(
                            "ServerCertClaim JWT iat (" + iat + ") is lower than highest-seen iat (" + highestSeenIat + ") - anti-rollback rejection");
                }
                if (highestSeenIat == null || iat > highestSeenIat) {
                    HIGHEST_SEEN_CLAIM_IAT.put(normalizedHost, iat);
                }
            }

            ASPinVerifier.CertificateClaim claim =
                    ASPinVerifier.parseVerifiedClaim(verifiedClaim.getPayload());
            if (!normalizedHost.equalsIgnoreCase(claim.getHost())) {
                throw new IllegalArgumentException(
                        "Certificate claim host does not match requested host");
            }

            long staleUntil = staleDeadline(
                    verifiedClaim.getCacheUntilMillis(),
                    verifiedClaim.getTtlSeconds(),
                    verifiedClaim.getExpirationTimeMillis());
            CachedClaim refreshed = new CachedClaim(
                    claim,
                    verifiedClaim.getExpirationTimeMillis(),
                    verifiedClaim.getCacheUntilMillis(),
                    staleUntil);
            CLAIM_CACHE.put(normalizedHost, refreshed);
            return claim;
        } catch (Exception refreshFailure) {
            // RFC 8767-style stale reuse is bounded by the token exp; it never
            // permits an expired claim to be used.
            if (cached != null && cached.isStaleUsable(now)) {
                return cached.claim;
            }
            throw refreshFailure;
        }
    }

    /** Backwards-compatible display helper; connection validation uses the full claim. */
    public static String getServerCertClaim(Context context, String host) throws Exception {
        ASPinVerifier.CertificateClaim claim = getValidatedServerCertClaim(context, host);
        return String.join(" | ", claim.getIssuers());
    }

    public static javax.net.ssl.HttpsURLConnection createValidatedASPinConnection(
            Context context, String host) throws Exception {
        return HttpsConn.createASPinConnection(
                host, getValidatedServerCertClaim(context, host));
    }

    static void clearCachesForTests() {
        KEY_CACHE.clear();
        CLAIM_CACHE.clear();
        HIGHEST_SEEN_KEY_IAT.clear();
        HIGHEST_SEEN_CLAIM_IAT.clear();
    }

    private static CachedKey authenticatedClaimKey(
            String host, java.security.PublicKey appPublicKey, long now) throws Exception {
        CachedKey cached = KEY_CACHE.get(host);
        if (cached != null && cached.isUsable(now)) {
            return cached;
        }

        String token = getPlaintextWellKnown(host, "ClaimSigningKey.jwt");
        JwtVerifier.VerifiedJwt verified = JwtVerifier.verifyJwtDetails(
                token, appPublicKey, now);

        long iat = verified.getIssueTimeMillis();
        if (iat > 0) {
            Long highestSeenIat = HIGHEST_SEEN_KEY_IAT.get(host);
            if (highestSeenIat != null && iat < highestSeenIat) {
                throw new IllegalArgumentException(
                        "ClaimSigningKey JWT iat (" + iat + ") is lower than highest-seen iat (" + highestSeenIat + ") - anti-rollback rejection");
            }
            if (highestSeenIat == null || iat > highestSeenIat) {
                HIGHEST_SEEN_KEY_IAT.put(host, iat);
            }
        }

        String jwk = JwtVerifier.extractConfirmationJwk(verified.getPayload());
        CachedKey refreshed = new CachedKey(
                jwk,
                verified.getExpirationTimeMillis(),
                verified.getCacheUntilMillis());
        KEY_CACHE.put(host, refreshed);
        return refreshed;
    }


    private static long staleDeadline(long cacheUntil, long ttlSeconds, long expiration) {
        long extension;
        try {
            extension = Math.multiplyExact(ttlSeconds, 1_000L);
            extension = Math.addExact(cacheUntil, extension);
        } catch (ArithmeticException e) {
            extension = Long.MAX_VALUE;
        }
        return Math.min(expiration, extension);
    }

    private static String normalizeHost(String host) {
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("ASPin server host is required");
        }
        String normalized = host.trim().toLowerCase(java.util.Locale.ROOT);
        if (normalized.contains("/") || normalized.contains(":")) {
            throw new IllegalArgumentException("ASPin host must be a hostname, not a URL");
        }
        return normalized;
    }

    private static String getPlaintextWellKnown(String host, String fileName) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) URI.create(
                "http://" + host + "/.well-known/" + fileName).toURL().openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(10_000);
        connection.setInstanceFollowRedirects(false);
        try {
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new java.io.IOException("HTTP " + connection.getResponseCode()
                        + " while retrieving " + fileName);
            }
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(
                            connection.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
                StringBuilder result = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line);
                }
                return result.toString();
            }
        } finally {
            connection.disconnect();
        }
    }

    private static final class CachedKey {
        private final String jwk;
        private final long expiration;
        private final long cacheUntil;

        private CachedKey(String jwk, long expiration, long cacheUntil) {
            this.jwk = jwk;
            this.expiration = expiration;
            this.cacheUntil = cacheUntil;
        }

        private boolean isUsable(long now) {
            return now < cacheUntil && now < expiration;
        }
    }

    private static final class CachedClaim {
        private final ASPinVerifier.CertificateClaim claim;
        private final long expiration;
        private final long cacheUntil;
        private final long staleUntil;

        private CachedClaim(
                ASPinVerifier.CertificateClaim claim,
                long expiration,
                long cacheUntil,
                long staleUntil) {
            this.claim = claim;
            this.expiration = expiration;
            this.cacheUntil = cacheUntil;
            this.staleUntil = staleUntil;
        }

        private boolean isUsable(long now) {
            return now < cacheUntil && now < expiration;
        }

        private boolean isStaleUsable(long now) {
            return now < staleUntil && now < expiration;
        }
    }
}
