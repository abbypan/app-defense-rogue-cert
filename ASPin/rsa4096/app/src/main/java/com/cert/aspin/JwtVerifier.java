package com.cert.aspin;

import java.util.Base64;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Set;

/** Verifies the two authenticated JWTs used by ASPin. */
public final class JwtVerifier {
    static {
        try {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Throwable ignored) {
        }
    }

    private JwtVerifier() {
    }

    public static String verifyJwtWithCert(String token, String certificatePem) throws Exception {
        PublicKey publicKey = PemUtils.parseX509Certificate(certificatePem).getPublicKey();
        return verifyJwt(token, publicKey);
    }

    public static VerifiedJwt verifyJwtWithCertDetails(
            String token, String certificatePem, long nowMillis) throws Exception {
        PublicKey publicKey = PemUtils.parseX509Certificate(certificatePem).getPublicKey();
        return verifyJwtDetails(token, publicKey, nowMillis);
    }

    public static String verifyJwtWithJwk(String token, String jwkOrPem) throws Exception {
        PublicKey publicKey = parseKeyFromJwkOrPem(jwkOrPem);
        return verifyJwt(token, publicKey);
    }

    public static VerifiedJwt verifyJwtWithJwkDetails(
            String token, String jwkOrPem, long nowMillis) throws Exception {
        PublicKey publicKey = parseKeyFromJwkOrPem(jwkOrPem);
        return verifyJwtDetails(token, publicKey, nowMillis);
    }

    public static PublicKey parseKeyFromJwkOrPem(String jwkOrPem) throws Exception {
        if (jwkOrPem == null || jwkOrPem.trim().isEmpty()) {
            throw new IllegalArgumentException("Key string cannot be null or empty");
        }
        String trimmed = jwkOrPem.trim();
        if (trimmed.contains("PUBLIC KEY") || trimmed.contains("CERTIFICATE") || trimmed.contains("BEGIN")) {
            Object parsed = PemUtils.parsePemString(trimmed);
            if (parsed instanceof X509Certificate cert) {
                return cert.getPublicKey();
            } else if (parsed instanceof PublicKey pk) {
                return pk;
            }
            return PemUtils.parsePublicKey(trimmed);
        }
        if (!trimmed.startsWith("{")) {
            byte[] keyBytes = Base64.getDecoder().decode(trimmed.replaceAll("\s+", ""));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            try {
                return KeyFactory.getInstance("EC").generatePublic(spec);
            } catch (Throwable t) {
                return KeyFactory.getInstance("RSA").generatePublic(spec);
            }
        }
        return JwkToPublicKeyConverter.convertJwkToPublicKey(trimmed);
    }

    public static String verifyJwt(String token, PublicKey publicKey) throws Exception {
        return verifyJwtDetails(token, publicKey, System.currentTimeMillis()).getPayload();
    }

    public static VerifiedJwt verifyJwtDetails(
            String token, PublicKey publicKey, long nowMillis) throws Exception {
        JWSVerifier verifier = verifierFor(publicKey);
        SignedJWT signedJwt = null;
        String trimmedToken = token.trim();
        if (trimmedToken.startsWith("{")) {
            JSONObject json = new JSONObject(trimmedToken);
            if (json.has("signatures")) {
                org.json.JSONArray sigs = json.getJSONArray("signatures");
                String payloadB64 = json.getString("payload");
                boolean verified = false;
                for (int i = 0; i < sigs.length(); i++) {
                    JSONObject sigObj = sigs.getJSONObject(i);
                    String headerStr = sigObj.optString("protected", sigObj.optString("header", ""));
                    String sigStr = sigObj.optString("signature", "");
                    if (!headerStr.isEmpty() && !sigStr.isEmpty()) {
                        String candidate = headerStr + "." + payloadB64 + "." + sigStr;
                        try {
                            SignedJWT candidateJwt = SignedJWT.parse(candidate);
                            if (candidateJwt.verify(verifier)) {
                                verifyHeaderKey(candidateJwt, publicKey);
                                signedJwt = candidateJwt;
                                verified = true;
                                break;
                            }
                        } catch (Throwable ignored) {}
                    }
                }
                if (!verified || signedJwt == null) {
                    throw new JOSEException("General JWS dual-signature verification failed");
                }
            }
        }
        if (signedJwt == null) {
            String compactToken = toCompactSerialization(token);
            signedJwt = SignedJWT.parse(compactToken);
            if (!signedJwt.verify(verifier)) {
                throw new JOSEException("JWT signature verification failed");
            }
            verifyHeaderKey(signedJwt, publicKey);
        }

        Date expiration = signedJwt.getJWTClaimsSet().getExpirationTime();
        if (expiration == null) {
            throw new IllegalArgumentException("JWT expiration time is required");
        }
        if (expiration.getTime() <= nowMillis) {
            throw new IllegalArgumentException("JWT has expired");
        }

        Date issueTime = signedJwt.getJWTClaimsSet().getIssueTime();
        if (issueTime == null) {
            throw new IllegalArgumentException("JWT issue time is required");
        }
        long issueTimeMillis = issueTime.getTime();
        if (issueTimeMillis > nowMillis) {
            throw new IllegalArgumentException("JWT is not yet valid");
        }
        if (expiration.getTime() <= issueTimeMillis) {
            throw new IllegalArgumentException("JWT requires iat < exp");
        }
        long ttlSeconds = (expiration.getTime() - issueTimeMillis) / 1_000L;
        long cacheUntilMillis = expiration.getTime();


        return new VerifiedJwt(
                signedJwt.getPayload().toString(),
                expiration.getTime(),
                ttlSeconds,
                cacheUntilMillis,
                issueTimeMillis);
    }

    /**
     * Extracts K_cpub from the RFC 7800-style confirmation claim required by the
     * ASPin construction: {@code "cnf": {"jwk": {...}}}.
     */
    public static String extractConfirmationJwk(String verifiedPayload)
            throws org.json.JSONException {
        JSONObject payload = new JSONObject(verifiedPayload);
        JSONObject confirmation = payload.optJSONObject("cnf");
        if (confirmation == null) {
            throw new IllegalArgumentException("ClaimSigningKey JWT is missing cnf");
        }
        JSONObject jwk = confirmation.optJSONObject("jwk");
        if (jwk != null) {
            return jwk.toString();
        }
        throw new IllegalArgumentException("ClaimSigningKey JWT is missing cnf.jwk");
    }

    private static JWSVerifier verifierFor(PublicKey publicKey) throws JOSEException {
        if (publicKey instanceof ECPublicKey ecPublicKey) {
            ECDSAVerifier verifier = new ECDSAVerifier(ecPublicKey);
            try {
                // verifier.getJCAContext().setProvider(null);
            } catch (Throwable ignored) {}
            return verifier;
        }
        if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            RSASSAVerifier verifier = new RSASSAVerifier(rsaPublicKey);
            try {
                // verifier.getJCAContext().setProvider(null);
            } catch (Throwable ignored) {}
            return verifier;
        }
        throw new IllegalArgumentException("Unsupported key type: " + publicKey.getAlgorithm());
    }

    private static String toCompactSerialization(String token) throws org.json.JSONException {
        if (!token.trim().startsWith("{")) {
            return token.trim();
        }
        JSONObject json = new JSONObject(token);
        String protectedHeader = json.optString("protected", json.optString("header", ""));
        String payload = json.optString("payload", "");
        String signature = json.optString("signature", "");
        if (protectedHeader.isEmpty() || payload.isEmpty() || signature.isEmpty()) {
            throw new IllegalArgumentException(
                    "JSON JWT is missing protected/header, payload, or signature");
        }
        return protectedHeader + "." + payload + "." + signature;
    }

    /**
     * The protected kid must identify the already selected verification key.
     * Verification keys are never accepted from a token header.
     */
    private static void verifyHeaderKey(SignedJWT signedJwt, PublicKey trustedPublicKey)
            throws Exception {
        if (!signedJwt.getHeader().getIncludedParams().equals(Set.of("alg", "kid"))) {
            throw new IllegalArgumentException(
                    "JWT protected header must contain only alg and kid");
        }
        String expectedKid = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(trustedPublicKey.getEncoded()));
        if (!expectedKid.equals(signedJwt.getHeader().getKeyID())) {
            throw new IllegalArgumentException(
                    "JWT kid does not identify the trusted verification key");
        }
    }

    public static final class VerifiedJwt {
        private final String payload;
        private final long expirationTimeMillis;
        private final long ttlSeconds;
        private final long cacheUntilMillis;
        private final long issueTimeMillis;

        private VerifiedJwt(
                String payload,
                long expirationTimeMillis,
                long ttlSeconds,
                long cacheUntilMillis,
                long issueTimeMillis) {
            this.payload = payload;
            this.expirationTimeMillis = expirationTimeMillis;
            this.ttlSeconds = ttlSeconds;
            this.cacheUntilMillis = cacheUntilMillis;
            this.issueTimeMillis = issueTimeMillis;
        }

        public String getPayload() {
            return payload;
        }

        public long getExpirationTimeMillis() {
            return expirationTimeMillis;
        }

        public long getTtlSeconds() {
            return ttlSeconds;
        }

        public long getCacheUntilMillis() {
            return cacheUntilMillis;
        }

        public long getIssueTimeMillis() {
            return issueTimeMillis;
        }
    }

}
