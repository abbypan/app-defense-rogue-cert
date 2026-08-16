package com.cert.aspin;

import java.util.Base64;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;

/** Verifies the two authenticated JWS artifacts used by ASPin. */
public final class JwsVerifier {
    static {
        try {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Throwable ignored) {
        }
    }

    private JwsVerifier() {
    }

    public static String verifyJwsWithCert(String token, String certificatePem) throws Exception {
        PublicKey publicKey = PemUtils.parseX509Certificate(certificatePem).getPublicKey();
        return verifyJws(token, publicKey);
    }

    public static VerifiedJws verifyJwsWithCertDetails(
            String token, String certificatePem, long nowMillis) throws Exception {
        PublicKey publicKey = PemUtils.parseX509Certificate(certificatePem).getPublicKey();
        return verifyJwsDetails(token, publicKey, nowMillis);
    }

    public static String verifyJwsWithJwk(String token, String jwkOrPem) throws Exception {
        PublicKey publicKey = parseKeyFromJwkOrPem(jwkOrPem);
        return verifyJws(token, publicKey);
    }

    public static VerifiedJws verifyJwsWithJwkDetails(
            String token, String jwkOrPem, long nowMillis) throws Exception {
        PublicKey publicKey = parseKeyFromJwkOrPem(jwkOrPem);
        return verifyJwsDetails(token, publicKey, nowMillis);
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

    public static String verifyJws(String token, PublicKey publicKey) throws Exception {
        return verifyJwsDetails(token, publicKey, System.currentTimeMillis()).getPayload();
    }

    public static VerifiedJws verifyJwsDetails(
            String token, PublicKey publicKey, long nowMillis) throws Exception {
        JWSVerifier verifier = verifierFor(publicKey);
        JWSObject signedJws = null;
        String trimmedToken = token.trim();
        if (!trimmedToken.startsWith("{")) {
            throw new IllegalArgumentException(
                    "ASPin requires General JWS JSON Serialization");
        }
        JSONObject json = new JSONObject(trimmedToken);
        if (!keys(json).equals(Set.of("payload", "signatures"))) {
            throw new IllegalArgumentException(
                    "General JWS must contain exactly payload and signatures");
        }
        org.json.JSONArray sigs = json.getJSONArray("signatures");
        if (sigs.length() < 1 || sigs.length() > 2) {
            throw new IllegalArgumentException("General JWS requires one or two signatures");
        }
        String payloadB64 = json.getString("payload");
        for (int i = 0; i < sigs.length(); i++) {
            JSONObject sigObj = sigs.getJSONObject(i);
            if (!keys(sigObj).equals(Set.of("protected", "signature"))) {
                throw new IllegalArgumentException(
                        "Each General JWS signature must contain protected and signature");
            }
            String headerStr = sigObj.getString("protected");
            String sigStr = sigObj.getString("signature");
            if (!headerStr.isEmpty() && !sigStr.isEmpty()) {
                String candidate = headerStr + "." + payloadB64 + "." + sigStr;
                try {
                    JWSObject candidateJws = JWSObject.parse(candidate);
                    if (candidateJws.verify(verifier)) {
                        verifyHeaderKey(candidateJws, publicKey);
                        signedJws = candidateJws;
                        break;
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        if (signedJws == null) {
            throw new JOSEException("No General JWS signature matches the trusted key");
        }

        String verifiedPayload = signedJws.getPayload().toString();
        JSONObject payload = new JSONObject(verifiedPayload);
        long issueTimeSeconds = requireNumericDate(payload, "iat");
        long expirationSeconds = requireNumericDate(payload, "exp");
        long issueTimeMillis = Math.multiplyExact(issueTimeSeconds, 1_000L);
        long expirationTimeMillis = Math.multiplyExact(expirationSeconds, 1_000L);
        if (expirationTimeMillis <= nowMillis) {
            throw new IllegalArgumentException("JWS has expired");
        }
        if (issueTimeMillis > nowMillis) {
            throw new IllegalArgumentException("JWS is not yet valid");
        }
        if (expirationTimeMillis <= issueTimeMillis) {
            throw new IllegalArgumentException("JWS requires iat < exp");
        }
        long ttlSeconds = expirationSeconds - issueTimeSeconds;

        return new VerifiedJws(
                verifiedPayload,
                expirationTimeMillis,
                ttlSeconds,
                expirationTimeMillis,
                issueTimeMillis);
    }

    private static long requireNumericDate(JSONObject payload, String name) {
        Object value = payload.opt(name);
        if (!(value instanceof Byte || value instanceof Short
                || value instanceof Integer || value instanceof Long)) {
            throw new IllegalArgumentException(
                    "JWS payload requires integer NumericDate " + name);
        }
        return ((Number) value).longValue();
    }

    /**
     * Extracts K_cpub from ASPin's confirmation member:
     * {@code "cnf": {"jwk": {...}}}.
     */
    public static String extractConfirmationJwk(String verifiedPayload)
            throws org.json.JSONException {
        JSONObject payload = new JSONObject(verifiedPayload);
        JSONObject confirmation = payload.optJSONObject("cnf");
        if (confirmation == null) {
            throw new IllegalArgumentException("ClaimSigningKey JWS is missing cnf");
        }
        JSONObject jwk = confirmation.optJSONObject("jwk");
        if (jwk != null) {
            return jwk.toString();
        }
        throw new IllegalArgumentException("ClaimSigningKey JWS is missing cnf.jwk");
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

    private static Set<String> keys(JSONObject object) {
        Set<String> result = new java.util.HashSet<>();
        java.util.Iterator<String> iterator = object.keys();
        while (iterator.hasNext()) result.add(iterator.next());
        return result;
    }

    /**
     * The protected kid must identify the already selected verification key.
     * Verification keys are never accepted from a token header.
     */
    private static void verifyHeaderKey(JWSObject signedJws, PublicKey trustedPublicKey)
            throws Exception {
        if (!signedJws.getHeader().getIncludedParams().equals(Set.of("alg", "kid"))) {
            throw new IllegalArgumentException(
                    "JWS protected header must contain only alg and kid");
        }
        String expectedKid = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(trustedPublicKey.getEncoded()));
        if (!expectedKid.equals(signedJws.getHeader().getKeyID())) {
            throw new IllegalArgumentException(
                    "JWS kid does not identify the trusted verification key");
        }
    }

    public static final class VerifiedJws {
        private final String payload;
        private final long expirationTimeMillis;
        private final long ttlSeconds;
        private final long cacheUntilMillis;
        private final long issueTimeMillis;

        private VerifiedJws(
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
