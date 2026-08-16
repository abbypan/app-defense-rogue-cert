package com.cert.aspin;

import org.json.JSONArray;
import org.json.JSONObject;

import com.google.common.net.InetAddresses;

import java.net.IDN;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/** Implements ASPin CertClaimCheck from the paper. */
public final class ASPinVerifier {
    public static String getAppSigningCertPem(android.content.Context context) {
        return AppInfo.getPrimarySigningCert(context);
    }

    private ASPinVerifier() {
    }

    public static CertificateClaim parseVerifiedClaim(
            String requestedHostname, String verifiedPayload, long expiresAtMillis)
            throws org.json.JSONException {
        JSONObject json = new JSONObject(verifiedPayload);
        String subject = required(json, "subject");
        List<String> sans = stringList(json.opt("san"));
        if (sans.isEmpty()) {
            throw new IllegalArgumentException("ASPin claim has no SAN");
        }
        List<String> issuers = stringList(json.opt("issuer"));
        if (issuers.isEmpty()) {
            throw new IllegalArgumentException("ASPin claim has no issuer");
        }
        return new CertificateClaim(
                requestedHostname, subject, sans, issuers, expiresAtMillis);
    }

    public static void verifyCertificate(
            String connectionHostname, CertificateClaim claim, X509Certificate[] validatedChain)
            throws CertificateException {
        verifyCertificate(
                connectionHostname, claim, validatedChain, System.currentTimeMillis());
    }

    static void verifyCertificate(
            String connectionHostname, CertificateClaim claim, X509Certificate[] validatedChain,
            long nowMillis) throws CertificateException {
        if (claim == null || validatedChain == null || validatedChain.length == 0) {
            throw new CertificateException("ASPin claim and validated certificate chain are required");
        }

        if (nowMillis >= claim.expiresAtMillis) {
            throw new CertificateException("The authenticated ASPin claim has expired");
        }

        if (!sameHostname(connectionHostname, claim.host)) {
            throw new CertificateException(
                    "TLS connection hostname differs from the ASPin claim lookup hostname");
        }
        X509Certificate issuerCertificate = directIssuer(validatedChain[0], validatedChain);
        byte[] issuerDer = issuerCertificate.getEncoded();
        for (String authorized : claim.issuerIdentifiers) {
            IssuerIdentifier identifier = parseIssuerIdentifier(authorized);
            if (MessageDigest.isEqual(
                    digest(identifier.hashName, issuerDer), identifier.hashValue)) {
                return;
            }
        }
        throw new CertificateException(
                "Direct issuer CA certificate is not authorized by the authenticated ASPin claim");
    }

    static boolean sameHostname(String first, String second) {
        return requireHostname(first).equals(requireHostname(second));
    }

    private static String normalizeDnsName(String name) {
        String trimmed = name.trim().replaceFirst("\\.$", "");
        if (trimmed.startsWith("*.")) {
            return "*." + IDN.toASCII(trimmed.substring(2), IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
        }
        return IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
    }

    private static String stripIpBrackets(String value) {
        return value.startsWith("[") && value.endsWith("]")
                ? value.substring(1, value.length() - 1) : value;
    }

    private static String requireHostname(String hostname) {
        if (hostname == null || hostname.trim().isEmpty()) {
            throw new IllegalArgumentException("Requested hostname is required");
        }
        String value = hostname.trim();
        if (value.contains("://") || value.contains("/")
                || value.contains("?") || value.contains("#") || value.endsWith(".")) {
            throw new IllegalArgumentException(
                    "ASPin API requires a hostname, not a URL");
        }
        String unbracketed = stripIpBrackets(value);
        if (InetAddresses.isInetAddress(unbracketed)) {
            return InetAddresses.toAddrString(InetAddresses.forString(unbracketed));
        }
        if (value.indexOf(':') >= 0 || value.indexOf('*') >= 0) {
            throw new IllegalArgumentException("Invalid requested hostname");
        }
        return normalizeDnsName(value);
    }

    private static X509Certificate directIssuer(
            X509Certificate leaf, X509Certificate[] validatedChain)
            throws CertificateException {
        if (validatedChain.length < 2) {
            throw new CertificateException(
                    "Validated TLS chain does not contain the leaf's direct issuer CA certificate");
        }
        X509Certificate candidate = validatedChain[1];
        if (!leaf.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) {
            throw new CertificateException(
                    "Second certificate in the validated TLS chain is not the leaf's issuer");
        }
        try {
            leaf.verify(candidate.getPublicKey());
            return candidate;
        } catch (GeneralSecurityException error) {
            throw new CertificateException(
                    "Leaf signature does not verify under its direct issuer CA certificate", error);
        }
    }

    static String issuerIdentifier(byte[] issuerCertificateDer, String hashName)
            throws CertificateException {
        return hashName + ":" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(digest(hashName, issuerCertificateDer));
    }

    private static IssuerIdentifier parseIssuerIdentifier(String value)
            throws CertificateException {
        int separator = value.indexOf(':');
        if (separator <= 0 || separator != value.lastIndexOf(':')) {
            throw new CertificateException("Malformed ASPin issuer identifier");
        }
        String hashName = value.substring(0, separator);
        String encoded = value.substring(separator + 1);
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException error) {
            throw new CertificateException("Malformed ASPin issuer digest", error);
        }
        int expectedLength = switch (hashName) {
            case "sha256" -> 32;
            case "sha384" -> 48;
            default -> throw new CertificateException(
                    "Unsupported ASPin issuer hash algorithm: " + hashName);
        };
        String canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
        if (decoded.length != expectedLength || !encoded.equals(canonical)) {
            throw new CertificateException("Malformed ASPin issuer digest");
        }
        return new IssuerIdentifier(hashName, decoded);
    }

    private static byte[] digest(String hashName, byte[] input) throws CertificateException {
        String javaName = switch (hashName) {
            case "sha256" -> "SHA-256";
            case "sha384" -> "SHA-384";
            default -> throw new CertificateException(
                    "Unsupported ASPin issuer hash algorithm: " + hashName);
        };
        try {
            return MessageDigest.getInstance(javaName).digest(input);
        } catch (NoSuchAlgorithmException error) {
            throw new CertificateException(javaName + " is unavailable", error);
        }
    }

    private static final class IssuerIdentifier {
        final String hashName;
        final byte[] hashValue;

        IssuerIdentifier(String hashName, byte[] hashValue) {
            this.hashName = hashName;
            this.hashValue = hashValue;
        }
    }

    private static String required(JSONObject json, String key) {
        String value = json.optString(key, "").trim();
        if (value.isEmpty()) {
            throw new IllegalArgumentException("ASPin claim missing required field: " + key);
        }
        return value;
    }

    private static List<String> stringList(Object value) {
        List<String> values = new ArrayList<>();
        if (value instanceof JSONArray array) {
            for (int i = 0; i < array.length(); i++) {
                String item = array.optString(i, "").trim();
                if (!item.isEmpty()) values.add(item);
            }
        } else if (value instanceof String string && !string.trim().isEmpty()) {
            values.add(string.trim());
        }
        return values;
    }

    private static List<String> validatedIssuerIdentifiers(List<String> issuers) {
        List<String> result = List.copyOf(issuers);
        if (result.isEmpty()) {
            throw new IllegalArgumentException("ASPin claim has no issuer");
        }
        for (String issuer : result) {
            try {
                parseIssuerIdentifier(issuer);
            } catch (CertificateException error) {
                throw new IllegalArgumentException("ASPin claim has an invalid issuer", error);
            }
        }
        return result;
    }

    public static final class CertificateClaim {
        private final String host;
        private final String subject;
        private final List<String> subjectAlternativeNames;
        private final List<String> issuerIdentifiers;
        private final long expiresAtMillis;

        CertificateClaim(String host, String subject, List<String> sans,
                List<String> issuerIdentifiers, long expiresAtMillis) {
            this.host = requireHostname(host);
            this.subject = subject == null ? "" : subject.trim();
            this.subjectAlternativeNames = List.copyOf(sans);
            this.issuerIdentifiers = validatedIssuerIdentifiers(issuerIdentifiers);
            if (expiresAtMillis <= 0) {
                throw new IllegalArgumentException("ASPin claim expiration must be positive");
            }
            this.expiresAtMillis = expiresAtMillis;
        }

        public String getHost() { return host; }
        public String getSubject() { return subject; }
        public List<String> getSubjectAlternativeNames() { return subjectAlternativeNames; }
        public List<String> getIssuerIdentifiers() { return issuerIdentifiers; }
        public long getExpiresAtMillis() { return expiresAtMillis; }

        /** Compatibility alias for the current experimental OS API. */
        public List<String> getIssuers() { return issuerIdentifiers; }
    }
}
