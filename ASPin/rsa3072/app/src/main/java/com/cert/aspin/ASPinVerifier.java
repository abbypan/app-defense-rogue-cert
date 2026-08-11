package com.cert.aspin;

import org.json.JSONArray;
import org.json.JSONObject;

import com.google.common.net.InetAddresses;

import java.net.IDN;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

/** Implements ASPin CertClaimCheck from the paper. */
public final class ASPinVerifier {
    public static String getAppSigningCertPem(android.content.Context context) {
        return AppInfo.getPrimarySigningCert(context);
    }

    private ASPinVerifier() {
    }

    public static CertificateClaim parseVerifiedClaim(
            String requestedHostname, String verifiedPayload)
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
        return new CertificateClaim(requestedHostname, subject, sans, issuers);
    }

    public static void verifyCertificate(
            String connectionHostname, CertificateClaim claim, X509Certificate certificate)
            throws CertificateException {
        if (claim == null || certificate == null) {
            throw new CertificateException("ASPin claim and leaf certificate are required");
        }

        if (!sameHostname(connectionHostname, claim.host)) {
            throw new CertificateException(
                    "TLS connection hostname differs from the ASPin claim lookup hostname");
        }
        if (!hostMatchesClaim(
                connectionHostname, claim.subject, claim.subjectAlternativeNames)) {
            throw new CertificateException(
                    "Requested hostname is not covered by the authenticated ASPin claim");
        }

        String actualIssuerIdentifier = issuerIdentifier(certificate);
        if (!claim.issuerIdentifiers.contains(actualIssuerIdentifier)) {
            throw new CertificateException(
                    "Certificate issuer is not authorized by the authenticated ASPin claim");
        }
    }

    static boolean hostMatchesClaim(String hostname, String subject, List<String> sans) {
        String host = requireHostname(hostname);
        boolean ipHost = isIpAddress(host);
        List<String> relevantSans = new ArrayList<>();
        for (String san : sans) {
            if (isIpAddress(san) == ipHost) {
                relevantSans.add(san);
            }
        }
        if (ipHost) {
            return relevantSans.stream().anyMatch(san -> ipAddressMatches(host, san));
        }
        if (!relevantSans.isEmpty()) {
            return relevantSans.stream().anyMatch(san -> dnsNameMatches(host, san));
        }
        String commonName = commonName(subject);
        return commonName != null && dnsNameMatches(host, commonName);
    }

    static boolean sameHostname(String first, String second) {
        return requireHostname(first).equals(requireHostname(second));
    }

    private static boolean dnsNameMatches(String expected, String presented) {
        String e = normalizeDnsName(expected);
        String p = normalizeDnsName(presented);
        if (p.startsWith("*.")) {
            String suffix = p.substring(1);
            return suffix.indexOf('.', 1) >= 0
                    && e.endsWith(suffix)
                    && e.indexOf('.') == e.length() - suffix.length();
        }
        if (p.indexOf('*') >= 0) return false;
        return e.equals(p);
    }

    private static String normalizeDnsName(String name) {
        String trimmed = name.trim().replaceFirst("\\.$", "");
        if (trimmed.startsWith("*.")) {
            return "*." + IDN.toASCII(trimmed.substring(2), IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
        }
        return IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
    }

    private static boolean isIpAddress(String value) {
        String candidate = stripIpBrackets(value.trim());
        return InetAddresses.isInetAddress(candidate);
    }

    private static boolean ipAddressMatches(String first, String second) {
        try {
            return InetAddresses.forString(stripIpBrackets(first.trim())).equals(
                    InetAddresses.forString(stripIpBrackets(second.trim())));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String stripIpBrackets(String value) {
        return value.startsWith("[") && value.endsWith("]")
                ? value.substring(1, value.length() - 1) : value;
    }

    private static String commonName(String subject) {
        try {
            X500Name name = X500Name.getInstance(new X500Principal(subject).getEncoded());
            org.bouncycastle.asn1.x500.RDN[] commonNames = name.getRDNs(BCStyle.CN);
            if (commonNames.length > 0 && commonNames[0].getFirst() != null) {
                return commonNames[0].getFirst().getValue().toString();
            }
        } catch (Exception ignored) {
            return null;
        }
        return null;
    }

    private static String requireHostname(String hostname) {
        if (hostname == null || hostname.trim().isEmpty()) {
            throw new IllegalArgumentException("Requested hostname is required");
        }
        String value = hostname.trim();
        if (value.contains("://") || value.contains("/")
                || value.contains("?") || value.contains("#")) {
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

    /**
     * Identifies the issuer from the certificate's DER-encoded X.500 Name, not a
     * provider-specific display string. The textual claim representation is
     * base64url(SHA-256(DER(issuer Name))) with an explicit algorithm prefix.
     */
    private static String issuerIdentifier(X509Certificate certificate)
            throws CertificateException {
        return issuerIdentifier(certificate.getIssuerX500Principal());
    }

    static String issuerIdentifier(X500Principal issuer) throws CertificateException {
        try {
            byte[] issuerDer = issuer.getEncoded();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(issuerDer);
            return "sha256:" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateException("SHA-256 is unavailable", e);
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

    public static final class CertificateClaim {
        private final String host;
        private final String subject;
        private final List<String> subjectAlternativeNames;
        private final List<String> issuerIdentifiers;

        CertificateClaim(String host, String subject, List<String> sans,
                List<String> issuerIdentifiers) {
            this.host = requireHostname(host);
            this.subject = subject == null ? "" : subject.trim();
            this.subjectAlternativeNames = List.copyOf(sans);
            this.issuerIdentifiers = List.copyOf(issuerIdentifiers);
        }

        public String getHost() { return host; }
        public String getSubject() { return subject; }
        public List<String> getSubjectAlternativeNames() { return subjectAlternativeNames; }
        public List<String> getIssuerIdentifiers() { return issuerIdentifiers; }

        /** Compatibility alias for the current experimental OS API. */
        public List<String> getIssuers() { return issuerIdentifiers; }
    }
}
