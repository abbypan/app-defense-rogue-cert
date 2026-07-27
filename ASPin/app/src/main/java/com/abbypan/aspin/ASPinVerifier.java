package com.abbypan.aspin;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.IDN;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Implements ASPin CertClaimCheck from the paper. */
public final class ASPinVerifier {
    private ASPinVerifier() {
    }

    public static CertificateClaim parseVerifiedClaim(String verifiedPayload)
            throws org.json.JSONException {
        JSONObject json = new JSONObject(verifiedPayload);
        String host = required(json, "host").toLowerCase(Locale.ROOT);
        String subject = json.optString("subject", "");
        List<String> sans = stringList(json.opt("san"));
        if (sans.isEmpty()) {
            sans = Collections.singletonList(host);
        }
        List<String> issuers = stringList(json.opt("issuer"));
        if (issuers.isEmpty()) {
            throw new IllegalArgumentException("ASPin claim has no issuer");
        }
        return new CertificateClaim(host, subject, sans, issuers);
    }

    public static void verifyCertificate(CertificateClaim claim, X509Certificate certificate)
            throws CertificateException {
        if (claim == null || certificate == null) {
            throw new CertificateException("ASPin claim and leaf certificate are required");
        }

        String actualIssuer = certificate.getIssuerX500Principal().getName();
        boolean issuerMatches = claim.issuers.stream()
                .anyMatch(expected -> distinguishedNamesEqual(expected, actualIssuer));
        if (!issuerMatches) {
            throw new CertificateException("ASPin issuer does not match authenticated claim");
        }

        if (!claim.subject.isEmpty()
                && !distinguishedNamesEqual(claim.subject, certificate.getSubjectX500Principal().getName())) {
            throw new CertificateException("ASPin subject does not match authenticated claim");
        }

        List<String> certificateDnsNames = dnsNames(certificate);
        for (String claimedSan : claim.subjectAlternativeNames) {
            boolean found = certificateDnsNames.stream()
                    .anyMatch(actual -> dnsNameMatches(claimedSan, actual));
            if (!found) {
                throw new CertificateException("ASPin SAN does not match authenticated claim: " + claimedSan);
            }
        }
        if (certificateDnsNames.stream().noneMatch(name -> dnsNameMatches(claim.host, name))) {
            throw new CertificateException("ASPin host is not present in the certificate SAN");
        }
    }

    private static List<String> dnsNames(X509Certificate certificate) throws CertificateException {
        List<String> names = new ArrayList<>();
        try {
            Collection<List<?>> sans = certificate.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0))) {
                        names.add(String.valueOf(san.get(1)).toLowerCase(Locale.ROOT));
                    }
                }
            }
        } catch (Exception e) {
            throw new CertificateException("Unable to read certificate SAN", e);
        }
        return names;
    }

    private static boolean dnsNameMatches(String expected, String presented) {
        String e = IDN.toASCII(expected).toLowerCase(Locale.ROOT);
        String p = IDN.toASCII(presented).toLowerCase(Locale.ROOT);
        if (p.startsWith("*.")) {
            String suffix = p.substring(1);
            return e.endsWith(suffix) && e.indexOf('.') == e.length() - suffix.length();
        }
        return e.equals(p);
    }

    private static boolean distinguishedNamesEqual(String first, String second) {
        try {
            return new javax.security.auth.x500.X500Principal(first)
                    .equals(new javax.security.auth.x500.X500Principal(second));
        } catch (IllegalArgumentException ignored) {
            return first.trim().equalsIgnoreCase(second.trim());
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
        private final List<String> issuers;

        private CertificateClaim(String host, String subject, List<String> sans, List<String> issuers) {
            this.host = host;
            this.subject = subject;
            this.subjectAlternativeNames = List.copyOf(sans);
            this.issuers = List.copyOf(issuers);
        }

        public String getHost() { return host; }
        public String getSubject() { return subject; }
        public List<String> getSubjectAlternativeNames() { return subjectAlternativeNames; }
        public List<String> getIssuers() { return issuers; }
    }
}
