package com.cert.aspin;

import android.content.Context;

/** Obtains ASPin certificate claims exclusively from the Android OS service. */
public final class AppTrustedServerCert {
    private AppTrustedServerCert() {
    }

    public static ASPinVerifier.CertificateClaim getValidatedServerCertClaim(
            Context context, String host) throws Exception {
        return OsAspinClient.getCertificateClaim(context, host).getClaim();
    }

    public static ASPinVerifier.CertificateClaim getValidatedServerCertClaimForApp(
            Context context, String targetAppId, String host) throws Exception {
        return OsAspinClient.getCertificateClaimForApp(context, targetAppId, host).getClaim();
    }

    /** Forces a fresh OS-service retrieval for controlled evaluation runs. */
    public static OsAspinClient.Result refreshValidatedServerCertClaim(
            Context context, String host) throws Exception {
        return OsAspinClient.refreshCertificateClaim(context, host);
    }

    public static OsAspinClient.Result refreshValidatedServerCertClaimForApp(
            Context context, String targetAppId, String host) throws Exception {
        return OsAspinClient.refreshCertificateClaimForApp(context, targetAppId, host);
    }

    /** Backwards-compatible display helper; validation uses the complete claim. */
    public static String getServerCertClaim(Context context, String host) throws Exception {
        ASPinVerifier.CertificateClaim claim = getValidatedServerCertClaim(context, host);
        return String.join(" | ", claim.getIssuers());
    }

    public static String getServerCertClaimForApp(
            Context context, String targetAppId, String host) throws Exception {
        ASPinVerifier.CertificateClaim claim =
                getValidatedServerCertClaimForApp(context, targetAppId, host);
        return String.join(" | ", claim.getIssuers());
    }

    public static javax.net.ssl.HttpsURLConnection createValidatedASPinConnection(
            Context context, String host) throws Exception {
        return HttpsConn.createASPinConnection(
                host, getValidatedServerCertClaim(context, host));
    }

    /** Kept for existing unit-test setup; caching is owned by the OS service. */
    static void clearCachesForTests() {
    }
}
