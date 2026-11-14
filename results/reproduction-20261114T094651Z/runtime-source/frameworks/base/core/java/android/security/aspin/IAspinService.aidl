package android.security.aspin;

import android.security.aspin.AspinCertificateClaim;

/** @hide */
interface IAspinService {
    AspinCertificateClaim getOwnCertificateClaim(String hostname, boolean forceRefresh);
    AspinCertificateClaim getCertificateClaimForApp(
            String targetPackageName, String hostname, boolean forceRefresh);
}
