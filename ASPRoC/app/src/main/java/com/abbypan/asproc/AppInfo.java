package com.abbypan.asproc;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import android.content.pm.Signature;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class AppInfo {

    /**
     * Returns the primary signing public key of the app in Base64 format.
     * @param context Application context
     * @return Base64-encoded public key, or null if not found/error
     */
    public static String getPrimarySigningCert(Context context) {
        try {
            PackageInfo packageInfo;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo = context.getPackageManager().getPackageInfo(
                        context.getPackageName(),
                        PackageManager.GET_SIGNING_CERTIFICATES
                );
            } else {
                packageInfo = context.getPackageManager().getPackageInfo(
                        context.getPackageName(),
                        PackageManager.GET_SIGNATURES
                );
            }

            Signature primarySig = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                if (packageInfo.signingInfo.getApkContentsSigners().length > 0) {
                    primarySig = packageInfo.signingInfo.getApkContentsSigners()[0];
                }
            } else {
                if (packageInfo.signatures.length > 0) {
                    primarySig = packageInfo.signatures[0];
                }
            }

            if (primarySig != null) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(
                        new java.io.ByteArrayInputStream(primarySig.toByteArray())
                );

                return PemUtils.convertX509ToPem(cert);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // Return null if not found or error
    }
}
