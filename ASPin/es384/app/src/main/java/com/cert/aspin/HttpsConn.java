package com.cert.aspin;

import android.net.http.X509TrustManagerExtensions;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** Native TLS plus ASPin's check of the native-validated certificate path. */
public final class HttpsConn {
    private HttpsConn() {
    }

    private static X509TrustManager createDefaultTrustManager() throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        // Android's default manager honors the calling APK's NSC configuration.
        trustManagerFactory.init((KeyStore) null);
        for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager x509TrustManager) {
                return x509TrustManager;
            }
        }
        throw new IllegalStateException("No default X509TrustManager available");
    }

    private static TrustManager[] getASPinTrustManagers(
            String host, ASPinVerifier.CertificateClaim claim) throws Exception {
        return getSupplementaryTrustManagers(host,
                chain -> ASPinVerifier.verifyCertificate(host, claim, chain));
    }

    private interface CertificateCheck {
        void verify(X509Certificate[] validatedChain) throws CertificateException;
    }

    private static TrustManager[] getSupplementaryTrustManagers(
            String host, CertificateCheck check) throws Exception {
        final X509TrustManager defaultTrustManager = createDefaultTrustManager();
        final X509TrustManagerExtensions trustManagerExtensions =
                new X509TrustManagerExtensions(defaultTrustManager);
        return new TrustManager[] { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return defaultTrustManager.getAcceptedIssuers();
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                if (chain == null || chain.length == 0) {
                    throw new CertificateException("TLS server did not provide a certificate chain");
                }
                List<X509Certificate> validatedPath = trustManagerExtensions.checkServerTrusted(
                        chain, authType, host);
                check.verify(requireValidatedPath(validatedPath));
            }

            public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                defaultTrustManager.checkClientTrusted(chain, authType);
            }
        }};
    }

    static X509Certificate[] requireValidatedPath(List<X509Certificate> validatedPath)
            throws CertificateException {
        if (validatedPath == null || validatedPath.isEmpty()) {
            throw new CertificateException(
                    "Native trust manager returned no validated certificate path");
        }
        return validatedPath.toArray(X509Certificate[]::new);
    }

    public static HttpsURLConnection create_conn(String url) throws Exception {
        return (HttpsURLConnection) URI.create(url).toURL().openConnection();
    }

    private static SSLSocketFactory createDefaultSslSocketFactory() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] {createDefaultTrustManager()}, new SecureRandom());
        return sslContext.getSocketFactory();
    }

    /** SCP and DCP are enforced here by their dedicated APKs' NSC configuration. */
    public static HttpsURLConnection createStandardTLSConnection(String host) throws Exception {
        resolveHost(host);
        HttpsURLConnection connection = create_conn("https://" + host);
        connection.setSSLSocketFactory(createDefaultSslSocketFactory());
        return connection;
    }

    public static HttpsURLConnection createASPinConnection(
            String host, ASPinVerifier.CertificateClaim authenticatedClaim) throws Exception {
        if (authenticatedClaim == null) {
            throw new IllegalArgumentException("An OS-authenticated ASPin claim is required");
        }
        resolveHost(host);
        HttpsURLConnection connection = create_conn("https://" + host);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, getASPinTrustManagers(host, authenticatedClaim), new SecureRandom());
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        return connection;
    }

    public static String get_content(HttpsURLConnection con) throws Exception {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(con.getInputStream()))) {
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
            return result.toString();
        }
    }

    /** Diagnostic metadata read only; policy authentication belongs to the OS service. */
    public static String getHttpContent(String urlString) throws Exception {
        Exception lastException = null;
        for (int retry = 0; retry < 3; retry++) {
            java.net.HttpURLConnection connection = null;
            try {
                URL url = URI.create(urlString).toURL();
                connection = (java.net.HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(5000);
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                        connection.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder result = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        result.append(line).append('\n');
                    }
                    return result.toString().trim();
                }
            } catch (Exception error) {
                lastException = error;
                try {
                    Thread.sleep(200);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw interrupted;
                }
            } finally {
                if (connection != null) connection.disconnect();
            }
        }
        throw lastException;
    }

    private static void resolveHost(String host) {
        for (int attempt = 0; attempt < 5; attempt++) {
            try {
                java.net.InetAddress.getByName(host);
                return;
            } catch (Exception ignored) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }
}
