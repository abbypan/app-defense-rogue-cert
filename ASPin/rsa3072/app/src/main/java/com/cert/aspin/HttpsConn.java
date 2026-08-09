package com.cert.aspin;

import java.io.BufferedReader;
import java.io.File;
//import java.io.InputStream;
import java.io.InputStreamReader;
//import java.net.MalformedURLException;
import java.net.URL;
import java.net.URI;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
//import java.net.URLConnection;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
//import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.json.JSONArray;
//import org.apache.directory.shared.asn1.der.ASN1InputStream;
import org.json.JSONObject;

import com.google.common.net.InternetDomainName;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
//import oracle.security.crypto.cert.CRLDistPoint;

import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1OctetString;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class HttpsConn {


    //private static JSONObject aspin_cache;
    
    // Pre-allocated empty array for bypass trust manager to avoid allocation overhead
    private static final X509Certificate[] EMPTY_CERT_ARRAY = new X509Certificate[0];
    
    private static X509TrustManager createDefaultTrustManager() throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);

        for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager x509TrustManager) {
                return x509TrustManager;
            }
        }
        throw new IllegalStateException("No default X509TrustManager available");
    }
    private static TrustManager[] getBypassTrustManagers() throws Exception {
        return new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return EMPTY_CERT_ARRAY;
                }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    // No-op: bypass all client certificate checks
                }
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // No-op: bypass all server certificate checks
                }
            }
        };
    }

    private static TrustManager[] getDefaultTrustManagers() throws Exception {
        final X509TrustManager defaultTrustManager = createDefaultTrustManager();
        return new TrustManager[] { defaultTrustManager };
    }

    private static TrustManager[] getSCPTrustManagers(String host, String expectedCertificateHash)
            throws Exception {
        return getSupplementaryTrustManagers((certificate) -> {
            if (expectedCertificateHash == null || expectedCertificateHash.isBlank()) {
                SCPVerifier.verifyPresetCertificate(host, certificate);
            } else {
                SCPVerifier.verifyCertificateHash(certificate, expectedCertificateHash);
            }
        });
    }

    private static TrustManager[] getDCPTrustManagers(String exp_spk) throws Exception {
        return getSupplementaryTrustManagers(
                certificate -> DCPVerifier.verifyCertificatePin(certificate, exp_spk));
    }

    private static TrustManager[] getASPinTrustManagers(ASPinVerifier.CertificateClaim claim)
            throws Exception {
        return getSupplementaryTrustManagers(
                certificate -> ASPinVerifier.verifyCertificate(claim, certificate));
    }

    private interface CertificateCheck {
        void verify(X509Certificate certificate) throws CertificateException;
    }

    private static TrustManager[] getSupplementaryTrustManagers(CertificateCheck check)
            throws Exception {
        final X509TrustManager defaultTrustManager = createDefaultTrustManager();
        return new TrustManager[] { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return defaultTrustManager.getAcceptedIssuers();
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                if (chain == null || chain.length == 0) {
                    throw new CertificateException("TLS server did not provide a certificate chain");
                }
                defaultTrustManager.checkServerTrusted(chain, authType);
                check.verify(chain[0]);
            }

            public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                defaultTrustManager.checkClientTrusted(chain, authType);
            }
        }};
    }

    // Constructor to initialize trust managers and SSL socket factories
    public HttpsConn() throws Exception {
    }

    //@Setup(Level.Iteration)
    public static void main(String[] args) throws Exception
    {
        //String trustStorePath = System.getProperty("java.home") + "/lib/security/cacerts";
        //System.out.println("trustStorePath: " + trustStorePath);

        //args: www.xxx.com, bypass/default/aspin, exp_issuer/dcp, exp_spk

        HttpsConn req = new HttpsConn();

        long startTime = System.nanoTime();

        HttpsURLConnection con = req.create_main_conn(args);
        String res = req.get_content(con);

        long endTime = System.nanoTime();
        //System.out.println(args[0] + "," + args[1] + "," + (endTime - startTime) / 1_000_000.0 );

        //System.out.println(res+"\n");
    }


    public static HttpsURLConnection create_conn(String url) throws Exception {

        URL uri;
        uri = URI.create(url).toURL();
        HttpsURLConnection con = (HttpsURLConnection) uri.openConnection();
        return con;
    }

    public static HttpsURLConnection create_main_conn(String[] para) throws Exception {
        //para: www.xxx.com, bypass/default/aspin, exp_issuer

        resolveHost(para[0]);
        URL url;
        url = URI.create("https://" + para[0]).toURL();
        HttpsURLConnection con = (HttpsURLConnection)url.openConnection();

        if(para[1].equals("default") || para[1].equals("standard")) {
            SSLSocketFactory defaultSslSocketFactory = createDefaultSslSocketFactory();
            con.setSSLSocketFactory(defaultSslSocketFactory);
        }else if(para[1].equals("bypass")) {
            SSLSocketFactory bypassSslSocketFactory = createBypassSslSocketFactory();
            con.setSSLSocketFactory(bypassSslSocketFactory);
            //HostnameVerifier hv = createBypassHostnameVerifier();
            //con.setHostnameVerifier(hv);
        }else if(para[1].equals("scp")) {
            String expectedHash = para.length > 2 ? para[2] : null;
            con.setSSLSocketFactory(createSCPSSLSocketFactory(para[0], expectedHash));
        }else if(para[1].equals("aspin")) {
            throw new IllegalArgumentException(
                    "ASPin requires an authenticated CertificateClaim; use createASPinConnection");
        }else if(para[1].equals("dcp")) {
            SSLSocketFactory dcpSslSocketFactory = createDCPSslSocketFactory(para[0], para[3]);
            con.setSSLSocketFactory(dcpSslSocketFactory);
        }
        return con;
    }



    public static boolean checkExpSPK(X509Certificate ee, String exp_spk) throws Exception {
        String normalizedExpSpk = exp_spk.replace(":", "").toLowerCase();
        String hashAlgorithm = spkHashAlgorithm(normalizedExpSpk);
        String spk = CertificateInfo.calcSubjecPKHash(hashAlgorithm, ee);
        return spk.equals(normalizedExpSpk);
    }

    private static String spkHashAlgorithm(String normalizedExpSpk) {
        if (normalizedExpSpk.length() == 64) {
            return "SHA-256";
        }
        if (normalizedExpSpk.length() == 96) {
            return "SHA-384";
        }
        throw new IllegalArgumentException("Expected SPK must be a SHA-256 or SHA-384 hex digest");
    }

    private static SSLSocketFactory createDefaultSslSocketFactory() throws Exception {
        TrustManager[] defaultTrustManagers = getDefaultTrustManagers();
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, defaultTrustManagers, new SecureRandom());
        return sslContext.getSocketFactory();
    }

    public static HttpsURLConnection createStandardTLSConnection(String host) throws Exception {
        return create_main_conn(new String[] { host, "standard" });
    }

    public static HttpsURLConnection createSCPConnection(String host) throws Exception {
        return create_main_conn(new String[] { host, "scp" });
    }

    public static HttpsURLConnection createSCPConnection(String host, String certificateHash)
            throws Exception {
        return create_main_conn(new String[] { host, "scp", certificateHash });
    }

    public static HttpsURLConnection createDCPConnection(String host, String authenticatedPin)
            throws Exception {
        return create_main_conn(new String[] { host, "dcp", "", authenticatedPin });
    }

    public static HttpsURLConnection createASPinConnection(
            String host, ASPinVerifier.CertificateClaim authenticatedClaim) throws Exception {
        resolveHost(host);
        URL url = URI.create("https://" + host).toURL();
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        TrustManager[] trustManagers = getASPinTrustManagers(authenticatedClaim);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, new SecureRandom());
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        return connection;
    }

    private static SSLSocketFactory createSCPSSLSocketFactory(
            String host, String expectedCertificateHash) throws Exception {
        TrustManager[] trustManagers = getSCPTrustManagers(host, expectedCertificateHash);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, new SecureRandom());
        return sslContext.getSocketFactory();
    }


    private static SSLSocketFactory createDCPSslSocketFactory(String host, String exp_spk) throws Exception {
        TrustManager[] dcpTrustManagers = getDCPTrustManagers(exp_spk);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, dcpTrustManagers, new SecureRandom());
        return sslContext.getSocketFactory();
    }

    private static HostnameVerifier createBypassHostnameVerifier() {
        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) { return true; }
        };
        return hv;
    }

    public static SSLSocketFactory createBypassSslSocketFactory() throws Exception {
        TrustManager[] bypassTrustManagers = getBypassTrustManagers();
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, bypassTrustManagers, new SecureRandom());
        return sslContext.getSocketFactory();
    }



    private void print_https_cert(HttpsURLConnection con) throws Exception {

        //System.out.println("Response Code : " + con.getResponseCode());
        //System.out.println("Cipher Suite : " + con.getCipherSuite());
        //System.out.println("\n");

        Certificate[] certs = con.getServerCertificates();
        for(Certificate cert : certs){
            //System.out.println("Cert Type : " + cert.getType());
            //System.out.println("Cert Hash Code : " + cert.hashCode());
            //System.out.println("Cert Public Key Algorithm : "
            //        + cert.getPublicKey().getAlgorithm());
            //System.out.println("Cert Public Key Format : "
            //        + cert.getPublicKey().getFormat());

            //String issuer = cert.getIssuerX500Principal().toString();
            //System.out.println("Cert Issuer Name: " + issuer);

            //System.out.println("\n");
        }

    }

    public static String get_content(HttpsURLConnection con) throws Exception {

        //System.out.println("****** Content of the URL ********");
        BufferedReader br =
                new BufferedReader(
                        new InputStreamReader(con.getInputStream()));

        String input;
        String res = "";
        while ((input = br.readLine()) != null){
            res = res + input;
            //System.out.println(input);
        }
        br.close();

        //System.out.println("\n");

        return res;
    }

    public static void print_content(HttpsURLConnection con) throws Exception {

        //System.out.println("****** Content of the URL ********");
        BufferedReader br =
                new BufferedReader(
                        new InputStreamReader(con.getInputStream()));

        String input;
        //String res = "";
        while ((input = br.readLine()) != null){
            //res = res + input;
            //System.out.println(input);
        }
        br.close();

        //System.out.println("\n");

        //return res;
    }


        public static String getHttpContent(String urlString) throws Exception {
        Exception lastEx = null;
        for (int retry = 0; retry < 3; retry++) {
            try {
                URL url = URI.create(urlString).toURL();
                java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    return sb.toString().trim();
                }
            } catch (Exception e) {
                lastEx = e;
                try { Thread.sleep(200); } catch (Throwable ignored) {}
            }
        }
        throw lastEx;
    }

    private static void resolveHost(String host) {
        for (int i = 0; i < 5; i++) {
            try {
                java.net.InetAddress.getByName(host);
                return;
            } catch (Throwable ignored) {
                try { Thread.sleep(200); } catch (Throwable ignored2) {}
            }
        }
    }

}
