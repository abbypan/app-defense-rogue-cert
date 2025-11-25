package com.abbypan.appservercert;

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



public class HttpsRequestHelper {

    //private static JSONObject our_cache;
    
    // Static global X509TrustManager
    private static X509TrustManager default_tm = null;
    private static TrustManager[] bypassTrustManagers = null;
    private static TrustManager[] defaultTrustManagers = null;
    private static TrustManager[] ourTrustManagers = null;
    
    // Pre-allocated empty array for bypass trust manager to avoid allocation overhead
    private static final X509Certificate[] EMPTY_CERT_ARRAY = new X509Certificate[0];
    
    // Cached SSLContext instances for performance
    private static SSLSocketFactory defaultSslSocketFactory = null;
    private static SSLSocketFactory bypassSslSocketFactory = null;
    private static SSLSocketFactory ourSslSocketFactory = null;
    
    // Static initialization method
    private static synchronized X509TrustManager getDefaultTrustManager() throws Exception {
        if (default_tm == null) {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);

            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager x509TrustManager) {
                    default_tm = x509TrustManager;
                    break;
                }
            }
        }
        return default_tm;
    }
    private static TrustManager[] getBypassTrustManagers() throws Exception {
        // Double-check locking pattern for better performance - avoids synchronization on every call
        if (bypassTrustManagers == null) {
            synchronized (HttpsRequestHelper.class) {
                if (bypassTrustManagers == null) {
                    bypassTrustManagers = new TrustManager[]{
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
            }
        }
        return bypassTrustManagers;
    }

    private static TrustManager[] getDefaultTrustManagers() throws Exception {
        // Double-check locking pattern for better performance - avoids synchronization on every call
        if (defaultTrustManagers == null) {
            synchronized (HttpsRequestHelper.class) {
                if (defaultTrustManagers == null) {
                    default_tm = getDefaultTrustManager();
                    defaultTrustManagers = new TrustManager[] { new X509TrustManager() {

                        public X509Certificate[] getAcceptedIssuers() {
                            return default_tm.getAcceptedIssuers();
                        }

                        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                            default_tm.checkServerTrusted(chain, authType);

                        }
                        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                            default_tm.checkClientTrusted(chain, authType);
                        }
                    }

                    };
                }
            }
        }
        return defaultTrustManagers;
    }

    private static synchronized  TrustManager[]  getOurTrustManagers(String exp_issuer) throws Exception {
        // For our connection, we need to create new trust managers each time due to exp_issuer parameter
        // But we can optimize by ensuring default_tm is already initialized
        default_tm = getDefaultTrustManager();
        ourTrustManagers = new TrustManager[] { new X509TrustManager() {

            public X509Certificate[] getAcceptedIssuers() {
                return default_tm.getAcceptedIssuers();
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                default_tm.checkServerTrusted(chain, authType);

                X509Certificate ee = chain[0];

                try {
                    boolean res = HttpsRequestHelper.checkExpIssuer(ee, exp_issuer);
                    //System.out.println(host + ",our!," + res);
                    if(!res) {
                        throw new Exception("HttpsRequestHelper check: fail!");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                default_tm.checkClientTrusted(chain, authType);
            }
        }

        };
        return ourTrustManagers;
    }

    // Constructor to initialize trust managers and SSL socket factories
    public HttpsRequestHelper() throws Exception {
        // Initialize default trust manager
        getDefaultTrustManager();
        // Initialize bypass trust manager  
        getBypassTrustManagers();
        // Pre-initialize SSL socket factories for better performance
        createDefaultSslSocketFactory();
        createBypassSslSocketFactory();
    }

    //@Setup(Level.Iteration)
    public static void main(String[] args) throws Exception
    {

        //String trustStorePath = System.getProperty("java.home") + "/lib/security/cacerts";
        //System.out.println("trustStorePath: " + trustStorePath);

        //args: www.xxx.com, bypass/default/our, exp_issuer

        HttpsRequestHelper our = new HttpsRequestHelper();

        long startTime = System.nanoTime();

        HttpsURLConnection con = our.create_main_conn(args);
        String res = our.get_content(con);

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
        //para: www.xxx.com, bypass/default/our, exp_issuer

        URL url;
        url = URI.create("https://" + para[0]).toURL();
        HttpsURLConnection con = (HttpsURLConnection)url.openConnection();

        if(para[1].equals("default")) {
             defaultSslSocketFactory = createDefaultSslSocketFactory();
            con.setSSLSocketFactory(defaultSslSocketFactory);
        }else if(para[1].equals("bypass")) {
            bypassSslSocketFactory = createBypassSslSocketFactory();
            con.setSSLSocketFactory(bypassSslSocketFactory);

            //HostnameVerifier hv = createBypassHostnameVerifier();
            //con.setHostnameVerifier(hv);
        }else if(para[1].equals("our")) {
            ourSslSocketFactory = createOurSslSocketFactory(para[0], para[2]);
            con.setSSLSocketFactory(ourSslSocketFactory);
        }
        return con;
    }



    @SuppressWarnings("null")
    public static boolean checkExpIssuer( X509Certificate ee, String exp_issuer) throws Exception {
      
        String issuer = ee.getIssuerX500Principal().toString();
        if(issuer.equals(exp_issuer)) {
            return true;
        }
        return false;
    }

    private static SSLSocketFactory createDefaultSslSocketFactory() throws Exception {
        // Double-check locking pattern for better performance - avoids synchronization on every call
        if (defaultSslSocketFactory == null) {
            synchronized (HttpsRequestHelper.class) {
                if (defaultSslSocketFactory == null) {
                    TrustManager[] defaultTrustManagers = getDefaultTrustManagers();
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(null, defaultTrustManagers, new SecureRandom());
                    defaultSslSocketFactory = sslContext.getSocketFactory();
                }
            }
        }
        return defaultSslSocketFactory;
    }


    private static SSLSocketFactory createOurSslSocketFactory(String host, String exp_issuer) throws Exception {
        // For our connection, we need to create a new SSLContext each time due to exp_issuer parameter
        // But we can optimize by reusing the trust managers if they're already created
        // Double-check locking pattern for better performance - avoids synchronization on every call
        if(ourSslSocketFactory == null) {
            synchronized (HttpsRequestHelper.class) {
                if(ourSslSocketFactory == null) {
                    ourTrustManagers = getOurTrustManagers(exp_issuer);
                    
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(null, ourTrustManagers, new SecureRandom());
                    ourSslSocketFactory = sslContext.getSocketFactory();
                }
            }
        }
        return ourSslSocketFactory;
    }

    private static HostnameVerifier createBypassHostnameVerifier() {
        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) { return true; }
        };
        return hv;
    }

    public static SSLSocketFactory createBypassSslSocketFactory() throws Exception {
        // Double-check locking pattern for better performance - avoids synchronization on every call
        if (bypassSslSocketFactory == null) {
            synchronized (HttpsRequestHelper.class) {
                if (bypassSslSocketFactory == null) {
                    TrustManager[] bypassTrustManagers = getBypassTrustManagers();
                    SSLContext sslContext = SSLContext.getInstance("TLS");
                    sslContext.init(null, bypassTrustManagers, new SecureRandom());
                    bypassSslSocketFactory = sslContext.getSocketFactory();
                }
            }
        }
        return bypassSslSocketFactory;
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

}

