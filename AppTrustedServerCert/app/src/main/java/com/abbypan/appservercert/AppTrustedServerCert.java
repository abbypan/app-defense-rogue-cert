package com.abbypan.appservercert;

import android.content.Context;
import android.util.Log;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.json.JSONObject;

/**
 * Class for managing trusted server certificates for the app
 * Provides functionality to store, retrieve, and validate server certificates
 */
public class AppTrustedServerCert {
    
    private static final String TAG = "AppTrustedServerCert";

    public static void main(String[] args) throws Exception {
        String host = args[0];
        // Note: This main method is for testing only - Context is not available in main
        //Log.d(TAG, "Testing with host: " + host);
    }  
    
    public  static String  getServerCertClaim(Context ts, String host) throws Exception {
 
        String appcert = AppInfo.getPrimarySigningCert(ts);
        //Log.d(TAG, "appcert: " + appcert);
 
        HttpsURLConnection csconn = HttpsConn.create_conn("https://" + host + "/.well-known/ClaimSigningKey.jwt");
        String csjwt = HttpsConn.get_content(csconn);
        //Log.d(TAG, "csjwt: " + csjwt);

        HttpsURLConnection certconn = HttpsConn.create_conn("https://" + host +
        "/.well-known/ServerCertClaim.jwt");
               String certclaim = HttpsConn.get_content(certconn);
        //Log.d(TAG, "certclaim: " + certclaim);

        String csverifyres = JwtVerifier.verifyJwtWithCert(csjwt, appcert);
        //Log.d(TAG, "csverifyres: " + csverifyres);
        String cs_jwk = new JSONObject(csverifyres).getString("cs_jwk");
        
        String claimres = JwtVerifier.verifyJwtWithJwk(certclaim, cs_jwk);
        //Log.d(TAG, "claimres: " + claimres);

        JSONObject claimjs = new JSONObject(claimres);
        String exphost = claimjs.getString("host");
        String expissuer = claimjs.getString("issuer");
        //Log.d(TAG, "exphost: " + exphost + ", expissuer: " + expissuer);
        // Return formatted string instead of updating UI directly


        if(host.equals(exphost)) {
                 return expissuer;
          //    return "appcert: \n" + appcert +
        //            "\n\ncsjwt: \n" + csjwt +
        //            "\n\nverify csjson -> appcert: " + csverifyres
        //            + "\n\nverify certclaim -> csjwk: " + claimres
        //            + "\n\nhost: " + exphost + ", issuer: " + expissuer ;
         }else{
          throw new Exception("Host mismatch: " + host + " != " + exphost);
        }
    }
}
