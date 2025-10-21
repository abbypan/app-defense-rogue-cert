package com.abbypan.appservercert;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.json.JSONObject;

import com.abbypan.appservercert.JsonUtils;
import com.abbypan.appservercert.JwtVerifier;

/**
 * Unit tests for JwtVerifier class
 * Tests JWT token creation and verification functionality
 */
public class JwtVerifierTest {

    @Test
    public void main() throws Exception {
        String appcert = JsonUtils.read_file("src/main/resources/my-app-cert.pem");
        String cscert = JsonUtils.read_file("src/main/resources/my-cs-cert.pem");

        String csjson = JsonUtils.read_file("src/main/resources/serverCertClaimSigningKey.jwt");
        //System.out.println(csjson);

        //X509Certificate certificate = PemUtils.parseX509Certificate(appcert);
        
        // Use the new method for JSON JWT verification
        String csverifyres = JwtVerifier.verifyJwtWithCert(csjson, appcert);
        System.out.println("verify csjson -> appcert: " + csverifyres);
        String cs_jwk = new JSONObject(csverifyres).getString("cs_jwk");

        String certclaim = JsonUtils.read_file("src/main/resources/serverCertClaim.jwt");
        //System.out.println(certclaim);

        //PublicKey publicKey = JwkToPublicKeyConverter.convertJwkToPublicKey(csverifyres);
        String claimres = JwtVerifier.verifyJwtWithJwk(certclaim, cs_jwk);
        System.out.println("verify certclaim -> csjwk: " + claimres);

        JSONObject claimjs = new JSONObject(claimres);
        String host = claimjs.getString("host");
        String expissuer = claimjs.getString("issuer");
        System.out.println("host: " + host + ", issuer: " + expissuer);

      //  String csverifyres2 = JwtVerifier.verifyJwtWithCert(csjson, cscert);
       // System.out.println("verify csjson -> cscert: " + csverifyres2);


    }

   
}
