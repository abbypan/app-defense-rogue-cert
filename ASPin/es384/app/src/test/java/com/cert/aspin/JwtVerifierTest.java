package com.cert.aspin;

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

import com.cert.aspin.JsonUtils;
import com.cert.aspin.JwtVerifier;

/**
 * Unit tests for JwtVerifier class
 * Tests JWT token creation and verification functionality
 */
public class JwtVerifierTest {

    @Test
    public void main() throws Exception {
        String alg = "es384";
      //  String alg = "es256";
       // String alg = "rsa4096";
      //  String alg = "rsa3072";

        String appcert = JsonUtils.read_file("src/main/resources/"+ alg + "/my-app-cert.pem");
        //String cscert = JsonUtils.read_file("src/main/resources/my-claim-cert.pem");

        String csjson = JsonUtils.read_file("src/main/resources/"+ alg + "/ClaimSigningKey.jwt");
        //System.out.println(csjson);

        String certclaim = JsonUtils.read_file("src/main/resources/"+ alg + "/ServerCertClaim.jwt");
        //System.out.println(certclaim);

        //X509Certificate certificate = PemUtils.parseX509Certificate(appcert);
        
        // Use the new method for JSON JWT verification
        String csverifyres = JwtVerifier.verifyJwtWithCert(csjson, appcert);
        System.out.println("verify csjson -> appcert: " + csverifyres);
        String cs_jwk = JwtVerifier.extractConfirmationJwk(csverifyres);


        //PublicKey publicKey = JwkToPublicKeyConverter.convertJwkToPublicKey(csverifyres);
        String claimres = JwtVerifier.verifyJwtWithJwk(certclaim, cs_jwk);
        System.out.println("verify certclaim -> csjwk: " + claimres);

        JSONObject claimjs = new JSONObject(claimres);
        String host = claimjs.getString("host");
        String expissuer = claimjs.getString("issuer");
        assertTrue(claimjs.has("subject"));
        assertTrue(claimjs.has("san"));
        assertTrue(claimjs.has("ttl"));
        System.out.println("host: " + host + ", issuer: " + expissuer);

      //  String csverifyres2 = JwtVerifier.verifyJwtWithCert(csjson, cscert);
       // System.out.println("verify csjson -> cscert: " + csverifyres2);


    }

   
}
