package com.cert.aspin;

import javax.net.ssl.HttpsURLConnection;

import org.junit.Test;

import static org.junit.Assert.assertThrows;

import com.cert.aspin.HttpsConn;

public class HttpsConnTest {


    @Test
    public void issuerOnlyAspInPathIsRejected() {
        assertThrows(IllegalArgumentException.class, () ->
                new HttpsConn().create_main_conn(new String[] {
                        "appservercert.run.place", "aspin", "CN=E7, O=Let's Encrypt, C=US"}));
    }


    public static void aspinConn(String host, String type, String exp_issuer) {
        // Benchmark code to be measured
        String[] para = { host, type, exp_issuer };
        HttpsConn aspin = null;
        try {
            aspin = new HttpsConn();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        HttpsURLConnection con = null;
        try {
            con = aspin.create_main_conn(para);
            aspin.print_content(con);

        } catch (Exception e) {
            MockLog.e("HttpsConnTest", "Failed to create connection: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
