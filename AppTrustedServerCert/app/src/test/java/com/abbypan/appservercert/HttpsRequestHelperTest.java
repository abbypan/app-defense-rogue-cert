package com.abbypan.appservercert;

import javax.net.ssl.HttpsURLConnection;

import org.junit.Test;

import com.abbypan.appservercert.HttpsRequestHelper;

public class HttpsRequestHelperTest {


    @Test
    public  void main() throws Exception {
        ourConn("https://appservercert.run.place", "our", "CN=E7, O=Let's Encrypt, C=US");

        ourConn("https://appservercert.run.place", "our", "CN=E6, O=Let's Encrypt, C=US");

        ourConn("https://appservercert.run.place", "default", null);

        ourConn("https://appservercert.run.place", "bypass", null);
    }


    public static void ourConn(String host, String type, String exp_issuer) {
        // Benchmark code to be measured
        String[] para = { host, type, exp_issuer };
        HttpsRequestHelper our = new HttpsRequestHelper();
        HttpsURLConnection con = null;
        try {
            con = our.create_main_conn(para);
            our.print_content(con);

        } catch (Exception e) {
            MockLog.e("HttpsRequestHelperTest", "Failed to create connection: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
