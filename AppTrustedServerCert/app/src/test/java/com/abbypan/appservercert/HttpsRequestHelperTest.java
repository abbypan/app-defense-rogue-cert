package com.abbypan.appservercert;

import javax.net.ssl.HttpsURLConnection;

import org.junit.Test;

import com.abbypan.appservercert.HttpsRequestHelper;

public class HttpsRequestHelperTest {


    @Test
    public  void main() throws Exception {
        asprocConn("https://appservercert.run.place", "asproc", "CN=E7, O=Let's Encrypt, C=US");

        asprocConn("https://appservercert.run.place", "asproc", "CN=E6, O=Let's Encrypt, C=US");

        asprocConn("https://appservercert.run.place", "default", null);

        asprocConn("https://appservercert.run.place", "bypass", null);
    }


    public static void asprocConn(String host, String type, String exp_issuer) {
        // Benchmark code to be measured
        String[] para = { host, type, exp_issuer };
        HttpsRequestHelper asproc = null;
        try {
            asproc = new HttpsRequestHelper();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        HttpsURLConnection con = null;
        try {
            con = asproc.create_main_conn(para);
            asproc.print_content(con);

        } catch (Exception e) {
            MockLog.e("HttpsRequestHelperTest", "Failed to create connection: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
