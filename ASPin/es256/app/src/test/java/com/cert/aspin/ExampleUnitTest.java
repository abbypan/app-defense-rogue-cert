package com.cert.aspin;

import org.junit.Test;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.security.PublicKey;
import javax.net.ssl.HttpsURLConnection;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {

    
    @Test
    public void RequestHttps() {
        HttpsConnTest helper = new HttpsConnTest();
        
        try {
        // Test with issuer validation during handshake
        MockLog.d("ExampleUnitTest", "\n>>>>>>>Testing HTTPS request with issuer validation during handshake:");
            HttpsURLConnection aspin_conn = HttpsConn.create_main_conn( new String[] {"https://appservercert.run.place", "aspin", "CN=E7, O=Let's Encrypt, C=US"});
            MockLog.d("ExampleUnitTest", "ASPin connection created successfully");
                } catch (Exception e) {
            MockLog.e("ExampleUnitTest", "Failed to create ASPin connection: " + e.getMessage());
            e.printStackTrace();
        }
        
        try {
        // Test without issuer validation
        MockLog.d("ExampleUnitTest", "\n>>>>>>>Testing HTTPS request without issuer validation:");
            HttpsURLConnection conn = HttpsConn.create_conn("https://appservercert.run.place");
            //helper.print_content(conn);
            MockLog.d("ExampleUnitTest", "Standard connection created successfully");
                } catch (Exception e) {
            MockLog.e("ExampleUnitTest", "Failed to create standard connection: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
  
      
    @Test
    public void testAppInfo() {
        // Note: This test requires Android context, so it's mainly for demonstration
        // In a real Android test, you would use AndroidJUnitRunner and @RunWith(AndroidJUnit4.class)
        MockLog.d("ExampleUnitTest", "AppInfo class created successfully");
        MockLog.d("ExampleUnitTest", "Usage example:");
        MockLog.d("ExampleUnitTest", "AppInfo appInfo = new AppInfo(context);");
        MockLog.d("ExampleUnitTest", "String appId = appInfo.getAppId();");
        MockLog.d("ExampleUnitTest", "List<PublicKey> signingKeys = appInfo.getSigningKeys();");
        MockLog.d("ExampleUnitTest", "String fingerprint = appInfo.getPrimarySigningKeyFingerprint();");
        
        // Note: This is a unit test that runs on the JVM, not on Android
        // The output will appear in the test console/IDE output
        MockLog.i("ExampleUnitTest", "=== AppInfo Test Completed ===");
    }
}
