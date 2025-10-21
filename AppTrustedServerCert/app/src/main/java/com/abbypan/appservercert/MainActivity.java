package com.abbypan.appservercert;

import java.util.HashMap;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import javax.net.ssl.HttpsURLConnection;

import org.json.JSONObject;

public class MainActivity extends AppCompatActivity {
    
    private static final String TAG = "MainActivity";
    private static final String OUR_HOST = "appservercert.run.place";
    //private static final String OUR_ISSUER = "CN=E7, O=Let's Encrypt, C=US";
    private static final String OUR_ISSUER = "CN=test issuer";
    
    private HttpsRequestHelper httpsRequestHelper;
   // private AppInfoManager appInfoManager;
    private EditText hostTextView;
    private EditText expIssuerTextView;
    private TextView responseTextView;
    private Button GetHTTPContentButton;
    private Button GetAndVerifyClaimButton;
    private Button JWTSCCSKBenchmarkButton;
    private Button JWTSCCBenchmarkButton;
    private Button httpsDefaultConnectionBenchmarkButton;
    private Button httpsBypassConnectionBenchmarkButton;
    private Button httpsOurConnectionBenchmarkButton;
    private Button httpsCreateConnBenchmarkButton;
    private Button getCertClaimJWTBenchmarkButton;
    private EditText maxBenchmarkAttemptNumber;
    private Handler mainHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        // Initialize HTTPS request helper
        try {
            httpsRequestHelper = new HttpsRequestHelper();
        } catch (Exception e) {
            // Handle initialization error
            e.printStackTrace();
        }
        
        // Initialize UI components
        hostTextView = findViewById(R.id.hostTextView);
        expIssuerTextView = findViewById(R.id.expIssuerTextView);
        responseTextView = findViewById(R.id.responseTextView);
        GetHTTPContentButton = findViewById(R.id.GetHTTPContentButton);
        GetAndVerifyClaimButton = findViewById(R.id.GetAndVerifyClaimButton);
        JWTSCCSKBenchmarkButton = findViewById(R.id.JWTSCCSKBenchmarkButton);
        JWTSCCBenchmarkButton = findViewById(R.id.JWTSCCBenchmarkButton);
        httpsDefaultConnectionBenchmarkButton = findViewById(R.id.httpsDefaultConnectionBenchmarkButton);
        httpsBypassConnectionBenchmarkButton = findViewById(R.id.httpsBypassConnectionBenchmarkButton);
        httpsOurConnectionBenchmarkButton = findViewById(R.id.httpsOurConnectionBenchmarkButton);
        httpsCreateConnBenchmarkButton = findViewById(R.id.httpsCreateConnBenchmarkButton);
        getCertClaimJWTBenchmarkButton = findViewById(R.id.getCertClaimJWTBenchmarkButton);
        maxBenchmarkAttemptNumber = findViewById(R.id.maxBenchmarkAttemptNumber);
        mainHandler = new Handler(Looper.getMainLooper());
        
        // Initialize app info manager
        //appInfoManager = new AppInfoManager(this, mainHandler, appInfoTextView);
       //AppInfo appInfo = new AppInfo(this);

        // Set initial host display
        updateHostDisplay(OUR_HOST);
        
        // Set initial expected issuer display
        updateExpIssuerDisplay(OUR_ISSUER);

        // Set up button click listeners
        GetHTTPContentButton.setOnClickListener(v -> {
            GetHTTPContent("https://" + getCurrentHost());
        });
        
        GetAndVerifyClaimButton.setOnClickListener(v -> {
            GetAndVerifyClaim();
        });
        
        JWTSCCSKBenchmarkButton.setOnClickListener(v -> {
            runVerifyJwtSigningKeyBenchmark();
        });
        
        JWTSCCBenchmarkButton.setOnClickListener(v -> {
            runVerifyJWTCertClaimBenchmark();
        });
        
        httpsDefaultConnectionBenchmarkButton.setOnClickListener(v -> {
            runHttpsDefaultConnectionBenchmark();
        });
        
        httpsBypassConnectionBenchmarkButton.setOnClickListener(v -> {
            runHttpsBypassConnectionBenchmark();
        });
        
        httpsOurConnectionBenchmarkButton.setOnClickListener(v -> {
            runHttpsOurConnectionBenchmark();
        });

        httpsCreateConnBenchmarkButton.setOnClickListener(v -> {
            runGetSigningKeyJWTBenchmark();
        });

        getCertClaimJWTBenchmarkButton.setOnClickListener(v -> {
            runGetCertClaimJWTBenchmark();
        });
    }

    /**
     * Update the host display EditText
     * @param host The host URL to display
     */
    public void updateHostDisplay(String host) {
        if (hostTextView != null) {
            hostTextView.setText(host);
        }
    }
    
    /**
     * Update the expected issuer display EditText
     * @param expIssuer The expected issuer to display
     */
    public void updateExpIssuerDisplay(String expIssuer) {
        if (expIssuerTextView != null) {
            expIssuerTextView.setText(expIssuer);
        }
    }
    
    /**
     * Get the current host URL from the EditText
     * @return The current host URL, or default URL if empty
     */
    public String getCurrentHost() {
        if (hostTextView != null) {
            String host = hostTextView.getText().toString().trim();
            return host.isEmpty() ? OUR_HOST : host;
        }
        return OUR_HOST;
    }
    
    /**
     * Get the current expected issuer from the EditText
     * @return The current expected issuer, or default issuer if empty
     */
    public String getCurrentExpIssuer() {
        if (expIssuerTextView != null) {
            String expIssuer = expIssuerTextView.getText().toString().trim();
            return expIssuer.isEmpty() ? OUR_ISSUER : expIssuer;
        }
        return OUR_ISSUER;
    }
    
    /**
     * Get the current max benchmark attempts from the EditText
     * @return The current max benchmark attempts, or default 1000 if empty or invalid
     */
    public int getCurrentMaxBenchmarkAttempts() {
        if (maxBenchmarkAttemptNumber != null) {
            String maxAttemptsStr = maxBenchmarkAttemptNumber.getText().toString().trim();
            if (!maxAttemptsStr.isEmpty()) {
                try {
                    int maxAttempts = Integer.parseInt(maxAttemptsStr);
                    return maxAttempts > 0 ? maxAttempts : 1000; // Ensure positive number
                } catch (NumberFormatException e) {
                    return 1000; // Default to 1000 if invalid input
                }
            }
        }
        return 1000; // Default to 1000
    }
    
    
    public void GetHTTPContent(String url) {
        // Show loading message
        mainHandler.post(() -> {
            responseTextView.setText("Getting HTTP content from: " + url + "\nPlease wait...");
        });
        
        // Perform network operation on background thread
        new Thread(() -> {
            try {
                HttpsURLConnection con = httpsRequestHelper.create_conn(url);
                String info = httpsRequestHelper.get_content(con);
                //String info = getAppSignedServerCertClaim(url);
                //Log.d(TAG, "HTTP content retrieved successfully from: " + url);
                
                // Update response text view on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTP content retrieved successfully!\nURL: " + url +
                     "\nTimestamp: " + java.text.DateFormat.getDateTimeInstance().format(new java.util.Date())
                     + "\n\nContent:\n" + info);
                });
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to get HTTP content from: " + url, e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Failed to get HTTP content!\nURL: " + url + "\nError: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "Failed to get HTTP content: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    public void GetAndVerifyClaim() {
        // Show loading message
        mainHandler.post(() -> {
            responseTextView.setText("Getting and verifying server certificate claim...\nPlease wait...");
        });
        
        // Perform network operation on background thread
        new Thread(() -> {
            try {
                // Get and verify server certificate claim
                String expIssuer = AppTrustedServerCert.getAppSignedServerCertClaim(this, getCurrentHost());
                
                // Update the response text view with server certificate claim on main thread
                mainHandler.post(() -> {
                    responseTextView.setText(expIssuer);
                    expIssuerTextView.setText(expIssuer);
                    
                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "Server certificate claim verified", Toast.LENGTH_SHORT).show();
                });
                
                // Also log the information
                //Log.d(TAG, "Server Certificate Claim:\n" + expIssuer);
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to get and verify server certificate claim: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Failed to get and verify server certificate claim: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "Failed to get and verify server certificate claim: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    public void runVerifyJwtSigningKeyBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running JWT signing key verification benchmark...\nPlease wait...");
        });
        
        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                // Get the JWT and certificate for benchmarking
                String host = getCurrentHost();
                String appcert = AppInfo.getPrimarySigningCert(this);
                
                // Get the JWT token to benchmark
                HttpsURLConnection csconn = HttpsRequestHelper.create_conn("https://" + host + "/.well-known/serverCertClaimSigningKey.jwt");
                String csjwt = HttpsRequestHelper.get_content(csconn);
                
                // Run benchmark with dynamic iterations
                String benchmarkResults = JwtBenchmark.runVerifyJwtSigningKeyBenchmark(csjwt, appcert, maxAttempts);
                
                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("JWT Signing Key Verification Benchmark Results\n" +
                                           "============================================\n\n" + benchmarkResults);
                    
                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "JWT Signing Key Benchmark completed", Toast.LENGTH_SHORT).show();
                });
                
                // Also log the results
                //Log.d(TAG, "JWT Signing Key Benchmark Results:\n" + benchmarkResults);
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to run JWT signing key benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("JWT Signing Key Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "JWT Signing Key Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    public void runVerifyJWTCertClaimBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running JWT server cert claim verification benchmark...\nPlease wait...");
        });
        
        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                // Get the JWT and JWK for benchmarking
                String host = getCurrentHost();
                String appcert = AppInfo.getPrimarySigningCert(this);
                
                // Get the signing key JWT
                HttpsURLConnection csconn = HttpsRequestHelper.create_conn("https://" + host + "/.well-known/serverCertClaimSigningKey.jwt");
                String csjwt = HttpsRequestHelper.get_content(csconn);
                
                // Verify the signing key JWT to get the JWK
                String csverifyres = JwtVerifier.verifyJwtWithCert(csjwt, appcert);
                String cs_jwk = new JSONObject(csverifyres).getString("cs_jwk");
                
                // Get the certificate claim JWT
                HttpsURLConnection certconn = HttpsRequestHelper.create_conn("https://" + host + "/.well-known/serverCertClaim.jwt");
                String certclaim = HttpsRequestHelper.get_content(certconn);
                
                // Run benchmark with dynamic iterations
                String benchmarkResults = JwtBenchmark.runVerifyJWTCertClaimBenchmark(certclaim, cs_jwk, maxAttempts);
                
                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("JWT Server Cert Claim Verification Benchmark Results\n" +
                                           "==================================================\n\n" + benchmarkResults);
                    
                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "JWT Server Cert Claim Benchmark completed", Toast.LENGTH_SHORT).show();
                });
                
                // Also log the results
                //Log.d(TAG, "JWT Server Cert Claim Benchmark Results:\n" + benchmarkResults);
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to run JWT server cert claim benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("JWT Server Cert Claim Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "JWT Server Cert Claim Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    public void runHttpsDefaultConnectionBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running HTTPS connection benchmark...\nPlease wait...");
        });
        
        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                // Get the URL for benchmarking
                String host = getCurrentHost();
                
                // Run benchmark with dynamic iterations
                String benchmarkResults = JwtBenchmark.runHttpsDefaultConnectionBenchmark(host, maxAttempts);
                
                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS Connection Benchmark Results\n" +
                                           "==================================\n\n" + benchmarkResults);
                    
                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "HTTPS Connection Benchmark completed", Toast.LENGTH_SHORT).show();
                });
                
                // Also log the results
                //Log.d(TAG, "HTTPS Connection Benchmark Results:\n" + benchmarkResults);
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to run HTTPS connection benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS Connection Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "HTTPS Connection Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    public void runHttpsBypassConnectionBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running HTTPS bypass connection benchmark...\nPlease wait...");
        });
        
        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                // Get the URL for benchmarking
                String host = getCurrentHost();
                
                // Run benchmark with dynamic iterations
                String benchmarkResults = JwtBenchmark.runHttpsBypassConnectionBenchmark(host, maxAttempts);
                
                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS Bypass Connection Benchmark Results\n" +
                                           "=======================================\n\n" + benchmarkResults);
                    
                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "HTTPS Bypass Connection Benchmark completed", Toast.LENGTH_SHORT).show();
                });
                
                // Also log the results
                //Log.d(TAG, "HTTPS Bypass Connection Benchmark Results:\n" + benchmarkResults);
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to run HTTPS bypass connection benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS Bypass Connection Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "HTTPS Bypass Connection Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    public void runHttpsOurConnectionBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running HTTPS our connection benchmark...\nPlease wait...");
        });
        
        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                // Get the host and expected issuer for benchmarking
                String host =  getCurrentHost();

                String expIssuer = getCurrentExpIssuer();

                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Test Our Conn:" + host + ", " + expIssuer);
                });

                // Run benchmark with dynamic iterations
                String benchmarkResults = JwtBenchmark.runHttpsOurConnectionBenchmark(host, expIssuer, maxAttempts);
                
                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS Our Connection Benchmark Results\n" +
                                           "=====================================\n\n" + benchmarkResults);
                    
                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "HTTPS Our Connection Benchmark completed", Toast.LENGTH_SHORT).show();
                });
                
                // Also log the results
                //Log.d(TAG, "HTTPS Our Connection Benchmark Results:\n" + benchmarkResults);
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to run HTTPS our connection benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS Our Connection Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "HTTPS Our Connection Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    public void runGetSigningKeyJWTBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running Get Signing Key JWT benchmark...\nPlease wait...");
        });
        
        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                // Get the host for benchmarking
                String host = getCurrentHost();
                
                // Run benchmark with dynamic iterations
                String benchmarkResults = JwtBenchmark.runGetSigningKeyJWTBenchmark(host, maxAttempts);
                
                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Get Signing Key JWT Benchmark Results\n" +
                                           "=====================================\n\n" + benchmarkResults);
                    
                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "Get Signing Key JWT Benchmark completed", Toast.LENGTH_SHORT).show();
                });
                
                // Also log the results
                //Log.d(TAG, "Get Signing Key JWT Benchmark Results:\n" + benchmarkResults);
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to run Get Signing Key JWT benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Get Signing Key JWT Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "Get Signing Key JWT Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    public void runGetCertClaimJWTBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running Get Cert Claim JWT benchmark...\nPlease wait...");
        });
        
        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                // Get the host for benchmarking
                String host = getCurrentHost();
                
                // Run benchmark with dynamic iterations
                String benchmarkResults = JwtBenchmark.runGetCertClaimJWTBenchmark(host, maxAttempts);
                
                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Get Cert Claim JWT Benchmark Results\n" +
                                           "===================================\n\n" + benchmarkResults);
                    
                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "Get Cert Claim JWT Benchmark completed", Toast.LENGTH_SHORT).show();
                });
                
                // Also log the results
                //Log.d(TAG, "Get Cert Claim JWT Benchmark Results:\n" + benchmarkResults);
                
            } catch (Exception e) {
                Log.e(TAG, "Failed to run Get Cert Claim JWT benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Get Cert Claim JWT Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "Get Cert Claim JWT Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();

    }
}
