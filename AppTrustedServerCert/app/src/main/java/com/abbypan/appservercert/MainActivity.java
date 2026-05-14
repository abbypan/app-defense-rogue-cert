package com.abbypan.appservercert;

import java.util.HashMap;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

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
    private static final String ASPROC_HOST = "es256.work.gd";
    private static final String DCP_HOST = "dcp.work.gd";
    //private static final String ASPROC_ISSUER = "CN=E7, O=Let's Encrypt, C=US";
    private static final String ASPROC_ISSUER = "CN=test issuer";

    private HttpsConn httpsConn;
   // private AppInfoManager appInfoManager;
    private EditText hostTextView;
    private EditText dcpHostTextView;
    private EditText expIssuerTextView;
    private EditText expSPKTextView;
    private TextView responseTextView;
    private Button GetHTTPContentButton;
    private Button GetAndVerifyClaimButton;
    private Button GetAndVerifyDCPButton;
    private Button JwtCskBenchmarkButton;
    private Button JwtSccBenchmarkButton;
    private Button DCPBenchmarkButton;
    private Button httpsDefaultConnectionBenchmarkButton;
    private Button httpsASPRoCConnectionBenchmarkButton;
    private Button getJwtCskBenchmarkButton;
    private Button getJwtSccBenchmarkButton;
    private EditText maxBenchmarkAttemptNumber;
    private Handler mainHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Initialize HTTPS request helper
        try {
            httpsConn = new HttpsConn();
        } catch (Exception e) {
            // Handle initialization error
            e.printStackTrace();
        }

        // Initialize UI components
        hostTextView = findViewById(R.id.hostTextView);
        dcpHostTextView = findViewById(R.id.dcpHostTextView);
        expIssuerTextView = findViewById(R.id.expIssuerTextView);
        expSPKTextView = findViewById(R.id.expSPKTextView);
        responseTextView = findViewById(R.id.responseTextView);
        GetHTTPContentButton = findViewById(R.id.GetHTTPContentButton);
        GetAndVerifyClaimButton = findViewById(R.id.GetAndVerifyClaimButton);
        GetAndVerifyDCPButton = findViewById(R.id.GetAndVerifyDCPButton);
        JwtCskBenchmarkButton = findViewById(R.id.JwtCskBenchmarkButton);
        JwtSccBenchmarkButton = findViewById(R.id.JwtSccBenchmarkButton);
        DCPBenchmarkButton = findViewById(R.id.DCPBenchmarkButton);
        httpsDefaultConnectionBenchmarkButton = findViewById(R.id.httpsDefaultConnectionBenchmarkButton);
        httpsASPRoCConnectionBenchmarkButton = findViewById(R.id.httpsASPRoCConnectionBenchmarkButton);
        getJwtCskBenchmarkButton = findViewById(R.id.getJwtCskBenchmarkButton);
        getJwtSccBenchmarkButton = findViewById(R.id.getJwtSccBenchmarkButton);
        maxBenchmarkAttemptNumber = findViewById(R.id.maxBenchmarkAttemptNumber);
        mainHandler = new Handler(Looper.getMainLooper());

        // Initialize app info manager
        //appInfoManager = new AppInfoManager(this, mainHandler, appInfoTextView);
       //AppInfo appInfo = new AppInfo(this);

        // Set initial host display
        updateHostDisplay(ASPROC_HOST);
        updateDCPHostDisplay(DCP_HOST);

        // Set initial expected issuer display
        updateExpIssuerDisplay(ASPROC_ISSUER);

        // Set up button click listeners
        GetHTTPContentButton.setOnClickListener(v -> {
            GetHTTPContent("https://" + getCurrentHost());
        });

        GetAndVerifyClaimButton.setOnClickListener(v -> {
            GetAndVerifyClaim();
        });

        GetAndVerifyDCPButton.setOnClickListener(v -> {
            GetAndVerifyDCP();
        });

        JwtCskBenchmarkButton.setOnClickListener(v -> {
            runVerifyJwtCskBenchmark();
        });

        JwtSccBenchmarkButton.setOnClickListener(v -> {
            runVerifyJwtSccBenchmark();
        });

        DCPBenchmarkButton.setOnClickListener(v -> {
            runVerifyDCPBenchmark();
        });

        httpsDefaultConnectionBenchmarkButton.setOnClickListener(v -> {
            runHttpsDefaultConnectionBenchmark();
        });

        httpsASPRoCConnectionBenchmarkButton.setOnClickListener(v -> {
            runHttpsASPRoCConnectionBenchmark();
        });

        getJwtCskBenchmarkButton.setOnClickListener(v -> {
            runGetJwtCskBenchmark();
        });

        getJwtSccBenchmarkButton.setOnClickListener(v -> {
            runGetJwtSccBenchmark();
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

    public void updateDCPHostDisplay(String host) {
        if (dcpHostTextView != null) {
            dcpHostTextView.setText(host);
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

    public void updateExpSPKDisplay(String expSPK) {
        if (expSPKTextView != null) {
            expSPKTextView.setText(expSPK);
        }
    }

    /**
     * Get the current host URL from the EditText
     * @return The current host URL, or default URL if empty
     */
    public String getCurrentHost() {
        if (hostTextView != null) {
            String host = hostTextView.getText().toString().trim();
            return host.isEmpty() ? ASPROC_HOST : host;
        }
        return ASPROC_HOST;
    }

    public String getCurrentHostAlgorithm() {
        return extractHostAlgorithm(getCurrentHost());
    }

    public static String extractHostAlgorithm(String host) {
        String normalizedHost = host.trim();
        int schemeIndex = normalizedHost.indexOf("://");
        if (schemeIndex >= 0) {
            normalizedHost = normalizedHost.substring(schemeIndex + 3);
        }

        int slashIndex = normalizedHost.indexOf('/');
        if (slashIndex >= 0) {
            normalizedHost = normalizedHost.substring(0, slashIndex);
        }

        int portIndex = normalizedHost.indexOf(':');
        if (portIndex >= 0) {
            normalizedHost = normalizedHost.substring(0, portIndex);
        }

        int dotIndex = normalizedHost.indexOf('.');
        return dotIndex >= 0 ? normalizedHost.substring(0, dotIndex) : normalizedHost;
    }

    public String getDCPHost() {
        if (dcpHostTextView != null) {
            String host = dcpHostTextView.getText().toString().trim();
            return host.isEmpty() ? DCP_HOST : host;
        }
        return DCP_HOST;
    }

    /**
     * Get the current expected issuer from the EditText
     * @return The current expected issuer, or default issuer if empty
     */
    public String getCurrentExpIssuer() {
        if (expIssuerTextView != null) {
            String expIssuer = expIssuerTextView.getText().toString().trim();
            return expIssuer.isEmpty() ? ASPROC_ISSUER : expIssuer;
        }
        return ASPROC_ISSUER;
    }

    public String getCurrentExpSPK() {
        if (expSPKTextView != null) {
            return expSPKTextView.getText().toString().trim();
        }
        return "";
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
                HttpsURLConnection con = httpsConn.create_conn(url);
                String info = HttpsConn.get_content(con);
                //String info = getServerCertClaim(url);
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
                String expIssuer = AppTrustedServerCert.getServerCertClaim(this, getCurrentHost());

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

    public void GetAndVerifyDCP() {
        mainHandler.post(() -> {
            responseTextView.setText("Getting and verifying DCP pin...\nPlease wait...");
        });

        new Thread(() -> {
            try {
                String host = getDCPHost();

                HttpsURLConnection pubkeyConn = HttpsConn.create_conn("https://" + host + "/.well-known/my-dcp-pubkey.pem");
                String dcpPublicKeyPem = HttpsConn.get_content(pubkeyConn);

                HttpsURLConnection dcpConn = HttpsConn.create_conn("https://" + host + "/.well-known/my-dcp-servercertpin.json");
                String dcpJson = HttpsConn.get_content(dcpConn);

                String pin = DCPVerifier.verifyDCPWithPublicKeyPem(dcpJson, dcpPublicKeyPem);

                mainHandler.post(() -> {
                    responseTextView.setText(pin);
                    expSPKTextView.setText(pin);
                    Toast.makeText(MainActivity.this, "DCP pin verified", Toast.LENGTH_SHORT).show();
                });

            } catch (Exception e) {
                Log.e(TAG, "Failed to get and verify DCP pin: " + e.getMessage(), e);
                mainHandler.post(() -> {
                    responseTextView.setText("Failed to get and verify DCP pin: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "Failed to get and verify DCP pin: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    public void runVerifyJwtCskBenchmark() {
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
                HttpsURLConnection csconn = HttpsConn.create_conn("https://" + host + "/.well-known/ClaimSigningKey.jwt");
                String csjwt = HttpsConn.get_content(csconn);

                // Run benchmark with dynamic iterations
                String benchmarkResults = BenchmarkVerifier.runVerifyJwtCskBenchmark(csjwt, appcert, maxAttempts);

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

    public void runVerifyJwtSccBenchmark() {
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
                HttpsURLConnection csconn = HttpsConn.create_conn("https://" + host + "/.well-known/ClaimSigningKey.jwt");
                String csjwt = HttpsConn.get_content(csconn);

                // Verify the signing key JWT to get the JWK
                String csverifyres = JwtVerifier.verifyJwtWithCert(csjwt, appcert);
                String cs_jwk = new JSONObject(csverifyres).getString("cs_jwk");

                // Get the certificate claim JWT
                HttpsURLConnection certconn = HttpsConn.create_conn("https://" + host + "/.well-known/ServerCertClaim.jwt");
                String certclaim = HttpsConn.get_content(certconn);

                // Run benchmark with dynamic iterations
                String benchmarkResults = BenchmarkVerifier.runVerifyJwtSccBenchmark(certclaim, cs_jwk, maxAttempts);

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

    public void runVerifyDCPBenchmark() {
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running DCP verification benchmark...\nPlease wait...");
        });

        new Thread(() -> {
            try {
                String dcp_host = getDCPHost();

                String host = getCurrentHost();
                String alg = extractHostAlgorithm(host);
                String dcpPubkeyFile = "resources/" + alg + "/my-dcp-pubkey.pem";
                String dcpPublicKeyPem = readResourceFile(dcpPubkeyFile);

                HttpsURLConnection dcpConn = HttpsConn.create_conn("https://" + dcp_host + "/.well-known/my-dcp-servercertpin.json");
                String dcpJson = HttpsConn.get_content(dcpConn);

                String benchmarkResults = BenchmarkVerifier.runVerifyDCPBenchmark(dcpJson, dcpPublicKeyPem, maxAttempts);

                mainHandler.post(() -> {
                    responseTextView.setText("DCP Verification Benchmark Results\n" +
                                           "==================================\n\n" + benchmarkResults);
                    Toast.makeText(MainActivity.this, "DCP Benchmark completed", Toast.LENGTH_SHORT).show();
                });

            } catch (Exception e) {
                Log.e(TAG, "Failed to run DCP benchmark: " + e.getMessage(), e);
                mainHandler.post(() -> {
                    responseTextView.setText("DCP Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "DCP Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    private String readResourceFile(String resourcePath) throws Exception {
        InputStream inputStream = getClassLoader().getResourceAsStream(resourcePath);
        if (inputStream == null && resourcePath.startsWith("resources/")) {
            inputStream = getClassLoader().getResourceAsStream(resourcePath.substring("resources/".length()));
        }

        try (InputStream stream = inputStream) {
            if (inputStream == null) {
                throw new IllegalArgumentException("Resource not found: " + resourcePath);
            }
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
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
                String benchmarkResults = BenchmarkVerifier.runHttpsDefaultConnectionBenchmark(host, maxAttempts);

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
                String benchmarkResults = BenchmarkVerifier.runHttpsBypassConnectionBenchmark(host, maxAttempts);

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

    public void runHttpsASPRoCConnectionBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running HTTPS ASPRoC connection benchmark...\nPlease wait...");
        });

        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                // Get the host and expected issuer for benchmarking
                String host =  getCurrentHost();

                String expIssuer = getCurrentExpIssuer();

                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Test ASPRoC Conn:" + host + ", " + expIssuer);
                });

                // Run benchmark with dynamic iterations
                String benchmarkResults = BenchmarkVerifier.runHttpsASPRoCConnectionBenchmark(host, expIssuer, maxAttempts);

                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS ASPRoC Connection Benchmark Results\n" +
                                           "=====================================\n\n" + benchmarkResults);

                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "HTTPS ASPRoC Connection Benchmark completed", Toast.LENGTH_SHORT).show();
                });

                // Also log the results
                //Log.d(TAG, "HTTPS ASPRoC Connection Benchmark Results:\n" + benchmarkResults);

            } catch (Exception e) {
                Log.e(TAG, "Failed to run HTTPS ASPRoC connection benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS ASPRoC Connection Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "HTTPS ASPRoC Connection Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    public void runGetJwtCskBenchmark() {
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
                String benchmarkResults = BenchmarkVerifier.runGetJwtCskBenchmark(host, maxAttempts);

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

    public void runGetJwtSccBenchmark() {
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
                String benchmarkResults = BenchmarkVerifier.runGetJwtSccBenchmark(host, maxAttempts);

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
