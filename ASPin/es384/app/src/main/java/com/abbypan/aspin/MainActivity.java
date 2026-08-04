package com.abbypan.aspin;

import java.util.HashMap;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Locale;
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
    private static final String ASPIN_HOST = "es384.idouzi.top";
    private static final String DCP_HOST = "dcp.idouzi.top";
    //private static final String ASPIN_ISSUER = "CN=E7, O=Let's Encrypt, C=US";
    private static final String ASPIN_ISSUER = "CN=test issuer";

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

    private Button AvgVerifTimeBenchmarkButton;
    private Button JwtCskBenchmarkButton;
    private Button JwtSccBenchmarkButton;
    private Button DCPBenchmarkButton;

    private Button httpsDefaultConnectionBenchmarkButton;
    private Button httpsSCPConnectionBenchmarkButton;
    private Button httpsASPinConnectionBenchmarkButton;
    private Button httpsDCPConnectionBenchmarkButton;

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
        AvgVerifTimeBenchmarkButton = findViewById(R.id.AvgVerifTimeBenchmarkButton);
        JwtCskBenchmarkButton = findViewById(R.id.JwtCskBenchmarkButton);
        JwtSccBenchmarkButton = findViewById(R.id.JwtSccBenchmarkButton);
        DCPBenchmarkButton = findViewById(R.id.DCPBenchmarkButton);
        httpsDefaultConnectionBenchmarkButton = findViewById(R.id.httpsDefaultConnectionBenchmarkButton);
        httpsSCPConnectionBenchmarkButton = findViewById(R.id.httpsSCPConnectionBenchmarkButton);
        httpsASPinConnectionBenchmarkButton = findViewById(R.id.httpsASPinConnectionBenchmarkButton);
        httpsDCPConnectionBenchmarkButton = findViewById(R.id.httpsDCPConnectionBenchmarkButton);
        maxBenchmarkAttemptNumber = findViewById(R.id.maxBenchmarkAttemptNumber);
        mainHandler = new Handler(Looper.getMainLooper());

        // Set initial host display
        updateHostDisplay(ASPIN_HOST);
        updateDCPHostDisplay(DCP_HOST);

        // Set initial expected issuer display
        updateExpIssuerDisplay(ASPIN_ISSUER);

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

        if (AvgVerifTimeBenchmarkButton != null) {
                    Button AvgVisitTimeBenchmarkButton = findViewById(R.id.AvgVisitTimeBenchmarkButton);
        if (AvgVisitTimeBenchmarkButton != null) {
            AvgVisitTimeBenchmarkButton.setOnClickListener(v -> runTableAvgVisitTimeBenchmark());
        }
        AvgVerifTimeBenchmarkButton.setOnClickListener(v -> {
                runTableAvgVerifTimeBenchmark();
            });
        }

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

        httpsSCPConnectionBenchmarkButton.setOnClickListener(v -> {
            runHttpsSCPConnectionBenchmark();
        });

        httpsASPinConnectionBenchmarkButton.setOnClickListener(v -> {
            runHttpsASPinConnectionBenchmark();
        });

        httpsDCPConnectionBenchmarkButton.setOnClickListener(v -> {
            runHttpsDCPConnectionBenchmark();
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
            return host.isEmpty() ? ASPIN_HOST : host;
        }
        return ASPIN_HOST;
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
            return expIssuer.isEmpty() ? ASPIN_ISSUER : expIssuer;
        }
        return ASPIN_ISSUER;
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
                String dcp_host = getDCPHost();

                String host = getCurrentHost();
                String alg = extractHostAlgorithm(host);

                String dcpPubkeyFile = "resources/" + alg + "/my-dcp-pubkey.pem";
                String dcpPublicKeyPem = readResourceFile(dcpPubkeyFile);

                HttpsURLConnection dcpConn = HttpsConn.create_conn("https://" + dcp_host + "/.well-known/DCPServerCertPin-" + alg + ".json");
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

    
    
    
    public void runTableAvgVerifTimeBenchmark() {
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running table:avgveriftime benchmark inside App...\nPlease wait (" + maxAttempts + " iterations)...");
        });

        new Thread(() -> {
            try {
                String host = getCurrentHost();
                String alg = extractHostAlgorithm(host);

                String appCertPem = null, tkJwt = null, tcJwt = null, dcpPublicKeyPem = null, dcpJson = null;

                try {
                    tkJwt = HttpsConn.getHttpContent("http://" + host + "/.well-known/ClaimSigningKey.jwt");
                    tcJwt = HttpsConn.getHttpContent("http://" + host + "/.well-known/ServerCertClaim.jwt");
                    dcpJson = HttpsConn.getHttpContent("http://dcp.idouzi.top/.well-known/DCPServerCertPin-" + alg + ".json");
                    dcpPublicKeyPem = readResourceFile("my-dcp-pubkey.pem");
                } catch (Exception netEx) {
                    Log.w(TAG, "HTTP fetch failed for " + alg + ", fallback to resources: " + netEx.getMessage());
                    tkJwt = readResourceFile("ClaimSigningKey.jwt");
                    tcJwt = readResourceFile("ServerCertClaim.jwt");
                    dcpPublicKeyPem = readResourceFile("my-dcp-pubkey.pem");
                    dcpJson = readResourceFile("DCPServerCertPin.json");
                }

                // Dynamically retrieve installed App signing cert as Trust Anchor
                java.security.PublicKey appPublicKey = AppInfo.getPrimarySigningPublicKey(this);
                if (appPublicKey == null) {
                    // appPublicKey fallback
                }

                String csVerifyRes = JwtVerifier.verifyJwt(tkJwt, appPublicKey);
                String csJwkJson = JwtVerifier.extractConfirmationJwk(csVerifyRes);

                double tkTimeMs = BenchmarkVerifier.benchmarkTkMs(tkJwt, appPublicKey, maxAttempts);
                double tcTimeMs = BenchmarkVerifier.benchmarkTcMs(tcJwt, csJwkJson, maxAttempts);
                double dcpTimeMs = BenchmarkVerifier.benchmarkDcpMs(dcpJson, dcpPublicKeyPem, maxAttempts);

                String report = String.format(Locale.ROOT,
                        "[%s Benchmark Results (%d iterations)]\n" +
                        "Tk Verification Time : %.2f ms\n" +
                        "Tc Verification Time : %.2f ms\n" +
                        "DCP Verification Time: %.2f ms\n",
                        alg, maxAttempts, tkTimeMs, tcTimeMs, dcpTimeMs);

                mainHandler.post(() -> {
                    responseTextView.setText(report);
                    Toast.makeText(MainActivity.this, alg + " Benchmark completed", Toast.LENGTH_SHORT).show();
                });

            } catch (Exception e) {
                Log.e(TAG, "Failed to run benchmark: " + e.getMessage(), e);
                mainHandler.post(() -> {
                    responseTextView.setText("Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }


    public void runVerifyJwtCskBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running CSK verification benchmark...\nPlease wait...");
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
                    responseTextView.setText("CSK Verification Benchmark Results\n" +
                                           "============================================\n\n" + benchmarkResults);

                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "CSK Verification Benchmark completed", Toast.LENGTH_SHORT).show();
                });

                // Also log the results
                //Log.d(TAG, "CSK Verification Benchmark Results:\n" + benchmarkResults);

            } catch (Exception e) {
                Log.e(TAG, "Failed to run CSK verification benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("CSK Verification Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "CSK Verification Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    public void runVerifyJwtSccBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running SCC  verification benchmark...\nPlease wait...");
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
                String cs_jwk = JwtVerifier.extractConfirmationJwk(csverifyres);

                // Get the certificate claim JWT
                HttpsURLConnection certconn = HttpsConn.create_conn("https://" + host + "/.well-known/ServerCertClaim.jwt");
                String certclaim = HttpsConn.get_content(certconn);

                // Run benchmark with dynamic iterations
                String benchmarkResults = BenchmarkVerifier.runVerifyJwtSccBenchmark(certclaim, cs_jwk, maxAttempts);

                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("SCC Verification Benchmark Results\n" +
                                           "==================================\n\n" + benchmarkResults);

                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "SCC Benchmark completed", Toast.LENGTH_SHORT).show();
                });

                // Also log the results
                //Log.d(TAG, "SCC Benchmark Results:\n" + benchmarkResults);

            } catch (Exception e) {
                Log.e(TAG, "Failed to run SCC benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("SCC Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "SCC Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
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

                HttpsURLConnection dcpConn = HttpsConn.create_conn("https://" + dcp_host + "/.well-known/DCPServerCertPin-" + alg + ".json");
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

    public void runHttpsASPinConnectionBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running HTTPS ASPin connection benchmark...\nPlease wait...");
        });

        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                String host =  getCurrentHost();
                ASPinVerifier.CertificateClaim claim =
                        AppTrustedServerCert.getValidatedServerCertClaim(this, host);

                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Test ASPin Conn: " + host);
                });

                // Run benchmark with dynamic iterations
                String benchmarkResults =
                        BenchmarkVerifier.runHttpsASPinConnectionBenchmark(host, claim, maxAttempts);

                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS ASPin Connection Benchmark Results\n" +
                                           "=====================================\n\n" + benchmarkResults);

                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "HTTPS ASPin Connection Benchmark completed", Toast.LENGTH_SHORT).show();
                });

                // Also log the results
                //Log.d(TAG, "HTTPS ASPin Connection Benchmark Results:\n" + benchmarkResults);

            } catch (Exception e) {
                Log.e(TAG, "Failed to run HTTPS ASPin connection benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS ASPin Connection Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "HTTPS ASPin Connection Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    public void runHttpsSCPConnectionBenchmark() {
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> responseTextView.setText(
                "Running HTTPS SCP connection benchmark...\nPlease wait..."));

        new Thread(() -> {
            try {
                String host = getCurrentHost();
                String benchmarkResults =
                        BenchmarkVerifier.runHttpsSCPConnectionBenchmark(host, maxAttempts);
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS SCP Connection Benchmark Results\n" +
                            "==================================\n\n" + benchmarkResults);
                    Toast.makeText(MainActivity.this,
                            "HTTPS SCP Connection Benchmark completed", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                Log.e(TAG, "Failed to run HTTPS SCP connection benchmark", e);
                mainHandler.post(() -> responseTextView.setText(
                        "HTTPS SCP Connection Benchmark failed: " + e.getMessage()));
            }
        }).start();
    }

    public void runHttpsDCPConnectionBenchmark() {
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running HTTPS DCP connection benchmark...\nPlease wait...");
        });

        new Thread(() -> {
            try {
                String host = getCurrentHost();
                String expSPK = getCurrentExpSPK();

                mainHandler.post(() -> {
                    responseTextView.setText("Test DCP Conn:" + host + ", " + expSPK);
                });

                String benchmarkResults = BenchmarkVerifier.runHttpsDCPConnectionBenchmark(host, expSPK, maxAttempts);

                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS DCP Connection Benchmark Results\n" +
                                           "==================================\n\n" + benchmarkResults);
                    Toast.makeText(MainActivity.this, "HTTPS DCP Connection Benchmark completed", Toast.LENGTH_SHORT).show();
                });

            } catch (Exception e) {
                Log.e(TAG, "Failed to run HTTPS DCP connection benchmark: " + e.getMessage(), e);
                mainHandler.post(() -> {
                    responseTextView.setText("HTTPS DCP Connection Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "HTTPS DCP Connection Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    public void runGetJwtCskBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running Get CSK  benchmark...\nPlease wait...");
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
                    responseTextView.setText("Get CSK Benchmark Results\n" +
                                           "========================\n\n" + benchmarkResults);

                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "Get CSK Benchmark completed", Toast.LENGTH_SHORT).show();
                });

                // Also log the results
                //Log.d(TAG, "Get CSK Benchmark Results:\n" + benchmarkResults);

            } catch (Exception e) {
                Log.e(TAG, "Failed to run Get CSK benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Get CSK Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "Get CSK Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    public void runGetJwtSccBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running Get SCC benchmark...\nPlease wait..."); });

        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                // Get the host for benchmarking
                String host = getCurrentHost();

                // Run benchmark with dynamic iterations
                String benchmarkResults = BenchmarkVerifier.runGetJwtSccBenchmark(host, maxAttempts);

                // Update the response text view with benchmark results on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Get SCC Benchmark Results\n" +
                                           "========================\n\n" + benchmarkResults);

                    // Show a toast to confirm
                    Toast.makeText(MainActivity.this, "Get SCC Benchmark completed", Toast.LENGTH_SHORT).show();
                });

                // Also log the results
                //Log.d(TAG, "Get SCC Benchmark Results:\n" + benchmarkResults);

            } catch (Exception e) {
                Log.e(TAG, "Failed to run Get SCC benchmark: " + e.getMessage(), e);
                // Update UI on main thread
                mainHandler.post(() -> {
                    responseTextView.setText("Get SCC Benchmark failed: " + e.getMessage());
                    Toast.makeText(MainActivity.this, "Get SCC Benchmark failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

    }

    @Override
    protected void onResume() {
        super.onResume();
        handleBenchmarkIntent(getIntent());
    }

    @Override
    protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleBenchmarkIntent(intent);
    }

    private void handleBenchmarkIntent(android.content.Intent intent) {
        if (intent == null || !intent.hasExtra("benchmark_type")) {
            return;
        }
        String benchmarkType = intent.getStringExtra("benchmark_type");
        int iterations = intent.getIntExtra("iterations", 2000);
        String csvPath = intent.getStringExtra("output_csv");
        intent.removeExtra("benchmark_type");

        if ("avgveriftime".equalsIgnoreCase(benchmarkType)) {
            runTableAvgVerifTimeBenchmarkAuto(iterations, csvPath);
        } else if ("avgvisittime".equalsIgnoreCase(benchmarkType)) {
            runTableAvgVisitTimeBenchmarkAuto(iterations, csvPath);
        }
    }

    public void runTableAvgVerifTimeBenchmarkAuto(int maxAttempts, String csvPath) {
        mainHandler.post(() -> responseTextView.setText("Running automated avgveriftime benchmark (" + maxAttempts + " iterations)..."));
        new Thread(() -> {
            try {
                try { Thread.sleep(1500); } catch (Throwable ignored) {}
                String host = getCurrentHost();
                String alg = extractHostAlgorithm(host);
                Map<String, String> algDisplayNames = new LinkedHashMap<>();
                algDisplayNames.put("rsa3072", "PS256 (RSA 3072)");
                algDisplayNames.put("rsa4096", "PS384 (RSA 4096)");
                algDisplayNames.put("es256", "ES256 (NIST P-256)");
                algDisplayNames.put("es384", "ES384 (NIST P-384)");

                String appCertPem = null, tkJwt = null, tcJwt = null, dcpPublicKeyPem = null, dcpJson = null;

                for (int attempt = 0; attempt < 5; attempt++) {
                    try {
                        if (tkJwt == null) tkJwt = HttpsConn.getHttpContent("http://" + host + "/.well-known/ClaimSigningKey.jwt");
                        if (tcJwt == null) tcJwt = HttpsConn.getHttpContent("http://" + host + "/.well-known/ServerCertClaim.jwt");
                        if (dcpJson == null) dcpJson = HttpsConn.getHttpContent("http://dcp.idouzi.top/.well-known/DCPServerCertPin-" + alg + ".json");
                        if (tkJwt != null && tcJwt != null && dcpJson != null) break;
                    } catch (Throwable ignored) {
                        try { Thread.sleep(500); } catch (Throwable ignored2) {}
                    }
                }

                if (tkJwt == null) tkJwt = readResourceFile("ClaimSigningKey.jwt");
                if (tcJwt == null) tcJwt = readResourceFile("ServerCertClaim.jwt");
                if (dcpJson == null) dcpJson = readResourceFile("DCPServerCertPin.json");
                try { dcpPublicKeyPem = readResourceFile("my-dcp-pubkey.pem"); } catch (Throwable t) { dcpPublicKeyPem = ""; }

                java.security.PublicKey appPublicKey = AppInfo.getPrimarySigningPublicKey(this);
                if (appPublicKey == null) {
                    // appPublicKey fallback
                }

                String csVerifyRes = JwtVerifier.verifyJwt(tkJwt, appPublicKey);
                boolean tkSuccess = csVerifyRes != null && !csVerifyRes.isEmpty();
                String csJwkJson = JwtVerifier.extractConfirmationJwk(csVerifyRes);

                String tcVerifyRes = JwtVerifier.verifyJwtWithJwk(tcJwt, csJwkJson);
                boolean tcSuccess = tcVerifyRes != null && !tcVerifyRes.isEmpty();

                String dcpPin = DCPVerifier.verifyPresetDCP(dcpJson);
                boolean dcpSuccess = dcpPin != null && !dcpPin.isEmpty();

                double tkTimeMs = BenchmarkVerifier.benchmarkTkMs(tkJwt, appPublicKey, maxAttempts);
                double tcTimeMs = BenchmarkVerifier.benchmarkTcMs(tcJwt, csJwkJson, maxAttempts);
                double dcpTimeMs = BenchmarkVerifier.benchmarkDcpMs(dcpJson, dcpPublicKeyPem, maxAttempts);

                String displayName = algDisplayNames.getOrDefault(alg, alg);
                String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new java.util.Date());
                String header = "Algorithm,Iterations,Tk_Avg_ms,Tc_Avg_ms,DCP_Avg_ms,Timestamp";
                String csvRow = String.format(Locale.ROOT, "%s,%d,%.2f,%.2f,%.2f,%s", displayName, maxAttempts, tkTimeMs, tcTimeMs, dcpTimeMs, timestamp);

                saveCsvResult(csvPath, header, csvRow);

                String report = "[" + displayName + " Verification Benchmark Result (" + maxAttempts + " iterations)]\n" +
                        "1. ASPin Tk Verification (System App Signing PublicKey): " + (tkSuccess ? "SUCCESS" : "FAILED") + " (Avg: " + String.format(Locale.ROOT, "%.2f", tkTimeMs) + " ms)\n" +
                        "2. ASPin Tc Verification (CSK JWK): " + (tcSuccess ? "SUCCESS" : "FAILED") + " (Avg: " + String.format(Locale.ROOT, "%.2f", tcTimeMs) + " ms)\n" +
                        "3. DCP Pin Verification (Preset DCP PubKey): " + (dcpSuccess ? "SUCCESS" : "FAILED") + " (Avg: " + String.format(Locale.ROOT, "%.2f", dcpTimeMs) + " ms)\n" +
                        "Saved to CSV: " + csvPath;

                mainHandler.post(() -> {
                    responseTextView.setText(report);
                    Toast.makeText(MainActivity.this, displayName + " Verification Benchmark Completed", Toast.LENGTH_SHORT).show();
                });
            } catch (Exception e) {
                Log.e(TAG, "AvgVerifTime auto benchmark failed", e);
                mainHandler.post(() -> responseTextView.setText("Auto benchmark failed: " + e.getMessage()));
            }
        }).start();
    }

                            public void runTableAvgVisitTimeBenchmarkAuto(int iterations, String csvPath) {
        final String host = (hostTextView != null && hostTextView.getText() != null && !hostTextView.getText().toString().trim().isEmpty()) ? hostTextView.getText().toString().trim() : ASPIN_HOST;
        mainHandler.post(() -> responseTextView.setText("Running automated avgvisittime benchmark (" + iterations + " iterations)..."));
        new Thread(() -> {
            try {
                try { Thread.sleep(1500); } catch (Throwable ignored) {}
                String alg = extractHostAlgorithm(host);
                Map<String, String> algDisplayNames = new LinkedHashMap<>();
                algDisplayNames.put("rsa3072", "PS256 (RSA 3072)");
                algDisplayNames.put("rsa4096", "PS384 (RSA 4096)");
                algDisplayNames.put("es256", "ES256 (NIST P-256)");
                algDisplayNames.put("es384", "ES384 (NIST P-384)");

                ASPinVerifier.CertificateClaim claim = null;
                try {
                    claim = AppTrustedServerCert.getValidatedServerCertClaim(this, host);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to get ASPin claim via HTTP: " + e.getMessage());
                }

                String dcpPin = null;
                try {
                    String dcpJson = HttpsConn.getHttpContent("http://dcp.idouzi.top/.well-known/DCPServerCertPin-" + alg + ".json");
                    dcpPin = DCPVerifier.verifyPresetDCP(dcpJson);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to get DCP pin via HTTP: " + e.getMessage());
                }

                String scpHash = null;
                try {
                    scpHash = SCPVerifier.getPresetCertificateHash(host);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to get SCP hash: " + e.getMessage());
                }

                final ASPinVerifier.CertificateClaim cachedClaim = claim;
                final String cachedDcpPin = dcpPin;
                final String cachedScpHash = scpHash;

                long totalTimeStandardTlsUs = 0, totalTimeASPinUs = 0, totalTimeSCPUs = 0, totalTimeDCPUs = 0;
                int successStandardTls = 0, successASPin = 0, successSCP = 0, successDCP = 0;
                String htmlStandard = "N/A", htmlASPin = "N/A", htmlSCP = "N/A", htmlDCP = "N/A";

                for (int i = 1; i <= iterations; i++) {
                    long t0 = System.nanoTime();
                    try {
                        HttpsURLConnection con = HttpsConn.createStandardTLSConnection(host);
                        con.setConnectTimeout(5000); con.setReadTimeout(5000);
                        String res = HttpsConn.get_content(con); con.disconnect();
                        if (res != null && !res.isEmpty()) {
                            htmlStandard = res.replaceAll("[\\r\\n,]", " ").trim();
                        }
                        successStandardTls++;
                    } catch (Throwable e) {
                        if (i == 1) Log.e(TAG, "StandardTLS fail: " + e.getClass().getName() + ": " + e.getMessage(), e);
                    } finally {
                        totalTimeStandardTlsUs += (System.nanoTime() - t0) / 1000;
                    }

                    long t1 = System.nanoTime();
                    try {
                        if (cachedClaim == null) throw new java.security.cert.CertificateException("ASPin claim verification using system app signing certificate failed; caching prohibited");
                        HttpsURLConnection con = HttpsConn.createASPinConnection(host, cachedClaim);
                        con.setConnectTimeout(5000); con.setReadTimeout(5000);
                        String res = HttpsConn.get_content(con); con.disconnect();
                        if (res != null && !res.isEmpty()) {
                            htmlASPin = res.replaceAll("[\\r\\n,]", " ").trim();
                        }
                        successASPin++;
                    } catch (Throwable e) {
                        if (i == 1) Log.e(TAG, "ASPin fail: " + e.getClass().getName() + ": " + e.getMessage(), e);
                    } finally {
                        totalTimeASPinUs += (System.nanoTime() - t1) / 1000;
                    }

                    long t2 = System.nanoTime();
                    try {
                        if (cachedScpHash == null) throw new java.security.cert.CertificateException("SCP hash missing");
                        HttpsURLConnection con = HttpsConn.createSCPConnection(host, cachedScpHash);
                        con.setConnectTimeout(5000); con.setReadTimeout(5000);
                        String res = HttpsConn.get_content(con); con.disconnect();
                        if (res != null && !res.isEmpty()) {
                            htmlSCP = res.replaceAll("[\\r\\n,]", " ").trim();
                        }
                        successSCP++;
                    } catch (Throwable e) {
                        if (i == 1) Log.e(TAG, "SCP fail: " + e.getClass().getName() + ": " + e.getMessage(), e);
                    } finally {
                        totalTimeSCPUs += (System.nanoTime() - t2) / 1000;
                    }

                    long t3 = System.nanoTime();
                    try {
                        if (cachedDcpPin == null) throw new java.security.cert.CertificateException("DCP pin verification using preset DCP public key failed; caching prohibited");
                        HttpsURLConnection con = HttpsConn.createDCPConnection(host, cachedDcpPin);
                        con.setConnectTimeout(5000); con.setReadTimeout(5000);
                        String res = HttpsConn.get_content(con); con.disconnect();
                        if (res != null && !res.isEmpty()) {
                            htmlDCP = res.replaceAll("[\\r\\n,]", " ").trim();
                        }
                        successDCP++;
                    } catch (Throwable e) {
                        if (i == 1) Log.e(TAG, "DCP fail: " + e.getClass().getName() + ": " + e.getMessage(), e);
                    } finally {
                        totalTimeDCPUs += (System.nanoTime() - t3) / 1000;
                    }
                }

                double avgStandardTlsMs = (totalTimeStandardTlsUs / 1000.0) / iterations;
                double avgASPinMs = (totalTimeASPinUs / 1000.0) / iterations;
                double avgSCPMs = (totalTimeSCPUs / 1000.0) / iterations;
                double avgDCPMs = (totalTimeDCPUs / 1000.0) / iterations;

                boolean allTlsSuccess = (successStandardTls == iterations) && (successASPin == iterations) && (successSCP == iterations) && (successDCP == iterations);
                double maxLatencyDeltaMs = Math.max(Math.max(avgStandardTlsMs, avgASPinMs), Math.max(avgSCPMs, avgDCPMs)) - Math.min(Math.min(avgStandardTlsMs, avgASPinMs), Math.min(avgSCPMs, avgDCPMs));
                boolean matchesTexDesign = allTlsSuccess && (maxLatencyDeltaMs < 5.0);

                String displayName = algDisplayNames.getOrDefault(alg, alg);
                String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new java.util.Date());
                String header = "Algorithm,Iterations,Host,StandardTLS_Avg_ms,ASPin_Avg_ms,SCP_Avg_ms,DCP_Avg_ms,TLS_Success_Standard,TLS_Success_ASPin,TLS_Success_SCP,TLS_Success_DCP,HTML_Standard,HTML_ASPin,HTML_SCP,HTML_DCP,Matches_TeX_Design,Timestamp";
                String csvRow = String.format(Locale.ROOT, "%s,%d,%s,%.2f,%.2f,%.2f,%.2f,%d,%d,%d,%d,\"%s\",\"%s\",\"%s\",\"%s\",%s,%s",
                        displayName, iterations, host, avgStandardTlsMs, avgASPinMs, avgSCPMs, avgDCPMs,
                        successStandardTls, successASPin, successSCP, successDCP,
                        htmlStandard, htmlASPin, htmlSCP, htmlDCP,
                        matchesTexDesign ? "PASS" : "FAIL", timestamp);

                saveCsvResult(csvPath, header, csvRow);

                String report = String.format(Locale.ROOT,
                        "[%s AvgVisitTime Benchmark Completed]\nStandardTLS: %s (%.2f ms) | HTML: %s\nASPin: %s (%.2f ms) | HTML: %s\nSCP: %s (%.2f ms) | HTML: %s\nDCP: %s (%.2f ms) | HTML: %s\nSaved to CSV: %s",
                        displayName,
                        successStandardTls > 0 ? "SUCCESS (" + successStandardTls + "/" + iterations + ")" : "FAIL", avgStandardTlsMs, htmlStandard,
                        successASPin > 0 ? "SUCCESS (" + successASPin + "/" + iterations + ")" : "FAIL", avgASPinMs, htmlASPin,
                        successSCP > 0 ? "SUCCESS (" + successSCP + "/" + iterations + ")" : "FAIL", avgSCPMs, htmlSCP,
                        successDCP > 0 ? "SUCCESS (" + successDCP + "/" + iterations + ")" : "FAIL", avgDCPMs, htmlDCP,
                        csvPath);

                mainHandler.post(() -> responseTextView.setText(report));
            } catch (Exception e) {
                Log.e(TAG, "AvgVisitTime auto benchmark failed", e);
                mainHandler.post(() -> responseTextView.setText("Auto benchmark failed: " + e.getMessage()));
            }
        }).start();
    }

    private void saveCsvResult(String csvPath, String header, String row) {
        try {
            java.io.File dir = getExternalFilesDir(null);
            if (dir == null) {
                dir = getFilesDir();
            }
            if (dir != null && !dir.exists()) {
                dir.mkdirs();
            }
            String fileName = "benchmark_result.csv";
            if (csvPath != null && !csvPath.isEmpty()) {
                java.io.File f = new java.io.File(csvPath);
                fileName = f.getName();
            }
            java.io.File file = new java.io.File(dir, fileName);

            boolean exists = file.exists();
            try (java.io.FileWriter writer = new java.io.FileWriter(file, true)) {
                if (!exists) {
                    writer.write(header + "\n");
                }
                writer.write(row + "\n");
            }
            Log.i(TAG, "CSV result saved to: " + file.getAbsolutePath());
        } catch (Exception e) {
            Log.e(TAG, "Failed to save CSV result: " + e.getMessage(), e);
        }
    }

    public void runTableAvgVisitTimeBenchmark() {
        runTableAvgVisitTimeBenchmarkAuto(getCurrentMaxBenchmarkAttempts(), null);
    }

    private String extractCertFromTkJwt(String tkJwt) {
        try {
            com.nimbusds.jwt.SignedJWT signedJwt = com.nimbusds.jwt.SignedJWT.parse(tkJwt);
            var chain = signedJwt.getHeader().getX509CertChain();
            if (chain != null && !chain.isEmpty()) {
                return chain.get(0).toString();
            }
        } catch (Exception ignored) {}
        try {
            return readResourceFile("my-app-cert.pem");
        } catch (Exception ignored) {}
        return null;
    }

}
