package com.cert.aspin;

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
    private static final String ASPIN_TARGET_APP_ID = "com.cert.aspin";
    private static final String ASPIN_HOST = "es384.idouzi.top";
    private static final String DCP_HOST = "dcp.idouzi.top";

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
    private Button JwsCskBenchmarkButton;
    private Button JwsSccBenchmarkButton;
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
        JwsCskBenchmarkButton = findViewById(R.id.JwsCskBenchmarkButton);
        JwsSccBenchmarkButton = findViewById(R.id.JwsSccBenchmarkButton);
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

        JwsCskBenchmarkButton.setOnClickListener(v -> {
            runVerifyJwsCskBenchmark();
        });

        JwsSccBenchmarkButton.setOnClickListener(v -> {
            runVerifyJwsSccBenchmark();
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

    private boolean isOwnAspinTarget() {
        return ASPIN_TARGET_APP_ID.equals(getPackageName());
    }

    private ASPinVerifier.CertificateClaim getValidatedAspinClaim(String host) throws Exception {
        return getValidatedAspinClaimResult(host).getClaim();
    }

    private OsAspinClient.Result getValidatedAspinClaimResult(String host) throws Exception {
        return isOwnAspinTarget()
                ? OsAspinClient.getCertificateClaim(this, host)
                : OsAspinClient.getCertificateClaimForApp(
                        this, ASPIN_TARGET_APP_ID, host);
    }

    private OsAspinClient.Result refreshValidatedAspinClaim(String host) throws Exception {
        return isOwnAspinTarget()
                ? AppTrustedServerCert.refreshValidatedServerCertClaim(this, host)
                : AppTrustedServerCert.refreshValidatedServerCertClaimForApp(
                        this, ASPIN_TARGET_APP_ID, host);
    }

    private String getAspinServerCertClaim(String host) throws Exception {
        return isOwnAspinTarget()
                ? AppTrustedServerCert.getServerCertClaim(this, host)
                : AppTrustedServerCert.getServerCertClaimForApp(
                        this, ASPIN_TARGET_APP_ID, host);
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
                String expIssuer = getAspinServerCertClaim(getCurrentHost());

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
        runTableAvgVerifTimeBenchmarkAuto(getCurrentMaxBenchmarkAttempts(), null);
    }


    public void runVerifyJwsCskBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running CSK verification benchmark...\nPlease wait...");
        });

        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                String host = getCurrentHost();
                long[] durations = new long[maxAttempts];
                for (int i = 0; i < maxAttempts; i++) {
                    durations[i] = refreshValidatedAspinClaim(host)
                            .getClaimKeyDownloadAndVerificationNanos();
                }
                String benchmarkResults = String.format(Locale.ROOT,
                        "OS-level T_k download and verification: mean %.3f ms over %d refreshes",
                        meanMillis(durations), maxAttempts);

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

    public void runVerifyJwsSccBenchmark() {
        // Show loading message
        int maxAttempts = getCurrentMaxBenchmarkAttempts();
        mainHandler.post(() -> {
            responseTextView.setText("Running SCC  verification benchmark...\nPlease wait...");
        });

        // Perform benchmark on background thread
        new Thread(() -> {
            try {
                String host = getCurrentHost();
                long[] durations = new long[maxAttempts];
                for (int i = 0; i < maxAttempts; i++) {
                    durations[i] = refreshValidatedAspinClaim(host)
                            .getClaimDownloadAndVerificationNanos();
                }
                String benchmarkResults = String.format(Locale.ROOT,
                        "OS-level T_c download and verification: mean %.3f ms over %d refreshes",
                        meanMillis(durations), maxAttempts);

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
                ASPinVerifier.CertificateClaim claim = getValidatedAspinClaim(host);

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

    public void runGetJwsCskBenchmark() {
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
                String benchmarkResults = BenchmarkVerifier.runGetJwsCskBenchmark(host, maxAttempts);

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

    public void runGetJwsSccBenchmark() {
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
                String benchmarkResults = BenchmarkVerifier.runGetJwsSccBenchmark(host, maxAttempts);

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
        } else if ("concurrency".equalsIgnoreCase(benchmarkType)) {
            runConcurrencyBenchmarkAuto(iterations,
                    intent.getIntExtra("threads", 8), csvPath);
        } else if ("claimprobe".equalsIgnoreCase(benchmarkType)) {
            runClaimProbeBenchmarkAuto(csvPath,
                    intent.getBooleanExtra("expect_success", true),
                    intent.getStringExtra("probe_label"),
                    intent.getBooleanExtra("force_refresh", false),
                    intent.getStringExtra("expected_error"));
        } else if ("parallelrefresh".equalsIgnoreCase(benchmarkType)) {
            runParallelRefreshBenchmarkAuto(csvPath,
                    intent.getStringExtra("second_host"));
        } else if ("expirybound".equalsIgnoreCase(benchmarkType)) {
            runDelegationExpiryBoundProbeAuto(csvPath);
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

                String dcpPublicKeyPem = readResourceFile("my-dcp-pubkey.pem");

                long[] tkDurations = new long[maxAttempts];
                long[] tcDurations = new long[maxAttempts];
                long[] totalDurations = new long[maxAttempts];
                int aspinSuccesses = 0;
                for (int attempt = 0; attempt < maxAttempts; attempt++) {
                    long totalStart = System.nanoTime();
                    OsAspinClient.Result result = refreshValidatedAspinClaim(host);
                    totalDurations[attempt] = System.nanoTime() - totalStart;
                    long tkNanos = result.getClaimKeyDownloadAndVerificationNanos();
                    long tcNanos = result.getClaimDownloadAndVerificationNanos();
                    if (result.getClaim() == null || tkNanos <= 0 || tcNanos <= 0) {
                        throw new IllegalStateException(
                                "Incomplete ASPin refresh at attempt " + attempt);
                    }
                    aspinSuccesses++;
                    tkDurations[attempt] = tkNanos;
                    tcDurations[attempt] = tcNanos;
                }

                long[] dcpDurations = new long[maxAttempts];
                int dcpSuccesses = 0;
                String dcpUrl = "http://" + getDCPHost()
                        + "/.well-known/DCPServerCertPin-"
                        + alg + ".json";
                for (int attempt = 0; attempt < maxAttempts; attempt++) {
                    long dcpStart = System.nanoTime();
                    try {
                        String dcpJson = HttpsConn.getHttpContent(dcpUrl);
                        String dcpPin = DCPVerifier.verifyDCPWithPublicKeyPem(
                                dcpJson, dcpPublicKeyPem);
                        if (dcpPin == null || dcpPin.isEmpty()) {
                            throw new IllegalStateException(
                                    "Empty DCP result at attempt " + attempt);
                        }
                        dcpSuccesses++;
                    } finally {
                        dcpDurations[attempt] = System.nanoTime() - dcpStart;
                    }
                }

                double tkTimeMs = meanMillis(tkDurations);
                double tcTimeMs = meanMillis(tcDurations);
                double totalTimeMs = meanMillis(totalDurations);
                double totalP50Ms = percentileMillis(totalDurations, 0.50);
                double totalP95Ms = percentileMillis(totalDurations, 0.95);
                double totalP99Ms = percentileMillis(totalDurations, 0.99);
                double dcpTimeMs = meanMillis(dcpDurations);
                double dcpP50Ms = percentileMillis(dcpDurations, 0.50);
                double dcpP95Ms = percentileMillis(dcpDurations, 0.95);
                double dcpP99Ms = percentileMillis(dcpDurations, 0.99);
                boolean benchmarkPassed =
                        aspinSuccesses == maxAttempts && dcpSuccesses == maxAttempts;

                String displayName = algDisplayNames.getOrDefault(alg, alg);
                String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new java.util.Date());
                String header = "Algorithm,Iterations,Tk_Mean_ms,Tc_Mean_ms,ASPin_Total_Mean_ms,ASPin_Total_P50_ms,ASPin_Total_P95_ms,ASPin_Total_P99_ms,DCP_Mean_ms,DCP_P50_ms,DCP_P95_ms,DCP_P99_ms,ASPin_Success_Count,DCP_Success_Count,Result,Timestamp";
                String csvRow = String.format(Locale.ROOT,
                        "%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%d,%d,%s,%s",
                        displayName, maxAttempts, tkTimeMs, tcTimeMs, totalTimeMs,
                        totalP50Ms, totalP95Ms, totalP99Ms, dcpTimeMs,
                        dcpP50Ms, dcpP95Ms, dcpP99Ms, aspinSuccesses,
                        dcpSuccesses, benchmarkPassed ? "PASS" : "FAIL", timestamp);

                saveCsvResult(csvPath, header, csvRow);

                String report = "[" + displayName + " Verification Benchmark Result (" + maxAttempts + " iterations)]\n" +
                        "1. ASPin Tk Download + Verification (OS service): " + aspinSuccesses + "/" + maxAttempts + " (Avg: " + String.format(Locale.ROOT, "%.2f", tkTimeMs) + " ms)\n" +
                        "2. ASPin Tc Download + Verification (OS service): " + aspinSuccesses + "/" + maxAttempts + " (Avg: " + String.format(Locale.ROOT, "%.2f", tcTimeMs) + " ms)\n" +
                        "3. Complete ASPin refresh (IPC + Tk + Tc + persistence + cache commit): " +
                        String.format(Locale.ROOT, "mean %.2f, p50 %.2f, p95 %.2f, p99 %.2f ms\n",
                                totalTimeMs, totalP50Ms, totalP95Ms, totalP99Ms) +
                        "4. DCP Pin Verification (Preset DCP PubKey): " + dcpSuccesses + "/" + maxAttempts +
                        String.format(Locale.ROOT, " (mean %.2f, p50 %.2f, p95 %.2f, p99 %.2f ms)\n",
                                dcpTimeMs, dcpP50Ms, dcpP95Ms, dcpP99Ms) +
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
                    claim = getValidatedAspinClaim(host);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to get ASPin claim via HTTP: " + e.getMessage());
                }

                String dcpPin = null;
                try {
                    String dcpJson = HttpsConn.getHttpContent("http://" + getDCPHost()
                            + "/.well-known/DCPServerCertPin-" + alg + ".json");
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

                long[] standardTlsDurations = new long[iterations];
                long[] aspinDurations = new long[iterations];
                long[] scpDurations = new long[iterations];
                long[] dcpDurations = new long[iterations];
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
                        standardTlsDurations[i - 1] = System.nanoTime() - t0;
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
                        aspinDurations[i - 1] = System.nanoTime() - t1;
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
                        scpDurations[i - 1] = System.nanoTime() - t2;
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
                        dcpDurations[i - 1] = System.nanoTime() - t3;
                    }
                }

                double avgStandardTlsMs = meanMillis(standardTlsDurations);
                double avgASPinMs = meanMillis(aspinDurations);
                double avgSCPMs = meanMillis(scpDurations);
                double avgDCPMs = meanMillis(dcpDurations);

                String serverPhase = getIntent().getStringExtra("server_phase");
                boolean rogueServerPhase = "rogueserver".equalsIgnoreCase(serverPhase);
                boolean expectedTlsOutcomes = rogueServerPhase
                        ? (successStandardTls == iterations) && (successASPin == 0)
                                && (successSCP == 0) && (successDCP == 0)
                        : (successStandardTls == iterations) && (successASPin == iterations)
                                && (successSCP == iterations) && (successDCP == iterations);
                // The design specifies the accept/reject behavior. Latency is an empirical
                // result reported by the benchmark, not a protocol-correctness invariant.
                boolean matchesTexDesign = expectedTlsOutcomes;

                String displayName = algDisplayNames.getOrDefault(alg, alg);
                String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new java.util.Date());
                String header = "Algorithm,Iterations,Host,StandardTLS_Mean_ms,ASPin_Mean_ms,SCP_Mean_ms,DCP_Mean_ms,StandardTLS_P95_ms,StandardTLS_P99_ms,ASPin_P95_ms,ASPin_P99_ms,SCP_P95_ms,SCP_P99_ms,DCP_P95_ms,DCP_P99_ms,TLS_Success_Standard,TLS_Success_ASPin,TLS_Success_SCP,TLS_Success_DCP,HTML_Standard,HTML_ASPin,HTML_SCP,HTML_DCP,Matches_TeX_Design,Timestamp";
                String csvRow = String.format(Locale.ROOT, "%s,%d,%s,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%d,%d,%d,%d,\"%s\",\"%s\",\"%s\",\"%s\",%s,%s",
                        displayName, iterations, host, avgStandardTlsMs, avgASPinMs, avgSCPMs, avgDCPMs,
                        percentileMillis(standardTlsDurations, 0.95),
                        percentileMillis(standardTlsDurations, 0.99),
                        percentileMillis(aspinDurations, 0.95),
                        percentileMillis(aspinDurations, 0.99),
                        percentileMillis(scpDurations, 0.95),
                        percentileMillis(scpDurations, 0.99),
                        percentileMillis(dcpDurations, 0.95),
                        percentileMillis(dcpDurations, 0.99),
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

    public void runConcurrencyBenchmarkAuto(int operations, int requestedThreads, String csvPath) {
        final String host = getCurrentHost();
        final int threads = Math.max(1, Math.min(requestedThreads, operations));
        new Thread(() -> {
            java.util.concurrent.ExecutorService executor =
                    java.util.concurrent.Executors.newFixedThreadPool(threads);
            try {
                getValidatedAspinClaim(host); // Warm the OS cache before measuring cache hits.
                long[] durations = new long[operations];
                java.util.concurrent.atomic.AtomicInteger next =
                        new java.util.concurrent.atomic.AtomicInteger();
                java.util.concurrent.atomic.AtomicInteger successes =
                        new java.util.concurrent.atomic.AtomicInteger();
                java.util.concurrent.CountDownLatch ready =
                        new java.util.concurrent.CountDownLatch(threads);
                java.util.concurrent.CountDownLatch start =
                        new java.util.concurrent.CountDownLatch(1);
                java.util.List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
                for (int worker = 0; worker < threads; worker++) {
                    futures.add(executor.submit(() -> {
                        ready.countDown();
                        start.await();
                        int index;
                        while ((index = next.getAndIncrement()) < operations) {
                            long begin = System.nanoTime();
                            try {
                                if (getValidatedAspinClaim(host) != null) {
                                    successes.incrementAndGet();
                                }
                            } finally {
                                durations[index] = System.nanoTime() - begin;
                            }
                        }
                        return null;
                    }));
                }
                ready.await();
                long wallStart = System.nanoTime();
                start.countDown();
                for (java.util.concurrent.Future<?> future : futures) future.get();
                long wallNanos = System.nanoTime() - wallStart;
                double throughput = operations / (wallNanos / 1_000_000_000.0);
                String timestamp = new java.text.SimpleDateFormat(
                        "yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new java.util.Date());
                boolean passed = successes.get() == operations;
                String header = "Operations,Threads,Successes,Failures,Mean_ms,P50_ms,P95_ms,P99_ms,Throughput_ops_s,Result,Timestamp";
                String row = String.format(Locale.ROOT,
                        "%d,%d,%d,%d,%.3f,%.3f,%.3f,%.3f,%.2f,%s,%s",
                        operations, threads, successes.get(),
                        operations - successes.get(), meanMillis(durations),
                        percentileMillis(durations, 0.50),
                        percentileMillis(durations, 0.95),
                        percentileMillis(durations, 0.99), throughput,
                        passed ? "PASS" : "FAIL", timestamp);
                saveCsvResult(csvPath, header, row);
            } catch (Exception e) {
                Log.e(TAG, "Concurrency benchmark failed", e);
            } finally {
                executor.shutdownNow();
            }
        }).start();
    }

    public void runClaimProbeBenchmarkAuto(
            String csvPath, boolean expectSuccess, String requestedLabel,
            boolean forceRefresh, String requestedExpectedError) {
        final String host = getCurrentHost();
        final String label = requestedLabel == null ? "probe" : requestedLabel;
        final String expectedError =
                requestedExpectedError == null ? "" : requestedExpectedError.trim();
        new Thread(() -> {
            long start = System.nanoTime();
            boolean success = false;
            long tkNanos = 0;
            long tcNanos = 0;
            String error = "";
            try {
                OsAspinClient.Result result = forceRefresh
                        ? refreshValidatedAspinClaim(host)
                        : getValidatedAspinClaimResult(host);
                success = result.getClaim() != null;
                tkNanos = result.getClaimKeyDownloadAndVerificationNanos();
                tcNanos = result.getClaimDownloadAndVerificationNanos();
            } catch (Exception e) {
                error = e.getClass().getSimpleName() + ":" + String.valueOf(e.getMessage());
            }
            long totalNanos = System.nanoTime() - start;
            boolean reasonMatch = expectedError.isEmpty()
                    || error.toLowerCase(Locale.ROOT)
                            .contains(expectedError.toLowerCase(Locale.ROOT));
            boolean pass = success == expectSuccess && reasonMatch;
            String timestamp = new java.text.SimpleDateFormat(
                    "yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new java.util.Date());
            String header = "Label,ForceRefresh,ExpectedSuccess,ObservedSuccess,ExpectedErrorSubstring,ReasonMatch,Total_ms,Tk_ms,Tc_ms,Result,Error,Timestamp";
            String row = String.format(Locale.ROOT,
                    "%s,%s,%s,%s,\"%s\",%s,%.3f,%.3f,%.3f,%s,\"%s\",%s",
                    label.replace(',', '_'), forceRefresh, expectSuccess, success,
                    expectedError.replace('"', '\'').replace(',', ' '), reasonMatch,
                    totalNanos / 1_000_000.0, tkNanos / 1_000_000.0,
                    tcNanos / 1_000_000.0, pass ? "PASS" : "FAIL",
                    error.replace('"', '\'').replace('\r', ' ').replace('\n', ' '),
                    timestamp);
            saveCsvResult(csvPath, header, row);
        }).start();
    }

    public void runParallelRefreshBenchmarkAuto(String csvPath, String requestedSecondHost) {
        final String firstHost = getCurrentHost();
        final String secondHost = requestedSecondHost == null
                ? "es384.idouzi.top" : requestedSecondHost.trim();
        new Thread(() -> {
            java.util.concurrent.ExecutorService executor =
                    java.util.concurrent.Executors.newFixedThreadPool(2);
            try {
                java.util.concurrent.CountDownLatch ready =
                        new java.util.concurrent.CountDownLatch(2);
                java.util.concurrent.CountDownLatch start =
                        new java.util.concurrent.CountDownLatch(1);
                java.util.concurrent.Callable<long[]> first = () -> {
                    ready.countDown(); start.await(); long begin = System.nanoTime();
                    OsAspinClient.Result result = refreshValidatedAspinClaim(firstHost);
                    return new long[] {System.nanoTime() - begin,
                            result.getClaimKeyDownloadAndVerificationNanos()
                                    + result.getClaimDownloadAndVerificationNanos()};
                };
                java.util.concurrent.Callable<long[]> second = () -> {
                    ready.countDown(); start.await(); long begin = System.nanoTime();
                    OsAspinClient.Result result = OsAspinClient.refreshCertificateClaimForApp(
                            this, "com.cert.aspin.caller", secondHost);
                    return new long[] {System.nanoTime() - begin,
                            result.getClaimKeyDownloadAndVerificationNanos()
                                    + result.getClaimDownloadAndVerificationNanos()};
                };
                java.util.concurrent.Future<long[]> firstResult = executor.submit(first);
                java.util.concurrent.Future<long[]> secondResult = executor.submit(second);
                ready.await(); long wallStart = System.nanoTime(); start.countDown();
                long[] firstTiming = firstResult.get(); long[] secondTiming = secondResult.get();
                long firstNanos = firstTiming[0]; long secondNanos = secondTiming[0];
                long combinedServiceWorkNanos = firstTiming[1] + secondTiming[1];
                long wallNanos = System.nanoTime() - wallStart;
                boolean overlapped = wallNanos < combinedServiceWorkNanos;
                String header = "FirstHost,SecondHost,First_ms,Second_ms,Wall_ms,"
                        + "CombinedServiceWork_ms,OverlapObserved,Result,Timestamp";
                String timestamp = new java.text.SimpleDateFormat(
                        "yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new java.util.Date());
                String row = String.format(Locale.ROOT,
                        "%s,%s,%.3f,%.3f,%.3f,%.3f,%s,%s,%s", firstHost, secondHost,
                        firstNanos / 1_000_000.0, secondNanos / 1_000_000.0,
                        wallNanos / 1_000_000.0, combinedServiceWorkNanos / 1_000_000.0, overlapped,
                        overlapped ? "PASS" : "FAIL", timestamp);
                saveCsvResult(csvPath, header, row);
            } catch (Exception e) { Log.e(TAG, "Parallel refresh benchmark failed", e); }
            finally { executor.shutdownNow(); }
        }).start();
    }

    public void runDelegationExpiryBoundProbeAuto(String csvPath) {
        final String host = getCurrentHost();
        new Thread(() -> {
            String error = "";
            boolean pass = false;
            long effectiveExp = 0;
            long tkExp = 0;
            long tcExp = 0;
            try {
                tkExp = tokenExpiration(HttpsConn.getHttpContent(
                        "http://" + host + "/.well-known/ClaimSigningKey.jws"));
                tcExp = tokenExpiration(HttpsConn.getHttpContent(
                        "http://" + host + "/.well-known/ServerCertClaim.jws"));
                OsAspinClient.Result result = refreshValidatedAspinClaim(host);
                effectiveExp = result.getExpiresAtMillis();
                pass = effectiveExp == Math.min(tkExp, tcExp);
            } catch (Exception e) {
                error = e.getClass().getSimpleName() + ":" + String.valueOf(e.getMessage());
            }
            String header = "EffectiveExp_ms,TkExp_ms,TcExp_ms,BoundMatches,Result,Error,Timestamp";
            String timestamp = new java.text.SimpleDateFormat(
                    "yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new java.util.Date());
            String row = String.format(Locale.ROOT, "%d,%d,%d,%s,%s,\"%s\",%s",
                    effectiveExp, tkExp, tcExp, pass, pass ? "PASS" : "FAIL",
                    error.replace('"', '\'').replace(',', ' '), timestamp);
            saveCsvResult(csvPath, header, row);
        }).start();
    }

    private static long tokenExpiration(String token) throws Exception {
        org.json.JSONObject general = new org.json.JSONObject(token);
        String encoded = general.getString("payload");
        byte[] payload = android.util.Base64.decode(encoded,
                android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING
                        | android.util.Base64.NO_WRAP);
        return Math.multiplyExact(new org.json.JSONObject(
                new String(payload, java.nio.charset.StandardCharsets.UTF_8)).getLong("exp"),
                1000L);
    }

    private static double meanMillis(long[] durations) {
        if (durations.length == 0) return 0.0;
        double total = 0.0;
        for (long duration : durations) total += duration;
        return total / durations.length / 1_000_000.0;
    }

    private static double percentileMillis(long[] durations, double percentile) {
        if (durations.length == 0) return 0.0;
        long[] sorted = durations.clone();
        java.util.Arrays.sort(sorted);
        int index = Math.max(0,
                Math.min(sorted.length - 1, (int) Math.ceil(percentile * sorted.length) - 1));
        return sorted[index] / 1_000_000.0;
    }

    private void saveCsvResult(String csvPath, String header, String row) {
        try {
            java.io.File dir = getFilesDir();
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

    private String extractCertFromTkJws(String tkJws) {
        try {
            org.json.JSONObject general = new org.json.JSONObject(tkJws);
            org.json.JSONObject entry = general.getJSONArray("signatures").getJSONObject(0);
            com.nimbusds.jose.JWSObject signedJws = com.nimbusds.jose.JWSObject.parse(
                    entry.getString("protected") + "." + general.getString("payload")
                            + "." + entry.getString("signature"));
            var chain = signedJws.getHeader().getX509CertChain();
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
