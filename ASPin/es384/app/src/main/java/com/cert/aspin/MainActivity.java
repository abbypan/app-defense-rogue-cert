package com.cert.aspin;

import java.util.Locale;

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

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private static final String ASPIN_TARGET_APP_ID = "com.cert.aspin";
    private static final String ASPIN_HOST = "es384.idouzi.top";

    private EditText hostTextView;
    private EditText expIssuerTextView;
    private TextView responseTextView;

    private Button GetHTTPContentButton;
    private Button GetAndVerifyClaimButton;

    private Handler mainHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Initialize UI components
        hostTextView = findViewById(R.id.hostTextView);
        expIssuerTextView = findViewById(R.id.expIssuerTextView);
        responseTextView = findViewById(R.id.responseTextView);
        GetHTTPContentButton = findViewById(R.id.GetHTTPContentButton);
        GetAndVerifyClaimButton = findViewById(R.id.GetAndVerifyClaimButton);
        mainHandler = new Handler(Looper.getMainLooper());

        // Set initial host display
        updateHostDisplay(ASPIN_HOST);

        // Set up button click listeners
        GetHTTPContentButton.setOnClickListener(v -> {
            GetHTTPContent("https://" + getCurrentHost());
        });

        GetAndVerifyClaimButton.setOnClickListener(v -> {
            GetAndVerifyClaim();
        });
        findViewById(R.id.ConnectASPinButton).setOnClickListener(v -> connectWithASPin());

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

    public void GetHTTPContent(String url) {
        // Show loading message
        mainHandler.post(() -> {
            responseTextView.setText("Getting HTTP content from: " + url + "\nPlease wait...");
        });

        // Perform network operation on background thread
        new Thread(() -> {
            try {
                HttpsURLConnection con = HttpsConn.create_conn(url);
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

    private void connectWithASPin() {
        final String host = getCurrentHost();
        mainHandler.post(() -> responseTextView.setText("Connecting with ASPin: " + host));
        new Thread(() -> {
            HttpsURLConnection connection = null;
            try {
                ASPinVerifier.CertificateClaim claim = getValidatedAspinClaim(host);
                connection = HttpsConn.createASPinConnection(host, claim);
                connection.setConnectTimeout(15000);
                connection.setReadTimeout(15000);
                String response = HttpsConn.get_content(connection);
                mainHandler.post(() -> responseTextView.setText(response));
            } catch (Exception error) {
                Log.e(TAG, "ASPin-protected connection failed", error);
                mainHandler.post(() -> responseTextView.setText(
                        "ASPin-protected connection failed: " + error.getMessage()));
            } finally {
                if (connection != null) connection.disconnect();
            }
        }, "aspin-connection").start();
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
        String requestedHost = intent.getStringExtra("target_hostname");
        if (requestedHost != null && !requestedHost.trim().isEmpty()) {
            updateHostDisplay(requestedHost.trim());
        }
        int iterations = intent.getIntExtra("iterations", 2000);
        String csvPath = intent.getStringExtra("output_csv");
        intent.removeExtra("benchmark_type");

        if ("avgveriftime".equalsIgnoreCase(benchmarkType)) {
            runExperimentRefreshBenchmark(iterations, csvPath);
        } else if ("avgvisittime".equalsIgnoreCase(benchmarkType)) {
            runExperimentConnectionBenchmark(
                    iterations, intent.getStringExtra("server_phase"), csvPath);
        } else if ("schemecomparison".equalsIgnoreCase(benchmarkType)) {
            SchemeComparisonBenchmark.start(this, getCurrentHost(), intent);
        } else if ("rttcache".equalsIgnoreCase(benchmarkType)) {
            RttCacheBenchmark.start(this, getCurrentHost(), intent);
        } else if ("policyscenario".equalsIgnoreCase(benchmarkType)) {
            PolicyScenarioBenchmark.start(this, getCurrentHost(), intent);
        } else if ("crosssign".equalsIgnoreCase(benchmarkType)) {
            CrossSignBenchmark.start(this, getCurrentHost(), intent);
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

    private void runExperimentRefreshBenchmark(int iterations, String csvPath) {
        mainHandler.post(() -> responseTextView.setText(
                "Running " + BuildConfig.BENCHMARK_MODE + " refresh benchmark..."));
        new Thread(() -> {
            try {
                String report = ExperimentBenchmark.runRefresh(
                        this, getCurrentHost(), iterations, csvPath);
                mainHandler.post(() -> responseTextView.setText(report));
            } catch (Exception e) {
                Log.e(TAG, "Experiment refresh benchmark failed", e);
                mainHandler.post(() -> responseTextView.setText(
                        "Refresh benchmark failed: " + e.getMessage()));
            }
        }).start();
    }

    private void runExperimentConnectionBenchmark(
            int iterations, String serverPhase, String csvPath) {
        mainHandler.post(() -> responseTextView.setText(
                "Running " + BuildConfig.BENCHMARK_MODE + " connection benchmark..."));
        new Thread(() -> {
            try {
                String report = ExperimentBenchmark.runConnections(
                        this, getCurrentHost(), iterations, serverPhase, csvPath);
                mainHandler.post(() -> responseTextView.setText(report));
            } catch (Exception e) {
                Log.e(TAG, "Experiment connection benchmark failed", e);
                mainHandler.post(() -> responseTextView.setText(
                        "Connection benchmark failed: " + e.getMessage()));
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
                String header = "Operations,Threads,Successes,Failures,Mean_ms,P50_ms,P95_ms,P99_ms,Throughput_ops_s,Result,Timestamp,API,Hostname,TargetAppId";
                String row = String.format(Locale.ROOT,
                        "%d,%d,%d,%d,%.3f,%.3f,%.3f,%.3f,%.2f,%s,%s,%s,%s,%s",
                        operations, threads, successes.get(),
                        operations - successes.get(), meanMillis(durations),
                        percentileMillis(durations, 0.50),
                        percentileMillis(durations, 0.95),
                        percentileMillis(durations, 0.99), throughput,
                        passed ? "PASS" : "FAIL", timestamp,
                        isOwnAspinTarget() ? "self" : "cross", host, ASPIN_TARGET_APP_ID);
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

}
