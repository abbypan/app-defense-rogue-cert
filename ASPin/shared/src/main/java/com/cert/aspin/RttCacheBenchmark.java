package com.cert.aspin;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.File;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

/** Raw observations for added RTT x policy-cache regime x certificate outcome.
 * Cold means debug-forced TWO-token retrieval, not a reset of protected H_k/H_c,
 * the TLS/DNS caches, or the process/JIT. Every attempt uses a new SSLContext.
 */
public final class RttCacheBenchmark {
    private static final int TIMEOUT_MS = 15_000;
    private RttCacheBenchmark() { }

    public static void start(Context context, String host, Intent intent) {
        new Thread(() -> {
            try {
                run(context, host, intent);
            } catch (Exception error) {
                Log.e("MainActivity", "RTT cache benchmark failed", error);
            }
        }, "aspin-rtt-cache-benchmark").start();
    }

    public static void run(Context context, String host, Intent intent) throws Exception {
        if (!BuildConfig.DEBUG) {
            throw new UnsupportedOperationException("RTT matrix requires a debuggable benchmark APK");
        }
        int count = intent.getIntExtra("iterations", 100);
        int warmups = intent.getIntExtra("warmups", 10);
        int addedRtt = intent.getIntExtra("added_rtt_ms", 0);
        int repeat = intent.getIntExtra("repeat", 1);
        String scheme = intent.getStringExtra("scheme");
        String phase = intent.getStringExtra("phase");
        String cache = RttBenchmarkChecks.cacheFor(scheme, intent.getStringExtra("policy_cache"));
        String expected = RttBenchmarkChecks.expectedOutcome(scheme, phase);
        if (count < 1 || warmups < 0 || addedRtt < 0 || repeat < 1) {
            throw new IllegalArgumentException("Invalid matrix dimensions");
        }
        String requiredMode = "TLS".equals(scheme) ? "primary"
                : "ASPin".equals(scheme) ? "primary"
                : "ASPin-compatible".equals(scheme) ? "compatible" : scheme.toLowerCase(Locale.ROOT);
        if (!requiredMode.equals(BuildConfig.BENCHMARK_MODE)) {
            throw new IllegalStateException("Wrong APK mode for requested scheme");
        }
        String outputPath = intent.getStringExtra("output_csv");
        if (outputPath == null || outputPath.isBlank()) throw new IllegalArgumentException("output_csv required");
        File output = new File(outputPath);
        File parent = output.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new IllegalStateException("Cannot create result directory");
        }
        File pending = File.createTempFile("rtt-pending-", ".csv", parent);
        boolean complete = false;
        try {
            double[] echo = calibrateEcho(intent.getIntExtra("echo_port", 19090));
            if ("hot".equals(cache) && !"DCP".equals(scheme)) {
                // Outside timed observations. Warm only token policy, not a TLS connection.
                OsAspinClient.refreshCertificateClaim(context, host);
            }
            if ("hot".equals(cache) && "DCP".equals(scheme)) {
                Observation warmed = measure(context, host, scheme, cache);
                if (!expected.equals(warmed.outcome)) throw new IllegalStateException("DCP preload failed");
            }
            for (int index = 0; index < warmups; index++) {
                Observation observation = measure(context, host, scheme, cache);
                if (!expected.equals(observation.outcome)) {
                    throw new IllegalStateException("Warmup did not reach " + expected
                            + ": " + observation.outcome + " " + observation.errorMessage);
                }
            }
            try (BufferedWriter writer = Files.newBufferedWriter(pending.toPath(), StandardCharsets.UTF_8)) {
                writer.write("Algorithm,Mode,Scheme,Phase,Cache,Added_RTT_ms,Repeat,Sample,"
                        + "Policy_ms,Connection_ms,Outcome_ms,AppRead_ms,Tk_ms,Tc_ms,"
                        + "Cache_Evidence,Outcome,Expected_Outcome,Result,Error_Class,Error_Message,"
                        + "Echo_RTT_P50_ms,Echo_RTT_P95_ms\n");
                for (int index = 1; index <= count; index++) {
                    Observation observation = measure(context, host, scheme, cache);
                    boolean passed = expected.equals(observation.outcome);
                    writer.write(String.format(Locale.ROOT,
                            "%s,%s,%s,%s,%s,%d,%d,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,"
                                    + "%s,%s,%s,%s,%s,%s,%.6f,%.6f%n",
                            host.substring(0, host.indexOf('.')), BuildConfig.BENCHMARK_MODE,
                            scheme, phase, cache, addedRtt, repeat, index,
                            millis(observation.policy), millis(observation.connection),
                            millis(observation.total), millis(observation.appRead),
                            millis(observation.tk), millis(observation.tc), observation.evidence,
                            observation.outcome, expected, passed ? "PASS" : "FAIL",
                            csv(observation.errorClass), csv(observation.errorMessage), echo[0], echo[1]));
                }
            }
            // A visible .csv is complete; host polling cannot pull a partial result.
            Files.move(pending.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING);
            complete = true;
        } finally {
            if (!complete) Files.deleteIfExists(pending.toPath());
        }
    }

    private static Observation measure(Context context, String host, String scheme, String cache) {
        Observation result = new Observation();
        OsAspinClient.Result policy = null;
        boolean dynamic = "ASPin".equals(scheme) || "ASPin-compatible".equals(scheme);
        // DCP runs independently inside NSC, not through an ASPin lookup. The host must
        // corroborate its cache condition against metadata-request counts in the server log.
        if ("DCP".equals(scheme)) result.evidence = "server-audit-required";
        long start = System.nanoTime();
        long connectionStart = 0;
        HttpsURLConnection connection = null;
        String stage = "policy_lookup_error";
        try {
            if (dynamic) {
                policy = "cold-forced-refresh".equals(cache)
                        ? OsAspinClient.refreshCertificateClaim(context, host)
                        : OsAspinClient.getCertificateClaim(context, host);
                result.tk = policy.getClaimKeyDownloadAndVerificationNanos();
                result.tc = policy.getClaimDownloadAndVerificationNanos();
                stage = "cache_evidence_error";
                checkPolicy(policy, cache);
                result.evidence = "hot".equals(cache) ? "hot-no-fetch" : "two-token-refresh";
            }
            connectionStart = System.nanoTime();
            result.policy = connectionStart - start;
            stage = "network_error";
            connection = dynamic
                    ? HttpsConn.createASPinConnection(host, policy.getClaim())
                    : HttpsConn.createStandardTLSConnection(host);
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty("Connection", "close");
            connection.setUseCaches(false);
            connection.connect();
            // Primary metric: time to TLS acceptance or policy rejection.
            result.connection = System.nanoTime() - connectionStart;
            result.total = System.nanoTime() - start;
            long readStart = System.nanoTime();
            if (connection.getResponseCode() != 200) {
                throw new IllegalStateException("Unexpected HTTP response after TLS acceptance");
            }
            try (var stream = connection.getInputStream()) {
                if (stream.read() < 0) throw new IllegalStateException("Empty benchmark response");
            }
            result.appRead = System.nanoTime() - readStart;
            result.outcome = "accepted";
        } catch (Exception error) {
            if (result.total == 0) {
                result.total = System.nanoTime() - start;
                if (connectionStart == 0) result.policy = result.total;
                else result.connection = System.nanoTime() - connectionStart;
            }
            result.fail("network_error".equals(stage)
                    && RttBenchmarkChecks.isPolicyRejection(error, scheme)
                    ? "policy_rejected" : stage, error);
        } finally {
            if (connection != null) connection.disconnect();
        }
        return result;
    }

    private static void checkPolicy(OsAspinClient.Result result, String cache) {
        if (result.getClaim() == null || result.getExpiresAtMillis()
                <= System.currentTimeMillis() + TIMEOUT_MS + 1_000) {
            throw new IllegalStateException("Claim too close to expiry for a controlled observation");
        }
        RttBenchmarkChecks.requireCacheEvidence(cache,
                result.getClaimKeyDownloadAndVerificationNanos(),
                result.getClaimDownloadAndVerificationNanos());
    }

    private static double[] calibrateEcho(int port) throws Exception {
        long[] times = new long[20];
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            socket.setTcpNoDelay(true);
            for (int index = 0; index < times.length; index++) {
                long start = System.nanoTime();
                socket.getOutputStream().write(index);
                socket.getOutputStream().flush();
                if (socket.getInputStream().read() != index) throw new IllegalStateException("Bad echo");
                times[index] = System.nanoTime() - start;
            }
        }
        Arrays.sort(times);
        return new double[] {millis(times[9]), millis(times[18])};
    }

    private static double millis(long nanos) { return nanos / 1_000_000.0; }
    private static String csv(String text) { return "\"" + text.replace("\"", "\"\"").replace('\n', ' ').replace('\r', ' ') + "\""; }

    private static final class Observation {
        long policy, connection, total, appRead, tk, tc;
        String evidence = "not-applicable", outcome = "network_error", errorClass = "", errorMessage = "";
        void fail(String kind, Exception error) {
            outcome = kind;
            errorClass = error.getClass().getName();
            errorMessage = String.valueOf(error.getMessage());
        }
    }
}
