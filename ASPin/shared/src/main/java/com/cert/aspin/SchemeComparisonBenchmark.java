package com.cert.aspin;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

/** Raw end-to-end observations for four independent schemes, plus native TLS.
 * No automatic fallback; time to acceptance/rejection excludes the HTTP read.
 * The host corroborates DCP cache behavior with server request counts.
 */
public final class SchemeComparisonBenchmark {
    private SchemeComparisonBenchmark() { }

    public static void start(Context context, String host, Intent intent) {
        new Thread(() -> {
            try { run(context, host, intent); }
            catch (Exception error) { Log.e("MainActivity", "Scheme comparison failed", error); }
        }, "aspin-scheme-comparison").start();
    }

    private static void run(Context context, String host, Intent intent) throws Exception {
        String mode = BuildConfig.BENCHMARK_MODE;
        String scheme = intent.getStringExtra("scheme");
        String cache = RttBenchmarkChecks.cacheFor(scheme, intent.getStringExtra("policy_cache"));
        String phase = intent.getStringExtra("phase");
        String expected = RttBenchmarkChecks.expectedOutcome(scheme, phase);
        String needed = "ASPin-compatible".equals(scheme) ? "compatible"
                : "ASPin".equals(scheme) || "TLS".equals(scheme) ? "primary"
                : scheme.toLowerCase(Locale.ROOT);
        if (!BuildConfig.DEBUG || !needed.equals(mode)) throw new IllegalStateException("Wrong benchmark APK");
        int iterations = intent.getIntExtra("iterations", 20);
        int warmups = intent.getIntExtra("warmups", 3);
        String label = intent.getStringExtra("scenario");
        if (iterations < 1 || warmups < 0 || label == null || !label.matches("[A-Za-z0-9-]+")) {
            throw new IllegalArgumentException("Invalid comparison configuration");
        }
        boolean aspin = "ASPin".equals(scheme) || "ASPin-compatible".equals(scheme);
        boolean reuseCachedPolicy = intent.getBooleanExtra("reuse_cached_policy", false);
        if (reuseCachedPolicy && (!aspin || !"hot".equals(cache))) {
            throw new IllegalArgumentException("Only a hot ASPin run can reuse the OS claim cache");
        }
        if ("hot".equals(cache) && !reuseCachedPolicy) {
            if (aspin) OsAspinClient.refreshCertificateClaim(context, host);
            else requireExpected(observe(context, host, scheme, cache, label + "-preload"), expected);
        }
        for (int index = 0; index < warmups; index++) {
            requireExpected(observe(context, host, scheme, cache, label + "-warmup"), expected);
        }
        File output = new File(intent.getStringExtra("output_csv"));
        File parent = output.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) throw new IllegalStateException("No output directory");
        File pending = File.createTempFile("comparison-pending-", ".csv", parent);
        try {
            try (BufferedWriter writer = Files.newBufferedWriter(pending.toPath(), StandardCharsets.UTF_8)) {
                writer.write("Scenario,Algorithm,Mode,Scheme,Phase,Cache,Sample,Policy_ms,Connection_ms,"
                        + "Outcome_ms,AppRead_ms,Tk_ms,Tc_ms,Outcome,Expected_Outcome,App_Request_Sent,"
                        + "Result,Error_Class,Error_Message\n");
                for (int sample = 1; sample <= iterations; sample++) {
                    Observation result = observe(context, host, scheme, cache, label + "-" + sample);
                    writer.write(String.format(Locale.ROOT,
                            "%s,%s,%s,%s,%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%s,%s,%s,%s,%s,%s%n",
                            label, host.split("\\.")[0], mode, scheme, phase, cache, sample,
                            ms(result.policy), ms(result.connection), ms(result.total), ms(result.read),
                            ms(result.tk), ms(result.tc), result.outcome, expected, result.sent,
                            expected.equals(result.outcome) ? "PASS" : "FAIL", quote(result.errorClass), quote(result.error)));
                }
            }
            Files.move(pending.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(pending.toPath());
        }
    }

    private static Observation observe(Context context, String host, String scheme, String cache, String tag) {
        Observation result = new Observation();
        long start = System.nanoTime(), connectionStart = 0;
        String stage = "policy_error";
        HttpsURLConnection connection = null;
        try {
            boolean aspin = "ASPin".equals(scheme) || "ASPin-compatible".equals(scheme);
            OsAspinClient.Result policy = null;
            if (aspin) {
                policy = "hot".equals(cache) ? OsAspinClient.getCertificateClaim(context, host)
                        : OsAspinClient.refreshCertificateClaim(context, host);
                result.tk = policy.getClaimKeyDownloadAndVerificationNanos();
                result.tc = policy.getClaimDownloadAndVerificationNanos();
                RttBenchmarkChecks.requireCacheEvidence(cache, result.tk, result.tc);
                if (policy.getExpiresAtMillis() <= System.currentTimeMillis() + 1000) {
                    throw new IllegalStateException("Policy too close to expiry");
                }
            }
            result.policy = System.nanoTime() - start;
            connectionStart = System.nanoTime();
            stage = "network_error";
            connection = aspin ? HttpsConn.createASPinConnection(host, policy.getClaim())
                    : HttpsConn.createStandardTLSConnection(host);
            connection.setConnectTimeout(15000); connection.setReadTimeout(15000);
            connection.setUseCaches(false); connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty("Connection", "close");
            connection.setRequestProperty("X-ASPin-Observation", tag);
            connection.connect();
            result.connection = System.nanoTime() - connectionStart;
            result.total = System.nanoTime() - start;
            stage = "application_error";
            long readStart = System.nanoTime();
            result.sent = true;
            if (connection.getResponseCode() != 200) throw new IllegalStateException("Application response is not 200");
            try (var stream = connection.getInputStream()) {
                if (stream.read() < 0) throw new IllegalStateException("Empty application response");
            }
            result.read = System.nanoTime() - readStart;
            result.outcome = "accepted";
        } catch (Exception failure) {
            if (result.total == 0) {
                result.total = System.nanoTime() - start;
                if (connectionStart == 0) result.policy = result.total;
                else result.connection = System.nanoTime() - connectionStart;
            }
            result.outcome = "network_error".equals(stage) && RttBenchmarkChecks.isPolicyRejection(failure, scheme)
                    ? "policy_rejected" : stage;
            result.errorClass = failure.getClass().getName();
            result.error = String.valueOf(failure.getMessage());
        } finally {
            if (connection != null) connection.disconnect();
        }
        return result;
    }

    private static void requireExpected(Observation value, String expected) {
        if (!expected.equals(value.outcome)) throw new IllegalStateException("Warmup: " + value.outcome + ": " + value.error);
    }
    private static String quote(String value) { return "\"" + value.replace("\"", "\"\"").replace('\n', ' ').replace('\r', ' ') + "\""; }
    private static double ms(long nanos) { return nanos / 1000000.0; }
    private static final class Observation {
        long policy, connection, total, read, tk, tc;
        boolean sent;
        String outcome = "unexpected_error", errorClass = "", error = "";
    }
}
