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

/** One controlled observation. Host controls publication/expiry between calls.
 * A failed lookup NEVER falls back to native-only TLS on this protected path.
 */
public final class PolicyScenarioBenchmark {
    private PolicyScenarioBenchmark() { }

    public static void start(Context context, String host, Intent intent) {
        new Thread(() -> {
            try { run(context, host, intent); }
            catch (Exception error) { Log.e("MainActivity", "Policy scenario benchmark failed", error); }
        }, "aspin-policy-scenario").start();
    }

    public static void run(Context context, String host, Intent intent) throws Exception {
        if (!BuildConfig.DEBUG) throw new UnsupportedOperationException("Debug benchmark only");
        String label = intent.getStringExtra("scenario");
        String operation = intent.getStringExtra("operation");
        String api = intent.getStringExtra("api");
        String target = intent.getStringExtra("target_package");
        String expected = intent.getStringExtra("expected_outcome");
        String errorKind = intent.getStringExtra("expected_error_kind");
        String requiredCache = intent.getStringExtra("required_cache");
        String outputPath = intent.getStringExtra("output_csv");
        if (label == null || !label.matches("[A-Za-z0-9-]+") || outputPath == null
                || !("native".equals(operation) || "protected".equals(operation))
                || !("self".equals(api) || "cross".equals(api))
                || ("cross".equals(api) && (target == null || target.isBlank()))) {
            throw new IllegalArgumentException("Invalid policy scenario configuration");
        }
        long notBefore = intent.getLongExtra("not_before_ms", 0);
        if (System.currentTimeMillis() < notBefore) throw new IllegalStateException("Expiry boundary not reached");
        boolean force = intent.getBooleanExtra("force_refresh", false);
        long start = System.nanoTime(), policyEnd = start, lookupStart = System.currentTimeMillis();
        long tk = 0, tc = 0, issued = 0, expires = 0;
        boolean lookupSucceeded = false, tlsAttempted = false, appSent = false;
        String outcome = "unexpected_error", errorClass = "", errorMessage = "", cache = "none";
        HttpsURLConnection connection = null;
        OsAspinClient.Result policy = null;
        String stage = "lookup";
        try {
            if ("protected".equals(operation)) {
                policy = "self".equals(api)
                        ? (force ? OsAspinClient.refreshCertificateClaim(context, host)
                                 : OsAspinClient.getCertificateClaim(context, host))
                        : (force ? OsAspinClient.refreshCertificateClaimForApp(context, target, host)
                                 : OsAspinClient.getCertificateClaimForApp(context, target, host));
                lookupSucceeded = true;
                tk = policy.getClaimKeyDownloadAndVerificationNanos();
                tc = policy.getClaimDownloadAndVerificationNanos();
                issued = policy.getIssuedAtMillis(); expires = policy.getExpiresAtMillis();
                cache = tk == 0 && tc == 0 ? "hot" : tk > 0 && tc > 0 ? "two-token-refresh" : "partial-refresh";
                stage = "evidence";
                if ("hot".equals(requiredCache) && !"hot".equals(cache)) throw new IllegalStateException("Expected hot OS cache");
                if ("two-token-refresh".equals(requiredCache) && !"two-token-refresh".equals(cache)) throw new IllegalStateException("Expected both token fetches");
                long margin = intent.getLongExtra("minimum_remaining_ms", 1000);
                if (expires <= System.currentTimeMillis() + margin) throw new IllegalStateException("Claim too close to expiry");
            }
            policyEnd = System.nanoTime();
            stage = "tls";
            connection = "protected".equals(operation)
                    ? HttpsConn.createASPinConnection(host, policy.getClaim())
                    : HttpsConn.createStandardTLSConnection(host);
            connection.setConnectTimeout(15_000); connection.setReadTimeout(15_000);
            connection.setUseCaches(false); connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty("Connection", "close");
            connection.setRequestProperty("X-ASPin-Observation", label);
            tlsAttempted = true;
            connection.connect();
            stage = "application";
            // Never send an HTTP application request until TLS + claim checks pass.
            appSent = true;
            if (connection.getResponseCode() != 200) throw new IllegalStateException("Non-200 application response");
            try (var stream = connection.getInputStream()) {
                if (stream.read() < 0) throw new IllegalStateException("Empty application response");
            }
            outcome = "accepted";
        } catch (Exception error) {
            if ("lookup".equals(stage)) policyEnd = System.nanoTime();
            errorClass = error.getClass().getName(); errorMessage = String.valueOf(error.getMessage());
            if ("lookup".equals(stage) && PolicyScenarioChecks.matchesLookupFailure(error, errorKind)) outcome = "lookup_refused";
            else if ("tls".equals(stage) && RttBenchmarkChecks.isPolicyRejection(error, "ASPin")) outcome = "policy_rejected";
        } finally {
            if (connection != null) connection.disconnect();
        }
        long end = System.nanoTime();
        boolean pass = PolicyScenarioChecks.passed(expected, outcome, tlsAttempted, appSent, lookupSucceeded);
        File output = new File(outputPath), parent = output.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) throw new IllegalStateException("No result directory");
        File pending = File.createTempFile("policy-pending-", ".csv", parent);
        try {
            try (BufferedWriter writer = Files.newBufferedWriter(pending.toPath(), StandardCharsets.UTF_8)) {
                writer.write("Scenario,Caller,API,Target,Operation,Force_Refresh,Lookup_Succeeded,Cache,"
                        + "Lookup_Start_ms,Issued_ms,Expires_ms,Tk_ms,Tc_ms,Policy_ms,Outcome_ms,"
                        + "TLS_Attempted,App_Request_Sent,Outcome,Expected_Outcome,Result,Error_Class,Error_Message\n");
                writer.write(String.format(Locale.ROOT,
                        "%s,%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%.6f,%.6f,%.6f,%.6f,%s,%s,%s,%s,%s,%s,%s%n",
                        label, context.getPackageName(), api, target == null ? "" : target, operation, force,
                        lookupSucceeded, cache, lookupStart, issued, expires, tk / 1e6, tc / 1e6,
                        (policyEnd - start) / 1e6, (end - start) / 1e6, tlsAttempted, appSent,
                        outcome, expected, pass ? "PASS" : "FAIL", csv(errorClass), csv(errorMessage)));
            }
            Files.move(pending.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(pending.toPath()); }
    }

    private static String csv(String value) {
        return "\"" + value.replace("\"", "\"\"").replace('\n', ' ').replace('\r', ' ') + "\"";
    }
}
