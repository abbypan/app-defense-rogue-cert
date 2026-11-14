package com.cert.aspin;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

/** Four independent protected schemes; native TLS controls use the primary APK. */
public final class ExperimentBenchmark {
    private static final int TIMEOUT_MILLIS = 5_000;

    private ExperimentBenchmark() {
    }

    public static String runRefresh(
            Context context, String host, int iterations, String outputCsv) throws Exception {
        String mode = BuildConfig.BENCHMARK_MODE;
        if ("scp".equals(mode) || "dcp".equals(mode)) {
            throw new IllegalStateException("This entry point measures only ASPin two-token refresh;"
                    + " measure DCP metadata retrieval inside the NSC handshake instead");
        }

        long[] total = new long[iterations];
        long[] tk = new long[iterations];
        long[] tc = new long[iterations];
        int successes = 0;
        for (int index = 0; index < iterations; index++) {
            long start = System.nanoTime();
            try {
                OsAspinClient.Result result =
                        AppTrustedServerCert.refreshValidatedServerCertClaim(context, host);
                tk[index] = result.getClaimKeyDownloadAndVerificationNanos();
                tc[index] = result.getClaimDownloadAndVerificationNanos();
                if (result.getClaim() == null || tk[index] <= 0 || tc[index] <= 0) {
                    throw new IllegalStateException("OS service returned incomplete refresh timing");
                }
                successes++;
            } finally {
                total[index] = System.nanoTime() - start;
            }
        }

        String scheme = "compatible".equals(mode) ? "ASPin-compatible" : "ASPin-primary";
        String header = "Algorithm,Mode,Scheme,Iterations,Tk_Mean_ms,Tc_Mean_ms,"
                + "Total_Mean_ms,Total_P50_ms,Total_P95_ms,Total_P99_ms,"
                + "Success_Count,Result,Timestamp";
        String row = String.format(Locale.ROOT,
                "%s,%s,%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%d,%s,%s",
                algorithm(host), mode, scheme, iterations, meanMillis(tk), meanMillis(tc),
                meanMillis(total), percentileMillis(total, 0.50),
                percentileMillis(total, 0.95), percentileMillis(total, 0.99), successes,
                successes == iterations ? "PASS" : "FAIL", timestamp());
        writeCsv(outputCsv, header, row);
        return String.format(Locale.ROOT,
                "%s refresh: %d/%d; mean %.3f ms; p95 %.3f ms; p99 %.3f ms",
                scheme, successes, iterations, meanMillis(total),
                percentileMillis(total, 0.95), percentileMillis(total, 0.99));
    }

    public static String runConnections(
            Context context, String host, int iterations, String serverPhase, String outputCsv)
            throws Exception {
        String mode = BuildConfig.BENCHMARK_MODE;
        boolean rogue = "rogueserver".equalsIgnoreCase(serverPhase);
        StringBuilder rows = new StringBuilder();
        StringBuilder report = new StringBuilder();

        ASPinVerifier.CertificateClaim primaryClaim = null;
        if ("primary".equals(mode) || "compatible".equals(mode)) {
            primaryClaim = AppTrustedServerCert.getValidatedServerCertClaim(context, host);
        }

        if ("primary".equals(mode)) {
            appendConnectionResult(rows, report, host, mode, "Native-TLS", serverPhase,
                    iterations, true, null);
            appendConnectionResult(rows, report, host, mode, "ASPin-primary", serverPhase,
                    iterations, !rogue, primaryClaim);
        } else if ("scp".equals(mode)) {
            appendConnectionResult(rows, report, host, mode, "SCP-NSC", serverPhase,
                    iterations, !rogue, null);
        } else if ("dcp".equals(mode)) {
            appendConnectionResult(rows, report, host, mode, "DCP-NSC", serverPhase,
                    iterations, !rogue, null);
        } else if ("compatible".equals(mode)) {
            appendConnectionResult(rows, report, host, mode, "ASPin-compatible", serverPhase,
                    iterations, !rogue, primaryClaim);
        } else {
            throw new IllegalStateException("Unknown benchmark mode: " + mode);
        }

        String header = "Algorithm,Mode,Scheme,ServerPhase,Iterations,Host,Mean_ms,P50_ms,"
                + "P95_ms,P99_ms,Success_Count,Expected_Success_Count,Result,Response,Timestamp";
        writeCsv(outputCsv, header, rows.toString().trim());
        return report.toString().trim();
    }

    private static void appendConnectionResult(
            StringBuilder rows, StringBuilder report, String host, String mode, String scheme,
            String serverPhase, int iterations, boolean expectedSuccess,
            ASPinVerifier.CertificateClaim claim) {
        long[] durations = new long[iterations];
        int successes = 0;
        int policyRejections = 0;
        int errors = 0;
        String response = "N/A";
        for (int index = 0; index < iterations; index++) {
            long start = System.nanoTime();
            HttpsURLConnection connection = null;
            try {
                connection = claim == null
                        ? HttpsConn.createStandardTLSConnection(host)
                        : HttpsConn.createASPinConnection(host, claim);
                connection.setConnectTimeout(TIMEOUT_MILLIS);
                connection.setReadTimeout(TIMEOUT_MILLIS);
                String content = HttpsConn.get_content(connection);
                response = sanitize(content);
                successes++;
            } catch (Exception error) {
                String policyScheme = "scp".equals(mode) ? "SCP"
                        : "dcp".equals(mode) ? "DCP" : "ASPin";
                if (RttBenchmarkChecks.isPolicyRejection(error, policyScheme)) policyRejections++;
                else errors++;
            } finally {
                if (connection != null) connection.disconnect();
                durations[index] = System.nanoTime() - start;
            }
        }

        int expectedSuccesses = expectedSuccess ? iterations : 0;
        boolean passed = errors == 0 && successes == expectedSuccesses
                && (expectedSuccess || policyRejections == iterations);
        if (rows.length() > 0) rows.append('\n');
        rows.append(String.format(Locale.ROOT,
                "%s,%s,%s,%s,%d,%s,%.3f,%.3f,%.3f,%.3f,%d,%d,%s,\"%s\",%s",
                algorithm(host), mode, scheme, serverPhase, iterations, host,
                meanMillis(durations), percentileMillis(durations, 0.50),
                percentileMillis(durations, 0.95), percentileMillis(durations, 0.99),
                successes, expectedSuccesses, passed ? "PASS" : "FAIL", response, timestamp()));
        if (report.length() > 0) report.append('\n');
        report.append(String.format(Locale.ROOT,
                "%s: %d/%d accepted; mean %.3f ms; p95 %.3f ms; %s",
                scheme, successes, iterations, meanMillis(durations),
                percentileMillis(durations, 0.95), passed ? "PASS" : "FAIL"));
    }

    private static void writeCsv(String outputCsv, String header, String rows) throws Exception {
        if (outputCsv == null || outputCsv.isBlank()) {
            throw new IllegalArgumentException("output_csv is required");
        }
        File output = new File(outputCsv);
        File parent = output.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("Cannot create benchmark output directory");
        }
        try (FileOutputStream stream = new FileOutputStream(output, false)) {
            stream.write((header + "\n" + rows + "\n").getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String algorithm(String host) {
        int separator = host.indexOf('.');
        return separator > 0 ? host.substring(0, separator) : host;
    }

    private static String sanitize(String value) {
        if (value == null || value.isEmpty()) return "N/A";
        return value.replaceAll("[\\r\\n,\\\"]", " ").trim();
    }

    private static String timestamp() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(new Date());
    }

    private static double meanMillis(long[] values) {
        double sum = 0;
        for (long value : values) sum += value;
        return values.length == 0 ? 0 : sum / values.length / 1_000_000.0;
    }

    private static double percentileMillis(long[] values, double percentile) {
        if (values.length == 0) return 0;
        long[] copy = Arrays.copyOf(values, values.length);
        Arrays.sort(copy);
        int index = (int) Math.ceil(percentile * copy.length) - 1;
        return copy[Math.max(0, Math.min(index, copy.length - 1))] / 1_000_000.0;
    }
}
