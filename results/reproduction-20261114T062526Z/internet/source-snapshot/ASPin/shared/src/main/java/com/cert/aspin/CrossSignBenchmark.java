package com.cert.aspin;

import android.content.Context;
import android.content.Intent;
import android.net.http.X509TrustManagerExtensions;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** Functional path-selection evidence, not a comparative latency benchmark. */
public final class CrossSignBenchmark {
    private CrossSignBenchmark() { }

    private static final class Observation {
        boolean nativeValid;
        boolean policyChecked;
        boolean policyRejected;
        boolean sawExtra;
        boolean sent;
        String selected = "";
        String leaf = "";
        String path = "";
        String peer = "";
        String pathDer = "";
    }

    public static void start(Context context, String host, Intent intent) {
        new Thread(() -> {
            try {
                String target = intent.getStringExtra("target_hostname");
                run(context, target == null ? host : target, intent);
            }
            catch (Exception error) { Log.e("MainActivity", "Cross-sign test failed", error); }
        }, "aspin-cross-sign").start();
    }

    public static void run(Context context, String host, Intent intent) throws Exception {
        if (!BuildConfig.DEBUG) throw new UnsupportedOperationException("Debug benchmark only");
        String scenario = intent.getStringExtra("scenario");
        String expectedIssuer = intent.getStringExtra("expected_issuer_id");
        String expectedExtra = intent.getStringExtra("expected_extra_id");
        String outputPath = intent.getStringExtra("output_csv");
        int iterations = intent.getIntExtra("iterations", 20);
        boolean expectedAccept = intent.getBooleanExtra("expect_success", true);
        if (iterations <= 0 || scenario == null || !scenario.matches("[A-Za-z0-9-]+")
                || expectedIssuer == null || !expectedIssuer.startsWith("sha256:")
                || outputPath == null) throw new IllegalArgumentException("Invalid cross-sign case");
        // Exercise real OS token verification in each case, including after
        // switching the manifest-rooted mode; never reuse an earlier root's RAM entry.
        OsAspinClient.Result policy = OsAspinClient.refreshCertificateClaim(context, host);
        ASPinVerifier.CertificateClaim claim = policy.getClaim();
        File output = new File(outputPath), parent = output.getParentFile();
        if (parent == null || (!parent.isDirectory() && !parent.mkdirs())) {
            throw new IllegalStateException("No result directory");
        }
        File pending = File.createTempFile("cross-sign-pending-", ".csv", parent);
        try {
            try (BufferedWriter writer = Files.newBufferedWriter(pending.toPath(), StandardCharsets.UTF_8)) {
                writer.write("Scenario,Attempt,Native_Valid,Selected_Issuer,Leaf_Digest,"
                        + "Extra_Seen,Policy_Checked,Policy_Rejected,Accepted,App_Request_Sent,Result,"
                        + "Mode,Claim_Issuers,Tk_ms,Tc_ms,Error,Validated_Path,Peer_Path,Validated_Path_DER\n");
                for (int attempt = 0; attempt < iterations; attempt++) {
                    Observation observed = new Observation();
                    HttpsURLConnection connection = null;
                    boolean accepted = false;
                    String failure = "";
                    try {
                        TrustManagerFactory factory = TrustManagerFactory.getInstance(
                                TrustManagerFactory.getDefaultAlgorithm());
                        factory.init((KeyStore) null);
                        X509TrustManager nativeManager = null;
                        for (TrustManager manager : factory.getTrustManagers()) {
                            if (manager instanceof X509TrustManager) nativeManager = (X509TrustManager) manager;
                        }
                        if (nativeManager == null) throw new IllegalStateException("No native trust manager");
                        X509TrustManager delegate = nativeManager;
                        X509TrustManagerExtensions extension = new X509TrustManagerExtensions(delegate);
                        TrustManager wrapper = new X509TrustManager() {
                            public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
                            public void checkClientTrusted(X509Certificate[] chain, String authType)
                                    throws CertificateException { delegate.checkClientTrusted(chain, authType); }
                            public void checkServerTrusted(X509Certificate[] peer, String authType)
                                    throws CertificateException {
                                List<X509Certificate> path = extension.checkServerTrusted(peer, authType, host);
                                X509Certificate[] selected = HttpsConn.requireValidatedPath(path);
                                if (selected.length < 2) throw new CertificateException("No direct issuer in native path");
                                observed.nativeValid = true;
                                observed.selected = identifier(selected[1]);
                                observed.leaf = identifier(selected[0]);
                                StringBuilder pathEvidence = new StringBuilder();
                                StringBuilder derEvidence = new StringBuilder();
                                for (X509Certificate item : selected) {
                                    if (pathEvidence.length() > 0) pathEvidence.append(';');
                                    pathEvidence.append(identifier(item));
                                    if (derEvidence.length() > 0) derEvidence.append(';');
                                    derEvidence.append(Base64.getUrlEncoder().withoutPadding()
                                            .encodeToString(item.getEncoded()));
                                }
                                observed.path = pathEvidence.toString();
                                observed.pathDer = derEvidence.toString();
                                StringBuilder peerEvidence = new StringBuilder();
                                for (X509Certificate item : peer) {
                                    if (peerEvidence.length() > 0) peerEvidence.append(';');
                                    peerEvidence.append(identifier(item));
                                }
                                observed.peer = peerEvidence.toString();
                                if (expectedExtra != null && !expectedExtra.isEmpty()) {
                                    for (X509Certificate candidate : peer) {
                                        if (expectedExtra.equals(identifier(candidate))) observed.sawExtra = true;
                                    }
                                }
                                observed.policyChecked = true;
                                try { ASPinVerifier.verifyCertificate(host, claim, selected); }
                                catch (CertificateException error) {
                                    observed.policyRejected = "Direct issuer CA certificate is not authorized by the authenticated ASPin claim"
                                            .equals(error.getMessage());
                                    throw error;
                                }
                            }
                        };
                        SSLContext tls = SSLContext.getInstance("TLS");
                        tls.init(null, new TrustManager[] { wrapper }, null);
                        connection = HttpsConn.create_conn("https://" + host + "/");
                        connection.setSSLSocketFactory(tls.getSocketFactory());
                        connection.setConnectTimeout(5_000); connection.setReadTimeout(5_000);
                        connection.setUseCaches(false); connection.setInstanceFollowRedirects(false);
                        connection.setRequestProperty("Connection", "close");
                        connection.setRequestProperty("X-ASPin-Observation", scenario + "-" + attempt);
                        connection.connect();
                        observed.sent = true;
                        if (connection.getResponseCode() != 200) throw new IllegalStateException("Non-200 response");
                        try (var stream = connection.getInputStream()) {
                            if (stream.read() < 0) throw new IllegalStateException("Empty response");
                        }
                        accepted = true;
                    } catch (Exception error) {
                        // Only the exact issuer-policy rejection can pass a negative case.
                        failure = error.getClass().getSimpleName() + ": " + String.valueOf(error.getMessage());
                    } finally { if (connection != null) connection.disconnect(); }
                    boolean pass = observed.nativeValid && observed.policyChecked
                            && expectedIssuer.equals(observed.selected)
                            && (expectedExtra == null || expectedExtra.isEmpty() || observed.sawExtra)
                            && (expectedAccept ? accepted && !observed.policyRejected && observed.sent
                                               : !accepted && observed.policyRejected && !observed.sent);
                    writer.write(String.format(Locale.ROOT,
                            "%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%.6f,%.6f,\"%s\",%s,%s,%s%n",
                            scenario, attempt, observed.nativeValid, observed.selected, observed.leaf,
                            observed.sawExtra, observed.policyChecked, observed.policyRejected,
                            accepted, observed.sent, pass ? "PASS" : "FAIL", BuildConfig.BENCHMARK_MODE,
                            String.join(";", claim.getIssuers()),
                            policy.getClaimKeyDownloadAndVerificationNanos() / 1e6,
                            policy.getClaimDownloadAndVerificationNanos() / 1e6,
                            failure.replace("\"", "\"\"").replace('\n', ' ').replace('\r', ' '),
                            observed.path, observed.peer, observed.pathDer));
                }
            }
            Files.move(pending.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(pending.toPath()); }
    }

    private static String identifier(X509Certificate certificate) throws CertificateException {
        try {
            return "sha256:" + Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (Exception error) { throw new CertificateException("Cannot hash native certificate", error); }
    }
}
