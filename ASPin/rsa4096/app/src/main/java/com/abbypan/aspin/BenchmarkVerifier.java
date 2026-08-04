package com.abbypan.aspin;

import java.util.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Locale;
import javax.net.ssl.HttpsURLConnection;

/**
 * Represents the results of a benchmark test for verification operations
 */
public class BenchmarkVerifier {
    private String operation;
    private long totalTimeUs;
    private long parseTimeUs;
    private long verificationTimeUs;
    private boolean success;
    private String errorMessage;
    private Date timestamp;
    private int attemptNumber;
    private String tokenType;
    private String algorithm;
    private int tokenSizeBytes;

    public BenchmarkVerifier() {
        this.timestamp = new Date();
        this.success = false;
    }

    // Getters
    public String getOperation() {
        return operation;
    }

    public long getTotalTimeUs() {
        return totalTimeUs;
    }

    public long getParseTimeUs() {
        return parseTimeUs;
    }

    public long getVerificationTimeUs() {
        return verificationTimeUs;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public int getAttemptNumber() {
        return attemptNumber;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getTokenSizeBytes() {
        return tokenSizeBytes;
    }

    // Setters
    public void setOperation(String operation) {
        this.operation = operation;
    }

    public void setTotalTimeUs(long totalTimeUs) {
        this.totalTimeUs = totalTimeUs;
    }

    public void setParseTimeUs(long parseTimeUs) {
        this.parseTimeUs = parseTimeUs;
    }

    public void setVerificationTimeUs(long verificationTimeUs) {
        this.verificationTimeUs = verificationTimeUs;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public void setAttemptNumber(int attemptNumber) {
        this.attemptNumber = attemptNumber;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public void setTokenSizeBytes(int tokenSizeBytes) {
        this.tokenSizeBytes = tokenSizeBytes;
    }

    /**
     * Get total time in seconds
     */
    public double getTotalTimeSeconds() {
        return totalTimeUs / 1_000_000.0;
    }

    /**
     * Get parse time in seconds
     */
    public double getParseTimeSeconds() {
        return parseTimeUs / 1_000_000.0;
    }

    /**
     * Get verification time in seconds
     */
    public double getVerificationTimeSeconds() {
        return verificationTimeUs / 1_000_000.0;
    }

    /**
     * Get token size in KB
     */
    public double getTokenSizeKB() {
        return tokenSizeBytes / 1024.0;
    }

    /**
     * Get a formatted summary of the JWT benchmark result
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("JWT Benchmark Summary:\n");
        sb.append("=====================\n");
        sb.append("Operation: ").append(operation).append("\n");
        sb.append("Attempt: ").append(attemptNumber).append("\n");
        sb.append("Timestamp: ").append(timestamp).append("\n");
        sb.append("Success: ").append(success).append("\n");
        sb.append("Token Type: ").append(tokenType).append("\n");
        sb.append("Algorithm: ").append(algorithm).append("\n");
        sb.append("Token Size: ").append(String.format(Locale.US, "%.2f", getTokenSizeKB())).append(" KB\n");
        
        if (success) {
            sb.append("Total Time: ").append(totalTimeUs).append("μs\n");
            sb.append("\nTiming Breakdown:\n");
            sb.append("  Parse Time: ").append(parseTimeUs).append("μs\n");
            sb.append("  Verification Time: ").append(verificationTimeUs).append("μs\n");
        } else {
            sb.append("Error: ").append(errorMessage).append("\n");
        }
        
        return sb.toString();
    }

    @Override
    public String toString() {
        return getSummary();
    }

    public static BenchmarkVerifier benchmarkHttpsASPinConnection(
            String host, ASPinVerifier.CertificateClaim claim, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("createHttpsASPinConnection");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS-ASPin");
        result.setTokenSizeBytes(host.getBytes().length);
        long startTime = System.nanoTime();
        try {
            long connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsConn.createASPinConnection(host, claim);
            HttpsConn.get_content(con);
            result.setParseTimeUs((System.nanoTime() - connectionStartTime) / 1_000);
            result.setVerificationTimeUs(0);
            result.setSuccess(true);
            result.setAlgorithm("HTTPS-ASPin");
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
        }
        result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        return result;
    }

    public static BenchmarkVerifier benchmarkHttpsSCPConnection(String host, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("createHttpsSCPConnection");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS-SCP");
        result.setTokenSizeBytes(SCPVerifier.getPresetCertificateHash(host).getBytes().length);
        long startTime = System.nanoTime();
        try {
            long connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsConn.createSCPConnection(host);
            HttpsConn.get_content(con);
            result.setParseTimeUs((System.nanoTime() - connectionStartTime) / 1_000);
            result.setVerificationTimeUs(0);
            result.setSuccess(true);
            result.setAlgorithm("HTTPS-SCP");
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
        }
        result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        return result;
    }

    /**
     * Benchmark HTTPS DCP connection creation
     */
    public static BenchmarkVerifier benchmarkHttpsDCPConnection(String host, String expSPK, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("createHttpsDCPConnection");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS-DCP");
        result.setTokenSizeBytes((host + expSPK).getBytes().length);

        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;

        try {
            connectionStartTime = System.nanoTime();

            HttpsURLConnection con = HttpsConn.create_main_conn(new String[] { host, "dcp", "", expSPK });
            HttpsConn.get_content(con);

            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000);
            result.setVerificationTimeUs(0);
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
            result.setAlgorithm("HTTPS-DCP");

        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        }

        return result;
    }

    /**
     * Benchmark HTTPS bypass connection creation
     */
    public static BenchmarkVerifier benchmarkHttpsBypassConnection(String host, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("createHttpsBypassConnection");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS-Bypass");
        result.setTokenSizeBytes(host.getBytes().length);
        
        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;
        
        try {
            connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsConn.create_main_conn(new String [] {host, "bypass"});
            HttpsConn.get_content(con);
            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000);
            
            result.setVerificationTimeUs(0);
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
            result.setAlgorithm("HTTPS-Bypass");
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        }
        
        return result;
    }

    /**
     * Benchmark HTTPS connection creation
     */
    public static BenchmarkVerifier benchmarkHttpsConnection(String host, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("createHttpsConnection");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS");
        result.setTokenSizeBytes(host.getBytes().length);
        
        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;
        
        try {
            connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsConn.create_main_conn(new String [] { host, "default"});
            HttpsConn.get_content(con);
            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000);
            
            result.setVerificationTimeUs(0);
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
            result.setAlgorithm("HTTPS");
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        }
        
        return result;
    }

    /**
     * Benchmark HTTPS connection creation for ServerCertClaim.jwt
     */
    public static BenchmarkVerifier benchmarkHttpsGetCertClaim(String host, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("getCertClaim");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS");
        result.setTokenSizeBytes(host.getBytes().length);
        
        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;
        
        try {
            connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsConn.create_conn("https://" + host + "/.well-known/ServerCertClaim.jwt");
            String info = HttpsConn.get_content(con);
            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000);
            
            result.setVerificationTimeUs(0);
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
            result.setAlgorithm("HTTPS");
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        }
        
        return result;
    }

    /**
     * Benchmark HTTPS connection creation for ClaimSigningKey.jwt
     */
    public static BenchmarkVerifier benchmarkGetSigningKeyJWT(String host, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("createConn");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS");
        result.setTokenSizeBytes(host.getBytes().length);
        
        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;
        
        try {
            connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsConn.create_conn("https://" + host + "/.well-known/ClaimSigningKey.jwt");
            String info = HttpsConn.get_content(con);

            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000);
            
            result.setVerificationTimeUs(0);
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
            result.setAlgorithm("HTTPS");
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        }
        
        return result;
    }

    /**
     * Benchmark JWT verification with JWK
     */
    public static BenchmarkVerifier benchmarkVerifyJwtWithJwk(String token, String jwkJson, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("verifyJwtWithJwk");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType(token.trim().startsWith("{") ? "JSON" : "Compact");
        result.setTokenSizeBytes(token.getBytes().length);
        
        long startTime = System.nanoTime();
        long parseStartTime, parseEndTime, verificationStartTime, verificationEndTime;
        
        try {
            parseStartTime = System.nanoTime();
            JwkToPublicKeyConverter.convertJwkToPublicKey(jwkJson);
            parseEndTime = System.nanoTime();
            result.setParseTimeUs((parseEndTime - parseStartTime) / 1_000);
            
            verificationStartTime = System.nanoTime();
            String payload = JwtVerifier.verifyJwtWithJwk(token, jwkJson);
            verificationEndTime = System.nanoTime();
            result.setVerificationTimeUs((verificationEndTime - verificationStartTime) / 1_000);
            
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
            
            if (token.contains("ES256")) {
                result.setAlgorithm("ES256");
            } else if (token.contains("ES384")) {
                result.setAlgorithm("ES384");
            } else if (token.contains("ES512")) {
                result.setAlgorithm("ES512");
            } else if (token.contains("RS256")) {
                result.setAlgorithm("RS256");
            } else if (token.contains("RS384")) {
                result.setAlgorithm("RS384");
            } else if (token.contains("RS512")) {
                result.setAlgorithm("RS512");
            } else {
                result.setAlgorithm("Unknown");
            }
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        }
        
        return result;
    }

    /**
     * Benchmark JWT verification with certificate
     */
    public static BenchmarkVerifier benchmarkVerifyJwtWithCert(String token, String cert, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("verifyJwtWithCert");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType(token.trim().startsWith("{") ? "JSON" : "Compact");
        result.setTokenSizeBytes(token.getBytes().length);
        
        long startTime = System.nanoTime();
        long parseStartTime, parseEndTime, verificationStartTime, verificationEndTime;
        
        try {
            parseStartTime = System.nanoTime();
            PemUtils.parseX509Certificate(cert);
            parseEndTime = System.nanoTime();
            result.setParseTimeUs((parseEndTime - parseStartTime) / 1_000);
            
            verificationStartTime = System.nanoTime();
            String payload = JwtVerifier.verifyJwtWithCert(token, cert);
            verificationEndTime = System.nanoTime();
            result.setVerificationTimeUs((verificationEndTime - verificationStartTime) / 1_000);
            
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
            
            if (token.contains("ES256")) {
                result.setAlgorithm("ES256");
            } else if (token.contains("ES384")) {
                result.setAlgorithm("ES384");
            } else if (token.contains("ES512")) {
                result.setAlgorithm("ES512");
            } else if (token.contains("RS256")) {
                result.setAlgorithm("RS256");
            } else if (token.contains("RS384")) {
                result.setAlgorithm("RS384");
            } else if (token.contains("RS512")) {
                result.setAlgorithm("RS512");
            } else {
                result.setAlgorithm("Unknown");
            }
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        }
        
        return result;
    }

    /**
     * Benchmark DCP pin verification with DCP public key PEM
     */
    public static BenchmarkVerifier benchmarkVerifyDCP(String dcpJson, String dcpPublicKeyPem, int attemptNumber) {
        BenchmarkVerifier result = new BenchmarkVerifier();
        result.setOperation("verifyDCP");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("DCP");
        result.setTokenSizeBytes(dcpJson.getBytes().length);

        long startTime = System.nanoTime();
        long parseStartTime, parseEndTime, verificationStartTime, verificationEndTime;

        try {
            parseStartTime = System.nanoTime();
            PemUtils.parsePemString(dcpPublicKeyPem);
            parseEndTime = System.nanoTime();
            result.setParseTimeUs((parseEndTime - parseStartTime) / 1_000);

            verificationStartTime = System.nanoTime();
            DCPVerifier.verifyDCPWithPublicKeyPem(dcpJson, dcpPublicKeyPem);
            verificationEndTime = System.nanoTime();
            result.setVerificationTimeUs((verificationEndTime - verificationStartTime) / 1_000);

            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
            result.setAlgorithm("DCP");

        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000);
        }

        return result;
    }

    public static String runHttpsASPinConnectionBenchmark(
            String host, ASPinVerifier.CertificateClaim claim, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();
        for (int i = 1; i <= iterations; i++) {
            results.add(benchmarkHttpsASPinConnection(host, claim, i));
        }
        return calculateBenchmarkStatistics(results);
    }

    public static String runHttpsSCPConnectionBenchmark(String host, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();
        for (int i = 1; i <= iterations; i++) {
            results.add(benchmarkHttpsSCPConnection(host, i));
        }
        return calculateBenchmarkStatistics(results);
    }

    public static String runHttpsDCPConnectionBenchmark(String host, String expSPK, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();

        for (int i = 1; i <= iterations; i++) {
            BenchmarkVerifier result = benchmarkHttpsDCPConnection(host, expSPK, i);
            results.add(result);

            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        return calculateBenchmarkStatistics(results);
    }

    public static String runHttpsBypassConnectionBenchmark(String url, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();
        
        for (int i = 1; i <= iterations; i++) {
            BenchmarkVerifier result = benchmarkHttpsBypassConnection(url, i);
            results.add(result);
            
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return calculateBenchmarkStatistics(results);
    }

    public static String runGetJwtSccBenchmark(String host, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();
        
        for (int i = 1; i <= iterations; i++) {
            BenchmarkVerifier result = benchmarkHttpsGetCertClaim(host, i);
            results.add(result);
            
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return calculateBenchmarkStatistics(results);
    }

    public static String runGetJwtCskBenchmark(String host, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();
        
        for (int i = 1; i <= iterations; i++) {
            BenchmarkVerifier result = benchmarkGetSigningKeyJWT(host, i);
            results.add(result);
            
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return calculateBenchmarkStatistics(results);
    }

    public static String runHttpsDefaultConnectionBenchmark(String host, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();
        
        for (int i = 1; i <= iterations; i++) {
            BenchmarkVerifier result = benchmarkHttpsConnection(host, i);
            results.add(result);
            
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return calculateBenchmarkStatistics(results);
    }

    public static String runVerifyJwtSccBenchmark(String token, String jwkJson, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();
        
        for (int i = 1; i <= iterations; i++) {
            BenchmarkVerifier result = benchmarkVerifyJwtWithJwk(token, jwkJson, i);
            results.add(result);
            
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return calculateBenchmarkStatistics(results);
    }

    public static String runVerifyDCPBenchmark(String dcpJson, String dcpPublicKeyPem, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();

        for (int i = 1; i <= iterations; i++) {
            BenchmarkVerifier result = benchmarkVerifyDCP(dcpJson, dcpPublicKeyPem, i);
            results.add(result);

            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        return calculateBenchmarkStatistics(results);
    }

    public static String runVerifyJwtCskBenchmark(String token, String cert, int iterations) {
        List<BenchmarkVerifier> results = new ArrayList<>();
        
        for (int i = 1; i <= iterations; i++) {
            BenchmarkVerifier result = benchmarkVerifyJwtWithCert(token, cert, i);
            results.add(result);
            
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return calculateBenchmarkStatistics(results);
    }

    private static String calculateBenchmarkStatistics(List<BenchmarkVerifier> results) {
        if (results.isEmpty()) {
            return "No benchmark results available.";
        }
        
        List<BenchmarkVerifier> successfulResults = new ArrayList<>();
        for (BenchmarkVerifier result : results) {
            if (result.isSuccess()) {
                successfulResults.add(result);
            }
        }
        
        if (successfulResults.isEmpty()) {
            return "All benchmark iterations failed.";
        }
        
        long totalTimeSum = 0;
        long parseTimeSum = 0;
        long verificationTimeSum = 0;
        long minTotalTime = Long.MAX_VALUE;
        long maxTotalTime = 0;
        
        for (BenchmarkVerifier result : successfulResults) {
            totalTimeSum += result.getTotalTimeUs();
            parseTimeSum += result.getParseTimeUs();
            verificationTimeSum += result.getVerificationTimeUs();
            minTotalTime = Math.min(minTotalTime, result.getTotalTimeUs());
            maxTotalTime = Math.max(maxTotalTime, result.getTotalTimeUs());
        }
        
        double avgTotalTime = (double) totalTimeSum / successfulResults.size();
        double avgParseTime = (double) parseTimeSum / successfulResults.size();
        double avgVerificationTime = (double) verificationTimeSum / successfulResults.size();
        
        StringBuilder sb = new StringBuilder();
        sb.append("JWT Verification Benchmark Results\n");
        sb.append("==================================\n");
        sb.append("Total Iterations: ").append(results.size()).append("\n");
        sb.append("Successful: ").append(successfulResults.size()).append("\n");
        sb.append("Failed: ").append(results.size() - successfulResults.size()).append("\n");
        sb.append("Success Rate: ").append(String.format(Locale.US, "%.1f", (double) successfulResults.size() / results.size() * 100)).append("%\n\n");
        
        if (!successfulResults.isEmpty()) {
            sb.append("Performance Statistics:\n");
            sb.append("  Average Total Time: ").append(String.format(Locale.US, "%.1f", avgTotalTime)).append("μs\n");
            sb.append("  Average Parse Time: ").append(String.format(Locale.US, "%.1f", avgParseTime)).append("μs\n");
            sb.append("  Average Verification Time: ").append(String.format(Locale.US, "%.1f", avgVerificationTime)).append("μs\n");
            sb.append("  Min Total Time: ").append(minTotalTime).append("μs\n");
            sb.append("  Max Total Time: ").append(maxTotalTime).append("μs\n");
        }
        
        return sb.toString();
    }

    // =========================================================================
    // Direct verification timing methods for table:avgveriftime benchmark (excludes download delay)
    // =========================================================================

    public static double benchmarkTkMs(String tkJwt, java.security.PublicKey appPublicKey, int iterations) throws Exception {
        for (int i = 0; i < 10; i++) {
            JwtVerifier.verifyJwt(tkJwt, appPublicKey);
        }
        long startNs = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            JwtVerifier.verifyJwt(tkJwt, appPublicKey);
        }
        long totalNs = System.nanoTime() - startNs;
        return (totalNs / 1_000_000.0) / iterations;
    }

    public static double benchmarkTcMs(String tcJwt, String csJwkJson, int iterations) throws Exception {
        java.security.PublicKey csPublicKey = JwtVerifier.parseKeyFromJwkOrPem(csJwkJson);
        for (int i = 0; i < 10; i++) {
            JwtVerifier.verifyJwt(tcJwt, csPublicKey);
        }
        long startNs = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            JwtVerifier.verifyJwt(tcJwt, csPublicKey);
        }
        long totalNs = System.nanoTime() - startNs;
        return (totalNs / 1_000_000.0) / iterations;
    }

    public static double benchmarkDcpMs(String dcpJson, String dcpPublicKeyPem, int iterations) throws Exception {
        for (int i = 0; i < 10; i++) {
            DCPVerifier.verifyDCPWithPublicKeyPem(dcpJson, dcpPublicKeyPem);
        }
        long startNs = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            DCPVerifier.verifyDCPWithPublicKeyPem(dcpJson, dcpPublicKeyPem);
        }
        long totalNs = System.nanoTime() - startNs;
        return (totalNs / 1_000_000.0) / iterations;
    }

    public static String generateAvgVerifTimeReport(Map<String, double[]> results, int iterations) {
        StringBuilder sb = new StringBuilder();
        sb.append("=========================================================\n");
        sb.append(" Table 1: Average Verification Time (table:avgveriftime)\n");
        sb.append(" Tested inside App context | Download excluded | N = ").append(iterations).append("\n");
        sb.append("=========================================================\n\n");

        sb.append(String.format(Locale.US, "%-20s %-10s %-10s %-15s\n", "Algorithm", "Tk (ms)", "Tc (ms)", "DCP Pin (ms)"));
        sb.append("---------------------------------------------------------\n");

        for (Map.Entry<String, double[]> entry : results.entrySet()) {
            String algLabel = entry.getKey();
            double[] times = entry.getValue();
            sb.append(String.format(Locale.US, "%-20s %-10.2f %-10.2f %-15.2f\n",
                    algLabel, times[0], times[1], times[2]));
        }

        sb.append("---------------------------------------------------------\n\n");
        sb.append("LaTeX Table Output:\n");
        sb.append("---------------------------------------------------------\n");
        sb.append("\\begin{table}[htbp]\n");
        sb.append("  \t\\caption{Average Verification Time (Milliseconds)}\n");
        sb.append("\t\\label {table:avgveriftime}\n");
        sb.append("\t\\centering\n");
        sb.append("\t\\scalebox{1}{\n");
        sb.append("\t\t\\begin{tabular}{  l r r r }\n");
        sb.append("\t\t\t\\hline\n");
        sb.append("\t\t\t\\textbf{Algorithm}   & \\multicolumn{2}{c}{\\textbf{ASPin}}  & \\textbf{DCP}                  \\\\\n");
        sb.append("\t\t\t~ &  $T_k$ &  $T_c$ & CertificatePin \\\\\n");
        sb.append("\t\t\t\\hline\n");

        for (Map.Entry<String, double[]> entry : results.entrySet()) {
            String algLabel = entry.getKey();
            double[] times = entry.getValue();
            sb.append(String.format(Locale.US, "\t\t    %-18s & %.2f  & %.2f & %.2f  \\\\\n",
                    algLabel, times[0], times[1], times[2]));
        }

        sb.append("\t\t\t\\hline\n");
        sb.append("\t\t\\end{tabular}\n");
        sb.append("\t\t}\n");
        sb.append("\\end{table}\n");

        return sb.toString();
    }
}
