package com.abbypan.appservercert;

import java.util.Date;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;

/**
 * Represents the results of a benchmark test for JWT verification operations
 */
public class JwtBenchmark {
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

    public JwtBenchmark() {
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
        sb.append("Token Size: ").append(String.format("%.2f", getTokenSizeKB())).append(" KB\n");
        
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

    /**
     * Benchmark HTTPS our connection creation
     */
    public static JwtBenchmark benchmarkHttpsOurConnection(String host, String expIssuer, int attemptNumber) {
        JwtBenchmark result = new JwtBenchmark();
        result.setOperation("createHttpsOurConnection");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS-Our");
        result.setTokenSizeBytes((host + expIssuer).getBytes().length);
        
        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;
        
        try {
            // Measure our connection creation time
            connectionStartTime = System.nanoTime();

            HttpsURLConnection con = HttpsRequestHelper.create_main_conn(new String[] { host, "our", expIssuer});
            HttpsRequestHelper.get_content(con);

            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Set verification time to 0 for connection benchmark
            result.setVerificationTimeUs(0);
            
            // Set success
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
            result.setAlgorithm("HTTPS-Our");
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
        }
        
        return result;
    }

    /**
     * Benchmark HTTPS bypass connection creation
     */
    public static JwtBenchmark benchmarkHttpsBypassConnection(String host, int attemptNumber) {
        JwtBenchmark result = new JwtBenchmark();
        result.setOperation("createHttpsBypassConnection");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS-Bypass");
        result.setTokenSizeBytes(host.getBytes().length);
        
        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;
        
        try {
            // Measure bypass connection creation time
            connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsRequestHelper.create_main_conn(new    String [] {host, "bypass"});
            HttpsRequestHelper.get_content(con);
            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Set verification time to 0 for connection benchmark
            result.setVerificationTimeUs(0);
            
            // Set success
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
            result.setAlgorithm("HTTPS-Bypass");
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
        }
        
        return result;
    }

    /**
     * Benchmark HTTPS connection creation
     */
    public static JwtBenchmark benchmarkHttpsConnection(String host, int attemptNumber) {
        JwtBenchmark result = new JwtBenchmark();
        result.setOperation("createHttpsConnection");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS");
        result.setTokenSizeBytes(host.getBytes().length);
        
        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;
        
        try {
            // Measure connection creation time
            connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsRequestHelper.create_main_conn(new    String [] { host, "default"});
            HttpsRequestHelper.get_content(con);
            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Set verification time to 0 for connection benchmark
            result.setVerificationTimeUs(0);
            
            // Set success
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
            result.setAlgorithm("HTTPS");
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
        }
        
        return result;
    }

    /**
     * Benchmark HTTPS connection creation for serverCertClaim.jwt
     */
    public static JwtBenchmark benchmarkHttpsGetCertClaim(String host, int attemptNumber) {
        JwtBenchmark result = new JwtBenchmark();
        result.setOperation("getCertClaim");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS");
        result.setTokenSizeBytes(host.getBytes().length);
        
        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;
        
        try {
            // Measure connection creation time
            connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsRequestHelper.create_conn("https://" + host + "/.well-known/serverCertClaim.jwt");
            String info = HttpsRequestHelper.get_content(con);
            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Set verification time to 0 for connection benchmark
            result.setVerificationTimeUs(0);
            
            // Set success
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
            result.setAlgorithm("HTTPS");
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
        }
        
        return result;
    }

    /**
     * Benchmark HTTPS connection creation for serverCertClaimSigningKey.jwt
     */
    public static JwtBenchmark benchmarkGetSigningKeyJWT(String host, int attemptNumber) {
        JwtBenchmark result = new JwtBenchmark();
        result.setOperation("createConn");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType("HTTPS");
        result.setTokenSizeBytes(host.getBytes().length);
        
        long startTime = System.nanoTime();
        long connectionStartTime, connectionEndTime;
        
        try {
            // Measure connection creation time
            connectionStartTime = System.nanoTime();
            HttpsURLConnection con = HttpsRequestHelper.create_conn("https://" + host + "/.well-known/serverCertClaimSigningKey.jwt");
            String info = HttpsRequestHelper.get_content(con);

            connectionEndTime = System.nanoTime();
            result.setParseTimeUs((connectionEndTime - connectionStartTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Set verification time to 0 for connection benchmark
            result.setVerificationTimeUs(0);
            
            // Set success
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
            result.setAlgorithm("HTTPS");
            
        } catch (Exception e) {
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
        }
        
        return result;
    }

    /**
     * Benchmark JWT verification with JWK
     */
    public static JwtBenchmark benchmarkVerifyJwtWithJwk(String token, String jwkJson, int attemptNumber) {
        JwtBenchmark result = new JwtBenchmark();
        result.setOperation("verifyJwtWithJwk");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType(token.trim().startsWith("{") ? "JSON" : "Compact");
        result.setTokenSizeBytes(token.getBytes().length);
        
        long startTime = System.nanoTime();
        long parseStartTime, parseEndTime, verificationStartTime, verificationEndTime;
        
        try {
            // Measure parsing time (JWK conversion)
            parseStartTime = System.nanoTime();
            // JWK parsing is part of the parsing phase
            JwkToPublicKeyConverter.convertJwkToPublicKey(jwkJson);
            parseEndTime = System.nanoTime();
            result.setParseTimeUs((parseEndTime - parseStartTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Measure verification time
            verificationStartTime = System.nanoTime();
            String payload = JwtVerifier.verifyJwtWithJwk(token, jwkJson);
            verificationEndTime = System.nanoTime();
            result.setVerificationTimeUs((verificationEndTime - verificationStartTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Set success
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Try to extract algorithm from token (simplified)
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
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
        }
        
        return result;
    }

    /**
     * Benchmark JWT verification with certificate
     */
    public static JwtBenchmark benchmarkVerifyJwtWithCert(String token, String cert, int attemptNumber) {
        JwtBenchmark result = new JwtBenchmark();
        result.setOperation("verifyJwtWithCert");
        result.setAttemptNumber(attemptNumber);
        result.setTokenType(token.trim().startsWith("{") ? "JSON" : "Compact");
        result.setTokenSizeBytes(token.getBytes().length);
        
        long startTime = System.nanoTime();
        long parseStartTime, parseEndTime, verificationStartTime, verificationEndTime;
        
        try {
            // Measure parsing time
            parseStartTime = System.nanoTime();
            // Parse certificate (this is part of the parsing phase)
            PemUtils.parseX509Certificate(cert);
            parseEndTime = System.nanoTime();
            result.setParseTimeUs((parseEndTime - parseStartTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Measure verification time
            verificationStartTime = System.nanoTime();
            String payload = JwtVerifier.verifyJwtWithCert(token, cert);
            verificationEndTime = System.nanoTime();
            result.setVerificationTimeUs((verificationEndTime - verificationStartTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Set success
            result.setSuccess(true);
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
            
            // Try to extract algorithm from token (simplified)
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
            result.setTotalTimeUs((System.nanoTime() - startTime) / 1_000); // Convert nanoseconds to microseconds
        }
        
        return result;
    }

    /**
     * Run multiple HTTPS our connection benchmark iterations and return statistics
     */
    public static String runHttpsOurConnectionBenchmark(String host, String expIssuer, int iterations) {
        List<JwtBenchmark> results = new ArrayList<>();
        
        // Run benchmark iterations
        for (int i = 1; i <= iterations; i++) {
            JwtBenchmark result = benchmarkHttpsOurConnection(host, expIssuer, i);
            results.add(result);
            
            // Small delay between iterations
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        // Calculate statistics
        return calculateBenchmarkStatistics(results);
    }

    /**
     * Run multiple HTTPS bypass connection benchmark iterations and return statistics
     */
    public static String runHttpsBypassConnectionBenchmark(String url, int iterations) {
        List<JwtBenchmark> results = new ArrayList<>();
        
        // Run benchmark iterations
        for (int i = 1; i <= iterations; i++) {
            JwtBenchmark result = benchmarkHttpsBypassConnection(url, i);
            results.add(result);
            
            // Small delay between iterations
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        // Calculate statistics
        return calculateBenchmarkStatistics(results);
    }

    /**
     * Run multiple Get Cert Claim JWT benchmark iterations and return statistics
     */
    public static String runGetCertClaimJWTBenchmark(String host, int iterations) {
        List<JwtBenchmark> results = new ArrayList<>();
        
        // Run benchmark iterations
        for (int i = 1; i <= iterations; i++) {
            JwtBenchmark result = benchmarkHttpsGetCertClaim(host, i);
            results.add(result);
            
            // Small delay between iterations
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        // Calculate statistics
        return calculateBenchmarkStatistics(results);
    }

    /**
     * Run multiple Get Signing Key JWT benchmark iterations and return statistics
     */
    public static String runGetSigningKeyJWTBenchmark(String host, int iterations) {
        List<JwtBenchmark> results = new ArrayList<>();
        
        // Run benchmark iterations
        for (int i = 1; i <= iterations; i++) {
            JwtBenchmark result = benchmarkGetSigningKeyJWT(host, i);
            results.add(result);
            
            // Small delay between iterations
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        // Calculate statistics
        return calculateBenchmarkStatistics(results);
    }

    /**
     * Run multiple HTTPS connection benchmark iterations and return statistics
     */
    public static String runHttpsDefaultConnectionBenchmark(String host, int iterations) {
        List<JwtBenchmark> results = new ArrayList<>();
        
        // Run benchmark iterations
        for (int i = 1; i <= iterations; i++) {
            JwtBenchmark result = benchmarkHttpsConnection(host, i);
            results.add(result);
            
            // Small delay between iterations
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        // Calculate statistics
        return calculateBenchmarkStatistics(results);
    }

    /**
     * Run multiple JWK benchmark iterations and return statistics
     */
    public static String runVerifyJWTCertClaimBenchmark(String token, String jwkJson, int iterations) {
        List<JwtBenchmark> results = new ArrayList<>();
        
        // Run benchmark iterations
        for (int i = 1; i <= iterations; i++) {
            JwtBenchmark result = benchmarkVerifyJwtWithJwk(token, jwkJson, i);
            results.add(result);
            
            // Small delay between iterations
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        // Calculate statistics
        return calculateBenchmarkStatistics(results);
    }

    /**
     * Run multiple benchmark iterations and return statistics
     */
    public static String runVerifyJwtSigningKeyBenchmark(String token, String cert, int iterations) {
        List<JwtBenchmark> results = new ArrayList<>();
        
        // Run benchmark iterations
        for (int i = 1; i <= iterations; i++) {
            JwtBenchmark result = benchmarkVerifyJwtWithCert(token, cert, i);
            results.add(result);
            
            // Small delay between iterations
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        // Calculate statistics
        return calculateBenchmarkStatistics(results);
    }

    /**
     * Calculate benchmark statistics from multiple results
     */
    private static String calculateBenchmarkStatistics(List<JwtBenchmark> results) {
        if (results.isEmpty()) {
            return "No benchmark results available.";
        }
        
        // Filter successful results
        List<JwtBenchmark> successfulResults = new ArrayList<>();
        for (JwtBenchmark result : results) {
            if (result.isSuccess()) {
                successfulResults.add(result);
            }
        }
        
        if (successfulResults.isEmpty()) {
            return "All benchmark iterations failed.";
        }
        
        // Calculate statistics
        long totalTimeSum = 0;
        long parseTimeSum = 0;
        long verificationTimeSum = 0;
        long minTotalTime = Long.MAX_VALUE;
        long maxTotalTime = 0;
        
        for (JwtBenchmark result : successfulResults) {
            totalTimeSum += result.getTotalTimeUs();
            parseTimeSum += result.getParseTimeUs();
            verificationTimeSum += result.getVerificationTimeUs();
            minTotalTime = Math.min(minTotalTime, result.getTotalTimeUs());
            maxTotalTime = Math.max(maxTotalTime, result.getTotalTimeUs());
        }
        
        double avgTotalTime = (double) totalTimeSum / successfulResults.size();
        double avgParseTime = (double) parseTimeSum / successfulResults.size();
        double avgVerificationTime = (double) verificationTimeSum / successfulResults.size();
        
        // Build statistics report
        StringBuilder sb = new StringBuilder();
        sb.append("JWT Verification Benchmark Results\n");
        sb.append("==================================\n");
        sb.append("Total Iterations: ").append(results.size()).append("\n");
        sb.append("Successful: ").append(successfulResults.size()).append("\n");
        sb.append("Failed: ").append(results.size() - successfulResults.size()).append("\n");
        sb.append("Success Rate: ").append(String.format("%.1f", (double) successfulResults.size() / results.size() * 100)).append("%\n\n");
        
        if (!successfulResults.isEmpty()) {
            sb.append("Performance Statistics:\n");
            sb.append("  Average Total Time: ").append(String.format("%.1f", avgTotalTime)).append("μs\n");
            sb.append("  Average Parse Time: ").append(String.format("%.1f", avgParseTime)).append("μs\n");
            sb.append("  Average Verification Time: ").append(String.format("%.1f", avgVerificationTime)).append("μs\n");
            sb.append("  Min Total Time: ").append(minTotalTime).append("μs\n");
            sb.append("  Max Total Time: ").append(maxTotalTime).append("μs\n");
            
            // Show individual results
            sb.append("\nIndividual Results:\n");
            for (int i = 0; i < Math.min(successfulResults.size(), 5); i++) {
                JwtBenchmark result = successfulResults.get(i);
                sb.append("  Attempt ").append(result.getAttemptNumber()).append(": ")
                  .append(result.getTotalTimeUs()).append("μs")
                  .append(" (Parse: ").append(result.getParseTimeUs()).append("μs, ")
                  .append("Verify: ").append(result.getVerificationTimeUs()).append("μs)\n");
            }
            
            if (successfulResults.size() > 5) {
                sb.append("  ... and ").append(successfulResults.size() - 5).append(" more results\n");
            }
        }
        
        return sb.toString();
    }
}
