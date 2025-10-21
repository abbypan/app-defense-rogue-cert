package com.abbypan.appservercert;

import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Represents the results of a benchmark test for HTTPS requests
 */
public class BenchmarkResult {
    private String url;
    private long totalTimeMs;
    private long dnsLookupTimeMs;
    private long connectionTimeMs;
    private long sslHandshakeTimeMs;
    private long certificateCaptureTimeMs;
    private long responseTimeMs;
    private int responseCode;
    private long responseSizeBytes;
    private boolean success;
    private String errorMessage;
    private Date timestamp;
    private int attemptNumber;

    public BenchmarkResult() {
        this.timestamp = new Date();
        this.success = false;
    }

    // Getters
    public String getUrl() {
        return url;
    }

    public long getTotalTimeMs() {
        return totalTimeMs;
    }

    public long getDnsLookupTimeMs() {
        return dnsLookupTimeMs;
    }

    public long getConnectionTimeMs() {
        return connectionTimeMs;
    }

    public long getSslHandshakeTimeMs() {
        return sslHandshakeTimeMs;
    }

    public long getCertificateCaptureTimeMs() {
        return certificateCaptureTimeMs;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public long getResponseSizeBytes() {
        return responseSizeBytes;
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

    // Setters
    public void setUrl(String url) {
        this.url = url;
    }

    public void setTotalTimeMs(long totalTimeMs) {
        this.totalTimeMs = totalTimeMs;
    }

    public void setDnsLookupTimeMs(long dnsLookupTimeMs) {
        this.dnsLookupTimeMs = dnsLookupTimeMs;
    }

    public void setConnectionTimeMs(long connectionTimeMs) {
        this.connectionTimeMs = connectionTimeMs;
    }

    public void setSslHandshakeTimeMs(long sslHandshakeTimeMs) {
        this.sslHandshakeTimeMs = sslHandshakeTimeMs;
    }

    public void setCertificateCaptureTimeMs(long certificateCaptureTimeMs) {
        this.certificateCaptureTimeMs = certificateCaptureTimeMs;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public void setResponseSizeBytes(long responseSizeBytes) {
        this.responseSizeBytes = responseSizeBytes;
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

    /**
     * Get total time in seconds
     */
    public double getTotalTimeSeconds() {
        return totalTimeMs / 1000.0;
    }

    /**
     * Get response size in KB
     */
    public double getResponseSizeKB() {
        return responseSizeBytes / 1024.0;
    }

    /**
     * Get response size in MB
     */
    public double getResponseSizeMB() {
        return responseSizeBytes / (1024.0 * 1024.0);
    }

    /**
     * Calculate throughput in bytes per second
     */
    public double getThroughputBytesPerSecond() {
        if (totalTimeMs > 0) {
            return (responseSizeBytes * 1000.0) / totalTimeMs;
        }
        return 0.0;
    }

    /**
     * Calculate throughput in KB per second
     */
    public double getThroughputKBPerSecond() {
        return getThroughputBytesPerSecond() / 1024.0;
    }

    /**
     * Calculate throughput in MB per second
     */
    public double getThroughputMBPerSecond() {
        return getThroughputBytesPerSecond() / (1024.0 * 1024.0);
    }

    /**
     * Get a formatted summary of the benchmark result
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Benchmark Summary:\n");
        sb.append("==================\n");
        sb.append("URL: ").append(url).append("\n");
        sb.append("Attempt: ").append(attemptNumber).append("\n");
        sb.append("Timestamp: ").append(timestamp).append("\n");
        sb.append("Success: ").append(success).append("\n");
        
        if (success) {
            sb.append("Response Code: ").append(responseCode).append("\n");
            sb.append("Total Time: ").append(String.format("%.3f", getTotalTimeSeconds())).append("s\n");
            sb.append("Response Size: ").append(String.format("%.2f", getResponseSizeKB())).append(" KB\n");
            sb.append("Throughput: ").append(String.format("%.2f", getThroughputKBPerSecond())).append(" KB/s\n");
            sb.append("\nTiming Breakdown:\n");
            sb.append("  DNS Lookup: ").append(dnsLookupTimeMs).append("ms\n");
            sb.append("  Connection: ").append(connectionTimeMs).append("ms\n");
            sb.append("  SSL Handshake: ").append(sslHandshakeTimeMs).append("ms\n");
            sb.append("  Certificate Capture: ").append(certificateCaptureTimeMs).append("ms\n");
            sb.append("  Response: ").append(responseTimeMs).append("ms\n");
        } else {
            sb.append("Error: ").append(errorMessage).append("\n");
        }
        
        return sb.toString();
    }

    @Override
    public String toString() {
        return getSummary();
    }
}
