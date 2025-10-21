package com.abbypan.appservercert;

import java.util.Date;

/**
 * Represents the results of a TLS connection benchmark test
 */
public class TlsBenchmarkResult {
    private String hostname;
    private int port;
    private String protocol;
    private String cipherSuite;
    private String certificateAlgorithm;
    private int certificateKeySize;
    
    // TLS Connection Timing
    private long totalConnectionTimeMs;
    private long tcpConnectionTimeMs;
    private long tlsHandshakeTimeMs;
    private long certificateValidationTimeMs;
    private long keyExchangeTimeMs;
    private long cipherNegotiationTimeMs;
    
    // Certificate Information
    private String certificateIssuer;
    private String certificateSubject;
    private Date certificateValidFrom;
    private Date certificateValidUntil;
    private boolean certificateValid;
    
    // Connection Status
    private boolean connectionSuccessful;
    private String errorMessage;
    private Date timestamp;
    private int attemptNumber;

    public TlsBenchmarkResult() {
        this.timestamp = new Date();
        this.connectionSuccessful = false;
        this.port = 443; // Default HTTPS port
    }

    // Getters
    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getCipherSuite() {
        return cipherSuite;
    }

    public String getCertificateAlgorithm() {
        return certificateAlgorithm;
    }

    public int getCertificateKeySize() {
        return certificateKeySize;
    }

    public long getTotalConnectionTimeMs() {
        return totalConnectionTimeMs;
    }

    public long getTcpConnectionTimeMs() {
        return tcpConnectionTimeMs;
    }

    public long getTlsHandshakeTimeMs() {
        return tlsHandshakeTimeMs;
    }

    public long getCertificateValidationTimeMs() {
        return certificateValidationTimeMs;
    }

    public long getKeyExchangeTimeMs() {
        return keyExchangeTimeMs;
    }

    public long getCipherNegotiationTimeMs() {
        return cipherNegotiationTimeMs;
    }

    public String getCertificateIssuer() {
        return certificateIssuer;
    }

    public String getCertificateSubject() {
        return certificateSubject;
    }

    public Date getCertificateValidFrom() {
        return certificateValidFrom;
    }

    public Date getCertificateValidUntil() {
        return certificateValidUntil;
    }

    public boolean isCertificateValid() {
        return certificateValid;
    }

    public boolean isConnectionSuccessful() {
        return connectionSuccessful;
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
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public void setCipherSuite(String cipherSuite) {
        this.cipherSuite = cipherSuite;
    }

    public void setCertificateAlgorithm(String certificateAlgorithm) {
        this.certificateAlgorithm = certificateAlgorithm;
    }

    public void setCertificateKeySize(int certificateKeySize) {
        this.certificateKeySize = certificateKeySize;
    }

    public void setTotalConnectionTimeMs(long totalConnectionTimeMs) {
        this.totalConnectionTimeMs = totalConnectionTimeMs;
    }

    public void setTcpConnectionTimeMs(long tcpConnectionTimeMs) {
        this.tcpConnectionTimeMs = tcpConnectionTimeMs;
    }

    public void setTlsHandshakeTimeMs(long tlsHandshakeTimeMs) {
        this.tlsHandshakeTimeMs = tlsHandshakeTimeMs;
    }

    public void setCertificateValidationTimeMs(long certificateValidationTimeMs) {
        this.certificateValidationTimeMs = certificateValidationTimeMs;
    }

    public void setKeyExchangeTimeMs(long keyExchangeTimeMs) {
        this.keyExchangeTimeMs = keyExchangeTimeMs;
    }

    public void setCipherNegotiationTimeMs(long cipherNegotiationTimeMs) {
        this.cipherNegotiationTimeMs = cipherNegotiationTimeMs;
    }

    public void setCertificateIssuer(String certificateIssuer) {
        this.certificateIssuer = certificateIssuer;
    }

    public void setCertificateSubject(String certificateSubject) {
        this.certificateSubject = certificateSubject;
    }

    public void setCertificateValidFrom(Date certificateValidFrom) {
        this.certificateValidFrom = certificateValidFrom;
    }

    public void setCertificateValidUntil(Date certificateValidUntil) {
        this.certificateValidUntil = certificateValidUntil;
    }

    public void setCertificateValid(boolean certificateValid) {
        this.certificateValid = certificateValid;
    }

    public void setConnectionSuccessful(boolean connectionSuccessful) {
        this.connectionSuccessful = connectionSuccessful;
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
     * Get total connection time in seconds
     */
    public double getTotalConnectionTimeSeconds() {
        return totalConnectionTimeMs / 1000.0;
    }

    /**
     * Get TLS handshake time in seconds
     */
    public double getTlsHandshakeTimeSeconds() {
        return tlsHandshakeTimeMs / 1000.0;
    }

    /**
     * Calculate TLS handshake percentage of total connection time
     */
    public double getTlsHandshakePercentage() {
        if (totalConnectionTimeMs > 0) {
            return (tlsHandshakeTimeMs * 100.0) / totalConnectionTimeMs;
        }
        return 0.0;
    }

    /**
     * Calculate certificate validation percentage of TLS handshake time
     */
    public double getCertificateValidationPercentage() {
        if (tlsHandshakeTimeMs > 0) {
            return (certificateValidationTimeMs * 100.0) / tlsHandshakeTimeMs;
        }
        return 0.0;
    }

    /**
     * Get a formatted summary of the TLS benchmark result
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("TLS Connection Benchmark Summary:\n");
        sb.append("==================================\n");
        sb.append("Hostname: ").append(hostname).append(":").append(port).append("\n");
        sb.append("Attempt: ").append(attemptNumber).append("\n");
        sb.append("Timestamp: ").append(timestamp).append("\n");
        sb.append("Connection Successful: ").append(connectionSuccessful).append("\n");
        
        if (connectionSuccessful) {
            sb.append("\nTLS Connection Details:\n");
            sb.append("Protocol: ").append(protocol != null ? protocol : "Unknown").append("\n");
            sb.append("Cipher Suite: ").append(cipherSuite != null ? cipherSuite : "Unknown").append("\n");
            sb.append("Certificate Algorithm: ").append(certificateAlgorithm != null ? certificateAlgorithm : "Unknown").append("\n");
            sb.append("Certificate Key Size: ").append(certificateKeySize > 0 ? certificateKeySize + " bits" : "Unknown").append("\n");
            
            sb.append("\nTiming Breakdown:\n");
            sb.append("Total Connection Time: ").append(String.format("%.3f", getTotalConnectionTimeSeconds())).append("s\n");
            sb.append("TCP Connection Time: ").append(tcpConnectionTimeMs).append("ms\n");
            sb.append("TLS Handshake Time: ").append(String.format("%.3f", getTlsHandshakeTimeSeconds())).append("s (")
              .append(String.format("%.1f", getTlsHandshakePercentage())).append("% of total)\n");
            sb.append("Certificate Validation: ").append(certificateValidationTimeMs).append("ms (")
              .append(String.format("%.1f", getCertificateValidationPercentage())).append("% of handshake)\n");
            sb.append("Key Exchange: ").append(keyExchangeTimeMs).append("ms\n");
            sb.append("Cipher Negotiation: ").append(cipherNegotiationTimeMs).append("ms\n");
            
            sb.append("\nCertificate Information:\n");
            sb.append("Subject: ").append(certificateSubject != null ? certificateSubject : "Unknown").append("\n");
            sb.append("Issuer: ").append(certificateIssuer != null ? certificateIssuer : "Unknown").append("\n");
            sb.append("Valid From: ").append(certificateValidFrom != null ? certificateValidFrom : "Unknown").append("\n");
            sb.append("Valid Until: ").append(certificateValidUntil != null ? certificateValidUntil : "Unknown").append("\n");
            sb.append("Currently Valid: ").append(certificateValid).append("\n");
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
