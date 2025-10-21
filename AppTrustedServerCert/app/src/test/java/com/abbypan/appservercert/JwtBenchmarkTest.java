package com.abbypan.appservercert;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for JwtBenchmark class
 */
public class JwtBenchmarkTest {

    @Test
    public void testJwtBenchmarkCreation() {
        JwtBenchmark benchmark = new JwtBenchmark();
        
        // Test default values
        assertNotNull(benchmark.getTimestamp());
        assertFalse(benchmark.isSuccess());
        assertEquals(0, benchmark.getTotalTimeMs());
        assertEquals(0, benchmark.getParseTimeMs());
        assertEquals(0, benchmark.getVerificationTimeMs());
    }

    @Test
    public void testJwtBenchmarkSettersAndGetters() {
        JwtBenchmark benchmark = new JwtBenchmark();
        
        // Test setters and getters
        benchmark.setOperation("testOperation");
        benchmark.setTotalTimeMs(1000);
        benchmark.setParseTimeMs(200);
        benchmark.setVerificationTimeMs(300);
        benchmark.setSuccess(true);
        benchmark.setErrorMessage("test error");
        benchmark.setAttemptNumber(1);
        benchmark.setTokenType("Compact");
        benchmark.setAlgorithm("ES256");
        benchmark.setTokenSizeBytes(1024);
        
        assertEquals("testOperation", benchmark.getOperation());
        assertEquals(1000, benchmark.getTotalTimeMs());
        assertEquals(200, benchmark.getParseTimeMs());
        assertEquals(300, benchmark.getVerificationTimeMs());
        assertTrue(benchmark.isSuccess());
        assertEquals("test error", benchmark.getErrorMessage());
        assertEquals(1, benchmark.getAttemptNumber());
        assertEquals("Compact", benchmark.getTokenType());
        assertEquals("ES256", benchmark.getAlgorithm());
        assertEquals(1024, benchmark.getTokenSizeBytes());
    }

    @Test
    public void testJwtBenchmarkCalculations() {
        JwtBenchmark benchmark = new JwtBenchmark();
        
        benchmark.setTotalTimeMs(1500);
        benchmark.setParseTimeMs(300);
        benchmark.setVerificationTimeMs(500);
        benchmark.setTokenSizeBytes(2048);
        
        // Test time calculations
        assertEquals(1.5, benchmark.getTotalTimeSeconds(), 0.001);
        assertEquals(0.3, benchmark.getParseTimeSeconds(), 0.001);
        assertEquals(0.5, benchmark.getVerificationTimeSeconds(), 0.001);
        
        // Test size calculations
        assertEquals(2.0, benchmark.getTokenSizeKB(), 0.001);
    }

    @Test
    public void testJwtBenchmarkSummary() {
        JwtBenchmark benchmark = new JwtBenchmark();
        
        benchmark.setOperation("verifyJwtWithCert");
        benchmark.setAttemptNumber(1);
        benchmark.setSuccess(true);
        benchmark.setTokenType("Compact");
        benchmark.setAlgorithm("ES256");
        benchmark.setTokenSizeBytes(1024);
        benchmark.setTotalTimeMs(1000);
        benchmark.setParseTimeMs(200);
        benchmark.setVerificationTimeMs(300);
        
        String summary = benchmark.getSummary();
        
        assertNotNull(summary);
        assertTrue(summary.contains("JWT Benchmark Summary"));
        assertTrue(summary.contains("verifyJwtWithCert"));
        assertTrue(summary.contains("Compact"));
        assertTrue(summary.contains("ES256"));
        assertTrue(summary.contains("1.000"));
    }

    @Test
    public void testJwtBenchmarkToString() {
        JwtBenchmark benchmark = new JwtBenchmark();
        benchmark.setOperation("test");
        
        String toString = benchmark.toString();
        String summary = benchmark.getSummary();
        
        assertEquals(summary, toString);
    }

    @Test
    public void testJwtJwkBenchmarkCreation() {
        // Test that JWK benchmark method exists and can be called
        // Note: This is a basic test - actual JWK verification would require valid JWK and JWT
        try {
            // This should not throw an exception even with invalid inputs
            JwtBenchmark result = JwtBenchmark.benchmarkVerifyJwtWithJwk("invalid.jwt.token", "invalid.jwk", 1);
            
            // Should create a benchmark result
            assertNotNull(result);
            assertEquals("verifyJwtWithJwk", result.getOperation());
            assertEquals(1, result.getAttemptNumber());
            assertFalse(result.isSuccess()); // Should fail with invalid inputs
        } catch (Exception e) {
            // If it throws an exception, that's also acceptable for invalid inputs
            assertTrue("Exception should contain error information", e.getMessage() != null);
        }
    }
}
