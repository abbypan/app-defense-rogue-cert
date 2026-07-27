package com.abbypan.aspin;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Simple unit tests for PemUtils X509 to PEM conversion
 */
public class PemUtilsSimpleTest {

    @Test
    public void testConvertX509ChainToPemWithNullArray() {
        try {
            PemUtils.convertX509ChainToPem(null);
            fail("Should throw exception for null array");
        } catch (IllegalArgumentException e) {
            assertTrue("Should contain appropriate error message", 
                    e.getMessage().contains("null"));
        }
    }

    @Test
    public void testConvertX509ChainToPemWithEmptyArray() {
        try {
            PemUtils.convertX509ChainToPem(new java.security.cert.X509Certificate[0]);
            fail("Should throw exception for empty array");
        } catch (IllegalArgumentException e) {
            assertTrue("Should contain appropriate error message", 
                    e.getMessage().contains("empty"));
        }
    }

    @Test
    public void testPemUtilsMethodsExist() {
        // Test that the new methods exist and can be called
        try {
            // These should not throw NoSuchMethodException
            PemUtils.class.getMethod("convertX509ToPem", java.security.cert.X509Certificate.class);
            PemUtils.class.getMethod("convertX509ToPem", java.security.cert.X509Certificate.class, int.class);
            PemUtils.class.getMethod("convertX509ChainToPem", java.security.cert.X509Certificate[].class);
        } catch (NoSuchMethodException e) {
            fail("Required methods should exist: " + e.getMessage());
        }
    }
}
