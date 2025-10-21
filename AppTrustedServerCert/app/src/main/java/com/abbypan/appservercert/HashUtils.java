package com.abbypan.appservercert;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for hash operations
 */
public class HashUtils {
    
    /**
     * Computes a hash digest of the input data using the specified algorithm
     * 
     * @param hashName the hash algorithm name (e.g., "SHA-256", "MD5", "SHA-1")
     * @param s the input data to hash
     * @return the hash digest as a byte array
     * @throws NoSuchAlgorithmException if the specified algorithm is not available
     */
    public static byte[] digest(String hashName, byte[] s) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(hashName);
        byte[] hash = digest.digest(s);
        return hash;
    }
}
