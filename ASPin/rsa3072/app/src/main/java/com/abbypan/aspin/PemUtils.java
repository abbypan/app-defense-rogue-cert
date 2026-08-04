package com.abbypan.aspin;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for PEM format operations
 * Supports parsing and converting keys and certificates
 */
public class PemUtils {    public static PublicKey parsePublicKey(String publicKeyPem) throws Exception {
        if (publicKeyPem == null || publicKeyPem.trim().isEmpty()) {
            throw new IllegalArgumentException("Public key PEM cannot be null or empty");
        }
        String upper = publicKeyPem.toUpperCase(java.util.Locale.ROOT);
        if (upper.contains("RSA")) {
            return parseRSAPublicKey(publicKeyPem);
        }
        try {
            return parseECDSAPublicKey(publicKeyPem);
        } catch (Throwable t) {
            return parseRSAPublicKey(publicKeyPem);
        }
    }

    
    private static final String TAG = "PemUtils";
    
    /**
     * Converts a PublicKey to PEM format string
     * 
     * @param publicKey the PublicKey to convert
     * @return PEM formatted string
     */
    public static String convertPublicKeyToPem(PublicKey publicKey) {
        try {
            // Get the encoded key bytes
            byte[] keyBytes = publicKey.getEncoded();
            
            // Encode to base64
            String base64Key = java.util.Base64.getEncoder().encodeToString(keyBytes);
            
            // Format as PEM with proper line breaks (64 characters per line)
            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.append("-----BEGIN PUBLIC KEY-----\n");
            
            // Add line breaks every 64 characters
            for (int i = 0; i < base64Key.length(); i += 64) {
                int endIndex = Math.min(i + 64, base64Key.length());
                pemBuilder.append(base64Key.substring(i, endIndex));
                if (endIndex < base64Key.length()) {
                    pemBuilder.append("\n");
                }
            }
            
            pemBuilder.append("\n-----END PUBLIC KEY-----");
            
            return pemBuilder.toString();
            
        } catch (Exception e) {
            return "Error converting public key to PEM format: " + e.getMessage();
        }
    }
    
    /**
     * Parse ECDSA public key from PEM format
     * 
     * @param publicKeyPem The ECDSA public key in PEM format
     * @return PublicKey object
     * @throws Exception if parsing fails
     */
    public static PublicKey parseECDSAPublicKey(String publicKeyPem) throws Exception {
        String publicKeyContent = publicKeyPem
                .replace("\r", "")
                .replace("\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN EC PUBLIC KEY-----", "")
                .replace("-----END EC PUBLIC KEY-----", "")
                .trim();
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(spec);
    }
    
    /**
     * Parse ECDSA private key from PEM format
     * 
     * @param privateKeyPem The ECDSA private key in PEM format
     * @return PrivateKey object
     * @throws Exception if parsing fails
     */
    public static PrivateKey parseECDSAPrivateKey(String privateKeyPem) throws Exception {
        try {
            // Remove PEM headers and footers
            String privateKeyContent = privateKeyPem
                    .replaceAll("\\n", "")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN EC PRIVATE KEY-----", "")
                    .replace("-----END EC PRIVATE KEY-----", "")
                    .trim();
            
            // Decode base64
            byte[] keyBytes = Base64.getDecoder().decode(privateKeyContent);
            
            // Create PKCS8EncodedKeySpec
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePrivate(spec);
            
        } catch (Exception e) {
            System.err.println(TAG + ": Error parsing ECDSA private key: " + e.getMessage());
            throw new Exception("Failed to parse ECDSA private key: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parse RSA public key from PEM format
     * 
     * @param publicKeyPem The RSA public key in PEM format
     * @return PublicKey object
     * @throws Exception if parsing fails
     */
    public static PublicKey parseRSAPublicKey(String publicKeyPem) throws Exception {
        String publicKeyContent = publicKeyPem
                .replace("\r", "")
                .replace("\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .trim();
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
    
    /**
     * Parse RSA private key from PEM format
     * 
     * @param privateKeyPem The RSA private key in PEM format
     * @return PrivateKey object
     * @throws Exception if parsing fails
     */
    public static PrivateKey parseRSAPrivateKey(String privateKeyPem) throws Exception {
        try {
            // Remove PEM headers and footers
            String privateKeyContent = privateKeyPem
                    .replaceAll("\\n", "")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .trim();
            
            // Decode base64
            byte[] keyBytes = Base64.getDecoder().decode(privateKeyContent);
            
            // Create PKCS8EncodedKeySpec
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
            
        } catch (Exception e) {
            System.err.println(TAG + ": Error parsing RSA private key: " + e.getMessage());
            throw new Exception("Failed to parse RSA private key: " + e.getMessage(), e);
        }
    }
    
    /**
     * Parse X509 certificate from PEM format
     * 
     * @param certificatePem The X509 certificate in PEM format
     * @return X509Certificate object
     * @throws Exception if parsing fails
     */
    public static X509Certificate parseX509Certificate(String certificatePem) throws Exception {
        try {
            // Remove PEM headers and footers
            String certificateContent = certificatePem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\n", "")
                    .trim();


            // Decode base64
            byte[] certificateBytes = Base64.getDecoder().decode(certificateContent);
            
            // Create certificate factory
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream certStream = new ByteArrayInputStream(certificateBytes);
            
            return (X509Certificate) certFactory.generateCertificate(certStream);
            
        } catch (Exception e) {
            System.err.println(TAG + ": Error parsing X509 certificate: " + e.getMessage());
            throw new Exception("Failed to parse X509 certificate: " + e.getMessage(), e);
        }
    }
    
    /**
     * Try to parse a PEM string as any supported key or certificate type
     * 
     * @param pemString The PEM string to parse
     * @return Object containing the parsed key or certificate
     * @throws Exception if parsing fails for all supported types
     */
    public static Object parsePemString(String pemString) throws Exception {
        if (pemString == null || pemString.trim().isEmpty()) {
            throw new Exception("PEM string is null or empty");
        }
        
        // Try to parse as X509 certificate first
        try {
            return parseX509Certificate(pemString);
        } catch (Exception e) {
            // Not a certificate, continue
        }
        
        // Try to parse as ECDSA public key
        try {
            return parseECDSAPublicKey(pemString);
        } catch (Exception e) {
            // Not an ECDSA public key, continue
        }
        
        // Try to parse as RSA public key
        try {
            return parseRSAPublicKey(pemString);
        } catch (Exception e) {
            // Not an RSA public key, continue
        }
        
        // Try to parse as ECDSA private key
        try {
            return parseECDSAPrivateKey(pemString);
        } catch (Exception e) {
            // Not an ECDSA private key, continue
        }
        
        // Try to parse as RSA private key
        try {
            return parseRSAPrivateKey(pemString);
        } catch (Exception e) {
            // Not an RSA private key, continue
        }
        
        throw new Exception("Unable to parse PEM string as any supported key or certificate type");
    }
    
    /**
     * Detect the type of PEM string
     * 
     * @param pemString The PEM string to analyze
     * @return String describing the type ("X509_CERTIFICATE", "ECDSA_PUBLIC_KEY", "RSA_PUBLIC_KEY", "ECDSA_PRIVATE_KEY", "RSA_PRIVATE_KEY", "UNKNOWN")
     */
    public static String detectPemType(String pemString) {
        if (pemString == null || pemString.trim().isEmpty()) {
            return "UNKNOWN";
        }
        
        String upperPem = pemString.toUpperCase();
        
        if (upperPem.contains("BEGIN CERTIFICATE")) {
            return "X509_CERTIFICATE";
        } else if (upperPem.contains("BEGIN PUBLIC KEY")) {
            if (upperPem.contains("BEGIN EC PUBLIC KEY") || upperPem.contains("BEGIN ECDSA PUBLIC KEY")) {
                return "ECDSA_PUBLIC_KEY";
            } else if (upperPem.contains("BEGIN RSA PUBLIC KEY")) {
                return "RSA_PUBLIC_KEY";
            } else {
                // Generic public key - try to determine by parsing
                try {
                    parseECDSAPublicKey(pemString);
                    return "ECDSA_PUBLIC_KEY";
                } catch (Exception e) {
                    try {
                        parseRSAPublicKey(pemString);
                        return "RSA_PUBLIC_KEY";
                    } catch (Exception e2) {
                        return "UNKNOWN_PUBLIC_KEY";
                    }
                }
            }
        } else if (upperPem.contains("BEGIN PRIVATE KEY")) {
            if (upperPem.contains("BEGIN EC PRIVATE KEY") || upperPem.contains("BEGIN ECDSA PRIVATE KEY")) {
                return "ECDSA_PRIVATE_KEY";
            } else if (upperPem.contains("BEGIN RSA PRIVATE KEY")) {
                return "RSA_PRIVATE_KEY";
            } else {
                // Generic private key - try to determine by parsing
                try {
                    parseECDSAPrivateKey(pemString);
                    return "ECDSA_PRIVATE_KEY";
                } catch (Exception e) {
                    try {
                        parseRSAPrivateKey(pemString);
                        return "RSA_PRIVATE_KEY";
                    } catch (Exception e2) {
                        return "UNKNOWN_PRIVATE_KEY";
                    }
                }
            }
        }
        
        return "UNKNOWN";
    }
    
    /**
     * Converts an X509Certificate to PEM format string
     * 
     * @param certificate the X509Certificate to convert
     * @return PEM formatted string
     */
    public static String convertX509ToPem(X509Certificate certificate) {
        try {
            // Get the encoded certificate bytes
            byte[] certBytes = certificate.getEncoded();
            
            // Encode to base64
            String base64Cert = Base64.getEncoder().encodeToString(certBytes);
            
            // Format as PEM with proper line breaks (64 characters per line)
            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.append("-----BEGIN CERTIFICATE-----\n");
            
            // Add line breaks every 64 characters
            for (int i = 0; i < base64Cert.length(); i += 64) {
                int endIndex = Math.min(i + 64, base64Cert.length());
                pemBuilder.append(base64Cert.substring(i, endIndex));
                if (endIndex < base64Cert.length()) {
                    pemBuilder.append("\n");
                }
            }
            
            pemBuilder.append("\n-----END CERTIFICATE-----\n");
            
            return pemBuilder.toString();
            
        } catch (Exception e) {
            System.err.println(TAG + ": Error converting X509 certificate to PEM: " + e.getMessage());
            throw new RuntimeException("Failed to convert X509 certificate to PEM: " + e.getMessage(), e);
        }
    }
    
    /**
     * Converts an X509Certificate to PEM format string with custom line length
     * 
     * @param certificate the X509Certificate to convert
     * @param lineLength the maximum number of characters per line (default is 64)
     * @return PEM formatted string
     */
    public static String convertX509ToPem(X509Certificate certificate, int lineLength) {
        try {
            // Get the encoded certificate bytes
            byte[] certBytes = certificate.getEncoded();
            
            // Encode to base64
            String base64Cert = Base64.getEncoder().encodeToString(certBytes);
            
            // Format as PEM with custom line breaks
            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.append("-----BEGIN CERTIFICATE-----\n");
            
            // Add line breaks every lineLength characters
            for (int i = 0; i < base64Cert.length(); i += lineLength) {
                int endIndex = Math.min(i + lineLength, base64Cert.length());
                pemBuilder.append(base64Cert.substring(i, endIndex));
                if (endIndex < base64Cert.length()) {
                    pemBuilder.append("\n");
                }
            }
            
            pemBuilder.append("\n-----END CERTIFICATE-----\n");
            
            return pemBuilder.toString();
            
        } catch (Exception e) {
            System.err.println(TAG + ": Error converting X509 certificate to PEM: " + e.getMessage());
            throw new RuntimeException("Failed to convert X509 certificate to PEM: " + e.getMessage(), e);
        }
    }
    
    /**
     * Converts multiple X509Certificates to PEM format string (certificate chain)
     * 
     * @param certificates array of X509Certificates to convert
     * @return PEM formatted string containing all certificates
     */
    public static String convertX509ChainToPem(X509Certificate[] certificates) {
        if (certificates == null || certificates.length == 0) {
            throw new IllegalArgumentException("Certificate array cannot be null or empty");
        }
        
        StringBuilder chainBuilder = new StringBuilder();
        
        for (int i = 0; i < certificates.length; i++) {
            if (certificates[i] == null) {
                throw new IllegalArgumentException("Certificate at index " + i + " is null");
            }
            
            chainBuilder.append(convertX509ToPem(certificates[i]));
            
            // Add separator between certificates (except for the last one)
            if (i < certificates.length - 1) {
                chainBuilder.append("\n");
            }
        }
        
        return chainBuilder.toString();
    }
}
