package com.abbypan.appservercert;

import android.util.Log;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1OctetString;

/**
 * Structured representation of SSL certificate information
 */
public class CertificateInfo {
    private String subject;
    private String issuer;
    private List<SubjectAlternativeName> subjectAlternativeNames;
    private Date validFrom;
    private Date validUntil;
    private String serialNumber;
    private String signatureAlgorithm;
    private PublicKey publicKey;
    private X509Certificate x509Certificate;
    private boolean isValid;
    private String errorMessage;

    public CertificateInfo() {
        this.subjectAlternativeNames = new ArrayList<>();
        this.isValid = false;
    }

    // Getters and Setters
    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public List<SubjectAlternativeName> getSubjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    public void setSubjectAlternativeNames(List<SubjectAlternativeName> subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
    }

    public void addSubjectAlternativeName(SubjectAlternativeName san) {
        this.subjectAlternativeNames.add(san);
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public void setX509Certificate(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
        // Automatically extract public key when certificate is set
        if (x509Certificate != null) {
            this.publicKey = x509Certificate.getPublicKey();
        }
    }

    public boolean isValid() {
        return isValid;
    }

    public void setValid(boolean valid) {
        isValid = valid;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    /**
     * Get all DNS names from Subject Alternative Names
     */
    public List<String> getDnsNames() {
        List<String> dnsNames = new ArrayList<>();
        for (SubjectAlternativeName san : subjectAlternativeNames) {
            if (san.getType() == SubjectAlternativeName.Type.DNS_NAME) {
                dnsNames.add(san.getValue());
            }
        }
        return dnsNames;
    }

    /**
     * Get all IP addresses from Subject Alternative Names
     */
    public List<String> getIpAddresses() {
        List<String> ipAddresses = new ArrayList<>();
        for (SubjectAlternativeName san : subjectAlternativeNames) {
            if (san.getType() == SubjectAlternativeName.Type.IP_ADDRESS) {
                ipAddresses.add(san.getValue());
            }
        }
        return ipAddresses;
    }

    /**
     * Check if the certificate is currently valid (not expired)
     */
    public boolean isCurrentlyValid() {
        if (validFrom == null || validUntil == null) {
            return false;
        }
        Date now = new Date();
        return now.after(validFrom) && now.before(validUntil);
    }

    /**
     * Get days until expiration
     */
    public long getDaysUntilExpiration() {
        if (validUntil == null) {
            return -1;
        }
        Date now = new Date();
        long diffInMillies = validUntil.getTime() - now.getTime();
        return diffInMillies / (24 * 60 * 60 * 1000);
    }

    /**
     * Extract the public key from the certificate
     * 
     * @return PublicKey object, or null if not available
     */
    public PublicKey extractPublicKey() {
        if (publicKey != null) {
            return publicKey;
        }
        
        if (x509Certificate != null) {
            return x509Certificate.getPublicKey();
        }
        
        return null;
    }

    /**
     * Get the public key in PEM format
     * 
     * @return Public key as PEM string, or null if not available
     */
    public String getPublicKeyPem() {
        PublicKey key = extractPublicKey();
        if (key == null) {
            return null;
        }
        
        try {
            byte[] keyBytes = key.getEncoded();
            String base64Key = java.util.Base64.getEncoder().encodeToString(keyBytes);
            
            StringBuilder pem = new StringBuilder();
            pem.append("-----BEGIN PUBLIC KEY-----\n");
            
            // Split into 64-character lines
            for (int i = 0; i < base64Key.length(); i += 64) {
                int end = Math.min(i + 64, base64Key.length());
                pem.append(base64Key.substring(i, end)).append("\n");
            }
            
            pem.append("-----END PUBLIC KEY-----");
            return pem.toString();
            
        } catch (Exception e) {
            System.err.println("Error converting public key to PEM: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get the public key algorithm
     * 
     * @return Algorithm name (e.g., "RSA", "EC", "DSA"), or null if not available
     */
    public String getPublicKeyAlgorithm() {
        PublicKey key = extractPublicKey();
        if (key == null) {
            return null;
        }
        return key.getAlgorithm();
    }

    /**
     * Get the public key format
     * 
     * @return Key format (e.g., "X.509", "PKCS#8"), or null if not available
     */
    public String getPublicKeyFormat() {
        PublicKey key = extractPublicKey();
        if (key == null) {
            return null;
        }
        return key.getFormat();
    }

    /**
     * Get the public key size in bits
     * 
     * @return Key size in bits, or -1 if not available
     */
    public int getPublicKeySize() {
        PublicKey key = extractPublicKey();
        if (key == null) {
            return -1;
        }
        
        try {
            if (key instanceof java.security.interfaces.RSAPublicKey) {
                return ((java.security.interfaces.RSAPublicKey) key).getModulus().bitLength();
            } else if (key instanceof java.security.interfaces.ECPublicKey) {
                return ((java.security.interfaces.ECPublicKey) key).getParams().getOrder().bitLength();
            } else if (key instanceof java.security.interfaces.DSAPublicKey) {
                return ((java.security.interfaces.DSAPublicKey) key).getParams().getP().bitLength();
            }
        } catch (Exception e) {
            System.err.println("Error getting public key size: " + e.getMessage());
        }
        
        return -1;
    }

    /**
     * Check if the public key is available
     * 
     * @return true if public key is available, false otherwise
     */
    public boolean hasPublicKey() {
        return extractPublicKey() != null;
    }

    @Override
    public String toString() {
        if (!isValid) {
            return "Certificate Information:\n" + (errorMessage != null ? errorMessage : "No certificate captured");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Certificate Information:\n");
        sb.append("======================\n");
        sb.append("Subject: ").append(subject).append("\n\n");
        sb.append("Issuer: ").append(issuer).append("\n\n");
        
        sb.append("Subject Alternative Names:\n");
        if (subjectAlternativeNames.isEmpty()) {
            sb.append("  No Subject Alternative Names found\n");
        } else {
            for (SubjectAlternativeName san : subjectAlternativeNames) {
                sb.append("  ").append(san.getTypeName()).append(": ").append(san.getValue()).append("\n");
            }
        }
        
        sb.append("\nAdditional Details:\n");
        sb.append("Valid From: ").append(validFrom).append("\n");
        sb.append("Valid Until: ").append(validUntil).append("\n");
        sb.append("Serial Number: ").append(serialNumber).append("\n");
        sb.append("Signature Algorithm: ").append(signatureAlgorithm).append("\n");
        sb.append("Currently Valid: ").append(isCurrentlyValid()).append("\n");
        sb.append("Days Until Expiration: ").append(getDaysUntilExpiration()).append("\n");
        
        // Public key information
        if (hasPublicKey()) {
            sb.append("\nPublic Key Information:\n");
            sb.append("Algorithm: ").append(getPublicKeyAlgorithm()).append("\n");
            sb.append("Format: ").append(getPublicKeyFormat()).append("\n");
            sb.append("Size: ").append(getPublicKeySize()).append(" bits\n");
        } else {
            sb.append("\nPublic Key: Not available\n");
        }
        
        return sb.toString();
    }

    /**
     * Inner class representing a Subject Alternative Name entry
     */
    public static class SubjectAlternativeName {
        public enum Type {
            OTHER_NAME(0, "Other Name"),
            RFC_822_NAME(1, "RFC 822 Name (Email)"),
            DNS_NAME(2, "DNS Name"),
            X400_ADDRESS(3, "X400 Address"),
            DIRECTORY_NAME(4, "Directory Name"),
            EDIPARTY_NAME(5, "EDIParty Name"),
            URI(6, "URI"),
            IP_ADDRESS(7, "IP Address"),
            REGISTERED_ID(8, "Registered ID");

            private final int code;
            private final String name;

            Type(int code, String name) {
                this.code = code;
                this.name = name;
            }

            public int getCode() {
                return code;
            }

            public String getName() {
                return name;
            }

            public static Type fromCode(int code) {
                for (Type type : values()) {
                    if (type.code == code) {
                        return type;
                    }
                }
                return OTHER_NAME; // Default fallback
            }
        }

        private Type type;
        private String value;

        public SubjectAlternativeName(Type type, String value) {
            this.type = type;
            this.value = value;
        }

        public Type getType() {
            return type;
        }

        public void setType(Type type) {
            this.type = type;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getTypeName() {
            return type.getName();
        }

        @Override
        public String toString() {
            return type.getName() + ": " + value;
        }
    }

    /**
     * Reads CRL (Certificate Revocation List) distribution points from a certificate
     * 
     * @param ee the X509Certificate to extract CRL from
     * @return the CRL distribution point URL as a string
     * @throws Exception if CRL extraction fails
     */
    public static String read_crl(X509Certificate ee) throws Exception {
        byte[] crl = ee.getExtensionValue("2.5.29.31"); // CRL Distribution Points
        //  System.out.println(">>> Cert CRL : " + new BigInteger(1, crl).toString(16)                 );

        Asn1OctetString octetString = new Asn1OctetString();
        for(int i=0; i<2; i++) {
            octetString.decode(crl);
            //   Asn1.dump(octetString);
            crl = 	octetString.getValue();
            octetString.decode(crl);
        }
        //  Asn1.dump(octetString);

        ByteBuffer buffer = ByteBuffer.wrap(octetString.getValue());
        Asn1ParseResult res = Asn1Parser.parse(buffer);
        byte[] crl_addr = res.readBodyBytes();
        String crl_str =         new String(crl_addr , StandardCharsets.UTF_8);
        //  System.out.println(">>> Cert CRL : " +        		crl_str        		);

        //   ASN1InputStream  crlis = new ASN1InputStream(crl);
        //com.hierynomus.asn1.types.constructed.ASN1Sequence s = crlis.iter;
        // byte[] crlr = crlis.readValue(crlis.readLength());
        //  ASN1Sequence  crlobj =  crlis.readObject();
        //     System.out.println(" >>> crl der size : " + crlis.readObject());

        //     ArrayList crlarr = (ArrayList) crlis.readObject().getValue();

        //   ASN1OctetString  crl_asn1 = new ASN1OctetString(crl);
        //    System.out.println(">>> Cert CRL : " +
        //       		 new BigInteger(1, crl_asn1.getValueBytes()).toString(16)

        // 		 new BigInteger(1, crl_asn1.getValue()).toString(16)
        //	                      );
        // InputStream stream = new ByteArrayInputStream(exampleString.getBytes(StandardCharsets.UTF_8));
        // InputStream stream = new ByteArrayInputStream(crl);

        return crl_str;
    }

    /**
     * Reads the CA domain from a certificate's CRL distribution points
     * 
     * @param ee the X509Certificate to extract CA domain from
     * @return the CA domain as a string
     * @throws Exception if CA domain extraction fails
     */
    public static String read_ca_dom(X509Certificate ee) throws Exception {
        return DomainExtractor.read_sld(read_crl(ee));
    }

    /**
     * Reads the subject public key from a certificate
     * 
     * @param ee the X509Certificate to extract public key from
     * @return the public key as DER-encoded byte array
     */
    public static byte[] readSubjectPK(X509Certificate ee) {
        PublicKey pk = ee.getPublicKey();
        //System.out.println(">>> Cert Public Key Algorithm : " + pk.getAlgorithm());

        byte[] pk_der = pk.getEncoded();
        //System.out.println(">>> Cert Public Key Algorithm : " + HexUtil.bytesToHex(pk_der) );

        return pk_der;
    }

    /**
     * Calculates the digest of the subject public key from a certificate
     * 
     * @param dgstAlg the digest algorithm to use (e.g., "SHA-256", "MD5", "SHA-1")
     * @param ee the X509Certificate to extract and hash the public key from
     * @return the digest as a hexadecimal string
     * @throws Exception if digest calculation fails
     */
    public static String calcSubjecPKHash(String dgstAlg, X509Certificate ee) throws Exception {
        byte[] pk_der = readSubjectPK(ee);
        //  System.out.println(">>> Cert Public Key DER : " + HexFormat.of().formatHex(pk_der) );

        byte[] dgst = HashUtils.digest(dgstAlg, pk_der);
        String s =  HexFormat.of().formatHex(dgst);
        //  System.out.println(">>> Cert Public Key Digest : " + s );

        return s;
    }

    /**
     * Checks if the certificate issuer matches the expected issuer
     * 
     * @param ee the X509Certificate to check
     * @param exp_issuer the expected issuer string to match against
     * @return true if the issuer matches, false otherwise
     * @throws Exception if issuer checking fails
     */
    public static boolean checkIssuer(X509Certificate ee, String exp_issuer) throws Exception {
        String issuer = ee.getIssuerX500Principal().toString();
        //Log.d("CertificateInfo", "issuer: " + issuer + " exp_issuer: " + exp_issuer);
        if(exp_issuer.equals(issuer)) {
            return true;
        }
        return false;
    }

    /**
     * Prints certificate information to the console
     * 
     * @param cert the X509Certificate to print information for
     */
    public static void print_cert(X509Certificate cert) {
        //Log.d("CertificateInfo", "Cert Type : " + cert.getType());
        //Log.d("CertificateInfo", "Cert Hash Code : " + cert.hashCode());
        //Log.d("CertificateInfo", "Cert Public Key Algorithm : "
        //        + cert.getPublicKey().getAlgorithm());
        //Log.d("CertificateInfo", "Cert Public Key Format : "
        //        + cert.getPublicKey().getFormat());

        String issuer = cert.getIssuerX500Principal().toString();
        //Log.d("CertificateInfo", "Cert Issuer Name: " + issuer);

        //Log.d("CertificateInfo", "");
    }
}
