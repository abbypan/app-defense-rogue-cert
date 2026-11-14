/* Copyright (C) 2026 The Android Open Source Project
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */
package android.security.net.config;

import android.os.Build;
import android.os.SystemProperties;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.IDN;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Independent experimental NSC DCP verifier. No ASPin API or delegated key is used.
 * The manifest supplies a DCP root which directly signs hostname-bound leaf-SPKI pins.
 * This baseline has signed expiry and a bounded in-process cache, not ASPin's persistent
 * rollback state, installed-target resolution, delegation or lineage migration. @hide
 */
final class DcpPinningVerifier {
    private static final int FLAGS = Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING;
    private final PublicKey mRoot;
    private final X509TrustManager mNativeTrustManager;
    private final LinkedHashMap<String, Policy> mCache = new LinkedHashMap<>();

    DcpPinningVerifier(PublicKey root, X509TrustManager nativeTrustManager) {
        mRoot = root;
        mNativeTrustManager = nativeTrustManager;
    }

    static PublicKey parsePublicKey(String encoded) throws GeneralSecurityException {
        String value = encoded.trim();
        if (value.isEmpty() || value.length() > 16384) {
            throw new GeneralSecurityException("Invalid DCP manifest public key");
        }
        byte[] der;
        if (value.matches("(?:[0-9a-fA-F]{2})+")) {
            der = new byte[value.length() / 2];
            for (int i = 0; i < der.length; i++) {
                der[i] = (byte) Integer.parseInt(value.substring(2 * i, 2 * i + 2), 16);
            }
        } else {
            der = Base64.decode(value, Base64.DEFAULT);
        }
        for (String type : List.of("EC", "RSA")) {
            try {
                return KeyFactory.getInstance(type).generatePublic(new X509EncodedKeySpec(der));
            } catch (GeneralSecurityException ignored) { }
        }
        throw new GeneralSecurityException("Unsupported DCP manifest public key");
    }

    void check(List<X509Certificate> path, String requestedHost) throws CertificateException {
        if (mRoot == null || path.isEmpty() || requestedHost == null) {
            throw new CertificateException("Dynamic pin policy context is missing");
        }
        try {
            String hostname = IDN.toASCII(requestedHost, IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
            final Policy policy;
            synchronized (mCache) {
                Policy cached = mCache.get(hostname);
                long now = System.currentTimeMillis();
                // Controlled experiments can force a metadata fetch per handshake. This is
                // only available on a userdebug/eng OS and never discards protected ASPin state.
                boolean force = Build.isDebuggable() && SystemProperties.getBoolean(
                        "debug.aspin.dcp_cold", false);
                if (!force && cached != null && cached.fresh(now)) {
                    policy = cached;
                } else {
                    policy = verify(download(hostname), hostname);
                    if (!policy.fresh(System.currentTimeMillis())) {
                        throw new CertificateException("Dynamic pin policy expired during retrieval");
                    }
                    if (mCache.size() >= 256) mCache.remove(mCache.keySet().iterator().next());
                    mCache.put(hostname, policy);
                }
            }
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(path.get(0).getPublicKey().getEncoded());
            for (byte[] pin : policy.pins) {
                if (MessageDigest.isEqual(digest, pin)) return;
            }
            throw new CertificateException("Dynamic pin verification failed");
        } catch (CertificateException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new CertificateException("Dynamic pin policy lookup failed", failure);
        }
    }

    private String download(String hostname) throws Exception {
        SSLContext tls = SSLContext.getInstance("TLS");
        // Deliberately use only the same native chain/hostname validator for metadata.
        // Passing the underlying delegate, not this NSC callback, prevents recursion without
        // bypassing native verification or disabling pinning on a business connection.
        tls.init(null, new TrustManager[] {mNativeTrustManager}, null);
        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://" + hostname
                + "/.well-known/DCPServerCertPin.jws").openConnection(Proxy.NO_PROXY);
        try {
            connection.setSSLSocketFactory(tls.getSocketFactory());
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            if (connection.getResponseCode() != 200) {
                throw new CertificateException("DCP metadata retrieval did not return HTTP 200");
            }
            try (InputStream input = connection.getInputStream();
                    ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (output.size() + count > 1024 * 1024) {
                        throw new CertificateException("DCP metadata exceeds response bound");
                    }
                    output.write(buffer, 0, count);
                }
                return output.toString(StandardCharsets.UTF_8.name());
            }
        } finally {
            connection.disconnect();
        }
    }

    private Policy verify(String encoded, String hostname) throws Exception {
        JSONObject object = new JSONObject(encoded);
        if (object.length() != 2 || !object.has("payload") || !object.has("signatures")) {
            throw new CertificateException("Invalid DCP General JWS");
        }
        JSONArray signatures = object.getJSONArray("signatures");
        if (signatures.length() != 1) throw new CertificateException("DCP needs one signature");
        JSONObject entry = signatures.getJSONObject(0);
        if (entry.length() != 2 || !entry.has("protected") || !entry.has("signature")) {
            throw new CertificateException("Invalid DCP signature entry");
        }
        String protectedPart = entry.getString("protected");
        String payloadPart = object.getString("payload");
        JSONObject header = new JSONObject(new String(decode(protectedPart), StandardCharsets.UTF_8));
        String kid = Base64.encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(mRoot.getEncoded()), FLAGS);
        if (header.length() != 2 || !header.has("alg") || !kid.equals(header.getString("kid"))) {
            throw new CertificateException("DCP kid does not match manifest key");
        }
        byte[] signature = decode(entry.getString("signature"));
        Signature verifier;
        String alg = header.getString("alg");
        if (("ES256".equals(alg) || "ES384".equals(alg)) && mRoot instanceof ECPublicKey) {
            int bits = ((ECPublicKey) mRoot).getParams().getCurve().getField().getFieldSize();
            int width = "ES256".equals(alg) ? 32 : 48;
            if (bits != width * 8 || signature.length != width * 2) {
                throw new CertificateException("DCP EC parameters do not match alg");
            }
            signature = ecdsaDer(signature, width);
            verifier = Signature.getInstance(width == 32 ? "SHA256withECDSA" : "SHA384withECDSA");
        } else if (("PS256".equals(alg) || "PS384".equals(alg)) && mRoot instanceof RSAPublicKey) {
            if (((RSAPublicKey) mRoot).getModulus().bitLength() < 2048) {
                throw new CertificateException("DCP RSA key is too small");
            }
            boolean sha256 = "PS256".equals(alg);
            verifier = Signature.getInstance(sha256 ? "SHA256withRSA/PSS" : "SHA384withRSA/PSS");
            verifier.setParameter(new PSSParameterSpec(sha256 ? "SHA-256" : "SHA-384", "MGF1",
                    sha256 ? MGF1ParameterSpec.SHA256 : MGF1ParameterSpec.SHA384,
                    sha256 ? 32 : 48, 1));
        } else {
            throw new CertificateException("DCP algorithm/key mismatch");
        }
        verifier.initVerify(mRoot);
        verifier.update((protectedPart + "." + payloadPart).getBytes(StandardCharsets.US_ASCII));
        if (!verifier.verify(signature)) throw new CertificateException("Invalid DCP signature");
        JSONObject payload = new JSONObject(new String(decode(payloadPart), StandardCharsets.UTF_8));
        if (payload.length() != 4 || !hostname.equals(payload.getString("hostname"))) {
            throw new CertificateException("DCP hostname mismatch");
        }
        long issued = seconds(payload, "iat");
        long expires = seconds(payload, "exp");
        JSONArray pins = payload.getJSONArray("pins");
        if (pins.length() == 0 || pins.length() > 64) throw new CertificateException("Invalid DCP pins");
        List<byte[]> values = new ArrayList<>();
        for (int i = 0; i < pins.length(); i++) {
            String value = pins.getString(i);
            if (!value.startsWith("sha256:")) throw new CertificateException("Unsupported DCP pin hash");
            byte[] digest = decode(value.substring(7));
            if (digest.length != 32) throw new CertificateException("Invalid DCP pin length");
            values.add(digest);
        }
        Policy result = new Policy(issued, expires, values);
        if (!result.fresh(System.currentTimeMillis())) throw new CertificateException("DCP policy is not fresh");
        return result;
    }

    private static long seconds(JSONObject object, String name) throws Exception {
        Object value = object.get(name);
        if (!(value instanceof Integer) && !(value instanceof Long)) {
            throw new CertificateException("DCP time must be an integer");
        }
        long seconds = ((Number) value).longValue();
        if (seconds <= 0) throw new CertificateException("Invalid DCP time");
        return Math.multiplyExact(seconds, 1000L);
    }

    private static byte[] decode(String value) throws CertificateException {
        byte[] bytes = Base64.decode(value, FLAGS);
        if (!value.equals(Base64.encodeToString(bytes, FLAGS))) {
            throw new CertificateException("Non-canonical DCP base64url");
        }
        return bytes;
    }

    private static byte[] ecdsaDer(byte[] raw, int width) {
        byte[] r = new BigInteger(1, java.util.Arrays.copyOfRange(raw, 0, width)).toByteArray();
        byte[] s = new BigInteger(1, java.util.Arrays.copyOfRange(raw, width, 2 * width)).toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30); out.write(4 + r.length + s.length);
        out.write(0x02); out.write(r.length); out.write(r, 0, r.length);
        out.write(0x02); out.write(s.length); out.write(s, 0, s.length);
        return out.toByteArray();
    }

    private static final class Policy {
        final long issued;
        final long expires;
        final List<byte[]> pins;
        Policy(long issued, long expires, List<byte[]> pins) {
            this.issued = issued; this.expires = expires; this.pins = pins;
        }
        boolean fresh(long now) { return issued <= now && now < expires && issued < expires; }
    }
}
