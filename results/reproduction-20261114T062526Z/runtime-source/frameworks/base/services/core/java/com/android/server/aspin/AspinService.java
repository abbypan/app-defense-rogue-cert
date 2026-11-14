/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.aspin;

import android.Manifest;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManagerInternal;
import android.content.pm.Signature;
import android.net.InetAddresses;
import android.os.Binder;
import android.os.Build;
import android.os.Environment;
import android.os.FileUtils;
import android.os.SystemClock;
import android.os.UserHandle;
import android.security.aspin.AspinCertificateClaim;
import android.security.aspin.IAspinService;
import android.security.net.config.ApplicationConfig;
import android.util.ArrayMap;
import android.util.AtomicFile;
import android.util.Base64;
import android.util.Slog;

import com.android.server.SystemService;
import com.android.server.LocalServices;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** OS-level implementation of the ASPin certificate-claim protocol. */
public final class AspinService extends SystemService {
    private static final String TAG = "AspinService";
    private static final String CLAIM_KEY_PATH = "/.well-known/ClaimSigningKey.jws";
    private static final String CERT_CLAIM_PATH = "/.well-known/ServerCertClaim.jws";
    private static final int CONNECT_TIMEOUT_MILLIS = 10_000;
    private static final int READ_TIMEOUT_MILLIS = 10_000;
    private static final int MAX_TOKEN_BYTES = 1024 * 1024;
    private static final String TOKEN_TYPE_KEY = "tk";
    private static final String TOKEN_TYPE_CLAIM = "tc";
    private static final String POLICY_PUBLIC_KEY_METADATA =
            "android.security.aspin.POLICY_PUBLIC_KEY";

    private final Object mLock = new Object();
    private final ArrayMap<String, RefreshLock> mRefreshLocks = new ArrayMap<>();
    private final AtomicFile mStateFile;
    private final ArrayMap<String, Long> mHighestSeenIat = new ArrayMap<>();
    // A missing file is a valid first-boot state. An existing file that cannot be parsed is not:
    // continuing with an empty map would silently discard anti-rollback protection.
    private boolean mPersistentStateAvailable;
    private final ArrayMap<String, CachedClaimKey> mClaimKeyCache = new ArrayMap<>();
    // Logical binding: (target app signing key, Subject, SAN, Issuer). Hostname is checked
    // against the cached SAN on lookup and is not a caller-controlled trust attribute.
    private final ArrayMap<String, CachedClaim> mClaimCache = new ArrayMap<>();

    public AspinService(Context context) {
        super(context);
        File stateDirectory = new File(Environment.getDataSystemDirectory(), "aspin");
        if (!stateDirectory.exists() && !stateDirectory.mkdirs()) {
            Slog.w(TAG, "Unable to create " + stateDirectory);
        }
        FileUtils.setPermissions(stateDirectory, 0700, -1, -1);
        mStateFile = new AtomicFile(new File(stateDirectory, "highest_seen_iat.json"),
                "aspin-state");
    }

    @Override
    public void onStart() {
        synchronized (mLock) {
            readStateLocked();
        }
        publishBinderService(Context.ASPIN_SERVICE, new BinderService());
    }

    private final class BinderService extends IAspinService.Stub {
        @Override
        public AspinCertificateClaim getOwnCertificateClaim(
                String hostname, boolean forceRefresh) {
            getContext().enforceCallingPermission(Manifest.permission.INTERNET,
                    "The ASPin service retrieves certificate-claim tokens");
            final int callingUid = Binder.getCallingUid();
            final int callingUserId = UserHandle.getUserId(callingUid);
            final String normalizedHostname = normalizeHostname(hostname);
            final long identity = Binder.clearCallingIdentity();
            try {
                String callerPackageName = resolveCallingPackageName(callingUid);
                return getCertificateClaimForTarget(callerPackageName, normalizedHostname,
                        forceRefresh, callingUid, callingUserId);
            } catch (IOException | JSONException | java.security.GeneralSecurityException e) {
                throw new IllegalStateException("ASPin validation failed: " + e.getMessage(), e);
            } finally {
                Binder.restoreCallingIdentity(identity);
            }
        }

        @Override
        public AspinCertificateClaim getCertificateClaimForApp(
                String targetPackageName, String hostname, boolean forceRefresh) {
            getContext().enforceCallingPermission(Manifest.permission.INTERNET,
                    "The ASPin service retrieves certificate-claim tokens");
            final int callingUid = Binder.getCallingUid();
            final int callingUserId = UserHandle.getUserId(callingUid);
            final String checkedTargetPackageName = requireTargetPackageName(targetPackageName);
            final String normalizedHostname = normalizeHostname(hostname);
            enforceTargetVisible(checkedTargetPackageName, callingUid, callingUserId);
            final long identity = Binder.clearCallingIdentity();
            try {
                return getCertificateClaimForTarget(checkedTargetPackageName, normalizedHostname,
                        forceRefresh, callingUid, callingUserId);
            } catch (IOException | JSONException | java.security.GeneralSecurityException e) {
                throw new IllegalStateException("ASPin validation failed: " + e.getMessage(), e);
            } finally {
                Binder.restoreCallingIdentity(identity);
            }
        }
    }

    private AspinCertificateClaim getCertificateClaimForTarget(String targetPackageName,
            String hostname, boolean forceRefresh, int callingUid, int callingUserId)
            throws IOException, JSONException, java.security.GeneralSecurityException {
        List<SignerIdentity> signers = resolveSigners(targetPackageName, callingUserId);
        X509TrustManager retrievalTrustManager =
                resolveNativeTrustManager(targetPackageName);
        if (forceRefresh && (!Build.IS_DEBUGGABLE
                || !isCallingUidDebuggable(callingUid, callingUserId))) {
            throw new SecurityException(
                    "Forced ASPin refresh is restricted to debuggable apps"
                            + " on debuggable builds");
        }
        String refreshContext = signers.get(0).currentDigest + "|" + hostname;
        RefreshLock refreshLock = acquireRefreshLock(refreshContext);
        try {
            synchronized (refreshLock) {
                return getCertificateClaim(
                        signers, hostname, forceRefresh, retrievalTrustManager);
            }
        } finally {
            releaseRefreshLock(refreshContext, refreshLock);
        }
    }

    private RefreshLock acquireRefreshLock(String context) {
        synchronized (mLock) {
            RefreshLock lock = mRefreshLocks.get(context);
            if (lock == null) {
                lock = new RefreshLock();
                mRefreshLocks.put(context, lock);
            }
            lock.users++;
            return lock;
        }
    }

    private void releaseRefreshLock(String context, RefreshLock lock) {
        synchronized (mLock) {
            lock.users--;
            if (lock.users == 0 && mRefreshLocks.get(context) == lock) {
                mRefreshLocks.remove(context);
            }
        }
    }

    private AspinCertificateClaim getCertificateClaim(List<SignerIdentity> signers, String hostname,
            boolean forceRefresh, X509TrustManager retrievalTrustManager)
            throws IOException, JSONException,
            java.security.GeneralSecurityException {
        // This sample is only for the initial cache lookup. Network retrieval can outlive a
        // token that is fresh here, so downloaded tokens are checked against a new sample and
        // both tokens are checked again immediately before persistent state is advanced.
        final long lookupNowMillis;
        SignerIdentity signer = signers.get(0);
        CachedClaimKey cachedClaimKey = null;
        synchronized (mLock) {
            ensurePersistentStateAvailableLocked();
            lookupNowMillis = System.currentTimeMillis();
            // Manifest K_s is an additional root, not a replacement for the installed K_a.
            // Each accepted root retains its own cache and protected H_k/H_c namespaces.
            for (SignerIdentity candidate : signers) {
                CachedClaimKey key = mClaimKeyCache.get(candidate.currentDigest + "|" + hostname);
                if (!forceRefresh && isFresh(key, lookupNowMillis)) {
                    CachedClaim cached = findCachedClaimLocked(candidate.currentDigest, hostname,
                            keyDigest(key.key), lookupNowMillis);
                    if (cached != null) {
                        return forHostnameWithoutMetrics(cached.claim, hostname);
                    }
                    if (cachedClaimKey == null) {
                        signer = candidate;
                        cachedClaimKey = key;
                    }
                }
            }
        }

        PublicKey claimKey;
        TokenTimes tkTimes;
        VerifiedJws verifiedTk = null;
        String tkToken = null;
        boolean downloadedTk = false;
        long tkNanos = 0L;
        if (!forceRefresh && isFresh(cachedClaimKey, lookupNowMillis)) {
            claimKey = cachedClaimKey.key;
            tkTimes = new TokenTimes(
                    cachedClaimKey.issuedAtMillis, cachedClaimKey.expiresAtMillis);
        } else {
            long tkStart = SystemClock.elapsedRealtimeNanos();
            tkToken = downloadToken(
                    hostname, CLAIM_KEY_PATH, forceRefresh, retrievalTrustManager);
            RootSelection selected = selectTokenRoot(tkToken, signers);
            signer = selected.signer;
            verifiedTk = selected.token;
            JSONObject tkPayload = verifiedTk.payload;
            tkTimes = validateTimes(tkPayload, System.currentTimeMillis());
            claimKey = publicKeyFromConfirmation(tkPayload);
            tkNanos = SystemClock.elapsedRealtimeNanos() - tkStart;
            downloadedTk = true;
        }

        long tcNanos = 0L;
        long tcStart = SystemClock.elapsedRealtimeNanos();
        String tcToken = downloadToken(
                hostname, CERT_CLAIM_PATH, forceRefresh, retrievalTrustManager);
        VerifiedJws verifiedTc;
        try {
            verifiedTc = verifyJws(tcToken, claimKey, true);
        } catch (SignatureException cachedKeyFailure) {
            tcNanos += SystemClock.elapsedRealtimeNanos() - tcStart;
            if (downloadedTk) {
                throw cachedKeyFailure;
            }

            // A fresh cached T_k can temporarily name the previous delegated key during a
            // claim-key rotation. Re-authenticate T_k under the OS-selected app identity and
            // retry T_c exactly once; never loop or accept T_c under an unauthenticated key.
            long tkStart = SystemClock.elapsedRealtimeNanos();
            tkToken = downloadToken(
                    hostname, CLAIM_KEY_PATH, forceRefresh, retrievalTrustManager);
            RootSelection selected = selectTokenRoot(tkToken, signers);
            signer = selected.signer;
            verifiedTk = selected.token;
            JSONObject tkPayload = verifiedTk.payload;
            tkTimes = validateTimes(tkPayload, System.currentTimeMillis());
            claimKey = publicKeyFromConfirmation(tkPayload);
            tkNanos = SystemClock.elapsedRealtimeNanos() - tkStart;
            downloadedTk = true;

            tcStart = SystemClock.elapsedRealtimeNanos();
            tcToken = downloadToken(
                    hostname, CERT_CLAIM_PATH, forceRefresh, retrievalTrustManager);
            verifiedTc = verifyJws(tcToken, claimKey, true);
        }
        tcNanos += SystemClock.elapsedRealtimeNanos() - tcStart;
        JSONObject tcPayload = verifiedTc.payload;
        TokenTimes tcTimes = validateTimes(tcPayload, System.currentTimeMillis());
        AspinCertificateClaim parsedClaim = parseClaim(
                tcPayload, hostname, tcTimes, 0L, 0L);
        long effectiveExpirationMillis = Math.min(tkTimes.expMillis, tcTimes.expMillis);
        AspinCertificateClaim claim = new AspinCertificateClaim(
                parsedClaim.getHostname(), parsedClaim.getSubject(),
                parsedClaim.getSubjectAlternativeNames(), parsedClaim.getIssuers(),
                parsedClaim.getIssuedAtMillis(), effectiveExpirationMillis,
                tkNanos, tcNanos);

        String claimIdentity = claimIdentityKey(claim);
        synchronized (mLock) {
            // Do not let an attacker-controlled download delay turn a token that was fresh at
            // validation time into an expired cache/state update. This also rechecks iat in case
            // the trusted wall clock moved backwards while the request was in progress.
            final long commitNowMillis = System.currentTimeMillis();
            ensureFresh(tkTimes, commitNowMillis);
            ensureFresh(tcTimes, commitNowMillis);

            HighestSeenUpdate tkUpdate = downloadedTk
                    ? prepareHighestSeenUpdateLocked(signer, hostname, null, TOKEN_TYPE_KEY,
                            tkTimes.iatMillis, tkToken, verifiedTk)
                    : null;
            HighestSeenUpdate tcUpdate = prepareHighestSeenUpdateLocked(
                    signer, claimIdentity, hostname, TOKEN_TYPE_CLAIM,
                    tcTimes.iatMillis, null, null);

            applyHighestSeenUpdateLocked(tkUpdate);
            applyHighestSeenUpdateLocked(tcUpdate);
            try {
                writeStateLocked();
            } catch (IOException | JSONException e) {
                restoreHighestSeenUpdateLocked(tcUpdate);
                restoreHighestSeenUpdateLocked(tkUpdate);
                throw e;
            }
            if (downloadedTk) {
                mClaimKeyCache.put(signer.currentDigest + "|" + hostname,
                        new CachedClaimKey(claimKey, tkTimes.iatMillis, tkTimes.expMillis));
            }
            removeCachedClaimsForIdentityLocked(signer.currentDigest, claimIdentity);
            mClaimCache.put(claimCacheKey(signer.currentDigest, claim),
                    new CachedClaim(signer.currentDigest, claimIdentity,
                            keyDigest(claimKey), claim));
        }
        return claim;
    }

    private CachedClaim findCachedClaimLocked(String signerDigest, String hostname,
            String claimKeyDigest, long nowMillis) {
        CachedClaim newest = null;
        for (int i = mClaimCache.size() - 1; i >= 0; i--) {
            CachedClaim candidate = mClaimCache.valueAt(i);
            if (nowMillis < candidate.claim.getIssuedAtMillis()
                    || nowMillis >= candidate.claim.getExpiresAtMillis()) {
                mClaimCache.removeAt(i);
                continue;
            }
            if (candidate.signerDigest.equals(signerDigest)
                    && candidate.claimKeyDigest.equals(claimKeyDigest)
                    && claimCoversHostname(candidate.claim, hostname)
                    && (newest == null || candidate.claim.getIssuedAtMillis()
                            > newest.claim.getIssuedAtMillis())) {
                newest = candidate;
            }
        }
        return newest;
    }

    private static boolean isFresh(CachedClaimKey cachedClaimKey, long nowMillis) {
        return cachedClaimKey != null
                && cachedClaimKey.issuedAtMillis <= nowMillis
                && nowMillis < cachedClaimKey.expiresAtMillis;
    }

    private void removeCachedClaimsForIdentityLocked(
            String signerDigest, String claimIdentity) {
        for (int i = mClaimCache.size() - 1; i >= 0; i--) {
            CachedClaim candidate = mClaimCache.valueAt(i);
            if (candidate.signerDigest.equals(signerDigest)
                    && candidate.claimIdentity.equals(claimIdentity)) {
                mClaimCache.removeAt(i);
            }
        }
    }

    private static boolean claimCoversHostname(AspinCertificateClaim claim, String hostname) {
        for (String san : claim.getSubjectAlternativeNames()) {
            if (sanMatchesHostname(san, hostname)) return true;
        }
        return false;
    }

    private static String claimIdentityKey(AspinCertificateClaim claim) {
        StringBuilder key = new StringBuilder();
        appendCacheField(key, canonicalSubject(claim.getSubject()));
        for (String san : claim.getSubjectAlternativeNames()) {
            appendCacheField(key, (isIpAddress(san) ? "ip:" : "dns:") + san);
        }
        return key.toString();
    }

    private static String claimCacheKey(String signerDigest, AspinCertificateClaim claim) {
        StringBuilder key = new StringBuilder(signerDigest);
        appendCacheField(key, claim.getSubject());
        for (String san : claim.getSubjectAlternativeNames()) appendCacheField(key, san);
        key.append('|');
        for (String issuer : claim.getIssuers()) appendCacheField(key, issuer);
        return key.toString();
    }

    private static void appendCacheField(StringBuilder key, String value) {
        key.append('|').append(value.length()).append(':').append(value);
    }

    private static AspinCertificateClaim forHostnameWithoutMetrics(
            AspinCertificateClaim claim, String hostname) {
        return new AspinCertificateClaim(hostname, claim.getSubject(),
                claim.getSubjectAlternativeNames(), claim.getIssuers(),
                claim.getIssuedAtMillis(), claim.getExpiresAtMillis(), 0L, 0L);
    }

    private List<SignerIdentity> resolveSigners(String packageName, int userId)
            throws java.security.GeneralSecurityException {
        final PackageManager packageManager = requirePackageManager();
        final PackageInfo packageInfo;
        try {
            packageInfo = packageManager.getPackageInfoAsUser(packageName,
                    PackageManager.PackageInfoFlags.of(
                            PackageManager.GET_SIGNING_CERTIFICATES
                                    | PackageManager.GET_META_DATA), userId);
        } catch (PackageManager.NameNotFoundException e) {
            throw new SecurityException("Unable to resolve target package " + packageName, e);
        }
        if (packageInfo.signingInfo == null
                || packageInfo.signingInfo.getApkContentsSigners().length != 1) {
            throw new SecurityException("ASPin requires one current signer for " + packageName);
        }

        PublicKey current = publicKeyFromAndroidSignature(
                packageInfo.signingInfo.getApkContentsSigners()[0]);
        List<PublicKey> lineage = new ArrayList<>();
        Signature[] history = packageInfo.signingInfo.hasPastSigningCertificates()
                ? packageInfo.signingInfo.getSigningCertificateHistory()
                : packageInfo.signingInfo.getApkContentsSigners();
        for (Signature signature : history) {
            lineage.add(publicKeyFromAndroidSignature(signature));
        }
        List<SignerIdentity> roots = new ArrayList<>();
        roots.add(new SignerIdentity(current, lineage));
        ApplicationInfo applicationInfo = packageInfo.applicationInfo;
        if (applicationInfo != null && applicationInfo.metaData != null) {
            String encodedPolicyKey = applicationInfo.metaData.getString(POLICY_PUBLIC_KEY_METADATA);
            if (encodedPolicyKey != null) {
                PublicKey policyKey = publicKeyFromManifest(encodedPolicyKey);
                if (!keyDigest(current).equals(keyDigest(policyKey))) {
                    roots.add(new SignerIdentity(policyKey, List.of(policyKey)));
                }
            }
        }
        return roots;
    }

    private static RootSelection selectTokenRoot(String token, List<SignerIdentity> roots)
            throws JSONException, java.security.GeneralSecurityException {
        SignatureException failure = new SignatureException(
                "T_k has no valid signature under the installed app or manifest ASPin root");
        // A valid installed-app signature takes precedence when both sign this same payload.
        // kid only filters against these OS-authenticated candidates; it never supplies a root.
        for (SignerIdentity root : roots) {
            try {
                return new RootSelection(root, verifyJws(token, root.currentKey, false));
            } catch (SignatureException rejected) {
                failure.addSuppressed(rejected);
            }
        }
        throw failure;
    }

    private static final class RootSelection {
        final SignerIdentity signer;
        final VerifiedJws token;

        RootSelection(SignerIdentity signer, VerifiedJws token) {
            this.signer = signer;
            this.token = token;
        }
    }

    private X509TrustManager resolveNativeTrustManager(String packageName) {
        try {
            return (X509TrustManager) ApplicationConfig.createInstanceForPackage(
                    getContext(), packageName).getTrustManager();
        } catch (PackageManager.NameNotFoundException e) {
            throw new SecurityException(
                    "Unable to resolve native TLS policy for " + packageName, e);
        }
    }

    private static PublicKey publicKeyFromManifest(String encoded)
            throws java.security.GeneralSecurityException {
        String value = encoded.trim();
        if (value.isEmpty() || value.length() > 16_384) {
            throw new SignatureException("Invalid ASPin manifest policy key");
        }
        final byte[] der;
        try {
            if ((value.length() & 1) == 0 && value.matches("[0-9a-fA-F]+")) {
                der = new byte[value.length() / 2];
                for (int i = 0; i < value.length(); i += 2) {
                    der[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
                }
            } else {
                der = Base64.decode(value, Base64.DEFAULT);
            }
        } catch (IllegalArgumentException e) {
            throw new SignatureException("Malformed ASPin manifest policy key", e);
        }
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(der);
        for (String algorithm : List.of("EC", "RSA")) {
            try {
                PublicKey key = KeyFactory.getInstance(algorithm).generatePublic(keySpec);
                if (key instanceof ECPublicKey || key instanceof RSAPublicKey) {
                    return key;
                }
            } catch (java.security.GeneralSecurityException ignored) {
                // Try the other supported key family.
            }
        }
        throw new SignatureException("Unsupported ASPin manifest policy key");
    }

    private static void enforceTargetVisible(String packageName, int callingUid, int userId) {
        PackageManagerInternal packageManagerInternal =
                LocalServices.getService(PackageManagerInternal.class);
        if (packageManagerInternal == null
                || packageManagerInternal.filterAppAccess(packageName, callingUid, userId)) {
            throw new SecurityException(
                    "Target package is not visible to the ASPin caller: " + packageName);
        }
    }

    private String resolveCallingPackageName(int callingUid) {
        String[] packageNames = requirePackageManager().getPackagesForUid(callingUid);
        if (packageNames == null || packageNames.length == 0) {
            throw new SecurityException("Unable to resolve the ASPin caller UID " + callingUid);
        }
        if (packageNames.length != 1) {
            throw new SecurityException(
                    "The hostname-only ASPin API requires a caller UID associated with exactly"
                            + " one package; use the cross-app API with an explicit target");
        }
        return packageNames[0];
    }

    private boolean isCallingUidDebuggable(int uid, int userId) {
        final PackageManager packageManager = requirePackageManager();
        String[] packageNames = packageManager.getPackagesForUid(uid);
        if (packageNames == null || packageNames.length == 0) return false;
        for (String packageName : packageNames) {
            try {
                ApplicationInfo applicationInfo = packageManager.getApplicationInfoAsUser(
                        packageName, PackageManager.ApplicationInfoFlags.of(0), userId);
                if ((applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) return false;
            } catch (PackageManager.NameNotFoundException e) {
                return false;
            }
        }
        return true;
    }

    private PackageManager requirePackageManager() {
        // This service is constructed during bootstrap, before PackageManagerService is
        // published. Resolve the framework wrapper lazily when an app actually calls the API.
        // ContextImpl retries while its cached value is null, so this becomes available after
        // PackageManagerService initialization without retaining the bootstrap-time null.
        PackageManager packageManager = getContext().getPackageManager();
        if (packageManager == null) {
            throw new IllegalStateException("Package manager is not ready");
        }
        return packageManager;
    }

    private static PublicKey publicKeyFromAndroidSignature(Signature signature)
            throws java.security.GeneralSecurityException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(signature.toByteArray()));
        return certificate.getPublicKey();
    }

    private HighestSeenUpdate prepareHighestSeenUpdateLocked(SignerIdentity signer, String context,
            String legacyContext, String tokenType, long iatMillis, String token,
            VerifiedJws verified)
            throws java.security.GeneralSecurityException, JSONException {
        long lineageHighest = Long.MIN_VALUE;
        boolean priorLineageStateExists = false;
        for (String digest : signer.lineageDigests) {
            Long value = mHighestSeenIat.get(stateKey(digest, context, tokenType));
            if (value != null) {
                lineageHighest = Math.max(lineageHighest, value);
                if (!digest.equals(signer.currentDigest)) {
                    priorLineageStateExists = true;
                }
            }
            if (legacyContext != null && !legacyContext.equals(context)) {
                Long legacyValue = mHighestSeenIat.get(
                        stateKey(digest, legacyContext, tokenType));
                if (legacyValue != null) {
                    lineageHighest = Math.max(lineageHighest, legacyValue);
                    if (!digest.equals(signer.currentDigest)) {
                        priorLineageStateExists = true;
                    }
                }
            }
        }
        if (lineageHighest != Long.MIN_VALUE && iatMillis < lineageHighest) {
            throw new SecurityException("ASPin anti-rollback rejected lower iat for " + tokenType);
        }

        String currentStateKey = stateKey(signer.currentDigest, context, tokenType);
        if (TOKEN_TYPE_KEY.equals(tokenType)
                && mHighestSeenIat.get(currentStateKey) == null
                && priorLineageStateExists) {
            PublicKey previousKey = signer.previousKey();
            if (previousKey == null || token == null || verified == null
                    || !verifyGeneralJwsSamePayload(token, previousKey, verified.payloadEncoded)) {
                throw new SecurityException(
                        "App signing-key transition requires old and new signatures");
            }
        }
        return new HighestSeenUpdate(
                currentStateKey, mHighestSeenIat.get(currentStateKey),
                lineageHighest == Long.MIN_VALUE ? iatMillis : Math.max(iatMillis, lineageHighest));
    }

    private void applyHighestSeenUpdateLocked(HighestSeenUpdate update) {
        if (update != null) mHighestSeenIat.put(update.key, update.newValue);
    }

    private void restoreHighestSeenUpdateLocked(HighestSeenUpdate update) {
        if (update == null) return;
        if (update.oldValue == null) {
            mHighestSeenIat.remove(update.key);
        } else {
            mHighestSeenIat.put(update.key, update.oldValue);
        }
    }

    private static String stateKey(String signerDigest, String context, String tokenType) {
        // Keep the original field order so an OS upgrade preserves existing T_k
        // state and can consult legacy hostname-keyed T_c state during migration.
        return signerDigest + "|" + context + "|" + tokenType;
    }

    private static TokenTimes validateTimes(JSONObject payload, long nowMillis)
            throws JSONException {
        long iatSeconds = requiredPositiveLong(payload, "iat");
        long expSeconds = requiredPositiveLong(payload, "exp");
        final long iatMillis;
        final long expMillis;
        try {
            iatMillis = Math.multiplyExact(iatSeconds, 1000L);
            expMillis = Math.multiplyExact(expSeconds, 1000L);
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException("ASPin token time is out of range", e);
        }
        if (expMillis <= iatMillis) {
            throw new SecurityException("ASPin token exp must be later than iat");
        }
        TokenTimes times = new TokenTimes(iatMillis, expMillis);
        ensureFresh(times, nowMillis);
        return times;
    }

    private static void ensureFresh(TokenTimes times, long nowMillis) {
        if (times.iatMillis > nowMillis || nowMillis >= times.expMillis) {
            throw new SecurityException("ASPin token is not fresh");
        }
    }

    private static long requiredPositiveLong(JSONObject payload, String name) throws JSONException {
        Object value = payload.get(name);
        // JSONTokener represents in-range integer literals as Integer or Long. Reject strings,
        // floating-point/exponent forms, and out-of-range integers rather than coercing or
        // truncating them into a NumericDate value.
        if (!(value instanceof Integer) && !(value instanceof Long)) {
            throw new JSONException(name + " must be a JSON integer");
        }
        long parsed = ((Number) value).longValue();
        if (parsed <= 0) {
            throw new JSONException(name + " must be positive");
        }
        return parsed;
    }

    private static AspinCertificateClaim parseClaim(JSONObject payload, String hostname,
            TokenTimes times, long tkNanos, long tcNanos) throws JSONException {
        String subject = payload.getString("subject").trim();
        if (subject.isEmpty()) {
            throw new JSONException("certificate claim subject is empty");
        }
        try {
            canonicalSubject(subject);
        } catch (IllegalArgumentException e) {
            throw new JSONException("certificate claim subject is not a valid X.500 Name");
        }
        List<String> sans = canonicalSans(requiredStringList(payload, "san"));
        List<String> issuers = requiredIssuerList(payload);
        boolean hostnameCovered = false;
        for (String san : sans) {
            if (sanMatchesHostname(san, hostname)) {
                hostnameCovered = true;
                break;
            }
        }
        if (!hostnameCovered) {
            throw new SecurityException(
                    "Signed ASPin SAN does not cover the requested hostname");
        }
        return new AspinCertificateClaim(hostname, subject, sans, issuers,
                times.iatMillis, times.expMillis, tkNanos, tcNanos);
    }

    private static String canonicalSubject(String subject) {
        return Base64.encodeToString(new X500Principal(subject.trim()).getEncoded(),
                Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private static List<String> canonicalSans(List<String> input) throws JSONException {
        List<String> result = new ArrayList<>();
        for (String san : input) {
            final String canonical;
            if (isIpAddress(san)) {
                canonical = InetAddresses.parseNumericAddress(stripIpBrackets(san)).getHostAddress();
            } else {
                canonical = canonicalDnsPattern(san);
            }
            if (!result.contains(canonical)) result.add(canonical);
        }
        result.sort(Comparator.naturalOrder());
        if (result.isEmpty()) {
            throw new JSONException("san must contain at least one DNS or IP name");
        }
        return Collections.unmodifiableList(result);
    }

    private static String canonicalDnsPattern(String pattern) throws JSONException {
        String trimmed = pattern.trim();
        boolean wildcard = trimmed.startsWith("*.");
        String name = wildcard ? trimmed.substring(2) : trimmed;
        try {
            String ascii = IDN.toASCII(name, IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
            if (ascii.isEmpty() || ascii.endsWith(".") || ascii.length() > 253
                    || (!wildcard && ascii.indexOf('*') >= 0)
                    || (wildcard && (ascii.indexOf('*') >= 0 || ascii.indexOf('.') < 0))) {
                throw new IllegalArgumentException("invalid DNS SAN");
            }
            return wildcard ? "*." + ascii : ascii;
        } catch (IllegalArgumentException e) {
            throw new JSONException("certificate claim contains an invalid DNS SAN");
        }
    }

    private static boolean sanMatchesHostname(String san, String hostname) {
        if (isIpAddress(hostname)) {
            if (!isIpAddress(san)) return false;
            try {
                return InetAddresses.parseNumericAddress(stripIpBrackets(hostname)).equals(
                        InetAddresses.parseNumericAddress(stripIpBrackets(san)));
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        if (isIpAddress(san)) return false;
        String host = hostname.toLowerCase(Locale.ROOT);
        String pattern = san.toLowerCase(Locale.ROOT);
        if (!pattern.contains("*")) return host.equals(pattern);
        if (!pattern.startsWith("*.") || pattern.indexOf('*', 1) != -1) return false;
        String suffix = pattern.substring(1);
        return host.endsWith(suffix)
                && host.length() > suffix.length()
                && host.lastIndexOf('.', host.length() - suffix.length() - 1) == -1;
    }

    private static boolean isIpAddress(String value) {
        try {
            InetAddresses.parseNumericAddress(stripIpBrackets(value.trim()));
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String stripIpBrackets(String value) {
        return value.startsWith("[") && value.endsWith("]")
                ? value.substring(1, value.length() - 1) : value;
    }

    private static List<String> requiredStringList(JSONObject payload, String name)
            throws JSONException {
        List<String> result = new ArrayList<>();
        Object value = payload.get(name);
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            for (int i = 0; i < array.length(); i++) {
                String item = array.getString(i).trim();
                if (!item.isEmpty()) result.add(item);
            }
        } else if (value instanceof String && !((String) value).trim().isEmpty()) {
            result.add(((String) value).trim());
        }
        if (result.isEmpty()) {
            throw new JSONException(name + " must contain at least one string");
        }
        return Collections.unmodifiableList(result);
    }

    private static List<String> requiredIssuerList(JSONObject payload) throws JSONException {
        List<String> supplied = requiredStringList(payload, "issuer");
        List<String> issuers = new ArrayList<>();
        final int base64Flags = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;
        for (String issuer : supplied) {
            try {
                int separator = issuer.indexOf(':');
                if (separator <= 0 || separator != issuer.lastIndexOf(':')) {
                    throw new IllegalArgumentException("missing or duplicate separator");
                }
                String hashName = issuer.substring(0, separator);
                String encodedDigest = issuer.substring(separator + 1);
                int expectedLength;
                if ("sha256".equals(hashName)) {
                    expectedLength = 32;
                } else if ("sha384".equals(hashName)) {
                    expectedLength = 48;
                } else {
                    throw new IllegalArgumentException("unsupported issuer hash algorithm");
                }
                byte[] digest = Base64.decode(encodedDigest, base64Flags);
                if (digest.length != expectedLength
                        || !encodedDigest.equals(Base64.encodeToString(digest, base64Flags))) {
                    throw new IllegalArgumentException("non-canonical base64url encoding");
                }
                if (!issuers.contains(issuer)) issuers.add(issuer);
            } catch (IllegalArgumentException e) {
                throw new JSONException(
                        "issuer must contain supported hash-name:unpadded-base64url-digest values");
            }
        }
        issuers.sort(Comparator.naturalOrder());
        return Collections.unmodifiableList(issuers);
    }

    private static PublicKey publicKeyFromConfirmation(JSONObject payload)
            throws JSONException, java.security.GeneralSecurityException {
        JSONObject confirmation = payload.getJSONObject("cnf");
        JSONObject jwk = confirmation.optJSONObject("jwk");
        if (jwk == null) {
            throw new JSONException("T_k cnf.jwk is required");
        }
        return publicKeyFromJwk(jwk);
    }

    private static String downloadToken(String hostname, String path,
            boolean allowDebugSpecialUseDestination, X509TrustManager trustManager)
            throws IOException, java.security.GeneralSecurityException {
        InetAddress[] addresses = InetAddress.getAllByName(hostname);
        if (addresses.length == 0) {
            throw new IOException("No address found for ASPin claim endpoint");
        }

        // Reject the complete answer if it mixes public and forbidden destinations. Debug-only
        // forced refresh permits loopback for the controlled ADB-reverse testbed. Native TLS
        // performs chain and hostname validation for the named HTTPS endpoint.
        for (InetAddress address : addresses) {
            if (isSpecialUseAddress(address) && !allowDebugSpecialUseDestination) {
                throw new IOException("ASPin claim endpoint resolves to a special-use address");
            }
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] {trustManager}, null);
        HttpsURLConnection connection = (HttpsURLConnection) new URL(
                "https://" + httpHostHeader(hostname) + path)
                .openConnection(Proxy.NO_PROXY);
        try {
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
            connection.setReadTimeout(READ_TIMEOUT_MILLIS);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTPS " + status + " retrieving " + path);
            }
            try (InputStream input = connection.getInputStream();
                    ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[8192];
                int total = 0;
                int read;
                while ((read = input.read(buffer)) != -1) {
                    total += read;
                    if (total > MAX_TOKEN_BYTES) {
                        throw new IOException("ASPin token exceeds size limit");
                    }
                    output.write(buffer, 0, read);
                }
                return new String(output.toByteArray(), StandardCharsets.UTF_8).trim();
            }
        } finally {
            connection.disconnect();
        }
    }

    private static String httpHostHeader(String hostname) {
        return hostname.indexOf(':') >= 0 ? "[" + stripIpBrackets(hostname) + "]" : hostname;
    }

    /** Returns true for destinations that an untrusted app must not make system_server fetch. */
    private static boolean isSpecialUseAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            return isSpecialUseIpv4(bytes, 0);
        }
        if (!(address instanceof Inet6Address) || bytes.length != 16) return true;

        int first = bytes[0] & 0xff;
        int second = bytes[1] & 0xff;
        // IPv4-compatible/mapped, discard-only, IETF protocol-assignment, documentation,
        // unique-local, link-local, multicast, and documentation-prefix destinations.
        boolean firstTwelveZero = true;
        for (int i = 0; i < 12; i++) firstTwelveZero &= bytes[i] == 0;
        if (firstTwelveZero) return true;
        if (first == 0x01 && second == 0x00) return true; // 100::/64 and reserved 0100::/8.
        if (first == 0x20 && second == 0x01
                && (((bytes[2] & 0xfe) == 0)
                        || ((bytes[2] & 0xff) == 0x0d && (bytes[3] & 0xff) == 0xb8))) {
            return true; // 2001::/23 and 2001:db8::/32.
        }
        if ((first & 0xfe) == 0xfc || (first == 0xfe && (second & 0xc0) == 0x80)
                || first == 0xff) {
            return true;
        }
        return first == 0x3f && (second & 0xf0) == 0xf0; // 3fff::/20 documentation.
    }

    private static boolean isSpecialUseIpv4(byte[] bytes, int offset) {
        int first = bytes[offset] & 0xff;
        int second = bytes[offset + 1] & 0xff;
        int third = bytes[offset + 2] & 0xff;
        return first == 0 || first == 10 || first == 127
                || (first == 100 && (second & 0xc0) == 0x40)
                || (first == 169 && second == 254)
                || (first == 172 && (second & 0xf0) == 16)
                || (first == 192 && second == 0 && third == 0)
                || (first == 192 && second == 0 && third == 2)
                || (first == 192 && second == 88 && third == 99)
                || (first == 192 && second == 168)
                || (first == 198 && (second == 18 || second == 19))
                || (first == 198 && second == 51 && third == 100)
                || (first == 203 && second == 0 && third == 113)
                || first >= 224;
    }

    private static VerifiedJws verifyJws(
            String token, PublicKey trustedKey, boolean requireSingleSignature)
            throws JSONException, java.security.GeneralSecurityException {
        if (!token.startsWith("{")) {
            throw new SignatureException("ASPin requires General JWS JSON Serialization");
        }
        JSONObject general = new JSONObject(token);
        if (!jsonKeys(general).equals(Set.of("payload", "signatures"))) {
            throw new SignatureException(
                    "General JWS must contain exactly payload and signatures");
        }
        String payloadEncoded = general.getString("payload");
        JSONArray signatures = general.getJSONArray("signatures");
        // T_k supports any non-empty signature array within MAX_TOKEN_BYTES. The trusted
        // context key selects its entry; unrelated owners do not become trust anchors.
        // T_c retains its single-signature profile.
        if (signatures.length() == 0 || (requireSingleSignature && signatures.length() != 1)) {
            throw new SignatureException("Invalid JWS signature count");
        }
        for (int i = 0; i < signatures.length(); i++) {
            JSONObject signature = signatures.getJSONObject(i);
            if (!jsonKeys(signature).equals(Set.of("protected", "signature"))) {
                throw new SignatureException(
                        "Each General JWS signature must contain protected and signature");
            }
            String protectedEncoded = signature.getString("protected");
            String signatureEncoded = signature.getString("signature");
            JSONObject header = decodeJson(protectedEncoded);
            if (headerMatchesKey(header, trustedKey)
                    && verifySignature(header, protectedEncoded + "." + payloadEncoded,
                            signatureEncoded, trustedKey)) {
                return new VerifiedJws(decodeJson(payloadEncoded), payloadEncoded);
            }
        }
        throw new SignatureException("No General JWS signature matches trusted key");
    }

    private static boolean verifyGeneralJwsSamePayload(String token, PublicKey trustedKey,
            String expectedPayloadEncoded) throws JSONException,
            java.security.GeneralSecurityException {
        if (!token.startsWith("{")) return false;
        JSONObject general = new JSONObject(token);
        String payloadEncoded = general.getString("payload");
        if (!MessageDigest.isEqual(payloadEncoded.getBytes(StandardCharsets.US_ASCII),
                expectedPayloadEncoded.getBytes(StandardCharsets.US_ASCII))) {
            return false;
        }
        JSONArray signatures = general.getJSONArray("signatures");
        for (int i = 0; i < signatures.length(); i++) {
            JSONObject signature = signatures.getJSONObject(i);
            String protectedEncoded = signature.getString("protected");
            JSONObject header = decodeJson(protectedEncoded);
            if (headerMatchesKey(header, trustedKey)
                    && verifySignature(header, protectedEncoded + "." + payloadEncoded,
                            signature.getString("signature"), trustedKey)) {
                return true;
            }
        }
        return false;
    }

    private static JSONObject decodeJson(String base64Url) throws JSONException {
        byte[] decoded;
        try {
            decoded = Base64.decode(base64Url, Base64.URL_SAFE | Base64.NO_WRAP
                    | Base64.NO_PADDING);
        } catch (IllegalArgumentException e) {
            throw new JSONException("Invalid base64url in JWS");
        }
        return new JSONObject(new String(decoded, StandardCharsets.UTF_8));
    }

    private static Set<String> jsonKeys(JSONObject object) {
        Set<String> result = new java.util.HashSet<>();
        java.util.Iterator<String> iterator = object.keys();
        while (iterator.hasNext()) result.add(iterator.next());
        return result;
    }

    private static boolean headerMatchesKey(JSONObject header, PublicKey trustedKey)
            throws JSONException, java.security.GeneralSecurityException {
        if (!jsonKeys(header).equals(Set.of("alg", "kid"))) {
            throw new SignatureException(
                    "JWS protected header must contain exactly alg and kid");
        }
        return keyDigest(trustedKey).equals(header.getString("kid"));
    }

    private static boolean verifySignature(JSONObject header, String signingInput,
            String signatureEncoded, PublicKey key)
            throws java.security.GeneralSecurityException, JSONException {
        String algorithm = header.getString("alg");
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.decode(signatureEncoded, Base64.URL_SAFE | Base64.NO_WRAP
                    | Base64.NO_PADDING);
        } catch (IllegalArgumentException e) {
            return false;
        }

        java.security.Signature verifier;
        switch (algorithm) {
            case "PS256":
                if (!(key instanceof RSAPublicKey)) return false;
                // Android Conscrypt exposes digest-specific RSA/PSS names rather than the
                // parameter-only RSASSA-PSS name used by some desktop JCA providers.
                verifier = java.security.Signature.getInstance("SHA256withRSA/PSS");
                verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                        MGF1ParameterSpec.SHA256, 32, 1));
                break;
            case "PS384":
                if (!(key instanceof RSAPublicKey)) return false;
                verifier = java.security.Signature.getInstance("SHA384withRSA/PSS");
                verifier.setParameter(new PSSParameterSpec("SHA-384", "MGF1",
                        MGF1ParameterSpec.SHA384, 48, 1));
                break;
            case "ES256":
                if (!(key instanceof ECPublicKey) || signatureBytes.length != 64) return false;
                verifier = java.security.Signature.getInstance("SHA256withECDSA");
                signatureBytes = joseEcdsaToDer(signatureBytes);
                break;
            case "ES384":
                if (!(key instanceof ECPublicKey) || signatureBytes.length != 96) return false;
                verifier = java.security.Signature.getInstance("SHA384withECDSA");
                signatureBytes = joseEcdsaToDer(signatureBytes);
                break;
            default:
                throw new SignatureException("Unsupported ASPin JWS alg " + algorithm);
        }
        verifier.initVerify(key);
        verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return verifier.verify(signatureBytes);
    }

    private static byte[] joseEcdsaToDer(byte[] joseSignature) throws SignatureException {
        int componentLength = joseSignature.length / 2;
        byte[] r = unsignedInteger(Arrays.copyOfRange(joseSignature, 0, componentLength));
        byte[] s = unsignedInteger(Arrays.copyOfRange(
                joseSignature, componentLength, joseSignature.length));
        int sequenceLength = 2 + r.length + 2 + s.length;
        ByteArrayOutputStream output = new ByteArrayOutputStream(sequenceLength + 3);
        output.write(0x30);
        writeDerLength(output, sequenceLength);
        output.write(0x02);
        writeDerLength(output, r.length);
        output.write(r, 0, r.length);
        output.write(0x02);
        writeDerLength(output, s.length);
        output.write(s, 0, s.length);
        return output.toByteArray();
    }

    private static byte[] unsignedInteger(byte[] value) {
        int first = 0;
        while (first < value.length - 1 && value[first] == 0) first++;
        byte[] stripped = Arrays.copyOfRange(value, first, value.length);
        if ((stripped[0] & 0x80) != 0) {
            byte[] padded = new byte[stripped.length + 1];
            System.arraycopy(stripped, 0, padded, 1, stripped.length);
            return padded;
        }
        return stripped;
    }

    private static void writeDerLength(ByteArrayOutputStream output, int length)
            throws SignatureException {
        if (length < 128) {
            output.write(length);
        } else if (length < 256) {
            output.write(0x81);
            output.write(length);
        } else {
            throw new SignatureException("ECDSA DER signature is unexpectedly long");
        }
    }

    private static PublicKey publicKeyFromJwk(JSONObject jwk)
            throws JSONException, java.security.GeneralSecurityException {
        String type = jwk.getString("kty");
        if ("RSA".equals(type)) {
            BigInteger modulus = new BigInteger(1, decodeBase64Url(jwk.getString("n")));
            BigInteger exponent = new BigInteger(1, decodeBase64Url(jwk.getString("e")));
            return KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(modulus, exponent));
        }
        if ("EC".equals(type)) {
            String curve = jwk.getString("crv");
            String curveName;
            if ("P-256".equals(curve)) {
                curveName = "secp256r1";
            } else if ("P-384".equals(curve)) {
                curveName = "secp384r1";
            } else {
                throw new SignatureException("Unsupported ASPin EC curve " + curve);
            }
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(curveName));
            ECParameterSpec parameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPoint point = new ECPoint(
                    new BigInteger(1, decodeBase64Url(jwk.getString("x"))),
                    new BigInteger(1, decodeBase64Url(jwk.getString("y"))));
            return KeyFactory.getInstance("EC").generatePublic(
                    new ECPublicKeySpec(point, parameterSpec));
        }
        throw new SignatureException("Unsupported ASPin JWK type " + type);
    }

    private static byte[] decodeBase64Url(String value) {
        return Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    private static String keyDigest(PublicKey key)
            throws java.security.GeneralSecurityException {
        return Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(key.getEncoded()),
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    private static String normalizeHostname(String hostname) {
        if (hostname == null) throw new IllegalArgumentException("hostname is required");
        String value = hostname.trim();
        if (value.isEmpty() || value.contains("/") || value.contains("\\")
                || value.endsWith(".")) {
            throw new IllegalArgumentException("hostname must be a canonical DNS name");
        }
        String unbracketed = stripIpBrackets(value);
        if (isIpAddress(unbracketed)) {
            return InetAddresses.parseNumericAddress(unbracketed).getHostAddress();
        }
        if (value.contains(":")) {
            throw new IllegalArgumentException("hostname must not include a port");
        }
        String ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES)
                .toLowerCase(Locale.ROOT);
        if (ascii.length() > 253) throw new IllegalArgumentException("hostname is too long");
        return ascii;
    }

    private static String requireTargetPackageName(String targetPackageName) {
        if (targetPackageName == null || targetPackageName.isEmpty()
                || !targetPackageName.equals(targetPackageName.trim())) {
            throw new IllegalArgumentException("targetPackageName is required");
        }
        return targetPackageName;
    }

    private void readStateLocked() {
        mHighestSeenIat.clear();
        mPersistentStateAvailable = false;
        if (!mStateFile.getBaseFile().exists()) {
            mPersistentStateAvailable = true;
            return;
        }
        try (FileInputStream input = mStateFile.openRead()) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            FileUtils.copy(input, output);
            byte[] data = output.toByteArray();
            JSONObject root = new JSONObject(new String(data, StandardCharsets.UTF_8));
            if (root.getInt("version") != 1) {
                throw new JSONException("Unsupported ASPin state version");
            }
            JSONArray entries = root.getJSONArray("entries");
            for (int i = 0; i < entries.length(); i++) {
                JSONObject entry = entries.getJSONObject(i);
                String key = entry.getString("key");
                long iatMillis = entry.getLong("iatMillis");
                if (key.isEmpty() || mHighestSeenIat.containsKey(key)) {
                    throw new JSONException("Invalid or duplicate ASPin state key");
                }
                mHighestSeenIat.put(key, iatMillis);
            }
            mPersistentStateAvailable = true;
        } catch (IOException | JSONException e) {
            mHighestSeenIat.clear();
            Slog.wtf(TAG, "Persistent ASPin anti-rollback state is unavailable;"
                    + " all ASPin queries will fail closed until the state is repaired", e);
        }
    }

    private void ensurePersistentStateAvailableLocked() {
        if (!mPersistentStateAvailable) {
            throw new IllegalStateException(
                    "Persistent ASPin anti-rollback state requires administrator recovery");
        }
    }

    private void writeStateLocked() throws IOException, JSONException {
        JSONObject root = new JSONObject();
        JSONArray entries = new JSONArray();
        for (Map.Entry<String, Long> entry : mHighestSeenIat.entrySet()) {
            JSONObject object = new JSONObject();
            object.put("key", entry.getKey());
            object.put("iatMillis", entry.getValue());
            entries.put(object);
        }
        root.put("version", 1);
        root.put("entries", entries);

        FileOutputStream output = null;
        try {
            output = mStateFile.startWrite();
            output.write(root.toString().getBytes(StandardCharsets.UTF_8));
            mStateFile.finishWrite(output);
            FileUtils.setPermissions(mStateFile.getBaseFile(), 0600, -1, -1);
        } catch (IOException e) {
            if (output != null) mStateFile.failWrite(output);
            throw e;
        }
    }

    private static final class SignerIdentity {
        final PublicKey currentKey;
        final String currentDigest;
        final List<PublicKey> lineageKeys;
        final List<String> lineageDigests;

        SignerIdentity(PublicKey currentKey, List<PublicKey> lineageKeys)
                throws java.security.GeneralSecurityException {
            this.currentKey = currentKey;
            currentDigest = keyDigest(currentKey);
            List<PublicKey> keys = new ArrayList<>(lineageKeys);
            List<String> digests = new ArrayList<>();
            for (PublicKey key : keys) digests.add(keyDigest(key));
            if (!digests.contains(currentDigest)) {
                digests.add(currentDigest);
                keys.add(currentKey);
            }
            this.lineageKeys = Collections.unmodifiableList(keys);
            lineageDigests = Collections.unmodifiableList(digests);
        }

        PublicKey previousKey() {
            int current = lineageDigests.indexOf(currentDigest);
            return current > 0 ? lineageKeys.get(current - 1) : null;
        }
    }

    private static final class VerifiedJws {
        final JSONObject payload;
        final String payloadEncoded;

        VerifiedJws(JSONObject payload, String payloadEncoded) {
            this.payload = payload;
            this.payloadEncoded = payloadEncoded;
        }
    }

    private static final class TokenTimes {
        final long iatMillis;
        final long expMillis;

        TokenTimes(long iatMillis, long expMillis) {
            this.iatMillis = iatMillis;
            this.expMillis = expMillis;
        }
    }

    private static final class CachedClaim {
        final String signerDigest;
        final String claimIdentity;
        final String claimKeyDigest;
        final AspinCertificateClaim claim;

        CachedClaim(String signerDigest, String claimIdentity, String claimKeyDigest,
                AspinCertificateClaim claim) {
            this.signerDigest = signerDigest;
            this.claimIdentity = claimIdentity;
            this.claimKeyDigest = claimKeyDigest;
            this.claim = claim;
        }
    }

    private static final class HighestSeenUpdate {
        final String key;
        final Long oldValue;
        final long newValue;

        HighestSeenUpdate(String key, Long oldValue, long newValue) {
            this.key = key;
            this.oldValue = oldValue;
            this.newValue = newValue;
        }
    }

    private static final class RefreshLock {
        int users;
    }

    private static final class CachedClaimKey {
        final PublicKey key;
        final long issuedAtMillis;
        final long expiresAtMillis;

        CachedClaimKey(PublicKey key, long issuedAtMillis, long expiresAtMillis) {
            this.key = key;
            this.issuedAtMillis = issuedAtMillis;
            this.expiresAtMillis = expiresAtMillis;
        }
    }
}
