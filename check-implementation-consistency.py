#!/usr/bin/env python3
"""Fail when TeX, App, signing, ProVerif, or benchmark semantics drift."""

import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
VARIANTS = ("es256", "es384", "rsa3072", "rsa4096")


def fail(message):
    raise SystemExit(f"ERROR: {message}")


def text(path):
    if not path.is_file():
        fail(f"missing {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require(path, *fragments):
    value = text(path)
    for fragment in fragments:
        if fragment not in value:
            fail(f"{path.relative_to(ROOT)} is missing {fragment!r}")


def forbid(path, *fragments):
    value = text(path)
    for fragment in fragments:
        if fragment in value:
            fail(f"{path.relative_to(ROOT)} contains obsolete form {fragment!r}")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_tex():
    paper = ROOT / "tex" / "paper_content.tex"
    abstract = ROOT / "tex" / "paper_abstract-sigconf.tex"
    require(
        abstract,
        "Refreshing both JWS objects averages 33.10--40.14\\,ms",
        "ASPin-minus-TLS sample-mean differences are 0.83--1.46\\,ms",
    )
    require(
        paper,
        r"T_k&=(K_{cpub},iat_k,exp_k)",
        r"T_c&=(Subject,SAN,IssuerSet,iat_c,exp_c)",
        "signed Subject/SAN defines the $T_c$ partition, and SAN restricts the hostname",
        "Only the signed SAN authorizes hostnames",
        "supplies only A's server hostname",
        "intentionally names App~B and B's server hostname",
        "The caller never supplies the key",
        "iat_k \\leq t_{\\mathrm{now}} < exp_k",
        "iat_c \\leq t_{\\mathrm{now}} < exp_c",
        r"IssuerId_H(c)=\mathrm{name}(H)",
        r"H\!\left(\mathrm{DER}(CA(c))\right)",
        r"\texttt{hash-name:}\allowbreak\texttt{hash-value}",
        "must return the exact ordered path it actually accepted",
        "never the raw peer-supplied certificate array",
        "Android's host-aware \\texttt{checkServer}\\allowbreak\\texttt{Trusted}",
        "returns the ordered path used for native validation",
        "Only this result, never the peer-supplied array",
        "General JWS JSON Serialization",
        "every ordinary publication has one signature entry",
        "one hostname has exactly one ASPin policy owner at any instant",
        "the fixed well-known URL carries no owner selector",
        "intentionally share one ASPin owner/trust domain",
        "package identifier adds no cache or anti-rollback partition",
        "Within that owner, at most one fresh canonical Subject/SAN partition may cover the hostname",
        r"maximum permitted $T_c$ lifetime",
        r"maximum allowed $exp_c-iat_c$",
        r"Each overlap JWS is served for its full $L_{\max}$ lifetime",
        r"$w_2$ & $T_c^{(2)}$ & CurrCert & CurrCA+NewCA",
        r"$w_3$ & $T_c^{(3)}$ & CurrCert & CurrCA+NewCA",
        r"$w_4$ & $T_c^{(4)}$ & NewCert & NewCA",
        r"migration model uses one symbolic step for $L_{\max}$",
        r"jointly publishes $T_c^{(4)}$ and deploys \emph{NewCert}",
        r"\emph{overlap} concerns CA identifiers, not cross-cutover validity",
        "operator staging and advance notice",
        "operator-staged CA migration",
        "one OS-level mechanism for retrieval, JWS verification, claim replacement",
        "private phase markers encode the recommended operator schedule",
        r"This is an ordering property, not policy rejection",
        r"each full-$L_{\max}$ phase-elapsed event",
        "whose delegated public key matches the key that authenticated the cached $T_c$",
        "retrieves and authenticates fresh $T_k$ once and retries $T_c$ exactly once",
        "a second $T_c$ failure rejects the query",
        "the protected highest-seen values do not expire or reset with cache eviction",
        "the worst case lasts until the cached old $T_k$ expires",
        "claim-host matching, cache isolation",
        "Native TLS, rather than the OS-level ASPin service, performs certificate hostname validation",
        "expired claims are never returned",
        "a query fails if refresh cannot obtain a fresh pair",
        r"$w_3$ & $T_c^{(3)}$ & CurrCert & CurrCA+NewCA & second staging interval",
        r"$iat_k\geq t_r$ and $iat_c\geq t_r$",
        "atomically establish and persist a protected epoch $t_r$",
        "All queries fail closed until that commit",
        r"\emph{CertClaimCheck} fails when the protected clock reaches $exp_{eff}$",
        r"returns the claim together with $exp_{eff}=\min(exp_k,exp_c)$",
        "a complete two-token refresh averages 33.10--40.14\\,ms",
        "ASPin-minus-TLS differences between sample means are 0.83--1.46\\,ms",
        "representative app-provisioned DCP systems considered here",
        "Compromising an artifact-only mirror affects availability",
        "does not itself provide rollback-resistant time",
        "Reported workloads do not exercise the current source's failure-only bounded claim-key-rotation retry",
        "serialized response-body bytes, excluding HTTP headers",
        "ASPin, SCP, and DCP then apply their respective supplementary checks",
        r"\textbf{Accepted/config.}",
    )
    forbid(
        paper,
        r"IssuerId(c)=\mathrm{b64url}(N_c)",
        r"\mathrm{DER}(c.issuer)",
        "No separate scope field is needed",
        "Thus two apps may claim the same hostname without crossing cache entries",
        "two \\emph{differently signed} apps may claim the same hostname",
        r"$w_0$ & $T_c^{(0)}$",
        r"CurrCert $\to$ NewCert",
        r"NewCert cutover occurs earlier while $T_c^{(2)}$ is fresh",
        "signed contents bind it to its phase",
        "exploit a migration gap",
        "and transitions consistently",
        "authenticated retrieval",
        "31.00--43.37",
        "0.90--1.39",
        "trusted-synchronized protected clock",
        "recovery interval",
        "expired queries fail",
        "Suppression fails closed.",
    )
    require(
        ROOT / "tex" / "figures" / "paper.drawio",
        "ClaimSigningKey.jws",
        "ServerCertClaim.jws",
        "Protected Signing Environment",
    )
    forbid(
        ROOT / "tex" / "figures" / "paper.drawio",
        "ClaimSigningKey.jwt",
        "ServerCertClaim.jwt",
        "serverCertClaimSigningKey.json",
        "serverCertClaim.json",
    )


def check_signing():
    for variant in VARIANTS:
        directory = ROOT / "signing" / variant
        tk_generator = directory / "gen_jws_ClaimSigningKey.py"
        tc_generator = directory / "gen_jws_ServerCertClaim.py"
        require(
            tk_generator,
            '"alg": algorithm',
            '"kid":',
            '"cnf": {"jwk":',
            '"signatures": [signature]',
            "token.serialize(compact=False)",
        )
        require(
            tc_generator,
            '"subject": subject',
            '"san": sans',
            '"issuer": [issuer]',
            "issuer_certificate.public_bytes(serialization.Encoding.DER)",
            'return f"{hash_name}:{value}"',
            "certificate.verify_directly_issued_by(issuer_certificate)",
            "x509.load_pem_x509_certificates",
            '"signatures": [signature]',
            "token.serialize(compact=False)",
        )
        forbid(tk_generator, '"pubkey":', '"ttl":', '"scope":', '"host":')
        forbid(
            tc_generator,
            '"pubkey":',
            '"ttl":',
            '"scope":',
            '"host":',
            "certificate.issuer.public_bytes()",
            "compact=True",
        )
        forbid(tk_generator, "compact=True")
    subprocess.run(
        [sys.executable, str(ROOT / "check-trust-artifacts.py")],
        cwd=ROOT,
        check=True,
    )


def check_apps():
    common_files = (
        "ASPinVerifier.java",
        "OsAspinClient.java",
        "HttpsConn.java",
        "AppTrustedServerCert.java",
        "PemUtils.java",
    )
    reference = ROOT / "ASPin" / VARIANTS[0] / "app" / "src" / "main" / "java" / "com" / "cert" / "aspin"
    for filename in common_files:
        expected = digest(reference / filename)
        for variant in VARIANTS[1:]:
            candidate = ROOT / "ASPin" / variant / "app" / "src" / "main" / "java" / "com" / "cert" / "aspin" / filename
            if digest(candidate) != expected:
                fail(f"App variants disagree in {filename}")

    for variant in VARIANTS:
        base = ROOT / "ASPin" / variant / "app" / "src" / "main"
        java = base / "java" / "com" / "cert" / "aspin"
        verifier = java / "ASPinVerifier.java"
        jws_verifier = java / "JwsVerifier.java"
        client = java / "OsAspinClient.java"
        https = java / "HttpsConn.java"
        main = java / "MainActivity.java"
        scp = java / "SCPVerifier.java"
        gradle = ROOT / "ASPin" / variant / "app" / "build.gradle"
        manifest = base / "AndroidManifest.xml"
        require(gradle, 'applicationId "com.cert.aspin"')
        require(manifest, '<package android:name="com.cert.aspin"')
        scp_text = text(scp)
        for pin_variant in VARIANTS:
            pin_path = ROOT / "signing" / pin_variant / "my-app-cert-scp-hash.txt"
            pin = text(pin_path).strip().lower()
            if len(pin) != 64 or any(ch not in "0123456789abcdef" for ch in pin):
                fail(f"invalid SCP SHA-256 pin in {pin_path.relative_to(ROOT)}")
            expected_pin = f'pins.put("{pin_variant}.idouzi.top", "{pin}");'
            if expected_pin not in scp_text:
                fail(
                    f"{scp.relative_to(ROOT)} does not contain the generated "
                    f"{pin_variant} SCP pin"
                )
        require(
            client,
            'getCertificateClaim(Context context, String hostname)',
            'getCertificateClaimForApp(',
            'String targetAppId, String hostname',
            'context.getSystemService(SERVICE_NAME)',
            'ASPinVerifier.sameHostname(hostname, returnedHostname)',
            'claimClass, platformClaim, "getExpiresAtMillis"',
            "expiresAtMillis);",
        )
        forbid(client, "PublicKey", "appSigningKey", "callerKey")
        require(
            verifier,
            "sameHostname(connectionHostname, claim.host)",
            "directIssuer(validatedChain[0], validatedChain)",
            "X509Certificate candidate = validatedChain[1]",
            "leaf.verify(candidate.getPublicKey())",
            'case "sha256" -> "SHA-256"',
            'case "sha384" -> "SHA-384"',
            "issuerCertificate.getEncoded()",
            "MessageDigest.isEqual(",
            "validatedIssuerIdentifiers(issuerIdentifiers)",
            "nowMillis >= claim.expiresAtMillis",
            'throw new CertificateException("The authenticated ASPin claim has expired")',
            "public long getExpiresAtMillis()",
        )
        require(
            jws_verifier,
            "ASPin requires General JWS JSON Serialization",
            'Set.of("payload", "signatures")',
            'Set.of("protected", "signature")',
        )
        forbid(jws_verifier, "toCompactSerialization", "SignedJWT")
        forbid(
            verifier,
            "hostMatchesClaim(",
            "commonName(",
            'json.optString("host"',
            "certificateDnsNames",
            "distinguishedNamesEqual",
            "issuer.getEncoded()",
        )
        require(
            https,
            "new X509TrustManagerExtensions(defaultTrustManager)",
            "List<X509Certificate> validatedPath = trustManagerExtensions.checkServerTrusted(",
            "chain, authType, host)",
            "check.verify(requireValidatedPath(validatedPath));",
            "static X509Certificate[] requireValidatedPath(",
            "ASPinVerifier.verifyCertificate(host, claim, chain)",
            "new InputStreamReader(con.getInputStream())",
        )
        forbid(
            https,
            "defaultTrustManager.checkServerTrusted(chain, authType);",
            "check.verify(chain);",
        )
        require(
            ROOT / "ASPin" / variant / "app" / "src" / "test" / "java"
            / "com" / "cert" / "aspin" / "CertificateValidationTest.java",
            "nativeValidatedPathIsPreservedForCertClaimCheck",
        )
        require(
            main,
            "OsAspinClient.getCertificateClaim(this, host)",
            "OsAspinClient.getCertificateClaimForApp(",
            "refreshValidatedAspinClaim(host)",
            "getClaimKeyDownloadAndVerificationNanos()",
            "getClaimDownloadAndVerificationNanos()",
            "OS-level T_k download and verification",
            "OS-level T_c download and verification",
        )
        forbid(
            main,
            '"https://" + host + "/.well-known/ClaimSigningKey.jws"',
            '"https://" + host + "/.well-known/ServerCertClaim.jws"',
            "JwsVerifier.verifyJwsWithCert(csjws",
            '"http://dcp.idouzi.top/',
        )

    matches = list((ROOT / "ASPin").rglob("*com.abbypan.aspin*"))
    if matches:
        fail("obsolete com.abbypan.aspin content remains")


def check_proverif():
    base = ROOT / "proverif" / "base.pvl"
    cache = ROOT / "proverif" / "aspin_cache.pv"
    rotation = ROOT / "proverif" / "aspin_key_rotation.pv"
    require(
        base,
        "jws_payload(bitstring, timestamp, timestamp)",
        "jws_general_sign(",
        "package_signing_record(bitstring, pkey)",
        "token_fresh(",
        "derive_ttl(",
        "event ClaimFreshAtCheck(bitstring)",
    )
    forbid(
        base,
        "get_scope(",
        "jws_payload(bitstring, timestamp, ttl)",
        "fun jws(",
        "jws_sign(",
    )
    for network_model in (
        "aspin_dns_hijacking.pv",
        "aspin_bgp_hijacking.pv",
        "aspin_mitm.pv",
    ):
        require(
            ROOT / "proverif" / network_model,
            "let connection_time = succ_t(curr) in",
            "token_fresh(key_iat,",
            "event ClaimFreshAtCheck(hostname)",
            "event(ClaimFreshAtCheck(",
        )
    require(
        cache,
        "claim_key_cache_entry(",
        "CrossDelegationCacheHit(",
        "resolve_os_key(target_record, target_app_id)",
        "in(c, jws_general(hk:",
        "in(c, jws_general(h0:",
        "token_fresh(key_iat, key_exp, iat3)",
        "token_fresh(key_iat, key_exp, cutover_time)",
        "let exp1 = succ_t(iat1) in",
        "let exp2 = succ_t(iat2) in",
        "let (=ttl_one) = derive_ttl(iat1, exp1) in",
        "let (=ttl_one) = derive_ttl(iat2, exp2) in",
        "token_expired(exp0, iat1)",
        "token_expired(exp1, iat2)",
        "token_expired(exp2, iat3)",
        "token_expired(exp2, cutover_time)",
        "let cutover_time = succ_t(iat2) in",
        "Only paper w4 deploys NewCert.",
        "MigrationJointCutover(",
        "same coordinated symbolic w4 transition",
        "MigrationPolicyPairAllowed(",
        "MigrationPhaseElapsed(window_overlap_1, iat2)",
        "MigrationPhaseElapsed(window_overlap_2, iat3)",
        "RollbackRejected(token_type_claim",
        "RollbackRejected(token_type_key",
    )
    forbid(
        cache,
        "out(migration_key_delivery, token_k)",
        "out(migration_current_delivery, token0)",
        "let cutover_time = iat2 in",
        "bridge_claim_key",
        "let (=succ_t(succ_t(iat1))) = exp1 in",
        "let (=succ_t(succ_t(iat2))) = exp2 in",
        "get_scope(",
    )
    require(
        rotation,
        "header_matches(h_old, pk_old)",
        "header_matches(h_new, pk_new)",
        "jws_dual_verify1(token1, pk_old)",
        "jws_dual_verify2(token1, pk_new)",
        "HighestIatTransferred",
        "in(c, replay_token:",
    )
    forbid(rotation, "rotation_old_delivery, (pk_old, pk_new, token0")


def check_benchmarks():
    apk_builder = ROOT / "gen-signed-apks.py"
    require(apk_builder, "default=24", "--max-workers={args.workers}")
    for filename in (
        "run-avgveriftime-benchmark.sh",
        "run-avgvisittime-benchmark.sh",
        "run-robustness-benchmark.sh",
    ):
        path = ROOT / filename
        require(path, "gen-trust-artifacts.py", "gen-signed-apks.py")
        forbid(path, "fastboot", "/mnt/code/aosp-main", "m systemimage")
    require(
        ROOT / "run-robustness-benchmark.sh",
        "post-restart-old-tc-replay.csv",
        "post-restart-old-tk-replay.csv",
        "clock-rollback.csv",
        "cross-app-concurrent-cache.csv",
        "parallel-cold-refresh.csv",
        "delegation-expiry.csv",
        "preflight-real-claim-refresh.csv",
        "--workers 24",
        '"$SCRIPT_DIR/realserver/etc/cert/es256/real-chain.pem"',
    )

    aosp_service = Path(
        "/mnt/code/aosp-main/aosp/frameworks/base/services/core/java/"
        "com/android/server/aspin/AspinService.java"
    )
    if aosp_service.is_file():
        require(
            aosp_service,
            "enforceTargetVisible(checkedTargetPackageName, callingUid, callingUserId)",
            "packageManagerInternal.filterAppAccess(packageName, callingUid, userId)",
            "claimIdentityKey(claim)",
            "Math.min(tkTimes.expMillis, tcTimes.expMillis)",
            "keyDigest(cachedClaimKey.key)",
            "candidate.claimKeyDigest.equals(claimKeyDigest)",
            "prepareHighestSeenUpdateLocked(",
            "ArrayMap<String, RefreshLock> mRefreshLocks",
            "sanMatchesHostname(san, hostname)",
            'Set.of("payload", "signatures")',
            'Set.of("protected", "signature")',
            'Set.of("alg", "kid")',
            'verifyJws(tkToken, signer.currentKey, MAX_SIGNATURES)',
            'verifyJws(tcToken, claimKey, 1)',
            '"sha256".equals(hashName)',
            '"sha384".equals(hashName)',
            "expectedLength = 32",
            "expectedLength = 48",
            "InetAddress.getAllByName(hostname)",
            "isSpecialUseAddress(address)",
            "openConnection(Proxy.NO_PROXY)",
            'connection.setRequestProperty("Host", httpHostHeader(hostname))',
            "ensurePersistentStateAvailableLocked()",
            "mPersistentStateAvailable = false",
            "all ASPin queries will fail closed until the state is repaired",
        )
        forbid(
            aosp_service,
            "checkAndUpdateHighestLocked(signer, hostname, TOKEN_TYPE_CLAIM",
            "synchronized (mLock) {\n            return getCertificateClaimLocked",
            'CLAIM_KEY_PATH = "/.well-known/ClaimSigningKey.jwt"',
            'CERT_CLAIM_PATH = "/.well-known/ServerCertClaim.jwt"',
            'header.has("pubkey")',
            'header.optJSONObject("jwk")',
            'header.optJSONArray("x5c")',
        )


def main():
    check_tex()
    check_signing()
    check_apps()
    check_proverif()
    check_benchmarks()
    print("TeX, App, signing, ProVerif, and benchmark implementations are consistent.")


if __name__ == "__main__":
    main()
