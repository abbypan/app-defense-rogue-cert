#!/usr/bin/env python3
"""Fail when TeX, App, signing, ProVerif, or benchmark semantics drift."""

import base64
import hashlib
import re
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
            label = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
            fail(f"{label} is missing {fragment!r}")


def require_across(paths, *fragments):
    value = "\n".join(text(path) for path in paths)
    for fragment in fragments:
        if fragment not in value:
            joined = ", ".join(str(path.relative_to(ROOT)) for path in paths)
            fail(f"{joined} are missing {fragment!r}")


def require_patterns(path, *patterns):
    value = text(path)
    for pattern in patterns:
        if re.search(pattern, value, flags=re.IGNORECASE) is None:
            fail(f"{path.relative_to(ROOT)} does not match {pattern!r}")


def require_patterns_across(paths, *patterns):
    value = "\n".join(text(path) for path in paths)
    for pattern in patterns:
        if re.search(pattern, value, flags=re.IGNORECASE) is None:
            joined = ", ".join(str(path.relative_to(ROOT)) for path in paths)
            fail(f"{joined} do not match {pattern!r}")


def forbid(path, *fragments):
    value = text(path)
    for fragment in fragments:
        if fragment in value:
            fail(f"{path.relative_to(ROOT)} contains obsolete form {fragment!r}")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_tex():
    paper = ROOT / "tex" / "paper_content.tex"
    appendix = ROOT / "tex" / "paper_appendix.tex"
    abstract = ROOT / "tex" / "paper_abstract-sigconf.tex"
    require_patterns(
        paper,
        r"latest authenticated installed version",
        r"OS returns failure, not a successful cached claim",
        r"app choice outside ASPin's protected path",
        r"future extension.*Google Play Store",
        r"denial of service \(DoS\)",
        r"signed time-to-live \(TTL\)",
        r"no OS-wide lifetime ceiling",
    )
    require(
        abstract,
        "all 1,280 measured attempts have the expected outcome",
        "independent NSC-based DCP",
        "data are sent only after all three succeed",
    )
    require_across(
        (paper, appendix),
        r"T_k&=(K_{cpub},iat_k,exp_k)",
        r"T_c&=(Subject,SAN,IssuerSet,iat_c,exp_c)",
        "Subject and SAN identify the $T_c$ anti-rollback partition",
        "Only the signed SAN authorizes hostnames",
        "App~A is the Target App and supplies only its server hostname",
        "App~B is the Target App",
        "intentionally names App~B and B's server hostname",
        "The caller never supplies the key",
        r"\textbf{Third-party service}",
        r"\textbf{App redistribution}",
        "CT & log keys & yes & no (audit) & OS & no",
        "SCP & fixed pin & no & yes & app & Certificate/CA change",
        "DCP & separate key & optional & yes & app & DCP key update",
        "That signature covers the manifest and thereby authenticates",
        "rather than maintaining a separate manifest-root store",
        r"the mode does not transfer rollback floors across $K_s$ replacements",
        "iat_k \\leq t_{\\mathrm{now}} < exp_k",
        "iat_c \\leq t_{\\mathrm{now}} < exp_c",
        r"IssuerId_H(c)=\mathrm{name}(H)",
        r"H\!\left(\mathrm{DER}(CA(c))\right)",
        r"\texttt{hash-name:}\allowbreak\texttt{hash-value}",
        "must return the exact ordered path it actually accepted",
        "never the raw peer-supplied certificate array",
        "Android's host-aware \\texttt{checkServer}\\allowbreak\\texttt{Trusted}",
        "supplies the native-validated ordered path",
        "supplies the native-validated ordered path to \\emph{CertClaimCheck}",
        "General JWS JSON Serialization",
        "one encoded payload and one or more signature entries",
        "The hostname does not select the policy owner",
        "The OS-verified signing identity defines the ASPin owner and trust domain",
        "Packages signed with the same identity share cache and anti-rollback state",
        "For each $(K_{apub},h)$, the publisher keeps at most one fresh canonical Subject/SAN partition",
        r"$w_2$ & $T_c^{(2)}$ & CurrCert & CurrCA+NewCA",
        r"$w_3$ & $T_c^{(3)}$ & NewCert & NewCA",
        r"jointly publishes $T_c^{(3)}$ and deploys \emph{NewCert}",
        r"\emph{overlap} concerns CA identifiers, not cross-cutover validity",
        "operator staging and advance notice",
        "operator-staged CA migration",
        "At every query, the OS-level ASPin service resolves the Target App's package name using its latest authenticated installed version",
        "The Target App's current app-signing certificate supplies $K_{apub}$",
        r"This is an ordering property, not policy rejection",
        "names the delegated public key that authenticated the cached $T_c$",
        "retrieves and authenticates fresh $T_k$ once and retries $T_c$ exactly once",
        "a second $T_c$ failure rejects the query",
        "The persistent highest-seen values continue to govern later replacements after cache eviction",
        "until the cached old $T_k$ expires",
        "checks their signatures, freshness, hostname authorization, and rollback state",
        "the native trust manager validates the certificate chain",
        "The claim must be unexpired at check time",
        "Only after both tokens pass all required checks does it atomically persist their issuance times",
        "Cache expiry forces refresh or refusal, not latest-policy adoption",
        "a missing, invalid, stale, or unavailable JWS makes the query fail",
        r"$w_2$ & $T_c^{(2)}$ & CurrCert & CurrCA+NewCA & $L_{\max}$ staging interval",
        "recovery is future work",
        "deleting protected state is invalid",
        r"\emph{CertClaimCheck} fails when the protected clock reaches $exp_f$",
        r"returns the claim together with $exp_f=\min(exp_k,exp_c)$",
        "All 1,280 measured attempts across the complete matrix had the expected outcome",
        "path or claim failure aborts the handshake",
        "performs hostname verification before connection use or data",
        "The app proceeds only after all three checks succeed",
        "representative app-provisioned DCP systems considered here",
        "Compromising an artifact-only mirror affects availability",
        "not rollback-resistant time",
        "The bounded cached-key retry remains unmeasured",
        "No historical local measurements enter the tables or summaries",
        "serialized response-body bytes, excluding HTTP headers",
        "before the ASPin, SCP, or DCP supplementary check",
        r"\textbf{Accepted}",
    )
    require_patterns_across(
        (paper, appendix),
        r"Server audits (?:require|confirm) no (?:business requests or )?metadata retrieval during the measured cache runs",
    )
    require_patterns(
        abstract,
        r"Across 64 (?:direct-Internet )?test cells",
    )
    require_patterns_across(
        (paper, appendix),
        r"same hostname may appear in multiple signing-key collections",
        r"trusted operator's deployment-profile upper bound on \$T_c\$ lifetime",
        r"\$exp_c-iat_c\\leq L_\{\\max\}\$",
        r"overlap publication, the operator sets \$exp_c-iat_c=L_\{\\max\}\$",
    )
    # Appendix D summarizes results in tables; detailed symbolic encodings are
    # documented separately without relaxing the manuscript's design checks.
    lifecycle_spec = ROOT / "spec" / "proverif-lifecycle.md"
    require(
        lifecycle_spec,
        r"migration model uses one symbolic step for $L_{\max}$",
        r"full-$L_{\max}$ phase-elapsed event",
    )
    require_patterns(
        lifecycle_spec,
        r"private phase markers encode the trusted operator's compliance with the recommended schedule",
    )
    forbid(
        paper,
        r"IssuerId(c)=\mathrm{b64url}(N_c)",
        r"\mathrm{DER}(c.issuer)",
        "No separate scope field is needed",
        "Thus two apps may claim the same hostname without crossing cache entries",
        "assigns exactly one logical ASPin policy owner to each hostname",
        "one logical policy owner for each hostname",
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
        "protected epoch $t_r$",
        r"$iat_k\geq t_r$",
        "opens TLS only after both checks",
        "33.10--40.14",
        "0.83--1.46",
        "2,558--2,735",
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
    require(
        ROOT / "signing" / "cosign_claim_signing_key.py",
        'action="append"',
        'nargs=3',
        'general["signatures"].append(signature)',
        'hashlib.sha256(public_der).digest()',
    )
    compatible_generator = ROOT / "signing" / "gen_compat_ClaimSigningKey.py"
    require(
        compatible_generator,
        'Path("my-dcp-key.pem")',
        '"my-dcp-pubkey.pem"',
        'Path("ClaimSigningKey.compat.jws")',
        '"cnf": {"jwk": claim_public_jwk}',
        '"signatures": [signature]',
    )
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
            '"issuer": issuers',
            "issuer_certificate.public_bytes(serialization.Encoding.DER)",
            'return f"{hash_name}:{value}"',
            "direct_issuer_certificates(certificate, chain)",
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
        gradle = ROOT / "ASPin" / variant / "app" / "build.gradle"
        manifest = base / "AndroidManifest.xml"
        require(
            gradle,
            'applicationId "com.cert.aspin"',
            'buildConfigField "String", "BENCHMARK_MODE", \'"scp"\'',
            'buildConfigField "String", "BENCHMARK_MODE", \'"dcp"\'',
            "aspinPolicyPublicKey:",
            'main.java.srcDir "../../shared/src/main/java"',
        )
        require(manifest, '<package android:name="com.cert.aspin"')
        pin_path = ROOT / "signing" / variant / "my-app-cert-scp-hash.txt"
        try:
            pin = base64.b64decode(text(pin_path).strip(), validate=True)
        except ValueError as error:
            fail(f"invalid Base64 SCP pin in {pin_path.relative_to(ROOT)}: {error}")
        if len(pin) != 32:
            fail(f"SCP pin is not a SHA-256 digest in {pin_path.relative_to(ROOT)}")
        require(
            ROOT / "ASPin" / variant / "app" / "src" / "scpBenchmark"
            / "res" / "xml" / "network_security_config.xml",
            "<pin-set>",
            '<pin digest="SHA-256">',
            f"{variant}.idouzi.top",
        )
        require(
            ROOT / "ASPin" / variant / "app" / "src" / "dcpBenchmark"
            / "AndroidManifest.xml",
            "android.security.dcp.POLICY_PUBLIC_KEY",
            "${dcpPolicyPublicKey}",
        )
        require(
            ROOT / "ASPin" / variant / "app" / "src" / "dcpBenchmark"
            / "res" / "xml" / "network_security_config.xml",
            "<dynamic-pin-set />",
            f"{variant}.idouzi.top",
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

    require(
        ROOT / "ASPin" / "shared" / "src" / "main" / "java" / "com"
        / "cert" / "aspin" / "ExperimentBenchmark.java",
        '"ASPin-primary"',
        '"SCP-NSC"',
        '"DCP-NSC"',
        '"ASPin-compatible"',
        "createStandardTLSConnection(host)",
        "createASPinConnection(host, claim)",
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
        "type jws_signature_list.",
        "jws_array_member(entry, tail) ->",
        "header_matches(header, context_key)",
        "sig_verify(jws_tosign(header, payload), signature, context_key)",
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
        "token_fresh(key_iat, key_exp, iat2)",
        "token_fresh(key_iat, key_exp, cutover_time)",
        "let exp1 = succ_t(iat1) in",
        "let exp2 = succ_t(iat2) in",
        "let (=ttl_one) = derive_ttl(iat1, exp1) in",
        "let (=ttl_one) = derive_ttl(iat2, exp2) in",
        "token_expired(exp0, iat1)",
        "token_expired(exp1, iat2)",
        "token_expired(exp1, cutover_time)",
        "let cutover_time = succ_t(iat1) in",
        "Only paper w3 deploys NewCert.",
        "MigrationJointCutover(",
        "same coordinated",
        "MigrationPolicyPairAllowed(",
        "MigrationPhaseElapsed(window_overlap, iat2)",
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
        "window_overlap_1",
        "window_overlap_2",
        "token_c_3",
        "paper w4",
        "Paper w4",
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
    subprocess.run(
        [sys.executable, str(ROOT / "proverif" / "generate_compatible_models.py"),
         "--check"],
        check=True,
    )
    for suffix in (
        "cache", "ca_migration", "claim_key_rotation", "root_rotation",
        "certificate_change", "cross_hostname_hc", "cross_sign", "multisig",
    ):
        compatible = ROOT / "proverif" / f"aspin_compat_{suffix}.pv"
        require(compatible, "event ManifestKeyBind(", "event ManifestKeyResolve(",
                "event AppManifestAuthenticated(", "event AppManifestSigned(")
        forbid(compatible, "resolve_os_key(", "OSManifestRootHistory",
               "ManifestUpdateAuthenticated")


def check_benchmarks():
    require(ROOT / "ASPin/shared/src/main/java/com/cert/aspin/CrossSignBenchmark.java",
            "extension.checkServerTrusted(peer, authType, host)",
            "observed.selected = identifier(selected[1])", "observed.sawExtra = true",
            "ASPinVerifier.verifyCertificate(host, claim, selected)",
            "observed.nativeValid && observed.policyChecked")
    require(ROOT / "summarize-lifecycle-results.py", "validate_cross_sign(rows, filename, root)",
            'Native_Valid="true"', "expected_issuer", 'expected["Extra_Seen"] = "true"')
    require(ROOT / "run-policy-scenario-benchmark.sh", "ASPIN_POLICY_SCENARIOS_ONLY=1")
    require(ROOT / "run-policy-scenario-matrix.py", '"primary", "compatible"',
            '"tk-bound", "tc-bound"', '"cross-invisible"', '"cross-uninstalled"',
            '"cross-substituted-root"', 'link.set_policy_transport("503")',
            'link.set_policy_transport("timeout")', '"Observed_App_Requests"',
            '"ordinary-expired-self"', '"debug-egress-denied"')
    require(ROOT / "ASPin/shared/src/main/java/com/cert/aspin/PolicyScenarioBenchmark.java",
            'OsAspinClient.getCertificateClaimForApp', 'PolicyScenarioChecks.matchesLookupFailure',
            'connection.connect()', '"X-ASPin-Observation"', 'Files.move(pending.toPath()')
    rtt = ROOT / "ASPin/shared/src/main/java/com/cert/aspin/RttCacheBenchmark.java"
    require(rtt, '"cold-forced-refresh"', '"hot-no-fetch"', '"two-token-refresh"',
            'connection.connect()', 'Files.move(pending.toPath()',
            'RttBenchmarkChecks.isPolicyRejection(error, scheme)',
            'Echo_RTT_P50_ms,Echo_RTT_P95_ms')
    require(ROOT / "run-rtt-cache-benchmark.sh", 'ASPIN_RTT_MATRIX_ONLY=1',
            'ASPIN_ADB_REVERSE_TRANSPORT=1', 'ASPIN_GENERATE_ROGUE_CA=1')
    require(ROOT / "run-robustness-benchmark.sh", 'ASPIN_RTT_MATRIX_ONLY:-0',
            'run-rtt-cache-matrix.py', 'ASPIN_RTT_VALUES_MS:-0,20,50,100,200')
    require(ROOT / "benchmark_rtt_network.py", 'self.host_interface',
            'self.peer_interface', 'milliseconds / 2', '"netns", "add"')
    apk_builder = ROOT / "gen-signed-apks.py"
    require(
        apk_builder,
        "default=24",
        "--max-workers={args.workers}",
        'choices=VARIANTS',
        'variants = args.variant or VARIANTS',
        '"scp": ("scpBenchmark", "-scp")',
        '"dcp": ("dcpBenchmark", "-dcp")',
    )
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
    require(
        ROOT / "run-avgvisittime-benchmark.sh",
        "--mode primary --mode scp --mode dcp",
        'run_one "$ALG" "$MODE" realserver',
        'run_one "$ALG" "$MODE" rogueserver',
        'activate-claim-signing-key.sh" "$alg" compat',
    )
    require(
        ROOT / "run-avgveriftime-benchmark.sh",
        "--mode primary --mode compatible",
        'run_one "$ALG" primary',
        'run_one "$ALG" compatible',
    )
    require(
        ROOT / "generate-lifecycle-artifacts.py",
        'subparsers.add_parser("ca-migration")',
        'subparsers.add_parser("claim-key-rotation")',
        'subparsers.add_parser("app-key-rotation")',
        'subparsers.add_parser("cross-sign")',
        '"tc-w2-overlap.jws"',
        '"tk-r2-dual.jws"',
        '"tk-r3-new-only.jws"',
    )
    require(
        ROOT / "run-lifecycle-benchmark.sh",
        'ASPIN_MIGRATION_LMAX_SECONDS:-30',
        '--variant es256 --mode primary',
        'ca-w1-new-cert-rejected',
        'ca-w2-new-cert-authorized',
        'ca-w3-current-cert-rejected',
        'claim-key-old-tk-new-tc-rejected',
        'claim-key-new-tk-old-tc-rejected',
        'claim-key-r1-replay-rejected',
        'app-key-r2-dual',
        'app-key-r3-new-only',
        'app-key-r2-replay-rejected',
        '--v1-signing-enabled false --v2-signing-enabled false',
        'summarize-lifecycle-results.py',
        'cross-sign-complete-b',
        'cross-sign-incomplete-b-rejected',
        'cross-sign-padding-rejected',
    )
    require(
        ROOT / "summarize-lifecycle-results.py",
        '"CA migration"',
        '"Claim-key rotation"',
        '"App-key rotation"',
        '"Cross-sign"',
        '"table_lifecycle_transitions.csv"',
    )
    require(
        ROOT / "run-cross-sign-benchmark.py",
        'for mode, suffix in (("primary", ""), ("compatible", "-compatible"))',
        'validator.validate_cross_sign(',
        'business = audit_requests(',
        'refresh_restored_policies(',
    )
    require(
        ROOT / "ASPin/shared/src/main/java/com/cert/aspin/CrossSignBenchmark.java",
        'OsAspinClient.refreshCertificateClaim(context, host)',
        'extension.checkServerTrusted(peer, authType, host)',
        'X-ASPin-Observation',
        'ASPinVerifier.verifyCertificate(host, claim, selected)',
    )
    require(
        ROOT / "summarize-cross-sign-results.py",
        'token.verify(key)',
        'leaf.verify_directly_issued_by(a); leaf.verify_directly_issued_by(b)',
        'VALIDATOR.validate_cross_sign(',
        'RUNNER.audit_requests(',
    )
    require(
        ROOT / "request-public-cross-certificates.py",
        'prepare_csr(', 'configure_a(', 'ACME.selected_account(',
        '"--csr", str(csr), "--private-key", str(key)',
    )
    require(
        ROOT / "run-public-cross-benchmark.py",
        'system_roots_only()', 'protocol.prepare(', 'audit_public_requests(',
        '"--mode", "public-primary", "--mode", "public-compatible"',
        '"--signal=USR2"',
    )
    require(
        ROOT / "summarize-public-cross-results.py",
        'selected[0] != leaf or selected[1] != issuer',
        'if identifiers[-1] not in trusted',
        '"direct_issuer_cross_signing_tested": False',
    )
    forbid(
        ROOT / "run-lifecycle-benchmark.sh",
        "fastboot",
        "m systemimage",
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
            "keyDigest(key.key)",
            "candidate.claimKeyDigest.equals(claimKeyDigest)",
            "prepareHighestSeenUpdateLocked(",
            "final long commitNowMillis = System.currentTimeMillis()",
            "ensureFresh(tkTimes, commitNowMillis)",
            "ensureFresh(tcTimes, commitNowMillis)",
            "ArrayMap<String, RefreshLock> mRefreshLocks",
            "sanMatchesHostname(san, hostname)",
            'Set.of("payload", "signatures")',
            'Set.of("protected", "signature")',
            'Set.of("alg", "kid")',
            'selectTokenRoot(tkToken, signers)',
            'verifyJws(token, root.currentKey, false)',
            'roots.add(new SignerIdentity(current, lineage))',
            'roots.add(new SignerIdentity(policyKey, List.of(policyKey)))',
            'verifyJws(tcToken, claimKey, true)',
            'boolean requireSingleSignature',
            'requireSingleSignature && signatures.length() != 1',
            '"sha256".equals(hashName)',
            '"sha384".equals(hashName)',
            "expectedLength = 32",
            "expectedLength = 48",
            "InetAddress.getAllByName(hostname)",
            "isSpecialUseAddress(address)",
            "openConnection(Proxy.NO_PROXY)",
            "HttpsURLConnection connection",
            "resolveNativeTrustManager(targetPackageName)",
            "ApplicationConfig.createInstanceForPackage(",
            "android.security.aspin.POLICY_PUBLIC_KEY",
            "publicKeyFromManifest(encodedPolicyKey)",
            "ensurePersistentStateAvailableLocked()",
            "mPersistentStateAvailable = false",
            "all ASPin queries will fail closed until the state is repaired",
            "if (!(value instanceof Integer) && !(value instanceof Long))",
            'throw new JSONException(name + " must be a JSON integer")',
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
            'Long.parseLong((String) value)',
            'MAX_SIGNATURES',
            'maximumSignatures',
        )

        nsc_root = Path(
            "/mnt/code/aosp-main/aosp/frameworks/base/packages/"
            "NetworkSecurityConfig/platform/src/android/security/net/config"
        )
        require(
            nsc_root / "XmlConfigSource.java",
            '"dynamic-pin-set".equals(tagName)',
            "setDynamicPinningEnabled(true)",
            "Static and dynamic pin sets are mutually exclusive",
        )
        require(
            nsc_root / "NetworkSecurityTrustManager.java",
            "checkDynamicPins(chain, hostname)",
            "new DcpPinningVerifier(config.getDcpVerificationKey(), mDelegate)",
        )
        require(
            nsc_root / "DcpPinningVerifier.java",
            "DCPServerCertPin.jws",
            "mNativeTrustManager",
            '"Dynamic pin verification failed"',
        )
        require(nsc_root / "XmlConfigSource.java", "android.security.dcp.POLICY_PUBLIC_KEY")
        forbid(nsc_root / "NetworkSecurityTrustManager.java", "IAspinService", "getOwnCertificateClaim")
        active_nsc = Path("/mnt/code/aosp-main/aosp/external/conscrypt/nsc/src/android/security/net/config")
        require(active_nsc / "XmlConfigSource.java", "dynamic-pin-set", "android.security.dcp.POLICY_PUBLIC_KEY")
        require(active_nsc / "NetworkSecurityTrustManager.java", "new DcpPinningVerifier", "checkStaticPins(chain)")
        require(active_nsc / "DcpPinningVerifier.java", "DCPServerCertPin.jws", "Build.isDebuggable()")


def main():
    check_tex()
    check_signing()
    check_apps()
    check_proverif()
    check_benchmarks()
    print("TeX, App, signing, ProVerif, and benchmark implementations are consistent.")


if __name__ == "__main__":
    main()
