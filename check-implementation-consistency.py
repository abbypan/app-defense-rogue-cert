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
    require(
        paper,
        r"T_k&=(K_{cpub},iat_k,exp_k)",
        r"T_c&=(Subject,SAN,IssuerSet,iat_c,exp_c)",
        "No separate scope field is needed",
        "supplies only A's server hostname",
        "intentionally names App~B and B's server hostname",
        "the caller never supplies the key",
        "iat_k \\leq t_{\\mathrm{now}} < exp_k",
        "iat_c \\leq t_{\\mathrm{now}} < exp_c",
        "DER}(c.issuer)",
    )


def check_signing():
    for variant in VARIANTS:
        directory = ROOT / "signing" / variant
        tk_generator = directory / "gen_jwt_ClaimSigningKey.py"
        tc_generator = directory / "gen_jwt_ServerCertClaim.py"
        require(tk_generator, '"alg": algorithm', '"kid":', '"cnf": {"jwk":')
        require(
            tc_generator,
            '"subject": subject',
            '"san": sans',
            '"issuer": [issuer]',
            "certificate.issuer.public_bytes()",
        )
        forbid(tk_generator, '"pubkey":', '"ttl":', '"scope":', '"host":')
        forbid(tc_generator, '"pubkey":', '"ttl":', '"scope":', '"host":')
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
        client = java / "OsAspinClient.java"
        https = java / "HttpsConn.java"
        main = java / "MainActivity.java"
        gradle = ROOT / "ASPin" / variant / "app" / "build.gradle"
        manifest = base / "AndroidManifest.xml"
        require(gradle, 'applicationId "com.cert.aspin"')
        require(manifest, '<package android:name="com.cert.aspin"')
        require(
            client,
            'getCertificateClaim(Context context, String hostname)',
            'getCertificateClaimForApp(',
            'String targetAppId, String hostname',
            'context.getSystemService(SERVICE_NAME)',
            'ASPinVerifier.sameHostname(hostname, returnedHostname)',
        )
        forbid(client, "PublicKey", "appSigningKey", "callerKey")
        require(
            verifier,
            "sameHostname(connectionHostname, claim.host)",
            "hostMatchesClaim(",
            "issuerIdentifier(certificate)",
            "certificate.getIssuerX500Principal()",
        )
        forbid(
            verifier,
            'json.optString("host"',
            "certificateDnsNames",
            "distinguishedNamesEqual",
        )
        require(
            https,
            "defaultTrustManager.checkServerTrusted(chain, authType);",
            "ASPinVerifier.verifyCertificate(host, claim, certificate)",
            "new InputStreamReader(con.getInputStream())",
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
            '"https://" + host + "/.well-known/ClaimSigningKey.jwt"',
            '"https://" + host + "/.well-known/ServerCertClaim.jwt"',
            "JwtVerifier.verifyJwtWithCert(csjwt",
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
        "jwt_payload(bitstring, timestamp, timestamp)",
        "package_signing_record(bitstring, pkey)",
        "token_fresh(",
        "derive_ttl(",
    )
    forbid(base, "get_scope(", "jwt_payload(bitstring, timestamp, ttl)")
    require(
        cache,
        "resolve_platform_key(target_record, target_app_id)",
        "in(c, jwt(hk:",
        "in(c, jwt(h0:",
        "token_fresh(key_iat, key_exp, iat3)",
        "RollbackRejected(token_type_claim",
        "RollbackRejected(token_type_key",
    )
    forbid(
        cache,
        "out(migration_key_delivery, token_k)",
        "out(migration_current_delivery, token0)",
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
        "--workers 24",
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
