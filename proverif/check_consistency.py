#!/usr/bin/env python3
"""Check that the ProVerif sources/results implement the current TeX design."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
TEX = ROOT.parent / "tex" / "paper_content.tex"

ASPIN_NETWORK_MODELS = (
    "aspin_dns_hijacking.pv",
    "aspin_bgp_hijacking.pv",
    "aspin_mitm.pv",
)

TEX_FRAGMENTS = (
    r"\subsubsection{ClaimKeySign}",
    r"\subsubsection{CertClaimSign}",
    r"\subsubsection{ClaimKeyVerify}",
    r"\subsubsection{CertClaimVerify}",
    r"\subsubsection{CertClaimCheck}",
    r"iat_k \leq t_{\mathrm{now}} < exp_k",
    r"iat_c \leq t_{\mathrm{now}} < exp_c",
    r"signature covers $K_{cpub}$, $iat_k$, and $exp_k$",
    r"signature covers $Claim$, $iat_c$, and $exp_c$",
    "requested server hostname to be covered by the signed server identity",
    "highest issuance time previously accepted",
    r"\mathrm{Cache}[K_{apub}]",
    "For each app-signing-key, requested-hostname, and token-type tuple",
    "keeps $T'_c$ available for at least two complete freshness windows",
    "both $sig_k^{old}$ and $sig_k^{new}$ over the identical transitional payload",
    r"\caption{ProVerif Outputs for Rogue Certificates with Unexpected Issuer Names}",
    r"\caption{ProVerif Outputs for Claim Caching, Migration, Rollback, and Key Rotation}",
    r"For $\neg\,event(E)$",
    r"is also \texttt{true}, but is vacuous",
    r"\texttt{not event(CrossSigningKeyCacheHit(...))}",
    r"\texttt{not event(CrossHostnameCacheHit(...))}",
    r"\texttt{not event(OldOnlyTokenAcceptedByNewKey(...))}",
    "Separate private phase-delivery channels",
)

NETWORK_MODEL_FRAGMENTS = (
    "get_iat(",
    "get_exp(",
    "header_matches(",
    "jwt_sig_verify(",
    "token_fresh(",
    "derive_ttl(",
    "get_subject_and_san(",
    "get_issuer(",
    "check_host(hostname,",
)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_fragments(path: Path, fragments: tuple[str, ...]) -> None:
    text = path.read_text(encoding="utf-8")
    for fragment in fragments:
        if fragment not in text:
            fail(f"{path.relative_to(ROOT.parent)} is missing: {fragment}")


def require_no_fragments(path: Path, fragments: tuple[str, ...]) -> None:
    text = path.read_text(encoding="utf-8")
    for fragment in fragments:
        if fragment in text:
            fail(f"{path.relative_to(ROOT.parent)} contains obsolete/unsafe form: {fragment}")


def result_lines(path: Path) -> list[str]:
    if not path.exists():
        fail(f"missing ProVerif result log: {path.relative_to(ROOT.parent)}")
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.startswith("RESULT ")
    ]


def find_result(lines: list[str], *terms: str) -> str:
    matches = [line for line in lines if all(term in line for term in terms)]
    if len(matches) != 1:
        fail(f"expected one RESULT containing {terms}, found {len(matches)}")
    return matches[0]


def require_outcome(lines: list[str], terms: tuple[str, ...], outcome: str) -> None:
    line = find_result(lines, *terms)
    if not line.endswith(outcome):
        fail(f"unexpected result:\n  {line}\nexpected suffix: {outcome}")


def check_sources() -> None:
    require_fragments(TEX, TEX_FRAGMENTS)
    require_fragments(
        ROOT / "base.pvl",
        (
            "jwt_payload(bitstring, timestamp, timestamp)",
            "get_iat(jwt_payload",
            "token_fresh(t, succ_t(t), t) = true",
            "derive_ttl(t, succ_t(t)) = ttl_one",
            "iat_older(t, succ_t(t)) = true",
            "token_expired(t, t) = true",
            "jws_dual_sign",
        ),
    )
    require_no_fragments(
        ROOT / "base.pvl",
        (
            "jwt_payload(bitstring, timestamp, ttl)",
            "get_scope(",
            "jwt_verify(",
            "get_ttl(jwt_payload",
            "token not expired",
        ),
    )

    for model_name in ASPIN_NETWORK_MODELS:
        model = ROOT / model_name
        require_fragments(model, NETWORK_MODEL_FRAGMENTS)
        require_no_fragments(
            model,
            ("let true =", "jwt_verify(", "get_ttl(", "get_scope(", "good_ttl"),
        )

    require_fragments(
        ROOT / "aspin_cache.pv",
        (
            "cache_entry(app_key, content, iat, exp)",
            "read_cached_claim(entry, other_key, iat)",
            "read_cached_claim(entry, app_key, iat)",
            "other_hostname, get_migration_identity(result)",
            "check_host(server_hostname, identity0)",
            "MigrationTransitionAvailable(window_overlap_1)",
            "MigrationTransitionAvailable(window_overlap_2)",
            "token_fresh(old_iat, common_exp, new_iat)",
            "iat_older(old_iat, new_iat)",
            "token_expired(exp, exp)",
        ),
    )
    require_no_fragments(
        ROOT / "aspin_cache.pv",
        ("let true =", "jwt_verify(", "get_ttl(", "get_scope(", "window_final"),
    )
    require_fragments(
        ROOT / "aspin_key_rotation.pv",
        (
            "jws_dual_sign",
            "jws_dual_verify1",
            "jws_dual_verify2",
            "token_fresh(old_iat, old_exp, iat2)",
            "iat_older(old_iat, iat2)",
            "OldOnlyTokenAcceptedByNewKey",
        ),
    )
    require_no_fragments(
        ROOT / "aspin_key_rotation.pv",
        ("let true =", "jwt_verify(", "get_ttl(", "get_scope("),
    )


def check_common_aspin(lines: list[str]) -> None:
    require_outcome(lines, ("not event(RSAccept(",), "is false.")
    require_outcome(lines, ("not event(AppConnRS(",), "is false.")
    require_outcome(lines, ("not event(AppReject(",), "is false.")
    require_outcome(
        lines, ("event(RSAccept(", "==> event(AppConnRS("), "is true."
    )
    require_outcome(lines, ("not event(MSAccept(",), "is true.")
    require_outcome(lines, ("not event(AppConnMS(",), "is true.")
    require_outcome(
        lines, ("event(MSAccept(", "==> event(AppConnMS("), "is true."
    )
    require_outcome(
        lines, ("event(ClaimKeyVerify(", "==> event(ClaimKeySign("), "is true."
    )
    require_outcome(
        lines,
        ("event(CertClaimVerify(pk(claim_sk)", "==> event(CertClaimSign("),
        "is true.",
    )


def check_tls_baseline(kind: str) -> None:
    lines = result_lines(ROOT / "result" / f"tls_{kind}.log")
    require_outcome(lines, ("not event(RSAccept(",), "is false.")
    require_outcome(lines, ("not event(AppConnRS(",), "is false.")
    require_outcome(lines, ("not event(AppReject(",), "is true.")
    require_outcome(lines, ("not event(MSAccept(",), "is false.")
    require_outcome(lines, ("not event(AppConnMS(",), "is false.")


def check_network_models() -> None:
    for kind in ("dns_hijacking", "bgp_hijacking", "mitm"):
        aspin = result_lines(ROOT / "result" / f"aspin_{kind}.log")
        check_common_aspin(aspin)
        check_tls_baseline(kind)

    aspin_mitm = result_lines(ROOT / "result" / "aspin_mitm.log")
    require_outcome(aspin_mitm, ("not event(MSConnRS(",), "is true.")
    tls_mitm = result_lines(ROOT / "result" / "tls_mitm.log")
    require_outcome(
        tls_mitm,
        ("event(RSAccept(", "==> event(AppConnRS("),
        "cannot be proved.",
    )
    require_outcome(
        tls_mitm,
        ("event(MSAccept(", "==> event(AppConnMS("),
        "cannot be proved.",
    )


def check_cache_migration() -> None:
    lines = result_lines(ROOT / "result" / "aspin-cache.log")
    require_outcome(
        lines,
        ("event(MigrationClaimCached(", "==> event(MigrationClaimPublished("),
        "is true.",
    )
    require_outcome(
        lines,
        ("event(MigrationClaimReturned(", "==> event(MigrationClaimAuthenticated("),
        "is true.",
    )
    for prerequisite in (
        "MigrationNewCertObtained(new_cert_issuer)",
        "MigrationTransitionAvailable(window_overlap_1)",
        "MigrationTransitionAvailable(window_overlap_2)",
    ):
        require_outcome(
            lines,
            ("event(MigrationCutover(", f"==> event({prerequisite}"),
            "is true.",
        )
    require_outcome(
        lines,
        (
            "event(MigrationCertAccepted(window_new_cert,new_cert_issuer,claim_transition_ca))",
            "event(MigrationClaimCached(window_overlap_2",
        ),
        "is true.",
    )
    for invalid in (
        "MigrationCertAccepted(window_new_cert,new_cert_issuer,claim_current_ca)",
        "MigrationCertAccepted(window_new_cert,real_cert_issuer,claim_new_ca)",
        "CrossSigningKeyCacheHit(",
        "CrossHostnameCacheHit(",
    ):
        require_outcome(lines, (f"not event({invalid}",), "is true.")

    require_outcome(lines, ("not event(RollbackRejected(",), "is false.")
    require_outcome(lines, ("not event(ExpiredTokenRejected(",), "is false.")
    require_outcome(lines, ("not event(EmergencyTokenRevoked(",), "is false.")
    require_outcome(
        lines,
        (
            "event(EmergencyReplacementAccepted(",
            "==> event(EmergencyReplacementPublished(",
        ),
        "is true.",
    )

    windows = (
        ("window_current", "real_cert_issuer", "claim_current_ca"),
        ("window_overlap_1", "real_cert_issuer", "claim_transition_ca"),
        ("window_overlap_2", "real_cert_issuer", "claim_transition_ca"),
    )
    for window, issuer, claim in windows:
        require_outcome(
            lines, (f"not event(MigrationWindowComplete({window}))",), "is false."
        )
        require_outcome(
            lines,
            (f"not event(MigrationCertAccepted({window},{issuer},{claim}))",),
            "is false.",
        )
        require_outcome(
            lines,
            (
                f"event(MigrationWindowComplete({window}))",
                f"event(MigrationCertAccepted({window},{issuer},{claim}))",
            ),
            "is true.",
        )
    require_outcome(
        lines,
        ("not event(MigrationWindowComplete(window_new_cert))",),
        "is false.",
    )
    for claim in ("claim_transition_ca", "claim_new_ca"):
        require_outcome(
            lines,
            (
                "not event(MigrationCertAccepted("
                f"window_new_cert,new_cert_issuer,{claim}))",
            ),
            "is false.",
        )
        require_outcome(
            lines,
            (
                "event(MigrationWindowComplete(window_new_cert))",
                "event(MigrationCertAccepted("
                f"window_new_cert,new_cert_issuer,{claim}))",
            ),
            "is true.",
        )


def check_key_rotation() -> None:
    lines = result_lines(ROOT / "result" / "aspin_key_rotation.log")
    for event in (
        "DualSigAppKeyVerify(",
        "KeyRotationNewAppVerified(",
        "KeyRotationCutoverVerified(",
        "KeyRotationOldReplayRejected(",
    ):
        require_outcome(lines, (f"not event({event}",), "is false.")
    require_outcome(
        lines, ("not event(OldOnlyTokenAcceptedByNewKey(",), "is true."
    )
    require_outcome(
        lines,
        ("event(KeyRotationNewAppVerified(", "==> event(KeyTokenPublished("),
        "is true.",
    )
    require_outcome(
        lines,
        ("event(KeyRotationCutoverVerified(", "==> event(KeyTokenPublished("),
        "is true.",
    )
    require_outcome(
        lines,
        (
            "event(KeyRotationOldReplayRejected(",
            "==> event(KeyRotationCutoverVerified(",
        ),
        "is true.",
    )


def main() -> None:
    check_sources()
    check_network_models()
    check_cache_migration()
    check_key_rotation()
    print("ProVerif sources, saved results, and TeX design are consistent.")


if __name__ == "__main__":
    main()
