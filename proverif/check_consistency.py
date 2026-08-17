#!/usr/bin/env python3
"""Check that the ProVerif sources/results implement the current TeX design."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent
TEX = ROOT.parent / "tex" / "paper_content.tex"

ASPIN_NETWORK_MODELS = (
    "aspin_dns_hijacking.pv",
    "aspin_bgp_hijacking.pv",
    "aspin_mitm.pv",
)

TEX_FRAGMENTS = (
    r"\subsubsection{Signing $T_k$}",
    r"\subsubsection{CertClaimSign}",
    r"\subsubsection{ClaimKeyVerify}",
    r"\subsubsection{CertClaimVerify}",
    r"\subsection{App-Controlled CertClaimCheck}",
    r"iat_k \leq t_{\mathrm{now}} < exp_k",
    r"iat_c \leq t_{\mathrm{now}} < exp_c",
    r"\emph{CertClaimCheck} fails when the protected clock reaches $exp_{eff}$",
    "signature covers the complete encoded payload",
    r"complete encoded payload containing Subject, SAN, $IssuerSet$, $iat_c$, and $exp_c$",
    "requires the requested server hostname to be covered by the signed SAN",
    r"IssuerId_H(c)=\mathrm{name}(H)",
    r"H\!\left(\mathrm{DER}(CA(c))\right)",
    "Concrete certificate-path construction and extraction, DER parsing, hashing, base64url encoding, and differences between the two concrete hostname implementations are outside the symbolic model",
    "highest issuance time previously accepted",
    r"\mathrm{Cache}[K_{apub}]",
    r"H_k[K_{apub},h]",
    r"H_c[K_{apub},Subject,SAN]",
    "intentionally share one ASPin owner/trust domain",
    "package identifier adds no cache or anti-rollback partition",
    "Cross-signing-key, cross-delegated-key, and cross-claim-host reads are unreachable",
    r"$iat_c^{(1)}<iat_c^{(2)}<iat_c^{(3)}$",
    r"$w_2$ & $T_c^{(2)}$ & CurrCert & CurrCA+NewCA",
    r"$w_3$ & $T_c^{(3)}$ & NewCert & NewCA",
    r"migration model uses one symbolic step for $L_{\max}$",
    r"jointly publishes $T_c^{(3)}$ and deploys \emph{NewCert}",
    r"\emph{overlap} concerns CA identifiers, not cross-cutover validity",
    "operator staging and advance notice",
    "operator-staged CA migration",
    "one OS-level mechanism for retrieval, JWS verification, claim replacement",
    r"This is an ordering property, not policy rejection",
    r"dual policy authorizes \emph{NewCA}",
    r"its full-$L_{\max}$ phase-elapsed event",
    r"no client phase progression or cache bridge into $w_3$",
    "both $sig_k^{old}$ and $sig_k^{new}$ over the identical encoded payload",
    r"\caption{ProVerif Outputs for Rogue Certificates with Unauthorized Issuer CA Identifiers}",
    r"\caption{ProVerif Outputs for Claim Caching, Migration, Rollback, and Key Rotation}",
    r"For $\neg\,event(E)$",
    r"is also \texttt{true}, but is vacuous",
    r"\texttt{not event(CrossSigningKeyCacheHit(...))}",
    r"\texttt{not event(CrossDelegationCacheHit(...))}",
    r"\texttt{not event(CrossHostnameCacheHit(...))}",
    r"\texttt{not event(OldOnlyTokenAcceptedByNewKey(...))}",
    "Private channels carry only phase markers",
    "All verifier inputs come from the public channel",
    "predecessors of both JWS types",
)

TEX_PATTERNS = (
    r"one hostname has exactly one(?: logical )?ASPin policy owner at any instant",
    r"trusted operator's deployment-profile upper bound on \$T_c\$ lifetime",
    r"\$exp_c-iat_c\\leq L_\{\\max\}\$",
    r"overlap publication, the operator sets \$exp_c-iat_c=L_\{\\max\}\$",
    r"private phase markers encode the trusted operator's compliance with the recommended schedule",
)

NETWORK_MODEL_FRAGMENTS = (
    "get_iat(",
    "get_exp(",
    "header_matches(",
    "jws_general_verify(",
    "token_fresh(",
    "derive_ttl(",
    "get_subject_and_san(",
    "get_issuer(",
    "check_host(hostname,",
    "let connection_time = succ_t(curr) in",
    "event ClaimFreshAtCheck(hostname)",
    "event(ClaimFreshAtCheck(",
)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_fragments(path: Path, fragments: tuple[str, ...]) -> None:
    text = path.read_text(encoding="utf-8")
    for fragment in fragments:
        if fragment not in text:
            fail(f"{path.relative_to(ROOT.parent)} is missing: {fragment}")


def require_patterns(path: Path, patterns: tuple[str, ...]) -> None:
    text = path.read_text(encoding="utf-8")
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE) is None:
            fail(f"{path.relative_to(ROOT.parent)} does not match: {pattern}")


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
    require_patterns(TEX, TEX_PATTERNS)
    require_no_fragments(
        TEX,
        (
            r"$w_0$ & $T_c^{(0)}$",
            r"CurrCert $\to$ NewCert",
            r"NewCert cutover occurs earlier while $T_c^{(2)}$ is fresh",
            "signed contents bind it to its phase",
            "exploit a migration gap",
            "and transitions consistently",
            "authenticated retrieval",
        ),
    )
    require_fragments(
        ROOT / "base.pvl",
        (
            "jws_payload(bitstring, timestamp, timestamp)",
            "jws_general_sign(",
            "get_iat(jws_payload",
            "token_fresh(t, succ_t(t), t) = true",
            "derive_ttl(t, succ_t(t)) = ttl_one",
            "iat_older(t, succ_t(t)) = true",
            "token_expired(t, t) = true",
            "jws_dual_sign",
            "ttl_four",
            "package_signing_record(bitstring, pkey)",
            "resolve_os_key(",
            "event ClaimFreshAtCheck(bitstring)",
        ),
    )
    require_no_fragments(
        ROOT / "base.pvl",
        (
            "jws_payload(bitstring, timestamp, ttl)",
            "get_scope(",
            "jws_verify(",
            "get_ttl(jws_payload",
            "token not expired",
            "fun jws(",
            "jws_sign(",
        ),
    )

    for model_name in ASPIN_NETWORK_MODELS:
        model = ROOT / model_name
        require_fragments(model, NETWORK_MODEL_FRAGMENTS)
        require_no_fragments(
            model,
            ("let true =", "jws_verify(", "get_ttl(", "get_scope(", "good_ttl"),
        )

    require_fragments(
        ROOT / "aspin_cache.pv",
        (
            "claim_key_cache_entry(",
            "cache_entry(app_key, claim_key, content, iat, exp)",
            "read_cached_claim(entry, other_key, claim_key, iat)",
            "entry, app_key, other_claim_key, iat)",
            "read_cached_claim(entry, app_key, claim_key, iat)",
            "other_hostname, get_migration_identity(result)",
            "check_host(server_hostname, identity0)",
            "MigrationTransitionAvailable(window_overlap)",
            "MigrationPhaseElapsed(window_overlap, iat2)",
            "MigrationJointCutover(",
            "MigrationPolicyPairAllowed(",
            "let token_c_0 = jws_general_sign(",
            "let token_c_1 = jws_general_sign(",
            "let token_c_2 = jws_general_sign(",
            "iat_older(iat0, iat1)",
            "iat_older(iat1, iat2)",
            "let exp1 = succ_t(iat1) in",
            "let exp2 = succ_t(iat2) in",
            "let (=ttl_one) = derive_ttl(iat1, exp1) in",
            "let (=ttl_one) = derive_ttl(iat2, exp2) in",
            "token_expired(exp0, iat1)",
            "token_expired(exp1, iat2)",
            "token_expired(exp1, cutover_time)",
            "let cutover_time = succ_t(iat1) in",
            "Only paper w3 deploys NewCert.",
            "transition claim is expired at the boundary and is not used to accept",
            "same coordinated",
            "token_fresh(old_iat, common_exp, new_iat)",
            "iat_older(old_iat, new_iat)",
            "token_expired(exp, exp)",
            "resolve_os_key(target_record, target_app_id)",
            "in(c, jws_general(hk:",
            "in(c, jws_general(h0:",
            "token_fresh(key_iat, key_exp, iat2)",
            "RollbackRejected(token_type_claim",
            "RollbackRejected(token_type_key",
        ),
    )
    require_no_fragments(
        ROOT / "aspin_cache.pv",
        (
            "let true =",
            "jws_verify(",
            "get_ttl(",
            "get_scope(",
            "window_final",
            "out(migration_key_delivery, token_k)",
            "out(migration_current_delivery, token0)",
            "let token0 = jws_general_sign(",
            "let token1 = jws_general_sign(",
            "let token2 = jws_general_sign(",
            "let token3 = jws_general_sign(",
            "let cutover_time = iat2 in",
            "bridge_claim_key",
            "published after that cutover",
            "let (=succ_t(succ_t(iat1))) = exp1 in",
            "let (=succ_t(succ_t(iat2))) = exp2 in",
            "window_overlap_1",
            "window_overlap_2",
            "token_c_3",
            "paper w4",
            "Paper w4",
        ),
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
            "HighestIatTransferred",
            "in(c, replay_token:",
        ),
    )
    require_no_fragments(
        ROOT / "aspin_key_rotation.pv",
        ("let true =", "jws_verify(", "get_ttl(", "get_scope("),
    )


def check_common_aspin(lines: list[str]) -> None:
    require_outcome(lines, ("not event(RSAccept(",), "is false.")
    require_outcome(lines, ("not event(AppConnRS(",), "is false.")
    require_outcome(lines, ("not event(AppReject(",), "is false.")
    require_outcome(
        lines, ("event(RSAccept(", "==> event(AppConnRS("), "is true."
    )
    require_outcome(
        lines, ("event(AppConnRS(", "==> event(ClaimFreshAtCheck("), "is true."
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
        "MigrationTransitionAvailable(window_overlap)",
        "MigrationPhaseElapsed(window_overlap,succ_t(succ_t(migration_time_0[])))",
    ):
        require_outcome(
            lines,
            ("event(MigrationJointCutover(", f"==> event({prerequisite}"),
            "is true.",
        )
    require_outcome(
        lines,
        (
            "event(MigrationCertAccepted(window_new_cert,new_cert_issuer,claim_new_ca))",
            "==> event(MigrationJointCutover(",
        ),
        "is true.",
    )
    for invalid in (
        "MigrationCertAccepted(window_new_cert,new_cert_issuer,claim_current_ca)",
        "MigrationCertAccepted(window_new_cert,new_cert_issuer,claim_transition_ca)",
        "MigrationCertAccepted(window_new_cert,real_cert_issuer,claim_new_ca)",
        "CrossSigningKeyCacheHit(",
        "CrossDelegationCacheHit(",
        "CrossHostnameCacheHit(",
    ):
        require_outcome(lines, (f"not event({invalid}",), "is true.")

    for incompatible in (
        "MigrationPolicyPairAllowed(new_cert_issuer,claim_current_ca)",
        "MigrationPolicyPairAllowed(real_cert_issuer,claim_new_ca)",
    ):
        require_outcome(lines, (f"not event({incompatible}",), "is true.")
    require_outcome(
        lines,
        (
            "not event(MigrationPolicyPairAllowed("
            "new_cert_issuer,claim_transition_ca))",
        ),
        "is false.",
    )

    require_outcome(
        lines, ("not event(RollbackRejected(token_type,",), "is false."
    )
    require_outcome(
        lines,
        (
            "not event(RollbackRejected(token_type_claim",
            "migration_time_0[]",
        ),
        "is false.",
    )
    require_outcome(
        lines,
        (
            "not event(RollbackRejected(token_type_key",
            "migration_time_0[]",
        ),
        "is false.",
    )
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
        ("window_overlap", "real_cert_issuer", "claim_transition_ca"),
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
    require_outcome(
        lines,
        (
            "not event(MigrationCertAccepted("
            "window_new_cert,new_cert_issuer,claim_new_ca))",
        ),
        "is false.",
    )
    require_outcome(
        lines,
        (
            "event(MigrationWindowComplete(window_new_cert))",
            "event(MigrationCertAccepted("
            "window_new_cert,new_cert_issuer,claim_new_ca))",
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
        "HighestIatTransferred(",
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
        ("event(HighestIatTransferred(", "==> event(DualSigAppKeyVerify("),
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
