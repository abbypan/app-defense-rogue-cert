#!/usr/bin/env python3
"""Check that the ProVerif sources/results implement the current TeX design."""

from pathlib import Path
import re
import sys

from generate_compatible_models import MODELS as COMPAT_LIFECYCLE_MODELS, instantiate


ROOT = Path(__file__).resolve().parent
TEX = ROOT.parent / "tex" / "paper_content.tex"
TEX_APPENDIX = ROOT.parent / "tex" / "paper_appendix.tex"
TEX_SOURCES = (TEX, TEX_APPENDIX)
SPEC_SOURCES = (
    ROOT.parent / "spec" / "proverif-models.md",
    ROOT.parent / "spec" / "proverif-lifecycle.md",
)

ASPIN_NETWORK_MODELS = (
    "aspin_dns_hijacking.pv",
    "aspin_bgp_hijacking.pv",
    "aspin_mitm.pv",
)
ASPIN_COMPAT_MODEL = "aspin_compat_manifest_key.pv"

TEX_FRAGMENTS = (
    r"\subsubsection{Signing~$T_k$}",
    r"\subsubsection{Signing~$T_c$}",
    r"\subsubsection{Verify~$T_k$}",
    r"\subsubsection{Verify~$T_c$}",
    r"\subsection{App-Controlled CertClaimCheck}",
    r"iat_k \leq t_{\mathrm{now}} < exp_k",
    r"iat_c \leq t_{\mathrm{now}} < exp_c",
    r"\emph{CertClaimCheck} fails when the protected clock reaches $exp_f$",
    "signature covers the complete encoded payload",
    r"complete encoded payload containing Subject, SAN, $IssuerSet$, $iat_c$, and $exp_c$",
    "requires the requested server hostname to be covered by the signed SAN",
    r"IssuerId_H(c)=\mathrm{name}(H)",
    r"H\!\left(\mathrm{DER}(CA(c))\right)",
    "highest issuance time previously accepted",
    r"\mathrm{Cache}[K_{apub}]",
    r"H_k[K_{apub},h]",
    r"H_c[K_{apub},Subject,SAN]",
    "The OS-verified signing identity defines the ASPin owner and trust domain",
    "Packages signed with the same identity share cache and anti-rollback state",
    r"$iat_c^{(1)}<iat_c^{(2)}<iat_c^{(3)}$",
    r"$w_2$ & $T_c^{(2)}$ & CurrCert & CurrCA+NewCA",
    r"$w_3$ & $T_c^{(3)}$ & NewCert & NewCA",
    r"jointly publishes $T_c^{(3)}$ and deploys \emph{NewCert}",
    r"\emph{overlap} concerns CA identifiers, not cross-cutover validity",
    "operator staging and advance notice",
    "operator-staged CA migration",
    "At every query, the OS-level ASPin service resolves the Target App's package name using its latest authenticated installed version",
    "The Target App's current app-signing certificate supplies $K_{apub}$",
    r"This is an ordering property, not policy rejection",
    r"dual policy authorizes \emph{NewCA}",
    r"no client phase progression or cache bridge into $w_3$",
    "contains $sig_k^{old}$ and $sig_k^{new}$ over the same encoded payload",
    "OS-authenticated signing-certificate lineage treats the old and new app signing keys as one logical owner",
    r"\caption{ProVerif Outputs for Rogue Certificates with Unauthorized Issuer CA Identifiers}",
    r"\label{table:cacheverif}",
    r"For $\neg\,event(E)$",
    "but is vacuous if its antecedent is unreachable",
    "predecessors of both JWS types",
    r"\subsection{Unknown App-Signing-Key Compatibility}",
    r"K_s=(K_{spub},K_{spriv})",
    "That signature covers the manifest and thereby authenticates",
    "rather than maintaining a separate manifest-root store",
    r"the mode does not transfer rollback floors across $K_s$ replacements",
    "We analyze twenty-nine symbolic models",
    "root resolution follows a matching manifest binding",
    r"compatibility-mode $T_k$ verification uses that resolved $K_{spub}$",
)

SPEC_FRAGMENTS = (
    "Concrete certificate-path construction and extraction, DER parsing, hashing, base64url encoding, and differences between the two concrete hostname implementations are outside the symbolic model",
    "Cross-signing-key, cross-delegated-key, and cross-claim-host reads are unreachable",
    r"migration model uses one symbolic step for $L_{\max}$",
    r"full-$L_{\max}$ phase-elapsed event",
    "protected state transfers only if transitional $T_k^{(2)}$ also verifies under the old and new keys",
    "lineage alone moves no prior state",
    r"transferred $H_k$",
    "is the lineage maximum",
    "Acceptance atomically commits the maximum",
    "not event(CrossSigningKeyCacheHit(...))",
    "not event(CrossDelegationCacheHit(...))",
    "not event(CrossHostnameCacheHit(...))",
    "old-only and nonmaximum-commit queries",
    "three-key OS lineage",
    r"Both $H_k/H_c$ maximum transfers",
    "Private channels carry phase markers",
    "Network tokens enter through the public channel",
    "The compatibility mode has its own model rather than sharing the primary-mode trust-root process",
    r"Separate compatibility lifecycle models cover caching, CA migration, claim-key rotation, and $K_s$ replacement",
)

TEX_PATTERNS = (
    r"same hostname may appear in multiple signing-key collections",
    r"trusted operator's deployment-profile upper bound on \$T_c\$ lifetime",
    r"\$exp_c-iat_c\\leq L_\{\\max\}\$",
    r"overlap publication, the operator sets \$exp_c-iat_c=L_\{\\max\}\$",
)

SPEC_PATTERNS = (
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


def combined_text(paths: tuple[Path, ...]) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def require_fragments_in_files(paths: tuple[Path, ...], fragments: tuple[str, ...]) -> None:
    text = combined_text(paths)
    for fragment in fragments:
        if fragment not in text:
            joined = ", ".join(str(path.relative_to(ROOT.parent)) for path in paths)
            fail(f"{joined} are missing: {fragment}")


def require_patterns_in_files(paths: tuple[Path, ...], patterns: tuple[str, ...]) -> None:
    text = combined_text(paths)
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE) is None:
            joined = ", ".join(str(path.relative_to(ROOT.parent)) for path in paths)
            fail(f"{joined} do not match: {pattern}")


def require_no_fragments_in_files(paths: tuple[Path, ...], fragments: tuple[str, ...]) -> None:
    text = combined_text(paths)
    for fragment in fragments:
        if fragment in text:
            joined = ", ".join(str(path.relative_to(ROOT.parent)) for path in paths)
            fail(f"{joined} contain obsolete/unsafe form: {fragment}")


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
    require_fragments_in_files(TEX_SOURCES, TEX_FRAGMENTS)
    require_patterns_in_files(TEX_SOURCES, TEX_PATTERNS)
    # Trace-level exposition lives in spec/; manuscript design requirements and
    # appendix labels must still be present in the TeX, not merely in a spec.
    require_fragments_in_files(SPEC_SOURCES, SPEC_FRAGMENTS)
    require_patterns_in_files(SPEC_SOURCES, SPEC_PATTERNS)
    require_fragments(ROOT.parent / "README.md", (
        "spec/proverif-models.md",
        "spec/proverif-lifecycle.md",
    ))
    require_no_fragments(TEX_APPENDIX, (
        "spec/", "proverif-models.md", "proverif-lifecycle.md",
    ))
    require_fragments(TEX_APPENDIX, (
        r"Both modes relate verified $T_k/T_c$ to matching signing events",
        "caller-root substitution and unauthorized-issuer data output are unreachable",
        r"\label{table:pv-availability}",
        r"\label{table:pv-certificate-change}",
        r"\label{table:pv-cross-sign}",
        r"\label{table:pv-migration}",
        r"\label{table:pv-claim-key}",
        r"\label{table:pv-app-key}",
        r"\label{app:lifecycle-limitations}",
    ))
    require_no_fragments(TEX_APPENDIX, (
        "Boundary &", r"\textbf{Result or boundary}",
        " & out of scope", " & assumed", " & abstracted", " & encoded profile",
    ))
    require_no_fragments_in_files(
        TEX_SOURCES,
        (
            r"$w_0$ & $T_c^{(0)}$",
            r"CurrCert $\to$ NewCert",
            r"NewCert cutover occurs earlier while $T_c^{(2)}$ is fresh",
            "signed contents bind it to its phase",
            "exploit a migration gap",
            "and transitions consistently",
            "authenticated retrieval",
            "assigns exactly one logical ASPin policy owner to each hostname",
            "one-owner-per-hostname",
            "simultaneous fresh partitions or distinct owners for one hostname",
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
            "manifest_key_record(bitstring, pkey)",
            "resolve_manifest_key(",
            "event ManifestKeyBind(bitstring, pkey)",
            "event ManifestKeyResolve(bitstring, pkey)",
            "event CompatClaimKeyVerify(",
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
        ROOT / ASPIN_COMPAT_MODEL,
        (
            "TrustedManifestInstall",
            "gen_sk_for_id(self_host_signing)",
            "manifest_key_record(target_app_id, pk_self_host)",
            "resolve_manifest_key(",
            "in(cm, manifest_record: bitstring)",
            "event ManifestKeyBind(target_app_id, pk_self_host)",
            "event ManifestKeyResolve(target_app_id, pk_self_host)",
            "event CompatClaimKeyVerify(",
            "jws_general_sign(",
            "header_matches(hk, pk_self_host)",
            "ClaimKeySign(",
            "ClaimKeyVerify(pk_self_host, pk_claim",
            "CertClaimVerify(",
            "let connection_time = succ_t(curr) in",
            "event ClaimFreshAtCheck(hostname)",
        ),
    )
    require_no_fragments(
        ROOT / ASPIN_COMPAT_MODEL,
        ("resolve_os_key(", "let true =", "jws_verify(", "get_ttl(", "get_scope("),
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
            "OSSigningLineageAuthenticated",
            "ProtectedLineageState",
            "LineageMaximumSelected",
            "NonMaximumLineageStateCommitted",
            "ClaimStateOldReplayRejected",
            "lineage_max(",
            "token_type_claim",
            "key_hostname_context",
            "claim_subject_san_context",
            "rotation_lineage_delivery",
            "in(c, replay_token:",
            "in(c, replay_claim_token:",
        ),
    )
    require_no_fragments(
        ROOT / "aspin_key_rotation.pv",
        ("let true =", "jws_verify(", "get_ttl(", "get_scope("),
    )
    require_fragments(
        ROOT / "aspin_ca_migration.pv",
        (
            "CAMigrationFullLmaxElapsed(t1, t2)",
            "CAMigrationJointActivation(t2)",
            "out(ca_migration_phase, (ca_window_1, t0)) |",
            "out(ca_migration_phase, (ca_window_2, t1)) |",
            "in(c, tk: bitstring)",
            "in(c, tc: bitstring)",
            "in(c, gen_cert(",
            "token_fresh(iatk, expk, now)",
            "token_fresh(iatc, expc, now)",
            "token_expired(expc, now)",
            "ca_native_trust(peer_issuer)",
            "ca_member(peer_issuer, issuers)",
            "CAMigrationExpiredPolicyRejected",
        ),
    )
    require_fragments(
        ROOT / "aspin_claim_key_rotation.pv",
        (
            "replacement_claim_signing",
            "ClaimRotationCacheEvicted",
            "ClaimRotationRetryStarted",
            "ClaimRotationRetrySucceeded",
            "ClaimRotationRetryExhausted",
            "in(c, first_tc: bitstring)",
            "in(c, refreshed_tk: bitstring)",
            "in(c, retry_tc: bitstring)",
            "jws_general_verify(first_tc, cached_key)",
            "jws_general_verify(refreshed_tk, root)",
            "jws_general_verify(retry_tc, refreshed_key)",
            "iat_not_older(kiat, highest_k)",
            "iat_not_older(ciat, highest_c)",
            "old_payload_new_signature",
            "claim_rotation_replay",
            "ClaimRotationRollbackRejected(claim_rotation_tk",
            "ClaimRotationRollbackRejected(claim_rotation_tc",
        ),
    )
    for model in ("aspin_ca_migration", "aspin_claim_key_rotation"):
        require_fragments(ROOT / "run.sh", (f"  {model}\n",))
        require_no_fragments(
            ROOT / f"{model}.pv",
            ("let true =", "jws_verify(", "get_ttl(", "get_scope("),
        )

    # The updated verifier itself must check both entries before accessing
    # lineage state; verification by an independent old app is insufficient.
    rotation = (ROOT / "aspin_key_rotation.pv").read_text(encoding="utf-8")
    updated = rotation.split("let UpdatedApp =", 1)[1].split(
        "let OldOnlySignatureAudit =", 1
    )[0]
    for fragment in (
        "header_matches(h_old, pk_old)",
        "jws_dual_verify1(token1, pk_old)",
        "jws_dual_verify2(token1, pk_new)",
    ):
        if fragment not in updated:
            fail(f"UpdatedApp is missing its transition check: {fragment}")

    for primary, compatible in COMPAT_LIFECYCLE_MODELS.items():
        path = ROOT / f"{compatible}.pv"
        if not path.is_file() or path.read_text(encoding="utf-8") != instantiate(primary):
            fail(f"stale compatibility instance: {path.name}")
        require_fragments(path, ("event ManifestKeyBind(", "event ManifestKeyResolve("))
        require_no_fragments(path, ("resolve_os_key(", "ManifestRootHistory", "ManifestUpdateAuthenticated"))
        require_fragments(path, ("sig_verify(apk_manifest, apk_signature, apk_signer)",
                                 "event AppManifestAuthenticated("))
        require_fragments(ROOT / "run.sh", (f"  {compatible}\n",))
    require_fragments(ROOT / "aspin_compat_root_rotation.pv", (
        "sig_verify(manifest, signature, apk_signer)",
        "event KsNewNamespaceBegins(", "event KsNewRootAccepted(",
        "event KsManifestRejected", "updated_app_version",
    ))
    require_no_fragments(ROOT / "aspin_compat_root_rotation.pv", (
        "HighestIatTransferred", "OSManifestRootHistory", "ManifestUpdateAuthenticated",
    ))
    for model, fragments in (
        ("aspin_certificate_change", (
            "renewal_certificate", "leaf_renewed", "leaf_rekeyed",
            "sig_verify(renewal_possession(challenge, certificate)",
            "CertificateChangeExpired", "CertificateChangeIssuerRejected",
        )),
        ("aspin_cross_hostname_hc", (
            "no_hostname_key_state", "cross_host_match(other_hostname, identity)",
            "iat_not_older(ciat, inherited_c)", "cross_host_max(inherited_c, ciat)",
            "HcOnlyTransferred", "HcOnlyReplayRejected",
        )),
    ):
        require_fragments(ROOT / f"{model}.pv", fragments)
        require_fragments(ROOT / "run.sh", (f"  {model}\n",))


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


def check_compat_model() -> None:
    lines = result_lines(ROOT / "result" / "aspin_compat_manifest_key.log")
    check_manifest_provenance(lines)
    require_outcome(
        lines,
        ("event(ManifestKeyResolve(", "==> event(ManifestKeyBind("),
        "is true.",
    )
    require_outcome(
        lines,
        ("event(CompatClaimKeyVerify(", "==> event(ManifestKeyResolve("),
        "is true.",
    )
    require_outcome(
        lines,
        ("event(ClaimKeyVerify(pk(root_sk)", "==> event(ClaimKeySign("),
        "is true.",
    )
    require_outcome(
        lines,
        ("event(CertClaimVerify(pk(claim_sk)", "==> event(CertClaimSign("),
        "is true.",
    )
    require_outcome(lines, ("not event(AppConnRS(",), "is false.")
    require_outcome(
        lines, ("event(AppConnRS(", "==> event(ClaimFreshAtCheck("), "is true."
    )
    require_outcome(lines, ("not event(AppReject(",), "is false.")
    require_outcome(lines, ("not event(AppConnMS(",), "is true.")
    require_outcome(lines, ("not event(MSAccept(",), "is true.")


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
        "ClaimStateOldReplayRejected(",
        "OSSigningLineageAuthenticated(",
    ):
        require_outcome(lines, (f"not event({event}",), "is false.")
    for token_type, context in (
        ("token_type_key", "key_hostname_context"),
        ("token_type_claim", "claim_subject_san_context"),
    ):
        require_outcome(
            lines,
            ("not event(LineageMaximumSelected(", token_type, context),
            "is false.",
        )
        require_outcome(
            lines,
            ("not event(HighestIatTransferred(", token_type, context),
            "is false.",
        )
        require_outcome(
            lines,
            ("not event(NonMaximumLineageStateCommitted(", token_type, context),
            "is true.",
        )
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
        ("event(CertClaimVerify(", "==> event(CertClaimSign("),
        "is true.",
    )
    require_outcome(
        lines,
        (
            "event(ProtectedLineageState(pk(gen_sk_for_id(app_signing))",
            "==> event(CertClaimVerify(",
        ),
        "is true.",
    )
    require_outcome(
        lines,
        (
            "event(ClaimStateOldReplayRejected(",
            "==> event(HighestIatTransferred(",
        ),
        "is true.",
    )
    for prerequisite in (
        "OSSigningLineageAuthenticated(",
        "LineageMaximumSelected(",
        "ProtectedLineageState(ancestor_key",
        "ProtectedLineageState(old_key",
        "DualSigAppKeyVerify(",
    ):
        require_outcome(
            lines,
            ("event(HighestIatTransferred(", f"==> event({prerequisite}"),
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


def check_dedicated_ca_migration() -> None:
    lines = result_lines(ROOT / "result" / "aspin_ca_migration.log")
    if len(lines) != 16:
        fail(f"CA migration: expected 16 results, found {len(lines)}")
    for source, prerequisite in (
        ("CAMigrationAuthenticated(", "CAMigrationPublished("),
        ("ClaimKeyVerify(", "ClaimKeySign("),
        ("CertClaimVerify(", "CertClaimSign("),
        ("CAMigrationJointActivation(", "CAMigrationOverlapPublished("),
        ("CAMigrationJointActivation(", "CAMigrationFullLmaxElapsed("),
    ):
        require_outcome(lines, (f"event({source}", f"==> event({prerequisite}"),
                        "is true.")
    for decision in (
        "CAMigrationAccepted(ca_window_1,real_cert_issuer,ca_current_only)",
        "CAMigrationAccepted(ca_window_2,real_cert_issuer,ca_overlap_set)",
        "CAMigrationAccepted(ca_window_2,ca_new_issuer,ca_overlap_set)",
        "CAMigrationAccepted(ca_window_3,ca_new_issuer,ca_new_only)",
        "CAMigrationRejected(ca_window_1,ca_new_issuer,ca_current_only)",
        "CAMigrationRejected(ca_window_3,real_cert_issuer,ca_new_only)",
        "CAMigrationExpiredPolicyRejected(ca_window_3,",
    ):
        require_outcome(lines, (f"not event({decision}",), "is false.")
    for terms in (
        ("not event(CAMigrationAccepted(window_", ",rogue_cert_issuer,"),
        ("not event(CAMigrationAccepted(window_", ",ca_new_issuer,ca_current_only)"),
        ("not event(CAMigrationAccepted(window_", ",real_cert_issuer,ca_new_only)"),
        ("not event(CAMigrationAccepted(ca_window_3,", ",ca_overlap_set)"),
    ):
        require_outcome(lines, terms, "is true.")


def check_delegated_claim_key_rotation() -> None:
    lines = result_lines(ROOT / "result" / "aspin_claim_key_rotation.log")
    if len(lines) != 13:
        fail(f"Claim-key rotation: expected 13 results, found {len(lines)}")
    for source, prerequisite in (
        ("ClaimKeyVerify(", "ClaimKeySign("),
        ("CertClaimVerify(", "CertClaimSign("),
        ("ClaimRotationRetrySucceeded(", "ClaimRotationRetryStarted("),
        ("ClaimRotationRetryExhausted(", "ClaimRotationRetryStarted("),
    ):
        require_outcome(lines, (f"event({source}", f"==> event({prerequisite}"),
                        "is true.")
    for event in (
        "ClaimRotationRetrySucceeded(",
        "ClaimRotationRetryExhausted(",
        "ClaimRotationRollbackRejected(claim_rotation_tk,",
        "ClaimRotationRollbackRejected(claim_rotation_tc,",
        "ClaimRotationAccepted(claim_rotation_cached,",
    ):
        require_outcome(lines, (f"not event({event}",), "is false.")
    old_key = "pk(gen_sk_for_id(claim_signing))"
    new_key = "pk(gen_sk_for_id(replacement_claim_signing))"
    for first, second in ((old_key, new_key), (new_key, old_key)):
        require_outcome(
            lines,
            ("not event(ClaimRotationAccepted(mode_", f",{first},{second},"),
            "is true.",
        )
    replay_results = [line for line in lines if line.startswith(
        "RESULT not event(ClaimRotationAccepted(claim_rotation_replay,"
    )]
    if len(replay_results) != 2 or any(
        not line.endswith("is true.") for line in replay_results
    ):
        fail("Claim-key rotation must exclude below-floor acceptance for both JWS types")


def check_certificate_change() -> None:
    lines = result_lines(ROOT / "result" / "aspin_certificate_change.log")
    if len(lines) != 12:
        fail(f"Certificate change: expected 12 results, found {len(lines)}")
    for event in ("leaf_original", "leaf_renewed", "leaf_rekeyed"):
        require_outcome(lines, ("not event(CertificateChangeAccepted(", f",{event},"),
                        "is false.")
    for source, prerequisite in (
        ("ClaimKeyVerify(", "ClaimKeySign("),
        ("CertClaimVerify(", "CertClaimSign("),
        ("CertificateChangeAccepted(", "CertificatePolicyAuthenticated("),
    ):
        require_outcome(lines, (f"event({source}", f"==> event({prerequisite}"), "is true.")
    for term in (
        ",rogue_cert_issuer,", ",leaf_invalid,", ",wrong_certificate_identity,",
        ",succ_t(succ_t(certificate_change_origin[]))",
    ):
        require_outcome(lines, ("not event(CertificateChangeAccepted(", term), "is true.")
    for event in ("CertificateChangeIssuerRejected(", "CertificateChangeExpired("):
        require_outcome(lines, (f"not event({event}",), "is false.")


def check_cross_hostname_hc() -> None:
    lines = result_lines(ROOT / "result" / "aspin_cross_hostname_hc.log")
    if len(lines) != 11:
        fail(f"Cross-hostname H_c: expected 11 results, found {len(lines)}")
    for source, prerequisite in (
        ("HcOnlyTransferred(", "CrossHostLineageAuthenticated("),
        ("HcOnlyTransferred(", "CrossHostClaimStateEstablished("),
        ("HcOnlyKeyInitialized(", "HcOnlyKeyContextAbsent("),
        ("ClaimKeyVerify(", "ClaimKeySign("),
        ("CertClaimVerify(", "CertClaimSign("),
    ):
        require_outcome(lines, (f"event({source}", f"==> event({prerequisite}"), "is true.")
    for time in ("succ_t(cross_hostname_origin[])",
                 "succ_t(succ_t(cross_hostname_origin[]))"):
        require_outcome(lines, ("not event(HcOnlyAccepted(", f",{time})"), "is false.")
    require_outcome(lines, ("not event(HcOnlyReplayRejected(",), "is false.")
    require_outcome(lines, ("not event(HcOnlyAccepted(", ",cross_hostname_origin[])"),
                    "is true.")
    for event in ("HcOnlyBelowFloorCommit(", "HcOnlyHostnameKeyLeak("):
        require_outcome(lines, (f"not event({event}",), "is true.")


def check_cross_sign() -> None:
    require_fragments_in_files(TEX_SOURCES, (
        r"\subsubsection{Cross-Signed Issuer Certificates}",
        r"\label{app:cross-sign-model}", r"\label{app:cross-sign-experiment}",
        "publisher includes every supported direct-issuer CA certificate variant",
        "All 360 attempts passed native validation",
        "that exact case remains covered by the model and host regressions",
    ))
    require_fragments_in_files(SPEC_SOURCES, (
        "All 15 primary and 18 compatibility queries have their expected outcomes",
    ))
    source = ROOT / "aspin_cross_sign.pv"
    require_fragments(source, ("cs_der_hash(direct)", "cs_pair(cs_der_hash(ca_a), cs_der_hash(ca_b))",
        "cs_ca_certificate(shared_key, cs_ca_subject, cs_root_a",
        "cs_ca_certificate(shared_key, cs_ca_subject, cs_root_b",
        "sig_verify(cs_leaf_content(", "CrossSignNativeValidated", "header_matches(",
        "token_fresh(ciat, cexp, now)", "cs_possession(challenge, leaf)"))
    require_fragments(ROOT / "run.sh", ("  aspin_cross_sign\n", "  aspin_compat_cross_sign\n"))
    lines = result_lines(ROOT / "result/aspin_cross_sign.log")
    if len(lines) != 15:
        fail("cross-sign: expected 15 query results")
    for source_event, prerequisite in (
        ("ClaimKeyVerify(", "ClaimKeySign("),
        ("CertClaimVerify(", "CertClaimSign("),
        ("CrossSignAccepted(", "CrossSignPolicyVerified("),
        ("CrossSignAccepted(", "CrossSignNativeValidated("),
    ):
        require_outcome(lines, (f"event({source_event}", f"==> event({prerequisite}"), "is true.")
    for event in (
        "CrossSignAccepted(cs_complete_policy,cs_variant_a,cs_no_extra)",
        "CrossSignAccepted(cs_complete_policy,cs_variant_b,cs_no_extra)",
        "CrossSignAccepted(cs_incomplete_policy,cs_variant_a,cs_no_extra)",
        "CrossSignRejected(cs_incomplete_policy,cs_variant_b,",
        "CrossSignExpired(",
        "CrossSignNativeValidated(cs_complete_policy,cs_variant_rogue)",
        "CrossSignRejected(cs_complete_policy,cs_variant_rogue,cs_no_extra)",
        "CrossSignPaddingRejected(cs_complete_policy,cs_variant_rogue)",
    ):
        require_outcome(lines, (f"not event({event}",), "is false.")
    require_outcome(lines, ("not event(CrossSignAccepted(cs_incomplete_policy,cs_variant_b,",), "is true.")
    require_outcome(lines, ("not event(CrossSignAccepted(", ",cs_variant_rogue,"), "is true.")


def check_multisig() -> None:
    require_fragments(ROOT / "base.pvl", (
        "type jws_signature_list.",
        "jws_signature_cons(bitstring, jws_signature_list)",
        "pred jws_array_member(bitstring, jws_signature_list) [memberOptim]",
        "jws_array_member(entry, tail) ->",
        "header_matches(header, context_key)",
        "sig_verify(jws_tosign(header, payload), signature, context_key)",
    ))
    for model in ("aspin_multisig", "aspin_compat_multisig", "aspin_multisig_rotation"):
        require_fragments(ROOT / "run.sh", (f"  {model}\n",))
        require_fragments(ROOT / f"{model}.pv", (
            "jws_signature_array(", "!GeneralJwsSignatureScanner", "in(c, tk: bitstring)",
        ))
    require_fragments_in_files(TEX_SOURCES, (
        r"\label{app:multisig-model}",
        "not device-tested",
    ))
    require_fragments_in_files(SPEC_SOURCES, (
        "unbounded symbolic signature list",
        "third and fourth entries",
    ))
    lines = result_lines(ROOT / "result/aspin_multisig.log")
    if len(lines) != 14:
        fail("multi-signature: expected 14 query results")
    for source, prerequisite in (
        ("ClaimKeyVerify(", "ClaimKeySign("),
        ("CertClaimVerify(", "CertClaimSign("),
        ("MultiSigClaim(", "MultiSigContext("),
    ):
        require_outcome(lines, (f"event({source}", f"==> event({prerequisite}"), "is true.")
    for root in ("app_signing", "other_app_signing"):
        require_outcome(lines, (f"not event(MultiSigDelegation(pk(gen_sk_for_id({root}))",),
                        "is false.")
    require_outcome(lines, ("not event(MultiSigArrayAccepted(",), "is false.")
    require_outcome(lines, ("not event(MultiSigClaim(", "real_cert_issuer"), "is false.")
    require_outcome(lines, ("not event(MultiSigClaim(", "other_app_signing"), "is true.")
    require_outcome(lines, ("not event(MultiSigClaim(", "rogue_cert_issuer"), "is true.")
    for label in ("ms_empty_array", "ms_missing_owner", "ms_forged_kid", "ms_spliced_payload"):
        require_outcome(lines, (f"not event(MultiSigAuditRejected({label}))",), "is false.")
    require_outcome(lines, ("not event(MultiSigAuditBypass(",), "is true.")

    rotation = result_lines(ROOT / "result/aspin_multisig_rotation.log")
    if len(rotation) != 13:
        fail("multi-signature rotation: expected 13 query results")
    for source, prerequisite in (
        ("MultiSigRotationVerified(", "MultiSigRotationSigned("),
        ("CertClaimVerify(", "CertClaimSign("),
        ("MultiSigTransferred(", "MultiSigLineage("),
        ("MultiSigTransferred(", "MultiSigRotationVerified("),
        ("MultiSigTransferred(", "MultiSigState("),
    ):
        require_outcome(rotation, (f"event({source}", f"==> event({prerequisite}"), "is true.")
    for event in ("CertClaimVerify(", "MultiSigCoHostedTransfer(",
                  "MultiSigTransferred(mr_with_lineage,", "MultiSigPairVerified(mr_cosign_only,",
                  "MultiSigNoLineageRefused(mr_cosign_only)"):
        require_outcome(rotation, (f"not event({event}",), "is false.")
    require_outcome(rotation, ("not event(MultiSigTransferred(mr_cosign_only,",), "is true.")
    require_outcome(rotation, ("not event(MultiSigNonMaximumCommit(",), "is true.")
    require_outcome(rotation, ("event(MultiSigTransferred(", "==> hk", " = succ_t(curr[])"), "is true.")


def check_compatible_lifecycles() -> None:
    substitutions = {
        "app_signing": "self_host_signing",
        "other_app_signing": "other_self_host_signing",
        "ancestor_app_signing": "ancestor_self_host_signing",
        "CrossHostLineageAuthenticated": "CrossHostOwnerAuthenticated",
    }

    def normalize(line: str, compatible: bool = False, same_root: bool = False) -> str:
        if compatible:
            mapped = dict(substitutions)
            if same_root:
                mapped["other_app_signing"] = "self_host_signing"
            line = re.sub(r"\b(" + "|".join(substitutions) + r")\b",
                          lambda match: mapped[match.group(0)], line)
        # ProVerif alpha-renames bound variables when extra events are added.
        return re.sub(r"\b([A-Za-z_]+)_\d+\b", r"\1", line)

    for primary, compatible in COMPAT_LIFECYCLE_MODELS.items():
        source_results = result_lines(ROOT / "result" / f"{primary}.log")
        actual_results = result_lines(ROOT / "result" / f"{compatible}.log")
        same_root = primary == "aspin_cross_hostname_hc"
        extra_count = 4 if same_root else 3
        if len(actual_results) != len(source_results) + extra_count:
            fail(f"{compatible}: missing lifecycle or manifest-authentication results")
        for expected, actual in zip(source_results, actual_results):
            if normalize(expected, compatible=True, same_root=same_root) != normalize(actual):
                fail(f"{compatible}: different lifecycle result:\n{expected}\n{actual}")
        check_manifest_provenance(actual_results)
        if same_root:
            require_outcome(
                actual_results,
                ("event(HcOnlyTransferred(", "==> event(AppManifestAuthenticated("),
                "is true.",
            )


def check_manifest_provenance(lines: list[str]) -> None:
    for source, prerequisite in (
        ("ManifestKeyResolve(", "ManifestKeyBind("),
        ("ManifestKeyBind(", "AppManifestAuthenticated("),
        ("AppManifestAuthenticated(", "AppManifestSigned("),
    ):
        require_outcome(lines, (f"event({source}", f"==> event({prerequisite}"), "is true.")


def check_compatible_root_rotation() -> None:
    lines = result_lines(ROOT / "result" / "aspin_compat_root_rotation.log")
    if len(lines) != 15:
        fail("compatible K_s replacement: missing query results")
    check_manifest_provenance(lines)
    for source, prerequisite in (
        ("KsNewRootAccepted(", "AppManifestAuthenticated("),
        ("ClaimKeyVerify(", "ClaimKeySign("),
        ("CertClaimVerify(", "CertClaimSign("),
    ):
        require_outcome(lines, (f"event({source}", f"==> event({prerequisite}"), "is true.")
    for event in (
        "KsOldRootState(", "KsNewRootAccepted(", "KsCutoverAccepted(",
        "KsNewNamespaceBegins(", "KsKeyReplayRejected(",
        "KsClaimReplayRejected(", "KsManifestRejected",
    ):
        require_outcome(lines, (f"not event({event}",), "is false.")
    require_outcome(lines, ("not event(KsOldOnlyTokenAccepted(",), "is true.")
    require_outcome(lines, ("not event(AppManifestAuthenticated(",
                            "unauthorized_manifest_root"), "is true.")


def check_availability_and_cross_app() -> None:
    require_fragments_in_files(TEX_SOURCES, (
        "conditional safety results, not a guarantee of delivery or eventual availability",
        "Silence does not itself generate a timeout",
        r"\label{table:remote-functional}",
        "not latency distributions or reliability estimates",
    ))
    require_patterns_in_files(TEX_SOURCES, (
        r"\b98(?:/98)?(?:\s+functional)?\s+observations\b",
    ))
    for model in ("aspin_availability", "aspin_cross_app"):
        source = ROOT / f"{model}.pv"
        require_fragments(source, ("header_matches(", "jws_general_verify(", "token_fresh(",
                                   "package_signing_record(", "resolve_os_key("))
        require_fragments(ROOT / "run.sh", (f"  {model}\n",))
    availability = result_lines(ROOT / "result/aspin_availability.log")
    if len(availability) != 15:
        fail("availability: missing query results")
    for event in ("AvailabilityData(label", "AvailabilityConnected(label", "AvailabilityReady(available_cached"):
        require_outcome(availability, (f"RESULT event({event}", "==>"), "is true.")
    for event in ("AvailabilityData(available_cached)", "AvailabilityData(available_restored)",
                  "AvailabilityRefused(unavailable_empty)", "AvailabilityRefused(unavailable_expired)",
                  "AvailabilityExpiredReplayRejected", "AvailabilityBoundExpired(delegation_bound)",
                  "AvailabilityBoundExpired(claim_bound)"):
        require_outcome(availability, (f"not event({event}",), "is false.")
    for event in ("AvailabilityData(unavailable_empty)", "AvailabilityData(unavailable_expired)",
                  "AvailabilityConnected(unavailable_empty)", "AvailabilityConnected(unavailable_expired)",
                  "AvailabilityData(replay_after_expiry)"):
        require_outcome(availability, (f"not event({event}",), "is true.")
    cross = result_lines(ROOT / "result/aspin_cross_app.log")
    if len(cross) != 10:
        fail("cross-app: missing query results")
    for event in ("CrossAppData(", "CrossAppPolicy("):
        require_outcome(cross, (f"RESULT event({event}", "==>"), "is true.")
    for event in ("CrossAppIssuerRejected", "CrossAppNativeValid(rogue_cert_issuer)",
                  "CrossAppTargetRefused(target_unavailable)"):
        require_outcome(cross, (f"not event({event}",), "is false.")
    require_outcome(cross, ("not event(CrossAppData(", "real_cert_issuer"), "is false.")
    require_outcome(cross, ("not event(CrossAppData(", "rogue_cert_issuer"), "is true.")
    require_outcome(cross, ("not event(CrossAppPolicy(", "other_app_signing"), "is true.")
    require_outcome(cross, ("not event(CrossAppResolved(",), "is true.")
    require_outcome(cross, ("not event(CrossAppData(", "target_unavailable"), "is true.")


def main() -> None:
    check_sources()
    check_network_models()
    check_compat_model()
    check_cache_migration()
    check_dedicated_ca_migration()
    check_delegated_claim_key_rotation()
    check_key_rotation()
    check_certificate_change()
    check_cross_sign()
    check_multisig()
    parallel = result_lines(ROOT / "result/aspin_parallel_roots.log")
    if len(parallel) != 10:
        fail("Parallel-root model must report all ten queries")
    for line, expected in zip(parallel, ["true"] * 4 + ["false"] * 2 + ["true"] * 4):
        if not line.endswith("is " + expected + "."):
            fail("Unexpected parallel-root proof outcome: " + line)
    check_cross_hostname_hc()
    check_compatible_lifecycles()
    check_compatible_root_rotation()
    check_availability_and_cross_app()
    print("ProVerif sources, saved results, and TeX design are consistent.")


if __name__ == "__main__":
    main()
