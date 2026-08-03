#!/usr/bin/env python3
"""Check that the ProVerif models/results match the protocol and tables in tex."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
TEX = ROOT.parent / "tex" / "paper_content.tex"
APPENDIX = ROOT.parent / "tex" / "paper_appendix.tex"

ASPIN_MODELS = (
    "aspin_dns_hijacking.pv",
    "aspin_bgp_hijacking.pv",
    "aspin_mitm.pv",
)

PROTOCOL_FRAGMENTS = (
    "jwt_sign(header, content, good_exp, good_ttl, sk_app_signing)",
    "jwt_sign(header2, content2, good_exp2, good_ttl2, sk_claim_signing)",
    "jwt_verify(jwt(h, plr, sr), pk_app_signing, curr)",
    "jwt_verify(jwt(h2, plr2, sr2), pk1_recv, curr)",
    "check_host(hostname, subj_and_san_recv)",
    "check_issuer(issuer_recv, system_ca_list)",
    "check_host(hostname, subject_and_san_claim)",
    "issuer_claim = issuer_recv",
    "get_ttl(plr)",
)

TEX_FRAGMENTS = (
    "ClaimKeySign($K_{app}, K_{cpub}$, aux)",
    "CertClaimSign($K_{claim}$, Claim, aux')",
    "ClaimKeyVerify($T_k,K_{apub}$)",
    "CertClaimVerify($T_c,K_{cpub}$)",
    "CertClaimCheck(Claim, Cert)",
    r"\texttt{not event(MSFakeServer(...))} & true & false",
    r"\texttt{not event(MSConn(...))} & true & false & true & false",
    r"\label{sec:cache}",
    "keeps $T'_c$ continuously available for at least two complete $ttl$-length cache windows",
    "Only after the overlap period ends does the app developer deploy \\emph{NewCert}",
)

APPENDIX_FRAGMENTS = (
    "jwt_sign(header, content, good_exp, good_ttl, sk_app_signing)",
    "jwt_sign(header2, content2, good_exp2, good_ttl2, sk_claim_signing)",
    "check_host(hostname, subject_and_san_claim)",
    "issuer_claim = issuer_recv",
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
            fail(f"{path.relative_to(ROOT.parent)} still contains obsolete format: {fragment}")


def results(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [line.strip() for line in lines if line.startswith("RESULT ")]


def find_result(lines: list[str], *terms: str) -> str:
    matches = [line for line in lines if all(term in line for term in terms)]
    if len(matches) != 1:
        fail(f"expected one RESULT containing {terms}, found {len(matches)}")
    return matches[0]


def require_outcome(lines: list[str], terms: tuple[str, ...], outcome: str) -> None:
    line = find_result(lines, *terms)
    if not line.endswith(outcome):
        fail(f"unexpected result:\n  {line}\nexpected suffix: {outcome}")


def check_common_reachability(lines: list[str]) -> None:
    require_outcome(lines, ("not event(RSConn(",), "is false.")
    require_outcome(lines, ("not event(AppConnRS(",), "is false.")
    require_outcome(lines, ("not event(AppRejectConn(",), "is false.")


def check_network(kind: str) -> None:
    aspin = results(ROOT / "result" / f"aspin_{kind}_hijacking.log")
    tls = results(ROOT / "result" / f"tls_{kind}_hijacking.log")
    check_common_reachability(aspin)
    require_outcome(aspin, ("not event(MSConn(",), "is true.")
    require_outcome(aspin, ("not event(AppConnMS(",), "is true.")
    require_outcome(aspin, ("event(MSConn(", "==> event(AppConnMS("), "is true.")

    require_outcome(tls, ("not event(RSConn(",), "is false.")
    require_outcome(tls, ("not event(AppConnRS(",), "is false.")
    require_outcome(tls, ("not event(AppRejectConn(",), "is true.")
    require_outcome(tls, ("not event(MSConn(",), "is false.")
    require_outcome(tls, ("not event(AppConnMS(",), "is false.")
    require_outcome(tls, ("event(MSConn(", "==> event(AppConnMS("), "is true.")


def check_mitm() -> None:
    aspin = results(ROOT / "result" / "aspin_mitm.log")
    tls = results(ROOT / "result" / "tls_mitm.log")
    check_common_reachability(aspin)
    require_outcome(aspin, ("not event(MSFakeServer(",), "is true.")
    require_outcome(aspin, ("not event(AppConnMS(",), "is true.")
    require_outcome(
        aspin, ("event(MSFakeServer(", "==> event(AppConnMS("), "is true."
    )
    require_outcome(aspin, ("not event(MSFakeClient(",), "is true.")
    require_outcome(
        aspin, ("event(RSConn(", "==> event(MSFakeClient("), "is false."
    )

    require_outcome(tls, ("not event(RSConn(",), "is false.")
    require_outcome(tls, ("not event(AppConnRS(",), "is false.")
    require_outcome(tls, ("event(RSConn(", "==> event(AppConnRS("), "cannot be proved.")
    require_outcome(tls, ("not event(AppRejectConn(",), "is true.")
    require_outcome(tls, ("not event(MSFakeServer(",), "is false.")
    require_outcome(tls, ("not event(AppConnMS(",), "is false.")
    require_outcome(
        tls, ("event(MSFakeServer(", "==> event(AppConnMS("), "cannot be proved."
    )
    require_outcome(tls, ("not event(MSFakeClient(",), "is false.")
    require_outcome(
        tls, ("event(RSConn(", "==> event(MSFakeClient("), "is false."
    )


def check_cache_migration() -> None:
    require_fragments(
        ROOT / "aspin_cache.pv",
        (
            "policy_current_ca",
            "policy_transition_ca",
            "policy_new_ca",
            "window_overlap_1",
            "window_overlap_2",
            "window_new_cert",
            "issuer_allowed(new_cert_issuer, policy_transition_ca)",
        ),
    )
    cache = results(ROOT / "result" / "aspin-cache.log")
    require_outcome(
        cache,
        ("event(MigrationClaimCached(", "==> event(MigrationClaimPublished("),
        "is true.",
    )
    windows = (
        ("window_current", "real_cert_issuer", "policy_current_ca"),
        ("window_overlap_1", "real_cert_issuer", "policy_transition_ca"),
        ("window_overlap_2", "real_cert_issuer", "policy_transition_ca"),
        ("window_new_cert", "new_cert_issuer", "policy_transition_ca"),
        ("window_final", "new_cert_issuer", "policy_new_ca"),
    )
    for window, issuer, policy in windows:
        require_outcome(
            cache, (f"not event(MigrationWindowComplete({window}))",), "is false."
        )
        require_outcome(
            cache,
            (f"not event(MigrationCertAccepted({window},{issuer},{policy}))",),
            "is false.",
        )
        require_outcome(
            cache,
            (
                f"event(MigrationWindowComplete({window}))",
                f"event(MigrationCertAccepted({window},{issuer},{policy}))",
            ),
            "is true.",
        )


def main() -> None:
    require_fragments(TEX, TEX_FRAGMENTS)
    require_fragments(APPENDIX, APPENDIX_FRAGMENTS)
    require_fragments(ROOT / "base.pvl", ("token not expired", "succ_t(now2)"))
    require_fragments(
        ROOT.parent / "ASPin/app/src/main/java/com/abbypan/aspin/JwtVerifier.java",
        ("cnf.jwk", "JWT x5c verification key is required", "getClaim(\"ttl\")"),
    )
    require_fragments(
        ROOT.parent / "ASPin/app/src/main/java/com/abbypan/aspin/AppTrustedServerCert.java",
        ("staleDeadline", "KEY_CACHE", "CLAIM_CACHE"),
    )
    for model in ASPIN_MODELS:
        require_fragments(ROOT / model, PROTOCOL_FRAGMENTS)

    check_network("dns")
    check_network("bgp")
    check_mitm()
    check_cache_migration()
    print("ProVerif models, saved results, and tex design are consistent.")


if __name__ == "__main__":
    main()
