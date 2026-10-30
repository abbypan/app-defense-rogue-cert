#!/usr/bin/env python3
"""Instantiate lifecycle models with OS-authenticated manifest policy roots."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MODELS = {
    "aspin_cache": "aspin_compat_cache",
    "aspin_ca_migration": "aspin_compat_ca_migration",
    "aspin_claim_key_rotation": "aspin_compat_claim_key_rotation",
    "aspin_certificate_change": "aspin_compat_certificate_change",
    "aspin_cross_sign": "aspin_compat_cross_sign",
    "aspin_cross_hostname_hc": "aspin_compat_cross_hostname_hc",
    "aspin_availability": "aspin_compat_availability",
    "aspin_cross_app": "aspin_compat_cross_app",
    "aspin_multisig": "aspin_compat_multisig",
}


def authenticated_binding(app: str, key: str, version: str = "installed_app_version") -> str:
    """Abstract native APK-signature verification, not a second trust store.

    These local bindings are authenticated-installation facts. The dedicated
    K_s-rotation model additionally consumes candidate signed APK abstractions
    on the public channel to check replacement under the package signer.
    """
    signer_id = "other_app_signing" if app == "caller_app_id" else "app_signing"
    return f"""  let apk_signer = pk(gen_sk_for_id({signer_id})) in
  let apk_manifest = app_manifest({app}, {key}, {version}) in
  event AppManifestSigned({app}, apk_signer, {key}, {version});
  let apk_signature = sig_sign(apk_manifest, gen_sk_for_id({signer_id})) in
  let (=true) = sig_verify(apk_manifest, apk_signature, apk_signer) in
  event AppManifestAuthenticated({app}, apk_signer, {key}, {version});
  event ManifestKeyBind({app}, {key});
"""


def binding_queries() -> str:
    return """query app: bitstring, root: pkey;
  event(ManifestKeyResolve(app, root)) ==> event(ManifestKeyBind(app, root)).
query app: bitstring, root: pkey, signer: pkey, version: bitstring;
  event(ManifestKeyBind(app, root)) ==>
  event(AppManifestAuthenticated(app, signer, root, version)).
query app: bitstring, root: pkey, signer: pkey, version: bitstring;
  event(AppManifestAuthenticated(app, signer, root, version)) ==>
  event(AppManifestSigned(app, signer, root, version)).
"""


def instantiate(source_name: str) -> str:
    source = (ROOT / f"{source_name}.pv").read_text(encoding="utf-8")
    # Whole identifiers avoid changing other_app_signing a second time.
    replacements = {
        "app_signing": "self_host_signing",
        "other_app_signing": "other_self_host_signing",
        "ancestor_app_signing": "ancestor_self_host_signing",
        "package_signing_record": "manifest_key_record",
        "resolve_os_key": "resolve_manifest_key",
        "CrossHostLineageAuthenticated": "CrossHostOwnerAuthenticated",
        "TrustedCrossHostLineage": "TrustedCrossHostOwner",
    }
    if source_name == "aspin_cross_hostname_hc":
        # The currently installed manifest selects ONE K_s. Shared H_c is
        # preserved across hostnames under that root, not across a K_s change.
        replacements["other_app_signing"] = "self_host_signing"
    source = re.sub(
        r"\b(" + "|".join(replacements) + r")\b",
        lambda match: replacements[match.group(0)],
        source,
    )
    # Each private registry record denotes a package authenticated at install
    # or update. Resolution is not a public caller-supplied trust-root API.
    record_pattern = re.compile(
        r"(?P<line>  let \w+ = manifest_key_record\(\s*"
        r"(?P<app>target_app_id|caller_app_id),\s*"
        r"(?P<key>pk\(gen_sk_for_id\(\w+\)\))\) in\n)"
    )
    source = record_pattern.sub(
        lambda match: (
            authenticated_binding(match["app"], match["key"])
            + match["line"]
        ),
        source,
    )
    resolve_pattern = re.compile(
        r"(?P<line>  let (?P<key>\w+) = resolve_manifest_key\(\w+,\s*"
        r"(?P<app>target_app_id|caller_app_id)\) in\n)"
    )
    source = resolve_pattern.sub(
        lambda match: match["line"]
        + f"  event ManifestKeyResolve({match['app']}, {match['key']});\n",
        source,
    )
    if source_name == "aspin_cross_hostname_hc":
        anchor = "  event CrossHostOwnerAuthenticated(old_root, new_root);"
        source = source.replace(anchor,
            authenticated_binding("target_app_id", "new_root") + anchor)
        source = source.replace(
            " * H_c for a shared signed Subject/SAN. A trusted app-signing lineage authorizes\n"
            " * owner continuity. A current-key-only T_k can initialize the new hostname;",
            " * H_c for a shared signed Subject/SAN. Both hostnames use the SAME\n"
            " * current manifest K_s. A current-key-only T_k initializes the new hostname;",
        )
        extra = """query old_root: pkey, new_root: pkey, host: bitstring,
      floor: timestamp, accepted: timestamp, merged: timestamp,
      signer: pkey, version: bitstring;
  event(HcOnlyTransferred(old_root, new_root, host, floor, accepted, merged)) ==>
  event(AppManifestAuthenticated(target_app_id, signer, new_root, version)).
"""
    else:
        extra = ""
    queries = binding_queries() + extra
    source = source.replace("\nprocess\n", "\n" + queries + "\nprocess\n")
    return (
        "(* Generated by generate_compatible_models.py from " + source_name
        + ".pv. K_s is bound by an authenticated installed manifest.\n"
        + " * Lifecycle checks are shared with the primary model; this file is\n"
        + " * independently parsed and verified, including manifest provenance. *)\n\n"
        + source
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for primary, compatible in MODELS.items():
        path = ROOT / f"{compatible}.pv"
        expected = instantiate(primary)
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                raise SystemExit(f"Stale generated model: {path.name}")
        else:
            path.write_text(expected, encoding="utf-8")
    print(f"{'Checked' if args.check else 'Generated'} {len(MODELS)} compatibility models")


if __name__ == "__main__":
    main()
