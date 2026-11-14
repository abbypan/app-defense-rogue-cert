#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")"
mkdir -p result
PROVERIF="${PROVERIF:-proverif}"
command -v "$PROVERIF" >/dev/null || {
  echo "ProVerif not found; activate its environment or set PROVERIF to its executable." >&2
  exit 127
}
python3 generate_compatible_models.py --check

models=(
  aspin_bgp_hijacking
  aspin_compat_manifest_key
  aspin_dns_hijacking
  aspin_mitm
  aspin_cache
  aspin_ca_migration
  aspin_claim_key_rotation
  aspin_key_rotation
  aspin_certificate_change
  aspin_cross_sign
  aspin_multisig
  aspin_multisig_rotation
  aspin_parallel_roots
  aspin_cross_hostname_hc
  aspin_compat_cache
  aspin_compat_ca_migration
  aspin_compat_claim_key_rotation
  aspin_compat_root_rotation
  aspin_compat_certificate_change
  aspin_compat_cross_sign
  aspin_compat_multisig
  aspin_compat_cross_hostname_hc
  aspin_availability
  aspin_compat_availability
  aspin_cross_app
  aspin_compat_cross_app
  tls_bgp_hijacking
  tls_dns_hijacking
  tls_mitm
)

# Fail before overwriting saved evidence when any source does not parse.
for model in "${models[@]}"; do
  "$PROVERIF" -parse-only -lib base.pvl "${model}.pv"
done

for model in "${models[@]}"; do
  if [[ "$model" == "aspin_cache" ]]; then
    # Keep both historical filenames synchronized for repository compatibility.
    "$PROVERIF" -lib base.pvl "${model}.pv" |
      tee result/aspin-cache.log result/aspin_cache.log
  else
    "$PROVERIF" -lib base.pvl "${model}.pv" | tee "result/${model}.log"
  fi
done

python3 check_consistency.py
