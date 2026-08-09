#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")"
mkdir -p result

models=(
  aspin_bgp_hijacking
  aspin_dns_hijacking
  aspin_mitm
  aspin_cache
  aspin_key_rotation
  tls_bgp_hijacking
  tls_dns_hijacking
  tls_mitm
)

# Fail before overwriting saved evidence when any source does not parse.
for model in "${models[@]}"; do
  proverif -parse-only -lib base.pvl "${model}.pv"
done

for model in "${models[@]}"; do
  if [[ "$model" == "aspin_cache" ]]; then
    # Keep both historical filenames synchronized for repository compatibility.
    proverif -lib base.pvl "${model}.pv" |
      tee result/aspin-cache.log result/aspin_cache.log
  else
    proverif -lib base.pvl "${model}.pv" | tee "result/${model}.log"
  fi
done

python3 check_consistency.py
