#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == "--help" ]]; then
    printf '%s\n' \
        'Usage: bash run-policy-scenario-benchmark.sh [independent-repeats=1]' \
        'Adds primary/compatible fail-closed availability and cross-app TLS tests.' \
        'ASPIN_POLICY_SHORT_SECONDS=60 (>=30), BENCHMARK_TIMEOUT_SECONDS=3600' \
        'Requires an authorized rooted ASPin device and a dedicated test host.' \
        'No AOSP build, flash, reboot, protected-state reset, or clock rollback.'
    exit 0
fi
export ASPIN_POLICY_SCENARIOS_ONLY=1
export ASPIN_RTT_MATRIX_ONLY=1
export ASPIN_ADB_REVERSE_TRANSPORT=1
export ASPIN_GENERATE_ROGUE_CA=1
exec bash "$SCRIPT_DIR/run-robustness-benchmark.sh" "${1:-1}"
