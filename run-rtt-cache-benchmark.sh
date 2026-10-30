#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == "--help" ]]; then
    printf '%s\n' \
        'Usage: bash run-rtt-cache-benchmark.sh [iterations-per-cell=100]' \
        'ASPIN_RTT_VALUES_MS=0,20,50,100,200 ASPIN_RTT_REPEATS=1 ASPIN_RTT_WARMUPS=10' \
        'Requires an authorized rooted ASPin device and a dedicated Linux test host.' \
        'Creates isolated netem/Nginx; restarts Android framework for compatible cache isolation.' \
        'No AOSP build, flash, kernel reboot, or clock rollback.'
    exit 0
fi
# Reuse certificate generation, debug trust, APK builds, clock synchronization,
# device locking and cleanup, but skip reboot/rollback/lifecycle experiments.
export ASPIN_RTT_MATRIX_ONLY=1
export ASPIN_ADB_REVERSE_TRANSPORT=1
export ASPIN_GENERATE_ROGUE_CA=1
exec bash "$SCRIPT_DIR/run-robustness-benchmark.sh" "${1:-100}"
