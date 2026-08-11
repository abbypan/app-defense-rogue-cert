#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
if [ -n "${ASPIN_JAVA_HOME:-}" ]; then
    export JAVA_HOME="$ASPIN_JAVA_HOME"
elif [ -x /usr/lib/jvm/java-17-openjdk/bin/java ]; then
    export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
fi

ITERATIONS="${1:-2000}"
THREADS="${ASPIN_CONCURRENCY_THREADS:-8}"
TIMEOUT_SECONDS="${BENCHMARK_TIMEOUT_SECONDS:-3600}"
SKIP_APP_BUILD="${ASPIN_SKIP_APP_BUILD:-0}"
PACKAGE="com.cert.aspin"
CALLER_PACKAGE="com.cert.aspin.caller"
ALGORITHMS=(es256 es384 rsa3072 rsa4096)
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$SCRIPT_DIR/results/robustness-$RUN_ID"
APK_DIR="$SCRIPT_DIR/results/apks"
SNAPSHOT_DIR="$RUN_DIR/token-snapshots"

if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]] ||
        ! [[ "$THREADS" =~ ^[1-9][0-9]*$ ]] ||
        ! [[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] ||
        ! [[ "$SKIP_APP_BUILD" =~ ^[01]$ ]]; then
    echo "ERROR: iterations, thread count, and timeout must be positive integers;" >&2
    echo "       ASPIN_SKIP_APP_BUILD must be 0 or 1." >&2
    exit 2
fi

DEVICE_ID="$(adb devices | awk '$2 == "device" {print $1; exit}')"
if [ -z "$DEVICE_ID" ]; then
    echo "ERROR: No Android device is connected." >&2
    exit 1
fi
if ! adb -s "$DEVICE_ID" shell service list | grep -q '[[:space:]]aspin:'; then
    echo "ERROR: The connected device does not expose the ASPin OS service." >&2
    echo "This script never builds AOSP or flashes a device." >&2
    exit 1
fi
if ! adb -s "$DEVICE_ID" shell 'su 0 id -u' 2>/dev/null | tr -d '\r' | grep -qx 0; then
    echo "ERROR: A rooted userdebug device is required for the clock test." >&2
    exit 1
fi
if ! sudo -n true; then
    echo "ERROR: Passwordless sudo is required to switch the local Nginx test profile." >&2
    exit 1
fi

mkdir -p "$RUN_DIR" "$APK_DIR" "$SNAPSHOT_DIR/v1" "$SNAPSHOT_DIR/v2"

wait_for_boot() {
    adb -s "$DEVICE_ID" wait-for-device
    for _ in $(seq 1 300); do
        if [ "$(adb -s "$DEVICE_ID" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: Device did not finish booting." >&2
    return 1
}

deploy_profile() {
    local profile="$1"
    local source_root="$SCRIPT_DIR/${profile}server"
    sudo -n cp -pr "$source_root/etc/." /etc/
    sudo -n cp -pr "$source_root/var/." /var/
    sudo -n systemctl restart nginx.service
    sudo -n systemctl is-active --quiet nginx.service
}

snapshot_es256_tokens() {
    local destination="$1"
    cp "$SCRIPT_DIR/realserver/var/www/es256/.well-known/ClaimSigningKey.jwt" \
        "$destination/ClaimSigningKey.jwt"
    cp "$SCRIPT_DIR/realserver/var/www/es256/.well-known/ServerCertClaim.jwt" \
        "$destination/ServerCertClaim.jwt"
}

deploy_es256_token_pair() {
    local tk_path="$1"
    local tc_path="$2"
    sudo -n cp "$tk_path" /var/www/es256/.well-known/ClaimSigningKey.jwt
    sudo -n cp "$tc_path" /var/www/es256/.well-known/ServerCertClaim.jwt
}

validate_csv() {
    local csv_path="$1"
    local result_column="$2"
    python3 - "$csv_path" "$result_column" <<'PY'
import csv
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
column = sys.argv[2]
with path.open(newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream))
if len(rows) != 1:
    raise SystemExit(f"{path}: expected exactly one result row, found {len(rows)}")
if column not in rows[0]:
    raise SystemExit(f"{path}: missing result column {column!r}")
if rows[0][column] != "PASS":
    raise SystemExit(f"{path}: {column}={rows[0][column]!r}, expected 'PASS'")
PY
}

run_benchmark() {
    local package_name="$1"
    local benchmark_type="$2"
    local output_name="$3"
    local result_column="$4"
    shift 4
    local device_csv="/sdcard/Android/data/$package_name/files/$output_name"
    local local_csv="$RUN_DIR/$output_name"

    adb -s "$DEVICE_ID" shell rm -f "$device_csv" >/dev/null 2>&1 || true
    rm -f "$local_csv"
    adb -s "$DEVICE_ID" logcat -c
    adb -s "$DEVICE_ID" shell am start -S -W \
        -n "$package_name/com.cert.aspin.MainActivity" \
        --es benchmark_type "$benchmark_type" \
        --es output_csv "$device_csv" "$@"

    for _ in $(seq 1 "$TIMEOUT_SECONDS"); do
        if adb -s "$DEVICE_ID" shell "[ -f '$device_csv' ]" 2>/dev/null; then
            adb -s "$DEVICE_ID" pull "$device_csv" "$local_csv" >/dev/null
            test -s "$local_csv"
            validate_csv "$local_csv" "$result_column"
            return 0
        fi
        sleep 1
    done
    echo "ERROR: $benchmark_type did not produce $device_csv." >&2
    adb -s "$DEVICE_ID" logcat -d -t 500 | tail -n 300 >&2 || true
    return 1
}

install_target() {
    local algorithm="$1"
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" install -r "$APK_DIR/ASPin-$algorithm.apk"
    adb -s "$DEVICE_ID" shell "su 0 cmd deviceidle whitelist +$PACKAGE" \
        >/dev/null 2>&1 || true
}

ORIGINAL_AUTO_TIME="$(adb -s "$DEVICE_ID" shell settings get global auto_time | tr -d '\r')"
CLOCK_CHANGED=0
SERVER_CHANGED=0
restore_clock() {
    if [ "$CLOCK_CHANGED" -eq 1 ]; then
        local host_epoch
        host_epoch="$(date +%s)"
        adb -s "$DEVICE_ID" shell "su 0 date -s '@$host_epoch'" >/dev/null 2>&1 || true
        adb -s "$DEVICE_ID" shell \
            "su 0 settings put global auto_time '$ORIGINAL_AUTO_TIME'" >/dev/null 2>&1 || true
        CLOCK_CHANGED=0
    fi
}
cleanup() {
    set +e
    restore_clock
    if [ "$SERVER_CHANGED" -eq 1 ]; then
        deploy_profile real
    fi
    adb -s "$DEVICE_ID" uninstall "$CALLER_PACKAGE" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

{
    echo "run_id=$RUN_ID"
    echo "iterations=$ITERATIONS"
    echo "threads=$THREADS"
    echo "device=$DEVICE_ID"
    echo "fingerprint=$(adb -s "$DEVICE_ID" shell getprop ro.build.fingerprint | tr -d '\r')"
    echo "kernel=$(adb -s "$DEVICE_ID" shell uname -a | tr -d '\r')"
    echo "repo_commit=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || echo uncommitted)"
    echo "transport=physical Pixel 8 connected to a local Nginx host"
    echo "aosp_build_or_flash=not performed by this script"
} > "$RUN_DIR/environment.txt"

# Generate one internally consistent token set and build only the benchmark apps.
# This script never builds a system image or flashes a device.
python3 "$SCRIPT_DIR/gen-trust-artifacts.py"
python3 "$SCRIPT_DIR/check-implementation-consistency.py"
snapshot_es256_tokens "$SNAPSHOT_DIR/v1"
if [ "$SKIP_APP_BUILD" -eq 0 ]; then
    python3 "$SCRIPT_DIR/gen-signed-apks.py" --workers 24 --output-dir "$APK_DIR"
    (cd "$SCRIPT_DIR/ASPin/es256" && \
        ./gradlew --max-workers=24 :app:assembleCrossAppCaller)
else
    python3 "$SCRIPT_DIR/gen-signed-apks.py" --workers 24 --skip-build \
        --output-dir "$APK_DIR"
fi

# Four-algorithm distributions: full forced refresh, successful cached
# connection, rejected rogue connection, and concurrent cache hits.
for algorithm in "${ALGORITHMS[@]}"; do
    deploy_profile real
    SERVER_CHANGED=1
    install_target "$algorithm"
    run_benchmark "$PACKAGE" avgveriftime "cold-refresh-$algorithm.csv" Result \
        --ei iterations "$ITERATIONS"
    run_benchmark "$PACKAGE" avgvisittime "cached-real-$algorithm.csv" \
        Matches_TeX_Design --ei iterations "$ITERATIONS" \
        --es server_phase realserver
    run_benchmark "$PACKAGE" concurrency "concurrent-cache-$algorithm.csv" Result \
        --ei iterations "$ITERATIONS" --ei threads "$THREADS"

    deploy_profile rogue
    run_benchmark "$PACKAGE" avgvisittime "cached-rogue-$algorithm.csv" \
        Matches_TeX_Design --ei iterations "$ITERATIONS" \
        --es server_phase rogueserver
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1 || true
done

# Direct persistence test. First accept v1, generate and accept higher-iat v2,
# reboot, then independently replay the still-fresh old Tc and old Tk. A mere
# successful post-restart query would not prove persistence; these lower-iat
# replay checks do.
deploy_profile real
install_target es256
run_benchmark "$PACKAGE" claimprobe lifecycle-v1-accepted.csv Result \
    --ez force_refresh true --ez expect_success true --es probe_label accept_v1

python3 "$SCRIPT_DIR/gen-trust-artifacts.py" --alg es256
snapshot_es256_tokens "$SNAPSHOT_DIR/v2"
deploy_profile real
run_benchmark "$PACKAGE" claimprobe lifecycle-v2-accepted.csv Result \
    --ez force_refresh true --ez expect_success true --es probe_label accept_v2

adb -s "$DEVICE_ID" reboot
wait_for_boot

deploy_es256_token_pair \
    "$SNAPSHOT_DIR/v2/ClaimSigningKey.jwt" \
    "$SNAPSHOT_DIR/v1/ServerCertClaim.jwt"
run_benchmark "$PACKAGE" claimprobe post-restart-old-tc-replay.csv Result \
    --ez force_refresh true --ez expect_success false \
    --es expected_error anti-rollback --es probe_label post_restart_old_tc

deploy_es256_token_pair \
    "$SNAPSHOT_DIR/v1/ClaimSigningKey.jwt" \
    "$SNAPSHOT_DIR/v2/ServerCertClaim.jwt"
run_benchmark "$PACKAGE" claimprobe post-restart-old-tk-replay.csv Result \
    --ez force_refresh true --ez expect_success false \
    --es expected_error anti-rollback --es probe_label post_restart_old_tk

deploy_es256_token_pair \
    "$SNAPSHOT_DIR/v2/ClaimSigningKey.jwt" \
    "$SNAPSHOT_DIR/v2/ServerCertClaim.jwt"
run_benchmark "$PACKAGE" claimprobe post-restart-current-tokens.csv Result \
    --ez force_refresh true --ez expect_success true \
    --es probe_label post_restart_current

# Freshness is tested separately from anti-rollback: move the protected test
# device clock behind v2's iat, require a not-fresh failure, then restore time.
ROLLBACK_EPOCH="$(( $(date +%s) - 172800 ))"
adb -s "$DEVICE_ID" shell "su 0 settings put global auto_time 0"
adb -s "$DEVICE_ID" shell "su 0 date -s '@$ROLLBACK_EPOCH'" >/dev/null
CLOCK_CHANGED=1
run_benchmark "$PACKAGE" claimprobe clock-rollback.csv Result \
    --ez force_refresh true --ez expect_success false \
    --es expected_error "not fresh" --es probe_label clock_rollback
restore_clock
run_benchmark "$PACKAGE" claimprobe clock-restored.csv Result \
    --ez force_refresh true --ez expect_success true \
    --es probe_label clock_restored

# App A and App B use unrelated signing keys. The caller first performs a
# forced named-target refresh, then measures the cached cross-app API under
# concurrency. This demonstrates separate signing domains, not participation
# by two external vendors.
adb -s "$DEVICE_ID" install -r \
    "$SCRIPT_DIR/ASPin/es256/app/build/outputs/apk/crossAppCaller/app-crossAppCaller.apk"
run_benchmark "$CALLER_PACKAGE" claimprobe cross-app-target-refresh.csv Result \
    --ez force_refresh true --ez expect_success true \
    --es probe_label cross_app_target_refresh
run_benchmark "$CALLER_PACKAGE" concurrency cross-app-concurrent-cache.csv Result \
    --ei iterations "$ITERATIONS" --ei threads "$THREADS"

python3 "$SCRIPT_DIR/summarize-robustness-results.py" "$RUN_DIR"

echo "Robustness benchmark results: $RUN_DIR"
for csv in "$RUN_DIR"/*.csv; do
    echo "==> $(basename "$csv")"
    cat "$csv"
done
