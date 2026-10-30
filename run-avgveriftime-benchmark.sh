#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
if [ -n "${ASPIN_JAVA_HOME:-}" ]; then
    export JAVA_HOME="$ASPIN_JAVA_HOME"
elif [ -x /usr/lib/jvm/java-21-openjdk/bin/java ]; then
    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
fi

ITERATIONS="${1:-2000}"
BENCHMARK_TIMEOUT_SECONDS="${BENCHMARK_TIMEOUT_SECONDS:-3600}"
RESULTS_DIR="$SCRIPT_DIR/results"
APKS_DIR="$RESULTS_DIR/apks"
PACKAGE="com.cert.aspin"
mkdir -p "$RESULTS_DIR" "$APKS_DIR"

if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]] ||
        ! [[ "$BENCHMARK_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "iterations and BENCHMARK_TIMEOUT_SECONDS must be positive integers" >&2
    exit 1
fi
if ! adb get-state >/dev/null 2>&1; then
    echo "no Android device connected through ADB" >&2
    exit 1
fi
DEVICE_ID="$(adb devices | awk '$2 == "device" {print $1; exit}')"

cleanup() {
    set +e
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1
    for alg in es256 es384 rsa3072 rsa4096; do
        "$SCRIPT_DIR/activate-claim-signing-key.sh" "$alg" primary >/dev/null 2>&1
    done
}
trap cleanup EXIT

wait_for_csv() {
    local device_csv="$1"
    local label="$2"
    local attempt
    for attempt in $(seq 1 "$BENCHMARK_TIMEOUT_SECONDS"); do
        if adb -s "$DEVICE_ID" shell "[ -f '$device_csv' ]" 2>/dev/null; then
            echo "$label completed after ${attempt}s"
            return 0
        fi
        sleep 1
    done
    echo "$label timed out" >&2
    return 1
}

run_one() {
    local alg="$1"
    local mode="$2"
    local suffix=""
    local token_mode=primary
    if [ "$mode" = compatible ]; then
        suffix=-compatible
        token_mode=compat
    fi
    local apk="$APKS_DIR/ASPin-${alg}${suffix}.apk"
    local device_csv="/sdcard/Android/data/${PACKAGE}/files/benchmark_${alg}_${mode}_refresh.csv"
    local local_csv="$RESULTS_DIR/benchmark_${alg}_${mode}_refresh.csv"

    "$SCRIPT_DIR/activate-claim-signing-key.sh" "$alg" "$token_mode"
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" install -r "$apk" >/dev/null
    adb -s "$DEVICE_ID" shell "su 0 cmd deviceidle whitelist +$PACKAGE" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" shell "rm -f '$device_csv'" >/dev/null 2>&1 || true
    rm -f "$local_csv"
    adb -s "$DEVICE_ID" shell am start -S -W -n "$PACKAGE/.MainActivity" \
        --es benchmark_type avgveriftime \
        --ei iterations "$ITERATIONS" \
        --es output_csv "$device_csv" >/dev/null
    wait_for_csv "$device_csv" "$alg/$mode refresh"
    adb -s "$DEVICE_ID" pull "$device_csv" "$local_csv" >/dev/null
    tail -n +2 "$local_csv" >> "$SUMMARY_CSV"
}

python3 "$SCRIPT_DIR/gen-trust-artifacts.py"
python3 "$SCRIPT_DIR/check-implementation-consistency.py"
python3 "$SCRIPT_DIR/gen-signed-apks.py" --workers 24 \
    --mode primary --mode compatible --output-dir "$APKS_DIR"

sudo -n cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
sudo -n cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
sudo -n systemctl restart nginx.service

SUMMARY_CSV="$RESULTS_DIR/table_refresh_summary.csv"
echo "Algorithm,Mode,Scheme,Iterations,Tk_Mean_ms,Tc_Mean_ms,Total_Mean_ms,Total_P50_ms,Total_P95_ms,Total_P99_ms,Success_Count,Result,Timestamp" > "$SUMMARY_CSV"

for ALG in es256 es384 rsa3072 rsa4096; do
    run_one "$ALG" primary
    run_one "$ALG" compatible
done

echo "refresh benchmark complete: $SUMMARY_CSV"
