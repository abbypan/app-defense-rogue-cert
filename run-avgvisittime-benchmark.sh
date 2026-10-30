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

restore_real_server() {
    set +e
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1
    sudo -n cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
    sudo -n cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
    for alg in es256 es384 rsa3072 rsa4096; do
        "$SCRIPT_DIR/activate-claim-signing-key.sh" "$alg" primary >/dev/null 2>&1
    done
    sudo -n systemctl restart nginx.service
}
trap restore_real_server EXIT

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
    adb -s "$DEVICE_ID" logcat -d -t 300 2>/dev/null | tail -n 200 || true
    return 1
}

apk_for_mode() {
    local alg="$1"
    local mode="$2"
    case "$mode" in
        primary) echo "$APKS_DIR/ASPin-${alg}.apk" ;;
        scp) echo "$APKS_DIR/ASPin-${alg}-scp.apk" ;;
        dcp) echo "$APKS_DIR/ASPin-${alg}-dcp.apk" ;;
        compatible) echo "$APKS_DIR/ASPin-${alg}-compatible.apk" ;;
    esac
}

run_one() {
    local alg="$1"
    local mode="$2"
    local phase="$3"
    local apk
    local device_csv
    local local_csv
    apk="$(apk_for_mode "$alg" "$mode")"
    device_csv="/sdcard/Android/data/${PACKAGE}/files/benchmark_${alg}_${mode}_${phase}_connections.csv"
    local_csv="$RESULTS_DIR/benchmark_${alg}_${mode}_${phase}_connections.csv"

    if [ "$phase" = realserver ]; then
        if [ "$mode" = primary ]; then
            "$SCRIPT_DIR/activate-claim-signing-key.sh" "$alg" primary
        elif [ "$mode" = compatible ]; then
            "$SCRIPT_DIR/activate-claim-signing-key.sh" "$alg" compat
        fi
    fi

    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" install -r "$apk" >/dev/null
    adb -s "$DEVICE_ID" shell "su 0 cmd deviceidle whitelist +$PACKAGE" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" shell "rm -f '$device_csv'" >/dev/null 2>&1 || true
    rm -f "$local_csv"

    adb -s "$DEVICE_ID" shell am start -S -W -n "$PACKAGE/.MainActivity" \
        --es benchmark_type avgvisittime \
        --es server_phase "$phase" \
        --ei iterations "$ITERATIONS" \
        --es output_csv "$device_csv" >/dev/null
    wait_for_csv "$device_csv" "$alg/$mode/$phase"
    adb -s "$DEVICE_ID" pull "$device_csv" "$local_csv" >/dev/null
    tail -n +2 "$local_csv" >> "$SUMMARY_CSV"
}

python3 "$SCRIPT_DIR/gen-trust-artifacts.py"
python3 "$SCRIPT_DIR/check-implementation-consistency.py"
python3 "$SCRIPT_DIR/gen-signed-apks.py" --workers 24 \
    --mode primary --mode scp --mode dcp --mode compatible --output-dir "$APKS_DIR"

SUMMARY_CSV="$RESULTS_DIR/table_connection_summary.csv"
echo "Algorithm,Mode,Scheme,ServerPhase,Iterations,Host,Mean_ms,P50_ms,P95_ms,P99_ms,Success_Count,Expected_Success_Count,Result,Response,Timestamp" > "$SUMMARY_CSV"

for ALG in es256 es384 rsa3072 rsa4096; do
    sudo -n cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
    sudo -n cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
    sudo -n systemctl restart nginx.service
    for MODE in primary scp dcp compatible; do
        run_one "$ALG" "$MODE" realserver
    done

    sudo -n cp -pr "$SCRIPT_DIR/rogueserver/etc/"* /etc/
    sudo -n cp -pr "$SCRIPT_DIR/rogueserver/var/"* /var/
    sudo -n systemctl restart nginx.service
    for MODE in primary scp dcp compatible; do
        run_one "$ALG" "$MODE" rogueserver
    done
done

echo "connection benchmark complete: $SUMMARY_CSV"
