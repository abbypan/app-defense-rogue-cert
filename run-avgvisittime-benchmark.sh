#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
if [ -n "${ASPIN_JAVA_HOME:-}" ]; then
    export JAVA_HOME="$ASPIN_JAVA_HOME"
elif [ -x /usr/lib/jvm/java-17-openjdk/bin/java ]; then
    export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
fi

ITERATIONS="${1:-2000}"
BENCHMARK_TIMEOUT_SECONDS="${BENCHMARK_TIMEOUT_SECONDS:-3600}"
RESULTS_DIR="$SCRIPT_DIR/results"
APKS_DIR="$RESULTS_DIR/apks"
mkdir -p "$RESULTS_DIR" "$APKS_DIR"

if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]] ||
        ! [[ "$BENCHMARK_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: iterations and BENCHMARK_TIMEOUT_SECONDS must be positive integers."
    exit 1
fi

echo "========================================================="
echo " ADB Android Device Benchmark: table:avgvisittime"
echo " Iterations = $ITERATIONS"
echo " PC Output Dir = $RESULTS_DIR"
echo " Signed APKs Dir = $APKS_DIR"
echo "========================================================="

if ! adb get-state >/dev/null 2>&1; then
    echo "ERROR: No Android device/emulator connected via ADB!"
    echo "Please connect an Android device or start an emulator via ADB."
    exit 1
fi

DEVICE_ID="$(adb devices | grep -v 'List' | grep 'device' | awk '{print $1}' | head -n 1)"
echo "Connected ADB Device: $DEVICE_ID"
PACKAGE="com.cert.aspin"

cleanup() {
    set +e
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1
    sudo -n cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
    sudo -n cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
    sudo -n systemctl restart nginx.service
}
trap cleanup EXIT

wait_for_device_csv() {
    local device_csv="$1"
    local label="$2"
    for attempt in $(seq 1 "$BENCHMARK_TIMEOUT_SECONDS"); do
        if adb -s "$DEVICE_ID" shell "[ -f '$device_csv' ]" 2>/dev/null; then
            echo "    $label finished on device after ${attempt}s!"
            return 0
        fi
        sleep 1
    done
    echo "ERROR: $label did not produce $device_csv within ${BENCHMARK_TIMEOUT_SECONDS}s."
    adb -s "$DEVICE_ID" logcat -d -t 300 2>/dev/null | tail -n 200 || true
    return 1
}

echo "--> Building and signing all algorithm-specific APKs using gen-signed-apks.py..."
python3 "$SCRIPT_DIR/gen-trust-artifacts.py"
python3 "$SCRIPT_DIR/check-implementation-consistency.py"
python3 "$SCRIPT_DIR/gen-signed-apks.py" --workers 24 --output-dir "$APKS_DIR"

SUMMARY_CSV="$RESULTS_DIR/table_avgvisittime_summary.csv"
echo "Algorithm,ServerPhase,Iterations,Host,StandardTLS_Mean_ms,ASPin_Mean_ms,SCP_Mean_ms,DCP_Mean_ms,StandardTLS_P95_ms,StandardTLS_P99_ms,ASPin_P95_ms,ASPin_P99_ms,SCP_P95_ms,SCP_P99_ms,DCP_P95_ms,DCP_P99_ms,TLS_Success_Standard,TLS_Success_ASPin,TLS_Success_SCP,TLS_Success_DCP,HTML_Standard,HTML_ASPin,HTML_SCP,HTML_DCP,Matches_TeX_Design,Timestamp" > "$SUMMARY_CSV"

for ALG in es256 es384 rsa3072 rsa4096; do
    TARGET_APK="$APKS_DIR/ASPin-${ALG}.apk"
    if [ ! -f "$TARGET_APK" ]; then
        echo "WARNING: Signed APK not found for $ALG: $TARGET_APK"
        continue
    fi

    echo ""
    echo "========================================================="
    echo "=== ALGORITHM: $ALG ==="
    echo "========================================================="

    # 1. Deploy realserver configuration & restart nginx
    echo "--> [1/6] Deploying realserver config to Nginx..."
    sudo -n cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
    sudo -n cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
    sudo -n systemctl restart nginx.service
    sleep 2

    echo "--> [2/6] Installing algorithm-signed APK ($TARGET_APK) to Android Device..."
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" 2>/dev/null || true
    adb -s "$DEVICE_ID" install -r "$TARGET_APK"
    adb -s "$DEVICE_ID" shell "su 0 cmd deviceidle whitelist +$PACKAGE" 2>/dev/null || true

    DEVICE_REAL_CSV="/sdcard/Android/data/${PACKAGE}/files/benchmark_${ALG}_realserver_avgvisittime.csv"
    LOCAL_REAL_CSV="$RESULTS_DIR/benchmark_${ALG}_realserver_avgvisittime.csv"

    adb -s "$DEVICE_ID" shell rm -f "$DEVICE_REAL_CSV" 2>/dev/null || true
    rm -f "$LOCAL_REAL_CSV" 2>/dev/null || true

    echo "--> [3/6] Executing Phase 1: realserver HTTPS Visit Benchmark on Device ($ALG)..."
    adb -s "$DEVICE_ID" shell am start -S -W -n "$PACKAGE/.MainActivity" \
        --es benchmark_type "avgvisittime" \
        --es server_phase "realserver" \
        --ei iterations "$ITERATIONS" \
        --es output_csv "$DEVICE_REAL_CSV"

    echo "--> Waiting for Phase 1 (realserver) benchmark on device to complete..."
    wait_for_device_csv "$DEVICE_REAL_CSV" "Phase 1 (realserver)"

    echo "--> Pulling Phase 1 (realserver) CSV result..."
    adb -s "$DEVICE_ID" pull "$DEVICE_REAL_CSV" "$LOCAL_REAL_CSV" 2>/dev/null || adb -s "$DEVICE_ID" shell "su 0 cat '$DEVICE_REAL_CSV'" > "$LOCAL_REAL_CSV" 2>/dev/null || true

    if [ -f "$LOCAL_REAL_CSV" ] && [ -s "$LOCAL_REAL_CSV" ]; then
        line="$(tail -n 1 "$LOCAL_REAL_CSV")"
        alg_col="$(echo "$line" | cut -d',' -f1)"
        rest_cols="$(echo "$line" | cut -d',' -f2-)"
        echo "${alg_col},realserver,${rest_cols}" >> "$SUMMARY_CSV"
        echo "    Saved Phase 1: $LOCAL_REAL_CSV"
    else
        echo "ERROR: Phase 1 CSV result for $ALG was not found or was empty."
        exit 1
    fi

    # 2. Deploy rogueserver configuration & restart nginx
    echo ""
    echo "--> [4/6] Deploying rogueserver config to Nginx..."
    sudo -n cp -pr "$SCRIPT_DIR/rogueserver/etc/"* /etc/
    sudo -n cp -pr "$SCRIPT_DIR/rogueserver/var/"* /var/
    sudo -n systemctl restart nginx.service
    sleep 2

    DEVICE_ROGUE_CSV="/sdcard/Android/data/${PACKAGE}/files/benchmark_${ALG}_rogueserver_avgvisittime.csv"
    LOCAL_ROGUE_CSV="$RESULTS_DIR/benchmark_${ALG}_rogueserver_avgvisittime.csv"

    adb -s "$DEVICE_ID" shell rm -f "$DEVICE_ROGUE_CSV" 2>/dev/null || true
    rm -f "$LOCAL_ROGUE_CSV" 2>/dev/null || true

    echo "--> [5/6] Executing Phase 2: rogueserver HTTPS Visit Benchmark on Device ($ALG)..."
    adb -s "$DEVICE_ID" shell am start -S -W -n "$PACKAGE/.MainActivity" \
        --es benchmark_type "avgvisittime" \
        --es server_phase "rogueserver" \
        --ei iterations "$ITERATIONS" \
        --es output_csv "$DEVICE_ROGUE_CSV"

    echo "--> Waiting for Phase 2 (rogueserver) benchmark on device to complete..."
    wait_for_device_csv "$DEVICE_ROGUE_CSV" "Phase 2 (rogueserver)"

    echo "--> Pulling Phase 2 (rogueserver) CSV result..."
    adb -s "$DEVICE_ID" pull "$DEVICE_ROGUE_CSV" "$LOCAL_ROGUE_CSV" 2>/dev/null || adb -s "$DEVICE_ID" shell "su 0 cat '$DEVICE_ROGUE_CSV'" > "$LOCAL_ROGUE_CSV" 2>/dev/null || true

    if [ -f "$LOCAL_ROGUE_CSV" ] && [ -s "$LOCAL_ROGUE_CSV" ]; then
        line="$(tail -n 1 "$LOCAL_ROGUE_CSV")"
        alg_col="$(echo "$line" | cut -d',' -f1)"
        rest_cols="$(echo "$line" | cut -d',' -f2-)"
        echo "${alg_col},rogueserver,${rest_cols}" >> "$SUMMARY_CSV"
        echo "    Saved Phase 2: $LOCAL_ROGUE_CSV"
    else
        echo "ERROR: Phase 2 CSV result for $ALG was not found or was empty."
        exit 1
    fi

    echo "--> [6/6] Uninstalling $PACKAGE ($ALG) from Android Device..."
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" || true
done

echo ""
echo "========================================================="
echo " table:avgvisittime Benchmark Completed Successfully!"
echo " Summary CSV Result: $SUMMARY_CSV"
echo "========================================================="
cat "$SUMMARY_CSV"
