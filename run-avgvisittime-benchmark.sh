#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"

ITERATIONS="${1:-5}"
RESULTS_DIR="$SCRIPT_DIR/results"
APKS_DIR="$RESULTS_DIR/apks"
mkdir -p "$RESULTS_DIR" "$APKS_DIR"

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

echo "--> Building and signing all algorithm-specific APKs using gen-signed-apks.py..."
python3 "$SCRIPT_DIR/gen-signed-apks.py" --output-dir "$APKS_DIR"

SUMMARY_CSV="$RESULTS_DIR/table_avgvisittime_summary.csv"
echo "Algorithm,ServerPhase,Iterations,Host,StandardTLS_Avg_ms,ASPin_Avg_ms,SCP_Avg_ms,DCP_Avg_ms,TLS_Success_Standard,TLS_Success_ASPin,TLS_Success_SCP,TLS_Success_DCP,HTML_Standard,HTML_ASPin,HTML_SCP,HTML_DCP,Matches_TeX_Design,Timestamp" > "$SUMMARY_CSV"

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

    PACKAGE="com.abbypan.aspin"

    # 1. Deploy realserver configuration & restart nginx
    echo "--> [1/6] Deploying realserver config to Nginx..."
    sudo cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
    sudo cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
    sudo systemctl restart nginx.service
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
        --ei iterations "$ITERATIONS" \
        --es output_csv "$DEVICE_REAL_CSV"

    echo "--> Waiting for Phase 1 (realserver) benchmark on device to complete..."
    for attempt in $(seq 1 3600); do
        if adb -s "$DEVICE_ID" shell "[ -f '$DEVICE_REAL_CSV' ]" 2>/dev/null; then
            echo "    Phase 1 (realserver) finished after ${attempt}s!"
            break
        fi
        sleep 1
    done

    echo "--> Pulling Phase 1 (realserver) CSV result..."
    adb -s "$DEVICE_ID" pull "$DEVICE_REAL_CSV" "$LOCAL_REAL_CSV" 2>/dev/null || adb -s "$DEVICE_ID" shell "su 0 cat '$DEVICE_REAL_CSV'" > "$LOCAL_REAL_CSV" 2>/dev/null || true

    if [ -f "$LOCAL_REAL_CSV" ] && [ -s "$LOCAL_REAL_CSV" ]; then
        line="$(tail -n 1 "$LOCAL_REAL_CSV")"
        alg_col="$(echo "$line" | cut -d',' -f1)"
        rest_cols="$(echo "$line" | cut -d',' -f2-)"
        echo "${alg_col},realserver,${rest_cols}" >> "$SUMMARY_CSV"
        echo "    Saved Phase 1: $LOCAL_REAL_CSV"
    fi

    # 2. Deploy rogueserver configuration & restart nginx
    echo ""
    echo "--> [4/6] Deploying rogueserver config to Nginx..."
    sudo cp -pr "$SCRIPT_DIR/rogueserver/etc/"* /etc/
    sudo cp -pr "$SCRIPT_DIR/rogueserver/var/"* /var/
    sudo systemctl restart nginx.service
    sleep 2

    DEVICE_ROGUE_CSV="/sdcard/Android/data/${PACKAGE}/files/benchmark_${ALG}_rogueserver_avgvisittime.csv"
    LOCAL_ROGUE_CSV="$RESULTS_DIR/benchmark_${ALG}_rogueserver_avgvisittime.csv"

    adb -s "$DEVICE_ID" shell rm -f "$DEVICE_ROGUE_CSV" 2>/dev/null || true
    rm -f "$LOCAL_ROGUE_CSV" 2>/dev/null || true

    echo "--> [5/6] Executing Phase 2: rogueserver HTTPS Visit Benchmark on Device ($ALG)..."
    adb -s "$DEVICE_ID" shell am start -S -W -n "$PACKAGE/.MainActivity" \
        --es benchmark_type "avgvisittime" \
        --ei iterations "$ITERATIONS" \
        --es output_csv "$DEVICE_ROGUE_CSV"

    echo "--> Waiting for Phase 2 (rogueserver) benchmark on device to complete..."
    for attempt in $(seq 1 3600); do
        if adb -s "$DEVICE_ID" shell "[ -f '$DEVICE_ROGUE_CSV' ]" 2>/dev/null; then
            echo "    Phase 2 (rogueserver) finished after ${attempt}s!"
            break
        fi
        sleep 1
    done

    echo "--> Pulling Phase 2 (rogueserver) CSV result..."
    adb -s "$DEVICE_ID" pull "$DEVICE_ROGUE_CSV" "$LOCAL_ROGUE_CSV" 2>/dev/null || adb -s "$DEVICE_ID" shell "su 0 cat '$DEVICE_ROGUE_CSV'" > "$LOCAL_ROGUE_CSV" 2>/dev/null || true

    if [ -f "$LOCAL_ROGUE_CSV" ] && [ -s "$LOCAL_ROGUE_CSV" ]; then
        line="$(tail -n 1 "$LOCAL_ROGUE_CSV")"
        alg_col="$(echo "$line" | cut -d',' -f1)"
        rest_cols="$(echo "$line" | cut -d',' -f2-)"
        echo "${alg_col},rogueserver,${rest_cols}" >> "$SUMMARY_CSV"
        echo "    Saved Phase 2: $LOCAL_ROGUE_CSV"
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
