#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"

ITERATIONS="${1:-5}"
RESULTS_DIR="$SCRIPT_DIR/results"
APKS_DIR="$RESULTS_DIR/apks"
mkdir -p "$RESULTS_DIR" "$APKS_DIR"

echo "========================================================="
echo " ADB Android Device Benchmark: table:avgveriftime"
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

SUMMARY_CSV="$RESULTS_DIR/table_avgveriftime_summary.csv"
echo "Algorithm,Iterations,Tk_Avg_ms,Tc_Avg_ms,DCP_Avg_ms,Timestamp" > "$SUMMARY_CSV"

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

    PACKAGE="com.cert.aspin"

    # 1. Deploy realserver configuration & restart nginx on PC
    echo "--> [1/5] Deploying realserver config to Nginx..."
    sudo cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
    sudo cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
    sudo systemctl restart nginx.service
    sleep 2

    # 2. Install algorithm-signed APK to Android Device
    echo "--> [2/5] Installing algorithm-signed APK ($TARGET_APK) to Android Device..."
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" 2>/dev/null || true
    adb -s "$DEVICE_ID" install -r "$TARGET_APK"
    adb -s "$DEVICE_ID" shell "su 0 cmd deviceidle whitelist +$PACKAGE" 2>/dev/null || true

    DEVICE_CSV="/sdcard/Android/data/${PACKAGE}/files/benchmark_${ALG}_avgveriftime.csv"
    LOCAL_CSV="$RESULTS_DIR/benchmark_${ALG}_avgveriftime.csv"

    adb -s "$DEVICE_ID" shell rm -f "$DEVICE_CSV" 2>/dev/null || true
    rm -f "$LOCAL_CSV" 2>/dev/null || true

    # 3. Execute Table 1 Verification Delay Benchmark on Device
    echo "--> [3/5] Executing Verification Delay Benchmark on Device ($ALG)..."
    adb -s "$DEVICE_ID" shell am start -S -W -n "$PACKAGE/.MainActivity" \
        --es benchmark_type "avgveriftime" \
        --ei iterations "$ITERATIONS" \
        --es output_csv "$DEVICE_CSV"

    echo "--> Waiting for verification benchmark on device to complete..."
    for attempt in $(seq 1 3600); do
        if adb -s "$DEVICE_ID" shell "[ -f '$DEVICE_CSV' ]" 2>/dev/null; then
            echo "    Benchmark finished on device after ${attempt}s!"
            break
        fi
        sleep 1
    done

    # 4. Pull CSV result from Android Device to PC
    echo "--> [4/5] Pulling CSV result from Android Device to PC..."
    adb -s "$DEVICE_ID" pull "$DEVICE_CSV" "$LOCAL_CSV" 2>/dev/null || adb -s "$DEVICE_ID" shell "su 0 cat '$DEVICE_CSV'" > "$LOCAL_CSV" 2>/dev/null || true

    if [ -f "$LOCAL_CSV" ] && [ -s "$LOCAL_CSV" ]; then
        tail -n +2 "$LOCAL_CSV" >> "$SUMMARY_CSV"
        echo "    Saved: $LOCAL_CSV"
    else
        echo "    WARNING: CSV result file for $ALG was not found."
    fi

    # 5. Uninstall package from Android device
    echo "--> [5/5] Uninstalling $PACKAGE ($ALG) from Android Device..."
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" || true
done

echo ""
echo "========================================================="
echo " table:avgveriftime Benchmark Completed Successfully!"
echo " Summary CSV Result: $SUMMARY_CSV"
echo "========================================================="
cat "$SUMMARY_CSV"
