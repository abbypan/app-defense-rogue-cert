#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
if [ -n "${ASPIN_JAVA_HOME:-}" ]; then
    export JAVA_HOME="$ASPIN_JAVA_HOME"
elif [ -x /usr/lib/jvm/java-17-openjdk/bin/java ]; then
    export JAVA_HOME=/usr/lib/jvm/java-17-openjdk
fi

TARGET_PACKAGE="com.cert.aspin"
CALLER_PACKAGE="com.cert.aspin.caller"
TARGET_APK="$SCRIPT_DIR/results/apks/ASPin-es256.apk"
CALLER_APK="$SCRIPT_DIR/ASPin/es256/app/build/outputs/apk/crossAppCaller/app-crossAppCaller.apk"
DEVICE_CSV="/sdcard/Android/data/$CALLER_PACKAGE/files/cross_app_target_claim.csv"
LOCAL_CSV="$SCRIPT_DIR/results/cross_app_target_claim.csv"

DEVICE_ID="$(adb devices | awk '$2 == "device" {print $1; exit}')"
if [ -z "$DEVICE_ID" ]; then
    echo "ERROR: No Android device is connected."
    exit 1
fi

cleanup() {
    set +e
    adb -s "$DEVICE_ID" uninstall "$CALLER_PACKAGE" >/dev/null 2>&1
    adb -s "$DEVICE_ID" uninstall "$TARGET_PACKAGE" >/dev/null 2>&1
    sudo -n cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
    sudo -n cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
    sudo -n systemctl restart nginx.service
}
trap cleanup EXIT

python3 "$SCRIPT_DIR/gen-signed-apks.py" --skip-build --output-dir "$SCRIPT_DIR/results/apks"
(cd "$SCRIPT_DIR/ASPin/es256" && ./gradlew --max-workers=24 :app:assembleCrossAppCaller)

sudo -n cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
sudo -n cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
sudo -n systemctl restart nginx.service

adb -s "$DEVICE_ID" install -r "$TARGET_APK"
adb -s "$DEVICE_ID" install -r "$CALLER_APK"
adb -s "$DEVICE_ID" shell rm -f "$DEVICE_CSV"
rm -f "$LOCAL_CSV"

adb -s "$DEVICE_ID" shell am start -S -W \
    -n "$CALLER_PACKAGE/com.cert.aspin.MainActivity" \
    --es benchmark_type avgveriftime \
    --ei iterations 1 \
    --es output_csv "$DEVICE_CSV"

for attempt in $(seq 1 120); do
    if adb -s "$DEVICE_ID" shell "[ -f '$DEVICE_CSV' ]" 2>/dev/null; then
        adb -s "$DEVICE_ID" pull "$DEVICE_CSV" "$LOCAL_CSV"
        cat "$LOCAL_CSV"
        exit 0
    fi
    sleep 1
done

echo "ERROR: App A did not obtain App B's ASPin claim within 120 seconds."
adb -s "$DEVICE_ID" logcat -d -t 300 | tail -n 200 || true
exit 1
