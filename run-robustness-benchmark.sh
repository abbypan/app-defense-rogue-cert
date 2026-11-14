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
THREADS="${ASPIN_CONCURRENCY_THREADS:-8}"
TIMEOUT_SECONDS="${BENCHMARK_TIMEOUT_SECONDS:-3600}"
SKIP_APP_BUILD="${ASPIN_SKIP_APP_BUILD:-0}"
RESUME_AFTER_REBOOT="${ASPIN_RESUME_AFTER_REBOOT:-0}"
RESUME_LIFECYCLE="${ASPIN_RESUME_LIFECYCLE:-0}"
EXPIRY_ONLY="${ASPIN_EXPIRY_ONLY:-0}"
RESUME_RUN_DIR="${ASPIN_RESUME_RUN_DIR:-}"
NETWORK_CHECK_HOST="${ASPIN_NETWORK_CHECK_HOST:-es256.idouzi.top}"
NETWORK_WAIT_SECONDS="${ASPIN_NETWORK_WAIT_SECONDS:-300}"
ASPIN_AOSP_FRAMEWORKS_BASE="${ASPIN_AOSP_FRAMEWORKS_BASE:-}"
ASPIN_FLASHED_IMAGE="${ASPIN_FLASHED_IMAGE:-}"
ADB_REVERSE_TRANSPORT="${ASPIN_ADB_REVERSE_TRANSPORT:-0}"
GENERATE_ROGUE_CA="${ASPIN_GENERATE_ROGUE_CA:-1}"
RTT_MATRIX_ONLY="${ASPIN_RTT_MATRIX_ONLY:-0}"
POLICY_SCENARIOS_ONLY="${ASPIN_POLICY_SCENARIOS_ONLY:-0}"
PACKAGE="com.cert.aspin"
CALLER_PACKAGE="com.cert.aspin.caller"
ALGORITHMS=(es256 es384 rsa3072 rsa4096)
RUN_ID="$(date +%Y%m%d-%H%M%S)"
if [ -n "$RESUME_RUN_DIR" ]; then
    RUN_DIR="$(realpath "$RESUME_RUN_DIR")"
    RUN_ID="$(basename "$RUN_DIR" | sed 's/^robustness-//')"
else
    RUN_DIR="$SCRIPT_DIR/results/robustness-$RUN_ID"
fi
APK_DIR="$SCRIPT_DIR/results/apks"
SNAPSHOT_DIR="$RUN_DIR/token-snapshots"
BENCHMARK_CERT_DIR=""
TRANSPORT_HOSTS_BACKED_UP=0
RTT_ORIGINAL_REVERSE=""

if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]] ||
        ! [[ "$THREADS" =~ ^[1-9][0-9]*$ ]] ||
        ! [[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] ||
        ! [[ "$SKIP_APP_BUILD" =~ ^[01]$ ]] ||
        ! [[ "$RESUME_AFTER_REBOOT" =~ ^[01]$ ]] ||
        ! [[ "$RESUME_LIFECYCLE" =~ ^[01]$ ]] ||
        ! [[ "$EXPIRY_ONLY" =~ ^[01]$ ]] ||
        ! [[ "$ADB_REVERSE_TRANSPORT" =~ ^[01]$ ]] ||
        ! [[ "$GENERATE_ROGUE_CA" =~ ^[01]$ ]] ||
        ! [[ "$RTT_MATRIX_ONLY" =~ ^[01]$ ]] ||
        ! [[ "$POLICY_SCENARIOS_ONLY" =~ ^[01]$ ]] ||
        ! [[ "$NETWORK_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: iterations, thread count, and timeout must be positive integers;" >&2
    echo "       ASPIN_SKIP_APP_BUILD, ASPIN_RESUME_AFTER_REBOOT," >&2
    echo "       ASPIN_RESUME_LIFECYCLE, ASPIN_EXPIRY_ONLY, and" >&2
    echo "       ASPIN_ADB_REVERSE_TRANSPORT, ASPIN_GENERATE_ROGUE_CA, and ASPIN_RTT_MATRIX_ONLY must be 0 or 1." >&2
    exit 2
fi
if [ "$POLICY_SCENARIOS_ONLY" -eq 1 ] && [ "$RTT_MATRIX_ONLY" -ne 1 ]; then
    echo "ERROR: Policy scenarios require isolated RTT-only harness setup." >&2
    exit 2
fi
if [ "$RTT_MATRIX_ONLY" -eq 1 ] && { [ "$ADB_REVERSE_TRANSPORT" -ne 1 ] \
        || [ "$GENERATE_ROGUE_CA" -ne 1 ] || [ "$RESUME_AFTER_REBOOT" -ne 0 ] \
        || [ "$RESUME_LIFECYCLE" -ne 0 ] || [ "$EXPIRY_ONLY" -ne 0 ]; }; then
    echo "ERROR: RTT-only runs require generated debug CAs and adb reverse, without resume modes." >&2
    exit 2
fi
if [ "$((RESUME_AFTER_REBOOT + RESUME_LIFECYCLE + EXPIRY_ONLY))" -gt 1 ]; then
    echo "ERROR: Select only one resume mode." >&2
    exit 2
fi
if { [ "$RESUME_AFTER_REBOOT" -eq 1 ] || [ "$RESUME_LIFECYCLE" -eq 1 ] \
        || [ "$EXPIRY_ONLY" -eq 1 ]; } \
        && [ -z "$RESUME_RUN_DIR" ]; then
    echo "ERROR: A resume mode requires ASPIN_RESUME_RUN_DIR." >&2
    exit 2
fi

DEVICE_ID="$(adb devices | awk '$2 == "device" {print $1; exit}')"
if [ -z "$DEVICE_ID" ]; then
    echo "ERROR: No Android device is connected." >&2
    exit 1
fi
BENCHMARK_LOCK_FILE="${ASPIN_BENCHMARK_LOCK_FILE:-/tmp/aspin-benchmark-${DEVICE_ID}.lock}"
exec 9>"$BENCHMARK_LOCK_FILE"
if ! flock -n 9; then
    echo "ERROR: Another ASPin benchmark already holds $BENCHMARK_LOCK_FILE." >&2
    echo "Wait for that run to finish; parallel runs share the device and Nginx state." >&2
    exit 1
fi
if [ "$RTT_MATRIX_ONLY" -eq 1 ]; then
    RTT_ORIGINAL_REVERSE="$(adb -s "$DEVICE_ID" reverse --list)"
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

generate_benchmark_certificates() {
    [ "$GENERATE_ROGUE_CA" -eq 1 ] || return 0
    BENCHMARK_CERT_DIR="$(mktemp -d /tmp/aspin-benchmark-ca.XXXXXX)"
    local profile ca_common_name
    for profile in authorized unexpected; do
        if [ "$profile" = authorized ]; then
            ca_common_name='ASPin Authorized Benchmark Test CA'
        else
            ca_common_name='ASPin Unexpected Issuer Test CA'
        fi
        openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 7 \
            -subj "/C=US/O=ASPin Benchmark/CN=$ca_common_name" \
            -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
            -addext 'keyUsage=critical,keyCertSign,cRLSign' \
            -keyout "$BENCHMARK_CERT_DIR/$profile-ca.key" \
            -out "$BENCHMARK_CERT_DIR/$profile-ca.crt" >/dev/null 2>&1
    done

    local algorithm hostname digest key_usage key_path csr_path cert_path
    local fullchain_path ext_path ca_path ca_key_path
    for profile in authorized unexpected; do
        ca_path="$BENCHMARK_CERT_DIR/$profile-ca.crt"
        ca_key_path="$BENCHMARK_CERT_DIR/$profile-ca.key"
        for algorithm in "${ALGORITHMS[@]}"; do
            hostname="$algorithm.idouzi.top"
            key_path="$BENCHMARK_CERT_DIR/$profile-$algorithm.key"
            csr_path="$BENCHMARK_CERT_DIR/$profile-$algorithm.csr"
            cert_path="$BENCHMARK_CERT_DIR/$profile-$algorithm.crt"
            fullchain_path="$BENCHMARK_CERT_DIR/$profile-$algorithm-fullchain.pem"
            ext_path="$BENCHMARK_CERT_DIR/$profile-$algorithm.ext"
            case "$algorithm" in
                es256)
                    openssl ecparam -name prime256v1 -genkey -noout \
                        -out "$key_path"
                    digest=-sha256
                    key_usage=digitalSignature
                    ;;
                es384)
                    openssl ecparam -name secp384r1 -genkey -noout \
                        -out "$key_path"
                    digest=-sha384
                    key_usage=digitalSignature
                    ;;
                rsa3072)
                    openssl genrsa -out "$key_path" 3072 \
                        >/dev/null 2>&1
                    digest=-sha256
                    key_usage=digitalSignature,keyEncipherment
                    ;;
                rsa4096)
                    openssl genrsa -out "$key_path" 4096 \
                        >/dev/null 2>&1
                    digest=-sha384
                    key_usage=digitalSignature,keyEncipherment
                    ;;
            esac
            openssl req -new -key "$key_path" \
                -subj "/CN=$hostname" -out "$csr_path" \
                >/dev/null 2>&1
            {
                echo 'basicConstraints=critical,CA:FALSE'
                echo "keyUsage=critical,$key_usage"
                echo 'extendedKeyUsage=serverAuth'
                echo "subjectAltName=DNS:$hostname"
            } > "$ext_path"
            openssl x509 -req -in "$csr_path" \
                -CA "$ca_path" -CAkey "$ca_key_path" -CAcreateserial -days 7 \
                "$digest" -extfile "$ext_path" -out "$cert_path" \
                >/dev/null 2>&1
            cp "$cert_path" "$fullchain_path"
            cat "$ca_path" >> "$fullchain_path"
            openssl verify -CAfile "$ca_path" "$cert_path" >/dev/null
            openssl x509 -checkend 3600 -noout -in "$cert_path" >/dev/null
        done
    done

    # The authorized issuer defines the policy-covered legitimate profile. The
    # unexpected issuer is trusted by native TLS but omitted from ASPin/SCP/DCP
    # policy artifacts. Only benchmark debug APKs trust either CA.
    for algorithm in "${ALGORITHMS[@]}"; do
        cp "$BENCHMARK_CERT_DIR/authorized-$algorithm.crt" \
            "$SCRIPT_DIR/realserver/etc/cert/$algorithm/real-cert.pem"
        cp "$BENCHMARK_CERT_DIR/authorized-$algorithm-fullchain.pem" \
            "$SCRIPT_DIR/realserver/etc/cert/$algorithm/real-fullchain.pem"
        cp "$BENCHMARK_CERT_DIR/authorized-$algorithm.key" \
            "$SCRIPT_DIR/realserver/etc/cert/$algorithm/real-privkey.pem"
        cp "$BENCHMARK_CERT_DIR/authorized-ca.crt" \
            "$SCRIPT_DIR/realserver/etc/cert/$algorithm/real-chain.pem"
        mkdir -p "$SCRIPT_DIR/ASPin/$algorithm/app/src/debug/res/raw"
        {
            cat "$BENCHMARK_CERT_DIR/authorized-ca.crt"
            cat "$BENCHMARK_CERT_DIR/unexpected-ca.crt"
        } > "$SCRIPT_DIR/ASPin/$algorithm/app/src/debug/res/raw/aspin_benchmark_ca.pem"
    done
    mkdir -p "$SCRIPT_DIR/ASPin/shared/src/main/res/raw"
    cp "$SCRIPT_DIR/ASPin/es256/app/src/debug/res/raw/aspin_benchmark_ca.pem" \
        "$SCRIPT_DIR/ASPin/shared/src/main/res/raw/aspin_benchmark_ca.pem"
}

wait_for_framework() {
    adb -s "$DEVICE_ID" wait-for-device
    for _ in $(seq 1 300); do
        if [ "$(adb -s "$DEVICE_ID" shell getprop sys.boot_completed 2>/dev/null \
                | tr -d '\r')" = "1" ] \
                && adb -s "$DEVICE_ID" shell service check package 2>/dev/null \
                    | grep -q found; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: Android framework did not become ready." >&2
    return 1
}

configure_reverse_transport() {
    [ "$ADB_REVERSE_TRANSPORT" -eq 1 ] || return 0
    local root_ready=0 remount_output expected_host_line actual_hosts
    for _ in $(seq 1 30); do
        if adb -s "$DEVICE_ID" root >/dev/null 2>&1; then
            adb -s "$DEVICE_ID" wait-for-device
            if adb -s "$DEVICE_ID" shell 'id -u' 2>/dev/null \
                    | tr -d '\r' | grep -qx 0; then
                root_ready=1
                break
            fi
        fi
        adb reconnect offline >/dev/null 2>&1 || true
        sleep 1
    done
    if [ "$root_ready" -ne 1 ]; then
        echo "ERROR: root adbd did not become ready." >&2
        return 1
    fi
    if ! remount_output="$(adb -s "$DEVICE_ID" remount 2>&1)"; then
        echo "ERROR: Could not remount the test system image for adb-reverse host routing." >&2
        echo "$remount_output" >&2
        return 1
    fi
    if [ "$TRANSPORT_HOSTS_BACKED_UP" -eq 0 ]; then
        adb -s "$DEVICE_ID" shell \
            'cp /system/etc/hosts /data/local/tmp/aspin-benchmark-hosts.before'
        TRANSPORT_HOSTS_BACKED_UP=1
    fi
    expected_host_line="127.0.0.1 es256.idouzi.top es384.idouzi.top rsa3072.idouzi.top rsa4096.idouzi.top dcp.idouzi.top"
    if ! adb -s "$DEVICE_ID" shell '
        printf "%s\n" \
            "127.0.0.1 localhost" \
            "::1 ip6-localhost" \
            "127.0.0.1 es256.idouzi.top es384.idouzi.top rsa3072.idouzi.top rsa4096.idouzi.top dcp.idouzi.top" \
            > /system/etc/hosts
    '; then
        echo "ERROR: Could not write the benchmark host mapping after adb remount." >&2
        echo "$remount_output" >&2
        return 1
    fi
    actual_hosts="$(adb -s "$DEVICE_ID" shell cat /system/etc/hosts 2>/dev/null \
        | tr -d '\r')"
    if ! grep -Fqx "$expected_host_line" <<<"$actual_hosts"; then
        echo "ERROR: The benchmark host mapping was not persisted on the device." >&2
        echo "$remount_output" >&2
        return 1
    fi
    adb -s "$DEVICE_ID" reverse tcp:80 tcp:80 >/dev/null
    adb -s "$DEVICE_ID" reverse tcp:443 tcp:443 >/dev/null
    if ! adb -s "$DEVICE_ID" reverse --list \
            | grep -Eq "^[^[:space:]]+[[:space:]]+tcp:443[[:space:]]+tcp:443$"; then
        echo "ERROR: adb reverse tcp:443 was not installed." >&2
        return 1
    fi
}

wait_for_boot() {
    adb -s "$DEVICE_ID" wait-for-device
    for _ in $(seq 1 300); do
        if [ "$(adb -s "$DEVICE_ID" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] \
                && adb -s "$DEVICE_ID" shell dumpsys user 2>/dev/null \
                    | grep -q 'Started users state: \[0=RUNNING_UNLOCKED\]'; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: Device did not finish booting." >&2
    return 1
}

wait_for_test_network() {
    # adb reverse mappings and the remounted hosts file disappear across a
    # device reboot, so recreate this local transport before every probe.
    configure_reverse_transport
    for _ in $(seq 1 "$NETWORK_WAIT_SECONDS"); do
        if adb -s "$DEVICE_ID" shell \
                "ping -c 1 -W 1 '$NETWORK_CHECK_HOST' >/dev/null 2>&1"; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: Test network did not become ready for $NETWORK_CHECK_HOST." >&2
    return 1
}

deploy_profile() {
    local profile="$1"
    local source_root="$SCRIPT_DIR/${profile}server"
    sudo -n cp -pr "$source_root/etc/." /etc/
    sudo -n cp -pr "$source_root/var/." /var/
    if [ "$profile" = rogue ] && [ "$GENERATE_ROGUE_CA" -eq 1 ]; then
        local algorithm
        for algorithm in "${ALGORITHMS[@]}"; do
            sudo -n cp "$BENCHMARK_CERT_DIR/unexpected-$algorithm.crt" \
                "/etc/cert/$algorithm/rogue-cert.crt"
            sudo -n cp "$BENCHMARK_CERT_DIR/unexpected-$algorithm-fullchain.pem" \
                "/etc/cert/$algorithm/rogue-fullchain.pem"
            sudo -n cp "$BENCHMARK_CERT_DIR/unexpected-$algorithm.key" \
                "/etc/cert/$algorithm/rogue-privkey.pem"
        done
    fi
    sudo -n systemctl restart nginx.service
    sudo -n systemctl is-active --quiet nginx.service
}

validate_server_certificates() {
    local profile algorithm certificate
    for profile in real rogue; do
        for algorithm in "${ALGORITHMS[@]}"; do
            if [ "$profile" = rogue ] && [ "$GENERATE_ROGUE_CA" -eq 1 ]; then
                certificate="$BENCHMARK_CERT_DIR/unexpected-$algorithm.crt"
            elif [ "$profile" = real ]; then
                certificate="$SCRIPT_DIR/realserver/etc/cert/$algorithm/real-cert.pem"
            else
                certificate="$SCRIPT_DIR/rogueserver/etc/cert/$algorithm/rogue-cert.crt"
            fi
            if ! openssl x509 -checkend 7200 -noout -in "$certificate" >/dev/null; then
                echo "ERROR: $profile/$algorithm certificate is expired or expires within two hours: $certificate" >&2
                return 1
            fi
        done
    done
}

snapshot_es256_tokens() {
    local destination="$1"
    cp "$SCRIPT_DIR/realserver/var/www/es256/.well-known/ClaimSigningKey.jws" \
        "$destination/ClaimSigningKey.jws"
    cp "$SCRIPT_DIR/realserver/var/www/es256/.well-known/ServerCertClaim.jws" \
        "$destination/ServerCertClaim.jws"
}

deploy_es256_token_pair() {
    local tk_path="$1"
    local tc_path="$2"
    sudo -n cp "$tk_path" /var/www/es256/.well-known/ClaimSigningKey.jws
    sudo -n cp "$tc_path" /var/www/es256/.well-known/ServerCertClaim.jws
}

generate_unequal_expiry_es256_pair() {
    # Exercise exp_eff=min(exp_k,exp_c) with observably different expirations.
    # Run this only after the rollback lifecycle, because it publishes a newer
    # logical version than the v1/v2 snapshots used by those replay checks.
    (
        cd "$SCRIPT_DIR/signing/es256"
        ASPIN_TOKEN_TTL_SECONDS=7200 python3 gen_jws_ClaimSigningKey.py
        ASPIN_TOKEN_TTL_SECONDS=3600 \
            python3 gen_jws_ServerCertClaim.py \
                "$SCRIPT_DIR/realserver/etc/cert/es256/real-cert.pem" \
                "$SCRIPT_DIR/realserver/etc/cert/es256/real-chain.pem"
    )
    python3 "$SCRIPT_DIR/check-trust-artifacts.py" --alg es256
    cp "$SCRIPT_DIR/signing/es256/ClaimSigningKey.jws" \
        "$SCRIPT_DIR/realserver/var/www/es256/.well-known/ClaimSigningKey.jws"
    cp "$SCRIPT_DIR/signing/es256/ServerCertClaim.jws" \
        "$SCRIPT_DIR/realserver/var/www/es256/.well-known/ServerCertClaim.jws"
    deploy_profile real
    SERVER_CHANGED=1
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
if not rows:
    raise SystemExit(f"{path}: expected at least one result row")
if column not in rows[0]:
    raise SystemExit(f"{path}: missing result column {column!r}")
for index, row in enumerate(rows, start=1):
    if row[column] != "PASS":
        raise SystemExit(
            f"{path}: row {index} has {column}={row[column]!r}, expected 'PASS'"
        )
PY
}

run_benchmark() {
    local package_name="$1"
    local benchmark_type="$2"
    local output_name="$3"
    local result_column="$4"
    shift 4
    # Keep benchmark output in credential-encrypted app-private storage.  This
    # remains available after the framework-only restart used to refresh the
    # temporary benchmark CA, unlike emulated-storage FUSE on some GSI builds.
    local device_csv="/data/user/0/$package_name/files/$output_name"
    local local_csv="$RUN_DIR/$output_name"

    echo "--> Running $benchmark_type: $output_name"
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
        if adb -s "$DEVICE_ID" logcat -d -s MainActivity:E '*:S' 2>/dev/null \
                | grep -qiE 'benchmark failed|probe failed'; then
            echo "ERROR: $benchmark_type failed before producing $device_csv." >&2
            adb -s "$DEVICE_ID" logcat -d -s MainActivity:E '*:S' >&2 || true
            return 1
        fi
        sleep 1
    done
    echo "ERROR: $benchmark_type did not produce $device_csv." >&2
    adb -s "$DEVICE_ID" logcat -d -t 500 | tail -n 300 >&2 || true
    return 1
}

install_target() {
    local algorithm="$1"
    local mode="${2:-primary}"
    local suffix=""
    case "$mode" in
        primary) suffix="" ;;
        scp) suffix=-scp ;;
        dcp) suffix=-dcp ;;
        compatible) suffix=-compatible ;;
        *) echo "ERROR: unknown APK mode: $mode" >&2; return 2 ;;
    esac
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" install -r "$APK_DIR/ASPin-$algorithm$suffix.apk"
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
synchronize_device_clock() {
    local host_epoch device_epoch delta
    host_epoch="$(date +%s)"
    adb -s "$DEVICE_ID" shell "su 0 settings put global auto_time 0" >/dev/null
    adb -s "$DEVICE_ID" shell "su 0 date -s '@$host_epoch'" >/dev/null
    CLOCK_CHANGED=1
    device_epoch="$(adb -s "$DEVICE_ID" shell date +%s | tr -d '\r')"
    if ! [[ "$device_epoch" =~ ^[0-9]+$ ]]; then
        echo "ERROR: Could not read the synchronized device clock." >&2
        return 1
    fi
    delta="$((device_epoch - host_epoch))"
    if [ "$delta" -lt -2 ] || [ "$delta" -gt 2 ]; then
        echo "ERROR: Device clock remains ${delta}s from the benchmark host." >&2
        return 1
    fi
    echo "Device clock synchronized to the benchmark host (${delta}s offset)."
}
cleanup() {
    set +e
    restore_clock
    if [ "$SERVER_CHANGED" -eq 1 ]; then
        deploy_profile real
    fi
    if [ "$RTT_MATRIX_ONLY" -eq 0 ]; then
        for algorithm in "${ALGORITHMS[@]}"; do
            "$SCRIPT_DIR/activate-claim-signing-key.sh" "$algorithm" primary \
                >/dev/null 2>&1 || true
        done
    fi
    if [ "$RTT_MATRIX_ONLY" -eq 0 ]; then
        adb -s "$DEVICE_ID" uninstall "$CALLER_PACKAGE" >/dev/null 2>&1 || true
    fi
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1 || true
    if [ "$RTT_MATRIX_ONLY" -eq 1 ]; then
        local device_transport device_port host_port
        for device_port in tcp:80 tcp:443 tcp:19090; do
            adb -s "$DEVICE_ID" reverse --remove "$device_port" >/dev/null 2>&1 || true
        done
        while read -r device_transport device_port host_port; do
            case "$device_port" in
                tcp:80|tcp:443|tcp:19090)
                    adb -s "$DEVICE_ID" reverse "$device_port" "$host_port" >/dev/null 2>&1 || true ;;
            esac
        done <<< "$RTT_ORIGINAL_REVERSE"
    else
        adb -s "$DEVICE_ID" reverse --remove-all >/dev/null 2>&1 || true
    fi
    if [ "$TRANSPORT_HOSTS_BACKED_UP" -eq 1 ]; then
        adb -s "$DEVICE_ID" shell \
            'cp /data/local/tmp/aspin-benchmark-hosts.before /system/etc/hosts' \
            >/dev/null 2>&1 || true
    fi
    if [[ "$BENCHMARK_CERT_DIR" == /tmp/aspin-benchmark-ca.* ]]; then
        rm -rf "$BENCHMARK_CERT_DIR"
    fi
}
trap cleanup EXIT

synchronize_device_clock
generate_benchmark_certificates
validate_server_certificates
wait_for_test_network

if [ "$EXPIRY_ONLY" -eq 1 ]; then
    test -s "$RUN_DIR/cold-refresh-primary-es256.csv"
    generate_unequal_expiry_es256_pair
    install_target es256
    run_benchmark "$PACKAGE" expirybound delegation-expiry.csv Result
    python3 "$SCRIPT_DIR/summarize-robustness-results.py" "$RUN_DIR"
    echo "Updated delegation-expiration probe: $RUN_DIR/delegation-expiry.csv"
    exit 0
fi

if [ "$RESUME_AFTER_REBOOT" -eq 0 ] && [ "$RESUME_LIFECYCLE" -eq 0 ]; then
{
    echo "run_id=$RUN_ID"
    echo "iterations=$ITERATIONS"
    echo "threads=$THREADS"
    echo "device=$DEVICE_ID"
    echo "fingerprint=$(adb -s "$DEVICE_ID" shell getprop ro.build.fingerprint | tr -d '\r')"
    echo "kernel=$(adb -s "$DEVICE_ID" shell uname -a | tr -d '\r')"
    echo "repo_commit=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || echo uncommitted)"
    echo "repo_dirty=$(git -C "$SCRIPT_DIR" status --porcelain 2>/dev/null | wc -l)"
    echo "repo_tracked_diff_sha256=$(git -C "$SCRIPT_DIR" diff --binary HEAD 2>/dev/null | sha256sum | awk '{print $1}')"
    echo "transport=physical Pixel 8 connected to a local Nginx host"
    echo "adb_reverse_transport=$ADB_REVERSE_TRANSPORT"
    echo "generated_authorized_issuer_ca=$GENERATE_ROGUE_CA"
    echo "generated_unexpected_issuer_ca=$GENERATE_ROGUE_CA"
    echo "benchmark_ca_trust=authorized and unexpected test CAs in debug APK network-security configuration only"
    echo "benchmark_cas_in_release_build=0"
    if [ "$GENERATE_ROGUE_CA" -eq 1 ]; then
        echo "authorized_issuer_ca_sha256=$(openssl x509 -in "$BENCHMARK_CERT_DIR/authorized-ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
        echo "authorized_issuer_ca_not_after=$(openssl x509 -in "$BENCHMARK_CERT_DIR/authorized-ca.crt" -noout -enddate | cut -d= -f2-)"
        echo "unexpected_issuer_ca_sha256=$(openssl x509 -in "$BENCHMARK_CERT_DIR/unexpected-ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
        echo "unexpected_issuer_ca_not_after=$(openssl x509 -in "$BENCHMARK_CERT_DIR/unexpected-ca.crt" -noout -enddate | cut -d= -f2-)"
    fi
    echo "aosp_build_or_flash=not performed by this script"
    if [ -n "$ASPIN_AOSP_FRAMEWORKS_BASE" ]; then
        echo "aosp_framework_branch=$(git -C "$ASPIN_AOSP_FRAMEWORKS_BASE" branch --show-current 2>/dev/null || echo unavailable)"
        echo "aosp_framework_commit=$(git -C "$ASPIN_AOSP_FRAMEWORKS_BASE" rev-parse HEAD 2>/dev/null || echo unavailable)"
        echo "aosp_framework_dirty=$(git -C "$ASPIN_AOSP_FRAMEWORKS_BASE" status --porcelain 2>/dev/null | wc -l)"
    fi
    if [ -s "$ASPIN_FLASHED_IMAGE" ]; then
        echo "flashed_image=$(basename "$ASPIN_FLASHED_IMAGE")"
        echo "flashed_image_sha256=$(sha256sum "$ASPIN_FLASHED_IMAGE" | awk '{print $1}')"
    fi
} > "$RUN_DIR/environment.txt"

# Generate one internally consistent token set and build only the benchmark apps.
# This script never builds a system image or flashes a device.
python3 "$SCRIPT_DIR/gen-trust-artifacts.py"
python3 "$SCRIPT_DIR/check-implementation-consistency.py"
snapshot_es256_tokens "$SNAPSHOT_DIR/v1"
if [ "$GENERATE_ROGUE_CA" -eq 1 ]; then
    mkdir -p "$RUN_DIR/benchmark-certificates"
    cp "$BENCHMARK_CERT_DIR/authorized-ca.crt" \
        "$RUN_DIR/benchmark-certificates/authorized-ca.crt"
    cp "$BENCHMARK_CERT_DIR/unexpected-ca.crt" \
        "$RUN_DIR/benchmark-certificates/unexpected-ca.crt"
    for algorithm in "${ALGORITHMS[@]}"; do
        cp "$BENCHMARK_CERT_DIR/authorized-$algorithm.crt" \
            "$RUN_DIR/benchmark-certificates/authorized-$algorithm.crt"
        cp "$BENCHMARK_CERT_DIR/unexpected-$algorithm.crt" \
            "$RUN_DIR/benchmark-certificates/unexpected-$algorithm.crt"
    done
fi
if [ "$SKIP_APP_BUILD" -eq 0 ]; then
    python3 "$SCRIPT_DIR/gen-signed-apks.py" --workers 24 \
        --mode primary --mode scp --mode dcp --mode compatible --output-dir "$APK_DIR"
    if [ "$RTT_MATRIX_ONLY" -eq 0 ]; then
        (cd "$SCRIPT_DIR/ASPin/es256" && \
            ./gradlew --max-workers=24 :app:assembleCrossAppCaller)
    fi
else
    python3 "$SCRIPT_DIR/gen-signed-apks.py" --workers 24 --skip-build \
        --mode primary --mode scp --mode dcp --mode compatible --output-dir "$APK_DIR"
fi

if [ "$RTT_MATRIX_ONLY" -eq 1 ]; then
    if [ "$POLICY_SCENARIOS_ONLY" -eq 1 ]; then
        # All builds are launched by the calling independent background job.
        if [ "$SKIP_APP_BUILD" -eq 0 ]; then
            (cd "$SCRIPT_DIR/ASPin/es256" && ./gradlew --max-workers=24 \
                :app:assembleCrossAppCaller :app:assembleCrossAppHidden \
                :app:assembleCompatibilityBenchmark)
        fi
        python3 "$SCRIPT_DIR/run-policy-scenario-matrix.py" \
            --device "$DEVICE_ID" --cert-dir "$BENCHMARK_CERT_DIR" \
            --apk-dir "$APK_DIR" --run-dir "$RUN_DIR/policy-scenarios" \
            --repeats "$ITERATIONS" --timeout "$TIMEOUT_SECONDS" \
            --short-seconds "${ASPIN_POLICY_SHORT_SECONDS:-60}"
        echo "Policy availability/cross-app results: $RUN_DIR/policy-scenarios"
        exit 0
    fi
    # Stop here: do not execute the standard suite's reboot/clock-rollback tests.
    python3 "$SCRIPT_DIR/run-rtt-cache-matrix.py" \
        --device "$DEVICE_ID" --cert-dir "$BENCHMARK_CERT_DIR" \
        --apk-dir "$APK_DIR" --run-dir "$RUN_DIR/rtt-cache" \
        --iterations "$ITERATIONS" --timeout "$TIMEOUT_SECONDS" \
        --rtts "${ASPIN_RTT_VALUES_MS:-0,20,50,100,200}" \
        --warmups "${ASPIN_RTT_WARMUPS:-10}" \
        --repeats "${ASPIN_RTT_REPEATS:-1}" --seed "${ASPIN_RTT_SEED:-2027}"
    echo "RTT/cache matrix results: $RUN_DIR/rtt-cache"
    exit 0
fi

# Fail fast before the long distributions if the controlled unauthorized-issuer-CA
# profile is not accepted by native TLS or is accidentally authorized by a pin.
deploy_profile real
SERVER_CHANGED=1
install_target es256
"$SCRIPT_DIR/activate-claim-signing-key.sh" es256 primary
run_benchmark "$PACKAGE" claimprobe preflight-real-claim-refresh.csv Result \
    --ez force_refresh true --ez expect_success true \
    --es probe_label preflight_real_refresh
run_benchmark "$PACKAGE" avgvisittime preflight-real-es256.csv \
    Result --ei iterations 1 --es server_phase realserver
deploy_profile rogue
run_benchmark "$PACKAGE" avgvisittime preflight-rogue-es256.csv \
    Result --ei iterations 1 --es server_phase rogueserver

# Four-algorithm distributions: full forced refresh, successful cached
# connection, rejected rogue connection, and concurrent cache hits.
for algorithm in "${ALGORITHMS[@]}"; do
    deploy_profile real
    SERVER_CHANGED=1
    install_target "$algorithm" primary
    "$SCRIPT_DIR/activate-claim-signing-key.sh" "$algorithm" primary
    run_benchmark "$PACKAGE" avgveriftime "cold-refresh-primary-$algorithm.csv" Result \
        --ei iterations "$ITERATIONS"
    run_benchmark "$PACKAGE" avgvisittime "cached-real-primary-$algorithm.csv" \
        Result --ei iterations "$ITERATIONS" \
        --es server_phase realserver
    run_benchmark "$PACKAGE" concurrency "concurrent-cache-$algorithm.csv" Result \
        --ei iterations "$ITERATIONS" --ei threads "$THREADS"

    install_target "$algorithm" scp
    run_benchmark "$PACKAGE" avgvisittime "cached-real-scp-$algorithm.csv" \
        Result --ei iterations "$ITERATIONS" --es server_phase realserver

    install_target "$algorithm" dcp
    run_benchmark "$PACKAGE" avgvisittime "cached-real-dcp-$algorithm.csv" \
        Result --ei iterations "$ITERATIONS" --es server_phase realserver

    # Only forced refresh is attributed to K_s here. The independent matrix
    # additionally isolates OS RAM before its compatible-mode cached batches.
    install_target "$algorithm" compatible
    "$SCRIPT_DIR/activate-claim-signing-key.sh" "$algorithm" compat
    run_benchmark "$PACKAGE" avgveriftime "cold-refresh-compatible-$algorithm.csv" Result \
        --ei iterations "$ITERATIONS"

    deploy_profile rogue
    for mode in primary scp dcp; do
        install_target "$algorithm" "$mode"
        run_benchmark "$PACKAGE" avgvisittime \
            "cached-rogue-$mode-$algorithm.csv" Result \
            --ei iterations "$ITERATIONS" --es server_phase rogueserver
    done
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1 || true
done

# Two different hostname contexts refresh concurrently. This specifically
# detects accidental global serialization around network retrieval.
deploy_profile real
install_target es256
"$SCRIPT_DIR/activate-claim-signing-key.sh" es256 primary
adb -s "$DEVICE_ID" install -r \
    "$SCRIPT_DIR/ASPin/es256/app/build/outputs/apk/crossAppCaller/app-crossAppCaller.apk"
run_benchmark "$PACKAGE" parallelrefresh parallel-cold-refresh.csv Result \
    --es second_host es384.idouzi.top
else
    test -s "$SNAPSHOT_DIR/v1/ClaimSigningKey.jws"
    test -s "$SNAPSHOT_DIR/v1/ServerCertClaim.jws"
    if [ "$RESUME_AFTER_REBOOT" -eq 1 ]; then
        test -s "$SNAPSHOT_DIR/v2/ClaimSigningKey.jws"
        test -s "$SNAPSHOT_DIR/v2/ServerCertClaim.jws"
        printf 'resumed_after_reboot=%s\n' "$(date -Iseconds)" \
            >> "$RUN_DIR/environment.txt"
    else
        printf 'resumed_at_lifecycle=%s\n' "$(date -Iseconds)" \
            >> "$RUN_DIR/environment.txt"
    fi
fi

# Direct persistence test. First accept v1, generate and accept higher-iat v2,
# reboot, then independently replay the still-fresh old Tc and old Tk. A mere
# successful post-restart query would not prove persistence; these lower-iat
# replay checks do.
if [ "$RESUME_AFTER_REBOOT" -eq 0 ]; then
    deploy_profile real
    install_target es256
    "$SCRIPT_DIR/activate-claim-signing-key.sh" es256 primary
    run_benchmark "$PACKAGE" claimprobe lifecycle-v1-accepted.csv Result \
        --ez force_refresh true --ez expect_success true --es probe_label accept_v1

    python3 "$SCRIPT_DIR/gen-trust-artifacts.py" --alg es256
    snapshot_es256_tokens "$SNAPSHOT_DIR/v2"
    deploy_profile real
    run_benchmark "$PACKAGE" claimprobe lifecycle-v2-accepted.csv Result \
        --ez force_refresh true --ez expect_success true --es probe_label accept_v2

    adb -s "$DEVICE_ID" reboot
    wait_for_boot
    # Some GSI boots restore an older hardware-clock value before network time
    # converges. Re-establish the controlled benchmark clock so the replay
    # probes exercise anti-rollback rather than failing earlier on freshness.
    synchronize_device_clock
else
    deploy_profile real
    SERVER_CHANGED=1
    install_target es256
    "$SCRIPT_DIR/activate-claim-signing-key.sh" es256 primary
fi
wait_for_test_network

deploy_es256_token_pair \
    "$SNAPSHOT_DIR/v2/ClaimSigningKey.jws" \
    "$SNAPSHOT_DIR/v1/ServerCertClaim.jws"
run_benchmark "$PACKAGE" claimprobe post-restart-old-tc-replay.csv Result \
    --ez force_refresh true --ez expect_success false \
    --es expected_error anti-rollback --es probe_label post_restart_old_tc

deploy_es256_token_pair \
    "$SNAPSHOT_DIR/v1/ClaimSigningKey.jws" \
    "$SNAPSHOT_DIR/v2/ServerCertClaim.jws"
run_benchmark "$PACKAGE" claimprobe post-restart-old-tk-replay.csv Result \
    --ez force_refresh true --ez expect_success false \
    --es expected_error anti-rollback --es probe_label post_restart_old_tk

deploy_es256_token_pair \
    "$SNAPSHOT_DIR/v2/ClaimSigningKey.jws" \
    "$SNAPSHOT_DIR/v2/ServerCertClaim.jws"
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
    --es expected_error fresh --es probe_label clock_rollback
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

generate_unequal_expiry_es256_pair
run_benchmark "$PACKAGE" expirybound delegation-expiry.csv Result

python3 "$SCRIPT_DIR/summarize-robustness-results.py" "$RUN_DIR"

echo "Robustness benchmark results: $RUN_DIR"
for csv in "$RUN_DIR"/*.csv; do
    echo "==> $(basename "$csv")"
    cat "$csv"
done
