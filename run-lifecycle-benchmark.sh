#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
if [ -n "${ASPIN_JAVA_HOME:-}" ]; then
    export JAVA_HOME="$ASPIN_JAVA_HOME"
elif [ -x /usr/lib/jvm/java-21-openjdk/bin/java ]; then
    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
fi
ITERATIONS="${1:-20}"
TIMEOUT_SECONDS="${BENCHMARK_TIMEOUT_SECONDS:-600}"
PACKAGE=com.cert.aspin
HOST=es256.idouzi.top
RESULTS_DIR="${ASPIN_LIFECYCLE_RESULTS_DIR:-$SCRIPT_DIR/results/lifecycle-$(date +%Y%m%d-%H%M%S)}"
APK_DIR="$SCRIPT_DIR/results/apks"
WORK_DIR="$(mktemp -d /tmp/aspin-lifecycle.XXXXXX)"
L_MAX_SECONDS="${ASPIN_MIGRATION_LMAX_SECONDS:-30}"
APKSIGNER="${APKSIGNER:-/opt/android-sdk/build-tools/35.0.0/apksigner}"
mkdir -p "$RESULTS_DIR" "$APK_DIR"

if ! [[ "$ITERATIONS" =~ ^[1-9][0-9]*$ ]] \
        || ! [[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] \
        || ! [[ "$L_MAX_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
    echo "iterations, timeout, and L_max must be positive integers" >&2
    exit 2
fi
if [ "$L_MAX_SECONDS" -lt 2 ]; then
    echo "ASPIN_MIGRATION_LMAX_SECONDS must be at least 2" >&2
    exit 2
fi

DEVICE_ID="$(adb devices | awk '$2 == "device" {print $1; exit}')"
if [ -z "$DEVICE_ID" ]; then
    echo "no Android device connected" >&2
    exit 1
fi
BENCHMARK_LOCK_FILE="${ASPIN_BENCHMARK_LOCK_FILE:-/tmp/aspin-benchmark-${DEVICE_ID}.lock}"
exec 9>"$BENCHMARK_LOCK_FILE"
if ! flock -n 9; then
    echo "another ASPin benchmark already holds $BENCHMARK_LOCK_FILE" >&2
    exit 1
fi
if ! adb -s "$DEVICE_ID" shell service check aspin 2>/dev/null | grep -q found; then
    echo "the device does not expose the ASPin service" >&2
    exit 1
fi
if [ ! -x "$APKSIGNER" ]; then
    echo "apksigner not found: $APKSIGNER" >&2
    exit 1
fi
ORIGINAL_AUTO_TIME="$(adb -s "$DEVICE_ID" shell settings get global auto_time | tr -d '\r')"
CLOCK_CHANGED=0

RAW_CA="$SCRIPT_DIR/ASPin/es256/app/src/debug/res/raw/aspin_benchmark_ca.pem"
RAW_CA_BACKUP="$WORK_DIR/aspin_benchmark_ca.pem.before"
cp "$RAW_CA" "$RAW_CA_BACKUP"
cp "$SCRIPT_DIR/ASPin/shared/src/main/res/raw/aspin_benchmark_ca.pem" \
    "$WORK_DIR/aspin_benchmark_ca.shared.before"
for artifact in ClaimSigningKey.jws ClaimSigningKey.primary.jws ServerCertClaim.jws; do
    cp "$SCRIPT_DIR/signing/es256/$artifact" "$WORK_DIR/$artifact.before"
done

cleanup() {
    set +e
    if [ "$CLOCK_CHANGED" -eq 1 ]; then
        host_epoch="$(date +%s)"
        adb -s "$DEVICE_ID" shell "su 0 date -s '@$host_epoch'" >/dev/null 2>&1 || true
        adb -s "$DEVICE_ID" shell \
            "su 0 settings put global auto_time '$ORIGINAL_AUTO_TIME'" \
            >/dev/null 2>&1 || true
    fi
    cp "$RAW_CA_BACKUP" "$RAW_CA"
    cp "$WORK_DIR/aspin_benchmark_ca.shared.before" \
        "$SCRIPT_DIR/ASPin/shared/src/main/res/raw/aspin_benchmark_ca.pem"
    for artifact in ClaimSigningKey.jws ClaimSigningKey.primary.jws ServerCertClaim.jws; do
        cp "$WORK_DIR/$artifact.before" "$SCRIPT_DIR/signing/es256/$artifact"
    done
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1
    sudo -n cp -pr "$SCRIPT_DIR/realserver/etc/"* /etc/
    sudo -n cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
    sudo -n systemctl restart nginx.service
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

synchronize_device_clock() {
    local host_epoch device_epoch delta
    host_epoch="$(date +%s)"
    adb -s "$DEVICE_ID" shell "su 0 settings put global auto_time 0" >/dev/null
    adb -s "$DEVICE_ID" shell "su 0 date -s '@$host_epoch'" >/dev/null
    CLOCK_CHANGED=1
    device_epoch="$(adb -s "$DEVICE_ID" shell date +%s | tr -d '\r')"
    if ! [[ "$device_epoch" =~ ^[0-9]+$ ]]; then
        echo "unable to read the synchronized device clock" >&2
        return 1
    fi
    delta="$((device_epoch - host_epoch))"
    if [ "$delta" -lt -2 ] || [ "$delta" -gt 2 ]; then
        echo "device clock remains ${delta}s from the benchmark host" >&2
        return 1
    fi
}

wait_until() {
    local epoch="$1"
    while [ "$(date +%s)" -lt "$epoch" ]; do sleep 1; done
}

wait_for_csv() {
    local path="$1"
    local attempt
    for attempt in $(seq 1 "$TIMEOUT_SECONDS"); do
        if adb -s "$DEVICE_ID" shell "[ -f '$path' ]" 2>/dev/null; then return 0; fi
        sleep 1
    done
    echo "timed out waiting for $path" >&2
    return 1
}

validate_csv() {
    python3 - "$1" <<'PY'
import csv, pathlib, sys
path = pathlib.Path(sys.argv[1])
with path.open(newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream))
if not rows or any(row.get("Result") != "PASS" for row in rows):
    raise SystemExit(f"{path}: lifecycle probe failed: {rows}")
PY
}

run_probe() {
    local name="$1"
    local expected="$2"
    local force="$3"
    local expected_error="${4:-}"
    local device_csv="/data/user/0/$PACKAGE/files/$name.csv"
    local local_csv="$RESULTS_DIR/$name.csv"
    adb -s "$DEVICE_ID" shell "rm -f '$device_csv'" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" shell am start -S -W -n "$PACKAGE/.MainActivity" \
        --es benchmark_type claimprobe --es output_csv "$device_csv" \
        --es probe_label "$name" --ez expect_success "$expected" \
        --ez force_refresh "$force" --es expected_error "$expected_error" >/dev/null
    wait_for_csv "$device_csv"
    adb -s "$DEVICE_ID" pull "$device_csv" "$local_csv" >/dev/null
    validate_csv "$local_csv"
}

run_connection() {
    local name="$1"
    local phase="$2"
    local device_csv="/data/user/0/$PACKAGE/files/$name.csv"
    local local_csv="$RESULTS_DIR/$name.csv"
    adb -s "$DEVICE_ID" shell "rm -f '$device_csv'" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" shell am start -S -W -n "$PACKAGE/.MainActivity" \
        --es benchmark_type avgvisittime --es server_phase "$phase" \
        --ei iterations "$ITERATIONS" --es output_csv "$device_csv" >/dev/null
    wait_for_csv "$device_csv"
    adb -s "$DEVICE_ID" pull "$device_csv" "$local_csv" >/dev/null
    validate_csv "$local_csv"
}

run_cross_sign() {
    local name="$1" expected="$2" issuer_cert="$3" extra_cert="${4:-}"
    local device_csv="/data/user/0/$PACKAGE/files/$name.csv"
    local local_csv="$RESULTS_DIR/$name.csv" issuer_id extra_id
    local -a extra_args=()
    read -r issuer_id extra_id < <(python3 - "$issuer_cert" "$extra_cert" <<'PY'
import base64, hashlib, sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
def identifier(path):
    if not path: return '-'
    der=x509.load_pem_x509_certificate(Path(path).read_bytes()).public_bytes(serialization.Encoding.DER)
    return 'sha256:'+base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b'=').decode()
print(identifier(sys.argv[1]), identifier(sys.argv[2]))
PY
)
    if [ "$extra_id" != - ]; then extra_args=(--es expected_extra_id "$extra_id"); fi
    adb -s "$DEVICE_ID" shell "rm -f '$device_csv'" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" shell am start -S -W -n "$PACKAGE/.MainActivity" \
        --es benchmark_type crosssign --es scenario "$name" \
        --ei iterations "$ITERATIONS" --ez expect_success "$expected" \
        --es expected_issuer_id "$issuer_id" "${extra_args[@]}" \
        --es output_csv "$device_csv" >/dev/null
    wait_for_csv "$device_csv"
    adb -s "$DEVICE_ID" pull "$device_csv" "$local_csv" >/dev/null
    validate_csv "$local_csv"
}

deploy_tokens() {
    sudo -n install -m 0644 "$1" /var/www/es256/.well-known/ClaimSigningKey.jws
    sudo -n install -m 0644 "$2" /var/www/es256/.well-known/ServerCertClaim.jws
}

deploy_certificate() {
    sudo -n install -m 0644 "$1" /etc/cert/es256/real-fullchain.pem
    sudo -n install -m 0600 "$2" /etc/cert/es256/real-privkey.pem
    sudo -n systemctl restart nginx.service
}

install_old_app() {
    adb -s "$DEVICE_ID" uninstall "$PACKAGE" >/dev/null 2>&1 || true
    adb -s "$DEVICE_ID" install -r "$APK_DIR/ASPin-es256.apk" >/dev/null
}

make_ca_and_leaf() {
    local label="$1"
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 7 \
        -subj "/C=US/O=ASPin Benchmark/CN=ASPin $label CA" \
        -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout "$WORK_DIR/$label-ca.key" -out "$WORK_DIR/$label-ca.crt" \
        >/dev/null 2>&1
    openssl ecparam -name prime256v1 -genkey -noout -out "$WORK_DIR/$label.key"
    openssl req -new -key "$WORK_DIR/$label.key" -subj "/CN=$HOST" \
        -out "$WORK_DIR/$label.csr" >/dev/null 2>&1
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' \
        'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
        "subjectAltName=DNS:$HOST" > "$WORK_DIR/$label.ext"
    openssl x509 -req -in "$WORK_DIR/$label.csr" -CA "$WORK_DIR/$label-ca.crt" \
        -CAkey "$WORK_DIR/$label-ca.key" -CAcreateserial -days 7 -sha256 \
        -extfile "$WORK_DIR/$label.ext" -out "$WORK_DIR/$label.crt" \
        >/dev/null 2>&1
    cp "$WORK_DIR/$label.crt" "$WORK_DIR/$label-fullchain.pem"
    cat "$WORK_DIR/$label-ca.crt" >> "$WORK_DIR/$label-fullchain.pem"
}

make_ca_and_leaf current
make_ca_and_leaf new
python3 "$SCRIPT_DIR/generate-cross-sign-fixtures.py" \
    --output-dir "$WORK_DIR/cross-sign" --hostname "$HOST"
cat "$WORK_DIR/current-ca.crt" "$WORK_DIR/new-ca.crt" \
    "$WORK_DIR/cross-sign/trusted-roots.pem" > "$RAW_CA"
cp "$RAW_CA" "$SCRIPT_DIR/ASPin/shared/src/main/res/raw/aspin_benchmark_ca.pem"

# Build and install before issuing short-lived lifecycle artifacts. This keeps
# compilation time outside every signed iat/exp interval.
python3 "$SCRIPT_DIR/gen-signed-apks.py" --workers 24 --variant es256 --mode primary \
    --output-dir "$APK_DIR"
install_old_app
sudo -n cp -pr "$SCRIPT_DIR/realserver/var/"* /var/
synchronize_device_clock

(cd "$SCRIPT_DIR/signing/es256" && python3 gen_jws_ClaimSigningKey.py)
cp "$SCRIPT_DIR/signing/es256/ClaimSigningKey.jws" \
    "$SCRIPT_DIR/signing/es256/ClaimSigningKey.primary.jws"
TK="$SCRIPT_DIR/signing/es256/ClaimSigningKey.primary.jws"
python3 "$SCRIPT_DIR/generate-lifecycle-artifacts.py" cross-sign \
    --signing-dir "$SCRIPT_DIR/signing/es256" \
    --fixture-dir "$WORK_DIR/cross-sign" --output-dir "$WORK_DIR/cross-sign/policies"
read -r CROSS_PARTIAL_IAT CROSS_FULL_IAT < <(python3 - "$WORK_DIR/cross-sign/policies/schedule.json" <<'PY'
import json, sys
v=json.load(open(sys.argv[1])); print(v['incomplete_iat'],v['complete_iat'])
PY
)
wait_until "$CROSS_PARTIAL_IAT"
deploy_certificate "$WORK_DIR/cross-sign/chain-a.pem" "$WORK_DIR/cross-sign/leaf.key"
deploy_tokens "$TK" "$WORK_DIR/cross-sign/policies/tc-incomplete.jws"
run_probe cross-sign-incomplete-policy true true
run_cross_sign cross-sign-incomplete-a true "$WORK_DIR/cross-sign/direct-a.pem"
deploy_certificate "$WORK_DIR/cross-sign/chain-b.pem" "$WORK_DIR/cross-sign/leaf.key"
run_cross_sign cross-sign-incomplete-b-rejected false "$WORK_DIR/cross-sign/direct-b.pem"
wait_until "$CROSS_FULL_IAT"
deploy_tokens "$TK" "$WORK_DIR/cross-sign/policies/tc-complete.jws"
run_probe cross-sign-complete-policy true true
run_cross_sign cross-sign-complete-b true "$WORK_DIR/cross-sign/direct-b.pem"
deploy_certificate "$WORK_DIR/cross-sign/chain-a.pem" "$WORK_DIR/cross-sign/leaf.key"
run_cross_sign cross-sign-complete-a true "$WORK_DIR/cross-sign/direct-a.pem"
deploy_certificate "$WORK_DIR/cross-sign/rogue-chain.pem" "$WORK_DIR/cross-sign/rogue-leaf.key"
run_cross_sign cross-sign-same-name-rejected false "$WORK_DIR/cross-sign/rogue-direct.pem"
deploy_certificate "$WORK_DIR/cross-sign/rogue-padded-chain.pem" "$WORK_DIR/cross-sign/rogue-leaf.key"
run_cross_sign cross-sign-padding-rejected false "$WORK_DIR/cross-sign/rogue-direct.pem" \
    "$WORK_DIR/cross-sign/direct-a.pem"

# Keep the later migration's first claim above the accepted cross-sign version.
cp "$WORK_DIR/cross-sign/policies/tc-complete.jws" "$SCRIPT_DIR/signing/es256/ServerCertClaim.jws"
python3 "$SCRIPT_DIR/generate-lifecycle-artifacts.py" ca-migration \
    --signing-dir "$SCRIPT_DIR/signing/es256" \
    --current-cert "$WORK_DIR/current.crt" --current-ca "$WORK_DIR/current-ca.crt" \
    --new-cert "$WORK_DIR/new.crt" --new-ca "$WORK_DIR/new-ca.crt" \
    --overlap-seconds "$L_MAX_SECONDS" --output-dir "$WORK_DIR/ca-migration"

read -r W1_IAT W2_IAT W2_EXP W3_IAT < <(python3 - "$WORK_DIR/ca-migration/schedule.json" <<'PY'
import json, sys
v=json.load(open(sys.argv[1])); print(v['w1_iat'],v['w2_iat'],v['w2_exp'],v['w3_iat'])
PY
)
TK="$SCRIPT_DIR/signing/es256/ClaimSigningKey.primary.jws"

wait_until "$W1_IAT"
deploy_certificate "$WORK_DIR/current-fullchain.pem" "$WORK_DIR/current.key"
deploy_tokens "$TK" "$WORK_DIR/ca-migration/tc-w1-current-only.jws"
run_probe ca-w1-current-policy true true
run_connection ca-w1-current-cert realserver

deploy_certificate "$WORK_DIR/new-fullchain.pem" "$WORK_DIR/new.key"
run_connection ca-w1-new-cert-rejected rogueserver
deploy_certificate "$WORK_DIR/current-fullchain.pem" "$WORK_DIR/current.key"

wait_until "$W2_IAT"
deploy_tokens "$TK" "$WORK_DIR/ca-migration/tc-w2-overlap.jws"
run_probe ca-w2-overlap-policy true true
run_connection ca-w2-current-cert realserver
deploy_certificate "$WORK_DIR/new-fullchain.pem" "$WORK_DIR/new.key"
run_connection ca-w2-new-cert-authorized realserver
deploy_certificate "$WORK_DIR/current-fullchain.pem" "$WORK_DIR/current.key"

wait_until "$W2_EXP"
deploy_certificate "$WORK_DIR/new-fullchain.pem" "$WORK_DIR/new.key"
deploy_tokens "$TK" "$WORK_DIR/ca-migration/tc-w3-new-only.jws"
run_probe ca-w3-joint-activation true true
run_connection ca-w3-new-cert realserver
deploy_certificate "$WORK_DIR/current-fullchain.pem" "$WORK_DIR/current.key"
run_connection ca-w3-current-cert-rejected rogueserver

# Delegated claim-key rotation: accept a still-fresh old pair, then authenticate
# a higher-iat T_k carrying a new K_c and its matching T_c.
sleep 1
(cd "$SCRIPT_DIR/signing/es256" && \
    ASPIN_TOKEN_TTL_SECONDS=300 python3 gen_jws_ClaimSigningKey.py && \
    ASPIN_TOKEN_TTL_SECONDS=300 python3 gen_jws_ServerCertClaim.py \
        "$WORK_DIR/current.crt" "$WORK_DIR/current-ca.crt")
cp "$SCRIPT_DIR/signing/es256/ClaimSigningKey.jws" \
    "$SCRIPT_DIR/signing/es256/ClaimSigningKey.primary.jws"
deploy_certificate "$WORK_DIR/current-fullchain.pem" "$WORK_DIR/current.key"
deploy_tokens "$SCRIPT_DIR/signing/es256/ClaimSigningKey.jws" \
    "$SCRIPT_DIR/signing/es256/ServerCertClaim.jws"
run_probe claim-key-r1-old true true
cp "$SCRIPT_DIR/signing/es256/ClaimSigningKey.jws" \
    "$WORK_DIR/claim-rotation-tk-r1-old.jws"
cp "$SCRIPT_DIR/signing/es256/ServerCertClaim.jws" \
    "$WORK_DIR/claim-rotation-tc-r1-old.jws"
python3 "$SCRIPT_DIR/generate-lifecycle-artifacts.py" claim-key-rotation \
    --signing-dir "$SCRIPT_DIR/signing/es256" --output-dir "$WORK_DIR/claim-rotation"
CLAIM_R2_IAT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["iat"])' \
    "$WORK_DIR/claim-rotation/schedule.json")"
wait_until "$CLAIM_R2_IAT"

# Both mixed pairs must fail: T_c must verify under the K_c selected by T_k.
deploy_tokens "$WORK_DIR/claim-rotation-tk-r1-old.jws" \
    "$WORK_DIR/claim-rotation/tc-new-claim-key.jws"
run_probe claim-key-old-tk-new-tc-rejected false true
deploy_tokens "$WORK_DIR/claim-rotation/tk-new-claim-key.jws" \
    "$WORK_DIR/claim-rotation-tc-r1-old.jws"
run_probe claim-key-new-tk-old-tc-rejected false true
deploy_tokens "$WORK_DIR/claim-rotation/tk-new-claim-key.jws" \
    "$WORK_DIR/claim-rotation/tc-new-claim-key.jws"
run_probe claim-key-r2-new true true
deploy_tokens "$WORK_DIR/claim-rotation-tk-r1-old.jws" \
    "$WORK_DIR/claim-rotation-tc-r1-old.jws"
run_probe claim-key-r1-replay-rejected false true anti-rollback

# Restore the original delegated key under a higher logical version before the
# app-signing-key transition.
wait_until "$((CLAIM_R2_IAT + 1))"
(cd "$SCRIPT_DIR/signing/es256" && \
    ASPIN_TOKEN_TTL_SECONDS=300 python3 gen_jws_ClaimSigningKey.py && \
    ASPIN_TOKEN_TTL_SECONDS=300 python3 gen_jws_ServerCertClaim.py \
        "$WORK_DIR/current.crt" "$WORK_DIR/current-ca.crt")
cp "$SCRIPT_DIR/signing/es256/ClaimSigningKey.jws" \
    "$SCRIPT_DIR/signing/es256/ClaimSigningKey.primary.jws"
deploy_tokens "$SCRIPT_DIR/signing/es256/ClaimSigningKey.jws" \
    "$SCRIPT_DIR/signing/es256/ServerCertClaim.jws"
run_probe app-key-r1-old true true

python3 "$SCRIPT_DIR/generate-lifecycle-artifacts.py" app-key-rotation \
    --old-signing-dir "$SCRIPT_DIR/signing/es256" \
    --new-signing-dir "$SCRIPT_DIR/signing/es384" \
    --claim-signing-dir "$SCRIPT_DIR/signing/es256" \
    --output-dir "$WORK_DIR/app-rotation"

"$APKSIGNER" rotate --out "$WORK_DIR/app-lineage.bin" \
    --old-signer --ks "$SCRIPT_DIR/signing/es256/my-app-key.keystore" \
    --ks-key-alias my_app --ks-pass pass:123456 --key-pass pass:123456 \
    --set-installed-data true \
    --new-signer --ks "$SCRIPT_DIR/signing/es384/my-app-key.keystore" \
    --ks-key-alias my_app --ks-pass pass:123456 --key-pass pass:123456
"$APKSIGNER" sign --out "$WORK_DIR/ASPin-es256-rotated.apk" \
    --ks "$SCRIPT_DIR/signing/es384/my-app-key.keystore" --ks-key-alias my_app \
    --ks-pass pass:123456 --key-pass pass:123456 \
    --v1-signing-enabled false --v2-signing-enabled false \
    --lineage "$WORK_DIR/app-lineage.bin" --rotation-min-sdk-version 28 \
    "$SCRIPT_DIR/ASPin/es256/app/build/outputs/apk/debug/app-debug.apk"

read -r R2_IAT R3_IAT < <(python3 - "$WORK_DIR/app-rotation/schedule.json" <<'PY'
import json, sys
v=json.load(open(sys.argv[1])); print(v['r2_iat'],v['r3_iat'])
PY
)
wait_until "$R2_IAT"
deploy_tokens "$WORK_DIR/app-rotation/tk-r2-dual.jws" \
    "$WORK_DIR/app-rotation/tc-r2-r3.jws"
adb -s "$DEVICE_ID" install -r "$WORK_DIR/ASPin-es256-rotated.apk" >/dev/null
run_probe app-key-r2-dual true true

wait_until "$R3_IAT"
deploy_tokens "$WORK_DIR/app-rotation/tk-r3-new-only.jws" \
    "$WORK_DIR/app-rotation/tc-r2-r3.jws"
run_probe app-key-r3-new-only true true
deploy_tokens "$WORK_DIR/app-rotation/tk-r2-dual.jws" \
    "$WORK_DIR/app-rotation/tc-r2-r3.jws"
run_probe app-key-r2-replay-rejected false true anti-rollback

mkdir -p "$RESULTS_DIR/artifacts/ca-migration" \
    "$RESULTS_DIR/artifacts/cross-sign" \
    "$RESULTS_DIR/artifacts/claim-key-rotation" \
    "$RESULTS_DIR/artifacts/app-key-rotation"
cp "$WORK_DIR/current-ca.crt" "$WORK_DIR/current.crt" \
    "$WORK_DIR/new-ca.crt" "$WORK_DIR/new.crt" "$RESULTS_DIR/artifacts/"
cp "$WORK_DIR/cross-sign/"*.pem "$WORK_DIR/cross-sign/policies/"*.jws \
    "$WORK_DIR/cross-sign/policies/schedule.json" "$RESULTS_DIR/artifacts/cross-sign/"
cp "$WORK_DIR/ca-migration/"*.jws "$WORK_DIR/ca-migration/schedule.json" \
    "$RESULTS_DIR/artifacts/ca-migration/"
cp "$WORK_DIR/claim-rotation/"*.jws \
    "$WORK_DIR/claim-rotation/new-claim-pubkey.pem" \
    "$WORK_DIR/claim-rotation/schedule.json" \
    "$RESULTS_DIR/artifacts/claim-key-rotation/"
cp "$WORK_DIR/app-rotation/"*.jws "$WORK_DIR/app-rotation/schedule.json" \
    "$WORK_DIR/app-lineage.bin" "$RESULTS_DIR/artifacts/app-key-rotation/"

python3 "$SCRIPT_DIR/summarize-lifecycle-results.py" "$RESULTS_DIR"

echo "lifecycle benchmark complete: $RESULTS_DIR"
