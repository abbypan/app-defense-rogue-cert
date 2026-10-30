#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALG="${1:-}"
MODE="${2:-}"

case "$ALG" in
    es256|es384|rsa3072|rsa4096) ;;
    *) echo "usage: $0 {es256|es384|rsa3072|rsa4096} {primary|compat}" >&2; exit 2 ;;
esac
case "$MODE" in
    primary|compat) ;;
    *) echo "usage: $0 {es256|es384|rsa3072|rsa4096} {primary|compat}" >&2; exit 2 ;;
esac

SOURCE="$SCRIPT_DIR/realserver/var/www/$ALG/.well-known/ClaimSigningKey.$MODE.jws"
ACTIVE_SOURCE="$SCRIPT_DIR/realserver/var/www/$ALG/.well-known/ClaimSigningKey.jws"
DEPLOYED="/var/www/$ALG/.well-known/ClaimSigningKey.jws"

if [ ! -f "$SOURCE" ]; then
    echo "missing generated token: $SOURCE" >&2
    exit 1
fi

cp -- "$SOURCE" "$ACTIVE_SOURCE"
sudo -n install -m 0644 -- "$SOURCE" "$DEPLOYED"
echo "Activated $MODE ClaimSigningKey JWS for $ALG"
