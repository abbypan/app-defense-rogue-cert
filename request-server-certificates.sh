#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "${ASPIN_CERTIFICATE_PYTHON:-python3}" "$SCRIPT_DIR/request-server-certificates.py" "$@"
