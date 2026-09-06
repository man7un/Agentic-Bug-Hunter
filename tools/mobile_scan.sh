#!/bin/bash
# =============================================================================
# Mobile App Scanner (apkleaks wrapper)
# Decompiles an APK and scans for hardcoded secrets, API keys, and endpoints
# Usage: ./mobile_scan.sh <app.apk> [target-name]
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_ok()   { echo -e "${GREEN}[+]${NC} $1"; }
log_err()  { echo -e "${RED}[-]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_info() { echo -e "${CYAN}[*]${NC} $1"; }

APK="${1:?Usage: $0 <app.apk> [target-name]}"
TARGET="${2:-$(basename "$APK" .apk)}"
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APKLEAKS="$BASE_DIR/tools/apkleaks/apkleaks.py"
OUT_DIR="$BASE_DIR/recon/${TARGET}/mobile"

if [ ! -f "$APK" ]; then
    log_err "APK not found: $APK"
    exit 1
fi

if ! command -v java &>/dev/null; then
    log_err "Java is required (jadx decompiler runs on the JVM). Install a JRE and retry."
    exit 1
fi

mkdir -p "$OUT_DIR"

log_info "Scanning $APK for secrets, endpoints & URIs..."
python3 "$APKLEAKS" -f "$APK" -o "$OUT_DIR/apkleaks.json" --json

if [ -s "$OUT_DIR/apkleaks.json" ]; then
    log_ok "Results → $OUT_DIR/apkleaks.json"
else
    log_warn "No output produced — check errors above"
fi
