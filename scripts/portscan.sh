#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Uso: portscan.sh <target_ip> <ports> <output_file>}"
PORTS="${2:?Uso: portscan.sh <target_ip> <ports> <output_file>}"
OUTFILE="${3:?Uso: portscan.sh <target_ip> <ports> <output_file>}"

mkdir -p "$(dirname "$OUTFILE")"

nmap -Pn -p "$PORTS" "$TARGET" > "$OUTFILE" 2>&1

echo "[OK] Portscan salvo em $OUTFILE"
