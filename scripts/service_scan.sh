#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Uso: service_scan.sh <target_ip> <ports> <output_file>}"
PORTS="${2:?Uso: service_scan.sh <target_ip> <ports> <output_file>}"
OUTFILE="${3:?Uso: service_scan.sh <target_ip> <ports> <output_file>}"

mkdir -p "$(dirname "$OUTFILE")"

nmap -Pn -sV -p "$PORTS" "$TARGET" > "$OUTFILE" 2>&1

echo "[OK] Enumeração de serviços salva em $OUTFILE"
