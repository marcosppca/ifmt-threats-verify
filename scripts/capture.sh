#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Uso: capture.sh <target_ip> <duration_seconds> <output_pcap>}"
DURATION="${2:?Uso: capture.sh <target_ip> <duration_seconds> <output_pcap>}"
OUTFILE="${3:?Uso: capture.sh <target_ip> <duration_seconds> <output_pcap>}"

mkdir -p "$(dirname "$OUTFILE")"

sudo timeout "$DURATION" tcpdump -i any host "$TARGET" -w "$OUTFILE" || true

if [ -f "$OUTFILE" ]; then
  sudo chown "$USER:$USER" "$OUTFILE" || true
fi

echo "[OK] Captura salva em $OUTFILE"
