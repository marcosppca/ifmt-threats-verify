#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Uso: availability.sh <target_ip> <count> <delay_seconds> <output_file>}"
COUNT="${2:?Uso: availability.sh <target_ip> <count> <delay_seconds> <output_file>}"
DELAY="${3:?Uso: availability.sh <target_ip> <count> <delay_seconds> <output_file>}"
OUTFILE="${4:?Uso: availability.sh <target_ip> <count> <delay_seconds> <output_file>}"

mkdir -p "$(dirname "$OUTFILE")"
: > "$OUTFILE"

for i in $(seq 1 "$COUNT"); do
  echo "### REQUEST $i" >> "$OUTFILE"
  curl -sS -o /dev/null -D - --max-time 5 "http://$TARGET/" >> "$OUTFILE" 2>&1 || true
  echo >> "$OUTFILE"
  sleep "$DELAY"
done

echo "[OK] Teste leve de disponibilidade salvo em $OUTFILE"
