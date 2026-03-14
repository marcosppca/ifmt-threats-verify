#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Uso: http_enum.sh <target_ip> <paths_file> <output_file>}"
PATHS_FILE="${2:?Uso: http_enum.sh <target_ip> <paths_file> <output_file>}"
OUTFILE="${3:?Uso: http_enum.sh <target_ip> <paths_file> <output_file>}"

mkdir -p "$(dirname "$OUTFILE")"
: > "$OUTFILE"

while IFS= read -r path; do
  [ -z "$path" ] && path="/"
  echo "### GET $path" >> "$OUTFILE"
  curl -sS -i --max-time 5 "http://$TARGET$path" >> "$OUTFILE" 2>&1 || true
  echo -e "\n" >> "$OUTFILE"
done < "$PATHS_FILE"

echo "[OK] Enumeração HTTP salva em $OUTFILE"
