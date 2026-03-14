#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Uso: rtsp_enum.sh <target_ip> <paths_file> <output_file>}"
PATHS_FILE="${2:?Uso: rtsp_enum.sh <target_ip> <paths_file> <output_file>}"
OUTFILE="${3:?Uso: rtsp_enum.sh <target_ip> <paths_file> <output_file>}"

mkdir -p "$(dirname "$OUTFILE")"
: > "$OUTFILE"

while IFS= read -r path; do
  URI="rtsp://$TARGET:554$path"

  {
    echo "### OPTIONS $URI"
    printf 'OPTIONS %s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CameraLab/1.0\r\n\r\n' "$URI" \
      | nc -w 3 "$TARGET" 554 || true
    echo
    echo "### DESCRIBE $URI"
    printf 'DESCRIBE %s RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: CameraLab/1.0\r\nAccept: application/sdp\r\n\r\n' "$URI" \
      | nc -w 3 "$TARGET" 554 || true
    echo
    echo
  } >> "$OUTFILE"
done < "$PATHS_FILE"

echo "[OK] Enumeração RTSP salva em $OUTFILE"
