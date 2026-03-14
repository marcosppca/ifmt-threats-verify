#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?Uso: auth_test.sh <ip> <outfile>}"
OUTFILE="${2:?Uso: auth_test.sh <ip> <outfile>}"

STREAM_PATH="/live/ch0"

# lista pequena de credenciais de teste
CREDS=(
"user:user"
"admin:admin"
"admin:12345"
"admin:password"
"user:password"
"guest:guest"
)

echo "RTSP authentication test for $TARGET" > "$OUTFILE"
echo "Stream path: $STREAM_PATH" >> "$OUTFILE"
echo "" >> "$OUTFILE"

for cred in "${CREDS[@]}"; do
    user="${cred%%:*}"
    pass="${cred##*:}"

    url="rtsp://${user}:${pass}@${TARGET}:554${STREAM_PATH}"

    echo "Testing: $user:$pass" >> "$OUTFILE"

    # tenta abrir conexão RTSP
    if timeout 3 ffprobe -v error "$url" >/dev/null 2>&1; then
        echo "[SUCCESS] Credencial válida: $user:$pass" >> "$OUTFILE"
        echo "URL: $url" >> "$OUTFILE"
        exit 0
    else
        echo "[FAILED]" >> "$OUTFILE"
    fi

    echo "" >> "$OUTFILE"
done

echo "Nenhuma credencial testada funcionou." >> "$OUTFILE"
