#!/usr/bin/env bash
set -euo pipefail

NETWORK="${1:?Uso: discover.sh <network_cidr> <output_file>}"
OUTFILE="${2:?Uso: discover.sh <network_cidr> <output_file>}"

mkdir -p "$(dirname "$OUTFILE")"

nmap -sn --send-ip "$NETWORK" -oN "$OUTFILE"

echo "[OK] Descoberta salva em $OUTFILE"
