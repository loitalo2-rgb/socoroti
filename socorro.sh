#!/usr/bin/env sh
# Lancador portatil do SocorroTI para Linux/macOS.
# Uso: ./socorro.sh rede diagnostico
set -e
cd "$(dirname "$0")" || exit 1

if command -v python3 >/dev/null 2>&1; then
    exec python3 -m socoroti "$@"
elif command -v python >/dev/null 2>&1; then
    exec python -m socoroti "$@"
else
    echo "SocorroTI precisa do Python 3.9+ (python3)." >&2
    exit 1
fi
