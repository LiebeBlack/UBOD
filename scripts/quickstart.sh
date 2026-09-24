#!/usr/bin/env bash
# quickstart.sh — Bóveda académica TODO-EN-UNO en un solo computador Linux.
#
# Compila (si falta), inicializa y levanta el servidor + panel en esta misma
# máquina, sin root ni servicios externos.
#
#   ./quickstart.sh            # PIN aleatorio (se muestra una vez)
#   ./quickstart.sh MiPin123   # PIN elegido por ti
#   GUI=1 ./quickstart.sh      # compila también la aplicación gráfica
#
set -euo pipefail
cd "$(dirname "$0")/../.."   # → Linux/vault

PIN="${1:-}"

# ¿Responde el panel? Con curl si existe; si no, con una conexión TCP de bash.
panel_ready() {
    if command -v curl >/dev/null 2>&1; then
        curl -s -o /dev/null "http://127.0.0.1:8443/" 2>/dev/null && return 0
        return 1
    fi
    (exec 3<>/dev/tcp/127.0.0.1/8443) >/dev/null 2>&1
}

echo "== 1/3 Compilando (release; la primera vez tarda unos minutos)…"
if [ ! -x target/release/vaultd ] || [ "${REBUILD:-0}" = "1" ]; then
    cargo build --release -p vaultd -p vaultctl
    if [ "${GUI:-0}" = "1" ]; then
        cargo build --release -p vault-gui
    fi
fi

echo "== 2/3 Inicializando bóveda en ~/.boveda …"
if [ -n "$PIN" ]; then
    target/release/vaultd --quickstart "$PIN" &
else
    target/release/vaultd --quickstart &
fi
VAULTD_PID=$!
trap 'kill $VAULTD_PID 2>/dev/null' EXIT

# esperar a que el panel responda
for _ in $(seq 1 30); do
    if panel_ready; then
        break
    fi
    sleep 0.5
done

echo
echo "== 3/3 Servidor arriba =="
echo "   Panel      : http://localhost:8443/   (abra este enlace y entre con el PIN)"
echo "   Canal mTLS : 127.0.0.1:8642"
echo "   CA         : ~/.boveda/data/ca.pem"
echo
echo "Emparejar ESTA máquina como dispositivo (otra terminal):"
echo "   código = botón «Generar código de emparejamiento» del panel"
echo "   ./target/release/vaultctl pair 127.0.0.1:8642 <CÓDIGO> AND_LOCAL --ca ~/.boveda/data/ca.pem"
echo "   ./target/release/vaultctl upload 127.0.0.1:8642 /ruta/documento.pdf"
echo
echo "App gráfica (100 % ventanas, sin tocar la consola):"
echo "   cargo build --release -p vault-gui   # una sola vez"
echo "   ./target/release/vault-gui           # y ya no hace falta terminal"
echo "   (mientras este servicio siga arriba, la app abre en MODO CONSULTA)"
echo
echo "Ctrl-C o 'kill $VAULTD_PID' para apagar."

wait $VAULTD_PID
