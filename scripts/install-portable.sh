#!/usr/bin/env bash
# install-portable.sh — empaqueta el sistema en /opt/intranet-suite/
# Jerarquía portable: bin/ lib/ config/ — sin instalar nada en el sistema
# anfitrión (ideal para Debian y distribuciones ligeras).
#
#   sudo ./scripts/install-portable.sh [--desktop] [--dest=/ruta]
#
set -euo pipefail
cd "$(dirname "$0")/.."

DEST="/opt/intranet-suite"
WITH_DESKTOP=0
for a in "$@"; do
    case "$a" in
        --desktop) WITH_DESKTOP=1 ;;
        --dest=*) DEST="${a#--dest=}" ;;
        /*) DEST="$a" ;;
        *) echo "aviso: argumento ignorado: $a" >&2 ;;
    esac
done

# El destino nunca puede ser un flag: se exige ruta absoluta.
case "$DEST" in
    /*) ;;
    *)
        echo "error: destino inválido «$DEST» (use --dest=/ruta/absoluta)" >&2
        exit 2
        ;;
esac

# Bajo sudo, $HOME apunta a root: la bóveda a empaquetar está en la del usuario
# que invocó el script.
INVOKER_HOME="$HOME"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    INVOKER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi
[ -n "$INVOKER_HOME" ] || INVOKER_HOME="$HOME"

echo "== Compilando release…"
cargo build --release -p vault-gui -p vaultd -p vaultctl -p vault-it

echo "== Empaquetando en $DEST…"
sudo mkdir -p "$DEST"/{bin,lib,config,data}
sudo install -m 0755 target/release/vault-gui "$DEST/bin/"
sudo install -m 0755 target/release/vaultd "$DEST/bin/"
sudo install -m 0755 target/release/vaultctl "$DEST/bin/"
# Herramienta interna de administración: se instala, pero no se anuncia.
sudo install -m 0755 target/release/vault-it "$DEST/bin/"

# lib/: los binarios son autocontenidos (Rust puro); se documenta y queda
# lista por si una configuración futura requiere librerías acompañantes.
sudo tee "$DEST/lib/README.txt" >/dev/null <<'EOF'
Los binarios de intranet-suite son estáticos respecto de sus dependencias
Rust (solo requieren las librerías de sistema del escritorio: OpenGL/X11/Wayland).
Este directorio existe por la jerarquía portable y para librerías opcionales.
EOF

# config/: clave pública de reportes + config del daemon de ejemplo
if [ -f "$INVOKER_HOME/.boveda/data/config/it.pub" ]; then
    sudo install -m 0644 "$INVOKER_HOME/.boveda/data/config/it.pub" "$DEST/config/it.pub"
elif [ -f "$INVOKER_HOME/.boveda/data/door/it.pub" ]; then
    sudo install -m 0644 "$INVOKER_HOME/.boveda/data/door/it.pub" "$DEST/config/it.pub"
fi
sudo tee "$DEST/config/vaultd.toml.example" >/dev/null <<'EOF'
# Copie a ~/.boveda/vaultd.toml y ajuste si hace falta.
vault_root = "/opt/intranet-suite/data/vault"
data_dir = "/opt/intranet-suite/data"
webui_listen = "127.0.0.1:8443"
sync_listen = "127.0.0.1:8642"
enable_sync = false
mdns_instance = "Boveda"
server_cn = "vault-server"
EOF

sudo chown -R "${SUDO_USER:-$USER}" "$DEST/data" 2>/dev/null || true

# lanzador de escritorio (100 % gráfico: el usuario nunca abre una terminal)
if [ "$WITH_DESKTOP" = "1" ]; then
    DESKTOP_DIR="$INVOKER_HOME/.local/share/applications"
    mkdir -p "$DESKTOP_DIR"
    cat >"$DESKTOP_DIR/intranet-suite.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Bóveda académica
Comment=Custodia documental institucional
Exec=$DEST/bin/vault-gui
Icon=application-x-archive
Terminal=false
Categories=Office;Education;
EOF
    echo "== Lanzador instalado: $DESKTOP_DIR/intranet-suite.desktop (menú → «Bóveda académica»)"
fi

echo "== Listo =="
echo "  Aplicación gráfica : $DEST/bin/vault-gui  (100 % ventanas, sin consola)"
echo "  Servidor           : $DEST/bin/vaultd --quickstart [PIN]"
echo "  Cliente            : $DEST/bin/vaultctl"
