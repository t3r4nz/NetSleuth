#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  NetSleuth — Global Wrapper Script
#
#  Allows running "netsleuth" from ANY directory on Kali Linux.
#  Installed to /usr/local/bin/netsleuth for system-wide access.
#
#  ┌─────────────────────────────────────────────────────────────┐
#  │  ¿POR QUÉ UN WRAPPER Y NO UN SYMLINK (ln -s)?              │
#  │                                                             │
#  │  Un enlace simbólico (ln -s main.py /usr/local/bin/...)     │
#  │  ejecutaría main.py con el Python GLOBAL del sistema,       │
#  │  ignorando el entorno virtual (env/).  Eso significa que    │
#  │  scapy, fastapi, etc. NO estarían disponibles y el script   │
#  │  fallaría con ModuleNotFoundError.                          │
#  │                                                             │
#  │  Este wrapper resuelve eso al invocar explícitamente el     │
#  │  binario Python del venv ($INSTALL_DIR/env/bin/python),     │
#  │  garantizando que todas las dependencias estén disponibles. │
#  │  También maneja el auto-escalado a root (necesario para     │
#  │  raw sockets) y valida que el entorno exista.               │
#  └─────────────────────────────────────────────────────────────┘
#
#  Usage:
#    netsleuth --help
#    netsleuth --active -t 30
#    netsleuth --stress-test 192.168.1.1 -t 10
#    netsleuth web                         # Launch web dashboard
#    netsleuth web --port 9000 -i eth0     # Custom port/iface
#
#  Installation:
#    sudo cp netsleuth.sh /usr/local/bin/netsleuth
#    sudo chmod +x /usr/local/bin/netsleuth
# ══════════════════════════════════════════════════════════════════

set -e

# ── Configuration ─────────────────────────────────────────────────
# Change this to wherever you cloned/installed NetSleuth.
# Common locations: /opt/NetSleuth, ~/NetSleuth, ~/tools/NetSleuth
INSTALL_DIR="/opt/NetSleuth"

# ── ANSI Colors ───────────────────────────────────────────────────
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
CYAN='\033[0;96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Helper functions ──────────────────────────────────────────────
die() {
    echo -e "${RED}${BOLD}  ✖  $1${RESET}" >&2
    exit 1
}

info() {
    echo -e "${CYAN}  ℹ${RESET}  $1"
}

# ── Step 1: Verify installation directory ─────────────────────────
if [ ! -d "$INSTALL_DIR" ]; then
    die "Directorio de instalación no encontrado: ${INSTALL_DIR}
    
  Solución:
    1. Clona el repo:  git clone https://github.com/t3r4nz/NetSleuth.git ${INSTALL_DIR}
    2. O edita INSTALL_DIR en este script:  sudo nano /usr/local/bin/netsleuth"
fi

# ── Step 2: Verify virtual environment ────────────────────────────
VENV_PYTHON="${INSTALL_DIR}/env/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    die "Entorno virtual no encontrado: ${VENV_PYTHON}

  Solución:
    cd ${INSTALL_DIR}
    python3 -m venv env
    source env/bin/activate
    pip install -r requirements.txt"
fi

# ── Step 3: Auto-escalate to root if needed ───────────────────────
# Raw sockets (scapy, stress test) require root privileges.
# If not running as root, re-exec this script with sudo.
if [ "$(id -u)" -ne 0 ]; then
    info "NetSleuth requiere root — re-ejecutando con sudo…"
    exec sudo "$0" "$@"
fi

# ── Step 4: Route to the correct entry point ──────────────────────
# "netsleuth web [args]"  → web_main.py
# "netsleuth [args]"      → main.py (CLI)

FIRST_ARG="${1:-}"

if [ "$FIRST_ARG" = "web" ]; then
    # Remove "web" from arguments, pass the rest to web_main.py
    shift
    ENTRY_POINT="${INSTALL_DIR}/web_main.py"
    info "Launching Web Dashboard…"
else
    ENTRY_POINT="${INSTALL_DIR}/main.py"
fi

# ── Step 5: Verify entry point exists ─────────────────────────────
if [ ! -f "$ENTRY_POINT" ]; then
    die "Entry point no encontrado: ${ENTRY_POINT}
    
  ¿Se movió o eliminó el archivo?
  Re-clona el repo: git clone https://github.com/t3r4nz/NetSleuth.git ${INSTALL_DIR}"
fi

# ── Step 6: Execute ───────────────────────────────────────────────
# Use the venv's Python binary directly — this is why a wrapper
# is superior to a symlink: it ensures the correct interpreter
# with all dependencies installed runs the script.
exec "$VENV_PYTHON" "$ENTRY_POINT" "$@"
