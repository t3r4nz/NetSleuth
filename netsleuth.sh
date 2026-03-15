#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  NetSleuth — Global Wrapper Script
#
#  Allows running "netsleuth" from ANY directory on Kali Linux.
#  Installed to /usr/local/bin/netsleuth for system-wide access.
#
#  Subcommands:
#    netsleuth                  → CLI passive scan (default)
#    netsleuth --active         → CLI active scan
#    netsleuth --stress-test IP → CLI stress test
#    netsleuth web              → Launch web dashboard
#    netsleuth update           → Update from GitHub + reinstall deps
#    netsleuth --help           → Show help
#
#  Installation:
#    sudo cp netsleuth.sh /usr/local/bin/netsleuth
#    sudo chmod +x /usr/local/bin/netsleuth
# ══════════════════════════════════════════════════════════════════

# ── Configuration ─────────────────────────────────────────────────
INSTALL_DIR="/opt/NetSleuth"

# ── ANSI Colors ───────────────────────────────────────────────────
R='\033[0;91m'    # Red
G='\033[0;92m'    # Green
Y='\033[0;93m'    # Yellow
C='\033[0;96m'    # Cyan
B='\033[1m'       # Bold
D='\033[2m'       # Dim
RST='\033[0m'     # Reset

# ── Helper functions ──────────────────────────────────────────────
die()  { echo -e "  ${R}${B}✖  $1${RST}" >&2; exit 1; }
ok()   { echo -e "  ${G}✔${RST}  $1"; }
info() { echo -e "  ${C}ℹ${RST}  $1"; }
warn() { echo -e "  ${Y}⚠${RST}  $1"; }
step() { echo -e "\n  ${B}$1${RST}"; }

# ── Validate installation ────────────────────────────────────────
check_install() {
    if [ ! -d "$INSTALL_DIR" ]; then
        die "Directorio no encontrado: ${INSTALL_DIR}

  Solución:
    1. Clona el repo:  git clone https://github.com/t3r4nz/NetSleuth.git ${INSTALL_DIR}
    2. O edita INSTALL_DIR:  sudo nano /usr/local/bin/netsleuth"
    fi
}

check_venv() {
    VENV_PYTHON="${INSTALL_DIR}/env/bin/python"
    if [ ! -f "$VENV_PYTHON" ]; then
        die "Entorno virtual no encontrado: ${VENV_PYTHON}

  Solución:
    cd ${INSTALL_DIR}
    python3 -m venv env
    source env/bin/activate
    pip install -r requirements.txt"
    fi
}

# ══════════════════════════════════════════════════════════════════
#  UPDATE FUNCTION
# ══════════════════════════════════════════════════════════════════
#
#  Lógica:
#    1. Verificar conexión a internet (ping a github.com)
#    2. git pull origin main — descargar últimos cambios
#    3. Activar venv y pip install --upgrade — actualizar deps
#    4. Reportar resultado
#
#  No requiere root para descargar código (si el usuario es dueño
#  de la carpeta). Solo requiere root para ejecutar la herramienta
#  después (raw sockets).
# ══════════════════════════════════════════════════════════════════

do_update() {
    echo ""
    echo -e "  ${C}${B}╔══════════════════════════════════════════╗${RST}"
    echo -e "  ${C}${B}║   NetSleuth — Actualizador               ║${RST}"
    echo -e "  ${C}${B}╚══════════════════════════════════════════╝${RST}"
    echo ""

    check_install

    # ── Step 1: Check internet ────────────────────────────────────
    step "[1/4] Verificando conexión a internet…"
    if ping -c 1 -W 3 github.com > /dev/null 2>&1; then
        ok "Conexión a GitHub exitosa."
    elif ping -c 1 -W 3 1.1.1.1 > /dev/null 2>&1; then
        warn "github.com no responde a ping pero hay conectividad."
        info "Continuando con git pull…"
    else
        die "Sin conexión a internet. Verifica tu red."
    fi

    # ── Step 2: Git pull ──────────────────────────────────────────
    step "[2/4] Descargando últimos cambios de GitHub…"
    cd "$INSTALL_DIR" || die "No se pudo acceder a ${INSTALL_DIR}"

    # Detect current branch
    BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    info "Rama actual: ${BRANCH}"

    # Stash local changes if any
    if ! git diff --quiet 2>/dev/null; then
        warn "Cambios locales detectados. Guardando con git stash…"
        git stash push -m "netsleuth-update-$(date +%Y%m%d-%H%M%S)" || true
    fi

    BEFORE=$(git rev-parse HEAD 2>/dev/null)
    git pull origin "$BRANCH" 2>&1 || die "git pull falló. Posible conflicto de merge.

  Solución manual:
    cd ${INSTALL_DIR}
    git status
    git stash pop  (si hay cambios guardados)"
    AFTER=$(git rev-parse HEAD 2>/dev/null)

    if [ "$BEFORE" = "$AFTER" ]; then
        ok "Ya estás en la última versión."
    else
        COMMITS=$(git log --oneline "${BEFORE}..${AFTER}" 2>/dev/null | wc -l)
        ok "${COMMITS} nuevo(s) commit(s) descargado(s)."
    fi

    # ── Step 3: Update dependencies ──────────────────────────────
    step "[3/4] Actualizando dependencias…"

    if [ ! -f "${INSTALL_DIR}/env/bin/python" ]; then
        warn "Entorno virtual no existe. Creando…"
        python3 -m venv "${INSTALL_DIR}/env" || die "No se pudo crear el venv."
    fi

    # shellcheck disable=SC1091
    source "${INSTALL_DIR}/env/bin/activate" || die "No se pudo activar el venv."
    pip install --upgrade pip > /dev/null 2>&1

    if [ -f "${INSTALL_DIR}/requirements.txt" ]; then
        pip install -r "${INSTALL_DIR}/requirements.txt" --upgrade 2>&1 \
            || die "pip install falló. Revisa requirements.txt."
        ok "Dependencias actualizadas."
    else
        warn "requirements.txt no encontrado. Omitiendo."
    fi

    deactivate 2>/dev/null || true

    # ── Step 4: Done ──────────────────────────────────────────────
    step "[4/4] Actualización completada."
    echo ""
    echo -e "  ${G}${B}╔══════════════════════════════════════════╗${RST}"
    echo -e "  ${G}${B}║   ✔  NetSleuth actualizado               ║${RST}"
    echo -e "  ${G}${B}╚══════════════════════════════════════════╝${RST}"
    echo ""

    # Show version info if available
    LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "sin tag")
    COMMIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "???")
    info "Versión: ${LATEST_TAG} (${COMMIT_SHORT})"
    info "Rama:    ${BRANCH}"
    echo ""

    exit 0
}

# ══════════════════════════════════════════════════════════════════
#  MAIN ROUTING
# ══════════════════════════════════════════════════════════════════

FIRST_ARG="${1:-}"

# Route: netsleuth update
if [ "$FIRST_ARG" = "update" ]; then
    do_update
fi

# ── For all other commands, we need root + venv ───────────────────
check_install
check_venv

# Auto-escalate to root (raw sockets require it)
if [ "$(id -u)" -ne 0 ]; then
    info "NetSleuth requiere root — re-ejecutando con sudo…"
    exec sudo "$0" "$@"
fi

# Route: netsleuth web [args]
if [ "$FIRST_ARG" = "web" ]; then
    shift
    ENTRY_POINT="${INSTALL_DIR}/web_main.py"
    info "Lanzando Web Dashboard…"
else
    ENTRY_POINT="${INSTALL_DIR}/main.py"
fi

# Verify entry point
if [ ! -f "$ENTRY_POINT" ]; then
    die "Entry point no encontrado: ${ENTRY_POINT}"
fi

# Execute with venv Python — this is why a wrapper > symlink
exec "$VENV_PYTHON" "$ENTRY_POINT" "$@"
