#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  NetSleuth — Install Script for Kali Linux / Debian / Ubuntu
#
#  This script automates:
#    1. Git clone from remote repo
#    2. Virtual environment creation (python3 -m venv env)
#    3. Dependency installation (pip install -r requirements.txt)
#    4. Final instructions for running the tool
#
#  Usage:  chmod +x install.sh && ./install.sh
#  Requirements: git, python3 (3.10+), pip
# ══════════════════════════════════════════════════════════════════

set -e  # Exit on any error

# ── ANSI Colors ───────────────────────────────────────────────────
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
CYAN='\033[0;96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Helper functions ──────────────────────────────────────────────

success() { echo -e "  ${GREEN}✔${RESET} $1"; }
error()   { echo -e "  ${RED}✖${RESET} $1"; }
info()    { echo -e "  ${CYAN}ℹ${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $1"; }

die() {
    error "$1"
    exit 1
}

# ── Banner ────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}${BOLD}"
echo "  ███╗   ██╗███████╗████████╗███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗"
echo "  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║"
echo "  ██╔██╗ ██║█████╗     ██║   ███████╗██║     █████╗  ██║   ██║   ██║   ███████║"
echo "  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║"
echo "  ██║ ╚████║███████╗   ██║   ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║"
echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝"
echo -e "${RESET}"
echo -e "  ${YELLOW}Kali Linux Installer${RESET}  ${DIM}v1.0.0${RESET}"
echo ""

# ── Step 0: Check prerequisites ──────────────────────────────────

echo -e "  ${BOLD}Verificando requisitos del sistema…${RESET}"
echo ""

# Git
if ! command -v git &> /dev/null; then
    die "Git no está instalado. Ejecuta: sudo apt install git"
fi
success "Git $(git --version | cut -d' ' -f3)"

# Python 3
if ! command -v python3 &> /dev/null; then
    die "Python 3 no está instalado. Ejecuta: sudo apt install python3"
fi

PYTHON_VER=$(python3 --version 2>&1 | cut -d' ' -f2)
PYTHON_MAJOR=$(echo "$PYTHON_VER" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VER" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    die "Python 3.10+ requerido. Versión actual: $PYTHON_VER"
fi
success "Python $PYTHON_VER"

# pip
if ! python3 -m pip --version &> /dev/null; then
    warn "pip no disponible. Intentando instalar…"
    sudo apt install -y python3-pip || die "No se pudo instalar pip."
fi
success "pip $(python3 -m pip --version | cut -d' ' -f2)"

# python3-venv
if ! python3 -m venv --help &> /dev/null 2>&1; then
    warn "python3-venv no instalado. Instalando…"
    sudo apt install -y python3-venv || die "No se pudo instalar python3-venv."
fi
success "python3-venv"

# libpcap (needed for scapy)
if ! dpkg -l | grep -q "libpcap-dev"; then
    warn "libpcap-dev no instalado. Instalando…"
    sudo apt install -y libpcap-dev || warn "No se pudo instalar libpcap-dev (scapy podría fallar)."
else
    success "libpcap-dev"
fi

echo ""

# ── Step 1: Clone repository ──────────────────────────────────────

echo -e "  ${BOLD}[1/4] Clonar repositorio${RESET}"
echo ""

read -rp "  Pega la URL del repositorio GitHub: " REPO_URL

if [ -z "$REPO_URL" ]; then
    die "URL del repositorio vacía. Abortando."
fi

# Extract repo name from URL for folder name
REPO_NAME=$(basename "$REPO_URL" .git)

if [ -d "$REPO_NAME" ]; then
    warn "La carpeta '${REPO_NAME}' ya existe."
    read -rp "  ¿Deseas eliminarla y clonar de nuevo? (s/N): " OVERWRITE
    if [ "$OVERWRITE" = "s" ] || [ "$OVERWRITE" = "S" ]; then
        rm -rf "$REPO_NAME"
        success "Carpeta eliminada."
    else
        info "Usando carpeta existente."
    fi
fi

if [ ! -d "$REPO_NAME" ]; then
    echo ""
    git clone "$REPO_URL" || die "git clone falló. Verifica la URL y tu acceso."
    success "Repositorio clonado en ./${REPO_NAME}"
fi

echo ""
cd "$REPO_NAME" || die "No se pudo entrar a la carpeta ${REPO_NAME}."

# ── Step 2: Create virtual environment ────────────────────────────

echo -e "  ${BOLD}[2/4] Crear entorno virtual${RESET}"
echo ""

if [ -d "env" ]; then
    info "Entorno virtual 'env/' ya existe, omitiendo creación."
else
    python3 -m venv env || die "No se pudo crear el entorno virtual."
    success "Entorno virtual creado en ./env"
fi

echo ""

# ── Step 3: Activate and install dependencies ─────────────────────

echo -e "  ${BOLD}[3/4] Instalar dependencias${RESET}"
echo ""

# shellcheck disable=SC1091
source env/bin/activate || die "No se pudo activar el entorno virtual."
success "Entorno virtual activado."

pip install --upgrade pip > /dev/null 2>&1
success "pip actualizado."

echo ""
info "Instalando dependencias desde requirements.txt…"
echo ""

pip install -r requirements.txt || die "pip install falló. Revisa requirements.txt."

echo ""
success "Todas las dependencias instaladas correctamente."
echo ""

# ── Step 4: Final instructions ────────────────────────────────────
#
#  ¿POR QUÉ USAMOS printf CON ANCHOS FIJOS EN VEZ DE echo?
#
#  Los códigos ANSI de color (\033[0;92m, etc.) son "caracteres
#  invisibles" — ocupan bytes pero no avanzan el cursor. Si los
#  pones dentro de un echo normal con bordes ║, la terminal cuenta
#  los bytes del código de color como si fueran texto visible,
#  desplazando el borde derecho hacia la derecha.
#
#  Solución: imprimimos cada línea con la misma cantidad de
#  caracteres VISIBLES, sin depender de echo para alinear.
#  Usamos printf con el texto pre-formateado y ponemos los bordes
#  fuera de las variables de color.
# ──────────────────────────────────────────────────────────────────

W=60  # Width of the box content (visible chars between borders)

# Function: print a bordered line with colored content
# Usage: bline "visible text" [color_code]
bline() {
    local text="$1"
    local color="${2:-}"
    local visible_len=${#text}
    local pad=$((W - visible_len))
    if [ -n "$color" ]; then
        printf "  │ %b%s%b%*s │\n" "$color" "$text" "$RESET" "$pad" ""
    else
        printf "  │ %s%*s │\n" "$text" "$pad" ""
    fi
}

echo -e "  ${BOLD}[4/4] ¡Instalación completada!${RESET}"
echo ""
echo "  ╭──────────────────────────────────────────────────────────────╮"
bline ""
bline "✔  NetSleuth v1.0.0 instalado correctamente" "${GREEN}${BOLD}"
bline ""
echo "  ├──────────────────────────────────────────────────────────────┤"
bline ""
bline "Comandos para ejecutar:" "${CYAN}${BOLD}"
bline ""
bline "# Activar entorno virtual" "$YELLOW"
bline "cd ${REPO_NAME} && source env/bin/activate"
bline ""
bline "# CLI — Escaneo pasivo" "$YELLOW"
bline "sudo env/bin/python main.py --timeout 60"
bline ""
bline "# CLI — Escaneo activo" "$YELLOW"
bline "sudo env/bin/python main.py --active -t 30"
bline ""
bline "# CLI — Stress Test" "$YELLOW"
bline "sudo env/bin/python main.py --stress-test 192.168.1.1"
bline ""
bline "# Web Dashboard" "$YELLOW"
bline "sudo env/bin/python web_main.py"
bline "-> Abrir http://localhost:8443" "$DIM"
bline ""
echo "  ╰──────────────────────────────────────────────────────────────╯"
echo ""
