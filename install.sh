#!/usr/bin/env bash
# NetSleuth — Automated Global Installer
# Destructive/Safe re-install to /opt/NetSleuth and global wrapper in /usr/local/bin

set -e

REPO_URL="https://github.com/t3r4nz/NetSleuth"
INSTALL_DIR="/opt/NetSleuth"
COMMAND_PATH="/usr/local/bin/netsleuth"

# 1. Require root
if [ "$EUID" -ne 0 ]; then
  echo -e "\n[!] FATAL: NetSleuth instalation requires root privileges."
  echo -e "    Please run: sudo ./install.sh\n"
  exit 1
fi

echo "[*] Starting automated installation of NetSleuth..."

# 2. Prepare /opt/NetSleuth (destructive sync)
if [ -d "$INSTALL_DIR" ]; then
    echo "[*] Found existing installation at $INSTALL_DIR. Updating via git pull..."
    cd "$INSTALL_DIR"
    git reset --hard HEAD
    git pull origin main || {
        echo "[!] Git pull failed. Attempting clean wipe..."
        cd /
        rm -rf "$INSTALL_DIR"
        git clone "$REPO_URL" "$INSTALL_DIR"
    }
else
    echo "[*] Cloning repository to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# 3. System dependencies
echo "[*] Installing/Verifying system dependencies (libpcap, python3-venv)..."
apt-get update -qq
apt-get install -y -qq python3-pip python3-venv libpcap-dev

# 4. Virtual Environment
echo "[*] Setting up isolated Python environment..."
if [ ! -d "env" ]; then
    python3 -m venv env
fi
./env/bin/pip install -q -r requirements.txt

# 5. Global Command Wrapper
echo "[*] Injecting global command wrapper at $COMMAND_PATH..."

cat << 'EOF' > "$COMMAND_PATH"
#!/usr/bin/env bash
# Auto-generated NetSleuth Global Wrapper

INSTALL_DIR="/opt/NetSleuth"

if [ "$EUID" -ne 0 ]; then
    echo -e "\n[!] NetSleuth requires root privileges (raw sockets). Auto-escalating...\n"
    exec sudo "$0" "$@"
fi

if [ "$1" == "update" ]; then
    echo "[*] Updating NetSleuth from GitHub..."
    cd "$INSTALL_DIR"
    git pull
    ./env/bin/pip install -r requirements.txt
    echo "[✔] Update complete."
    exit 0
fi

# Execute main application directly via venv
exec "$INSTALL_DIR/env/bin/python" "$INSTALL_DIR/main.py" "$@"
EOF

# Apply execution permissions
chmod +x "$COMMAND_PATH"

echo "================================================================"
echo " ✔ NetSleuth successfully installed globally!"
echo "================================================================"
echo " You can now run the web dashboard from anywhere by typing:"
echo -e " \033[1;32mnetsleuth\033[0m"
echo ""
echo " To fetch future updates, run:"
echo -e " \033[1;34mnetsleuth update\033[0m"
echo "================================================================"
