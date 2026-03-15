#!/usr/bin/env bash
# NetSleuth — Fix Path Global Installer
# Instalador de comando fijo usando rutas absolutas

set -e

# Requiere root
if [ "$EUID" -ne 0 ]; then
  echo -e "\n[!] Por favor, ejecuta como root (sudo ./fix_path.sh)\n"
  exit 1
fi

# 1. Detectar el directorio absoluto real de este script
# Esto evita que $PWD apunte a un lugar incorrecto si se ejecuta con sudo desde otro lado
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
echo "[*] Directorio de NetSleuth detectado: $DIR"

# 2. Crear el alias global en /usr/bin
# (Usar /usr/bin en vez de /usr/local/bin evade problemas del $PATH predeterminado en ZSH de Kali)
TARGET="/usr/bin/netsleuth"
echo "[*] Generando ejecutable en $TARGET..."

cat << 'EOF' > "$TARGET"
#!/usr/bin/env bash
# Auto-generado por fix_path.sh
# Redirige todo al intérprete virtual usando rutas absolutas rígidas.

TARGET_DIR="___DIR___"

if [ "$EUID" -ne 0 ]; then
    echo -e "\n[!] Elevando privilegios. NetSleuth requiere root (raw sockets)...\n"
    exec sudo "$0" "$@"
fi

# Ejecutar main.py con el env de NetSleuth (rutas absolutas, cero ambigüedades)
exec "$TARGET_DIR/env/bin/python" "$TARGET_DIR/main.py" "$@"
EOF

# Inyectar el verdadero path en el placeholder
sed -i "s|___DIR___|$DIR|g" "$TARGET"

# 3. Aplicar permisos de ejecución
# (Se aplica tanto a este mismo archivo como al wrapper generado, según requerimiento)
chmod +x "$DIR/fix_path.sh"
chmod +x "$TARGET"

echo "[✔] ¡Listo! Instalación del comando global fija."
echo "Puedes ejecutar 'netsleuth' desde el terminal de ZSH y siempre funcionará."
