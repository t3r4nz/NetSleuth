<p align="center">
  <img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Ubuntu%20%7C%20macOS-blueviolet?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/scapy-2.5%2B-orange?style=flat-square" alt="Scapy">
</p>

<h1 align="center">🔍 NetSleuth</h1>

<p align="center">
  <strong>Passive & Active Network Reconnaissance Tool</strong><br>
  <em>Identifica dispositivos ocultos en tu red — incluso detrás de firewalls en modo DROP.</em>
</p>

---

## 📋 Descripción

**NetSleuth** es una herramienta de reconocimiento de red escrita en Python que combina **análisis pasivo** y **sondeo activo** para descubrir e identificar cada dispositivo conectado a tu red local — PCs, móviles, Smart TVs, impresoras, routers e IoT.

### ¿Qué lo diferencia?

Los escáneres tradiciones (como `arp-scan`) solo detectan dispositivos que responden a peticiones ARP. Los dispositivos con firewalls configurados en **modo DROP** permanecen invisibles. NetSleuth resuelve esto con una arquitectura dual:

1. **Motor Pasivo** — Escucha silenciosamente el tráfico de red (ARP, DHCP, TCP) y construye un perfil de cada dispositivo mediante fingerprinting de Option 55 y TCP/IP stack.
2. **Motor Activo** — Envía ráfagas de paquetes ARP broadcast y TCP SYN hacia toda la subred usando `send()` fire-and-forget. Incluso si el dispositivo descarta el paquete, el router debe resolver su MAC vía ARP — y nuestro motor pasivo lo captura.

---

## ✨ Características

| Feature | Descripción |
|---|---|
| 🌐 **Web Dashboard** | Interfaz web dark mode en tiempo real vía WebSocket (FastAPI + TailwindCSS) |
| 🕵️ **Escaneo Pasivo** | Captura ARP, DHCP y TCP sin generar tráfico en la red |
| ⚡ **Escaneo Activo** | ARP sweep + TCP SYN probes fire-and-forget (~3s para /24) |
| 🔥 **Stress Test** | Inyección de paquetes a máxima velocidad vía raw sockets (100K+ PPS) con métricas en tiempo real |
| 🖥️ **OS Fingerprinting** | Identifica Windows, Linux, macOS, Android, iOS vía DHCP Option 55 (21 firmas) |
| 📱 **Anti-MAC Randomization** | Detecta MACs aleatorias (Android 10+, iOS 14+) via bit U/L del IEEE 802 |
| 🌐 **TCP/IP Fingerprinting** | Análisis de TTL, Window Size y opciones TCP (similar a p0f) |
| 🏭 **MAC Vendor Lookup** | Resolución automática del fabricante via macvendors.com |
| 🛡️ **ARP IP Filtering** | Filtra IPs inválidas (0.0.0.0, 169.254.x.x) — previene envenenamiento de tabla |
| 🔄 **Smart Merge** | DeviceStore nunca sobreescribe una IP válida con una nula |
| 🔌 **Auto-detección** | Detecta interfaz y subred automáticamente |
| 🏗️ **Clean Architecture** | Patrones Observer, Factory, Strategy |
| 🧵 **No-bloqueante** | Sniffer y scanner activo en hilos daemon con graceful shutdown |
| 🔄 **Auto-Update** | `netsleuth update` descarga cambios y actualiza dependencias |

---

## ⚡ Comienzo Rápido

```
╭──────────────────────────────────────────────────────────────╮
│                                                              │
│  ✔  NetSleuth v1.0.0 — Guía Rápida                          │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  # Instalar y lanzar                                         │
│  cd NetSleuth && source env/bin/activate                     │
│  sudo env/bin/python main.py                                 │
│  → Abrir http://localhost:8443                               │
│                                                              │
│  # Puerto e interfaz personalizados                          │
│  sudo env/bin/python main.py --port 9000 -i eth0             │
│                                                              │
│  # Con wrapper global (si lo instalaste)                     │
│  netsleuth                        # Lanzar dashboard         │
│  netsleuth --port 9000            # Puerto custom            │
│  netsleuth update                 # Actualizar desde GitHub  │
│                                                              │
╰──────────────────────────────────────────────────────────────╯
```

---

## 📂 Estructura del Proyecto

```
NetSleuth/
├── main.py                          # Único entry point (Web UI + Uvicorn)
├── install.sh                       # Instalador automático (Kali/Debian)
├── install_sys.sh                   # Instalador del comando global
├── netsleuth.sh                     # Wrapper global (referencia)
├── pyproject.toml                   # Metadata & dependencies
├── requirements.txt                 # Pinned dependencies
├── README.md
│
├── src/
│   ├── core/                        # Domain layer (zero external deps)
│   │   ├── interfaces.py            # Abstract ports (ABCs)
│   │   ├── models.py                # Device, Packet, Fingerprint
│   │   ├── observer.py              # Observer pattern (thread-safe)
│   │   ├── analyzer_factory.py      # Factory pattern
│   │   └── exceptions.py            # Custom exceptions
│   │
│   ├── analyzers/                   # Protocol analyzers
│   │   ├── arp_analyzer.py          # ARP → MAC/IP (con filtro 0.0.0.0)
│   │   ├── dhcp_analyzer.py         # DHCP Option 55 + MAC randomization
│   │   └── tcp_analyzer.py          # TCP/IP stack fingerprinting
│   │
│   ├── engine/                      # Infrastructure
│   │   ├── sniffer.py               # Passive capture (scapy, threaded)
│   │   ├── active_scanner.py        # Active probes (fire-and-forget)
│   │   ├── stress_tester.py         # High-speed raw socket flood + metrics
│   │   ├── analysis_engine.py       # Packet → Device pipeline
│   │   └── network_utils.py         # Privilege check, auto-detect
│   │
│   ├── services/                    # Application services
│   │   ├── vendor_lookup.py         # MAC vendor API (httpx + cache)
│   │   └── device_store.py          # Thread-safe device registry (smart merge)
│   │
│   └── web/                         # Web presentation layer (única UI)
│       ├── app.py                   # FastAPI + REST + WebSocket
│       └── templates/
│           └── index.html           # SPA dashboard (Tailwind dark mode)
│
└── tests/
```

---

## 🚀 Instalación

### Kali Linux (Recomendado)

#### Opción A: Instalación automática

```bash
# Descargar y ejecutar el instalador
git clone https://github.com/t3r4nz/NetSleuth.git
cd NetSleuth
chmod +x install.sh && ./install.sh
```

#### Opción B: Instalación manual

```bash
# 1. Clonar el repositorio
git clone https://github.com/t3r4nz/NetSleuth.git
cd NetSleuth

# 2. Instalar dependencias del sistema
sudo apt update && sudo apt install -y python3-pip python3-venv libpcap-dev

# 3. Crear entorno virtual e instalar dependencias
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt

# 4. Verificar instalación
sudo env/bin/python main.py
# → Abre http://localhost:8443
```

#### Instalar como comando global (opcional)

Permite ejecutar `netsleuth` desde **cualquier directorio** sin activar el venv:

```bash
# Un solo comando — detecta la ruta automáticamente
chmod +x install_sys.sh
sudo ./install_sys.sh

# Listo — usar desde cualquier ubicación
netsleuth                                     # Lanzar dashboard
netsleuth update                              # Actualizar desde GitHub
```

> **Nota:** El script `install_sys.sh` detecta automáticamente la ruta del proyecto.
> Si necesitas cambiarla después: `sudo nano /usr/local/bin/netsleuth`

### Ubuntu / Debian

```bash
# Dependencias del sistema (necesarias para scapy)
sudo apt update
sudo apt install python3-pip python3-venv libpcap-dev

# Luego seguir los pasos de Kali Linux arriba
```

### Windows

```powershell
# Requisitos previos:
# 1. Instalar Npcap desde https://npcap.com (marcar "WinPcap API-compatible Mode")
# 2. Instalar Python 3.10+ desde https://python.org

git clone https://github.com/tu-usuario/NetSleuth.git
cd NetSleuth
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Ejecutar como Administrador
python main.py --help
```

---

## 💻 Uso

NetSleuth se gestiona **100% desde el navegador** a través del Web Dashboard.

### 🌐 Lanzar el Dashboard

```bash
# Método 1: Directamente con Python
cd NetSleuth
source env/bin/activate
sudo env/bin/python main.py

# Método 2: Con el wrapper global (si lo instalaste)
netsleuth
```

Abre tu navegador en **http://localhost:8443** para acceder al panel.

### Opciones de línea de comandos

| Flag | Descripción | Default |
|---|---|---|
| `--port PORT` | Puerto HTTP del dashboard | `8443` |
| `--host HOST` | Dirección de bind | `0.0.0.0` |
| `-i, --interface IFACE` | Interfaz de red para escanear | auto-detect |
| `-v, --verbose` | Logging detallado (debug) | off |

```bash
# Ejemplo: puerto custom + interfaz específica + verbose
sudo python main.py --port 9000 -i eth0 -v
```

### 🕵️ Desde el Dashboard puedes:

- **Escaneo Pasivo** — Captura ARP/DHCP/TCP sin generar tráfico
- **Escaneo Activo** — ARP sweep + TCP SYN probes fire-and-forget
- **Stress Test** — Inyección UDP a velocidad máxima (requiere escribir `YES` para confirmar)
- **Kill Switch** — Botón `⚠ ABORT` para detener todo al instante

> ⚠️ El stress test puede causar **DoS** — solo úsalo en redes de tu propiedad.

### 🔄 Actualizar NetSleuth

```bash
# Con el wrapper global
netsleuth update

# Manualmente
cd /opt/NetSleuth
git pull origin main
source env/bin/activate
pip install -r requirements.txt --upgrade
```

### Ejemplo de salida (escaneo activo)

```
  Mode:      ACTIVE
  Interface: eth0
  Subnet:    192.168.1.0/24
  Timeout:   30s

  📊 Scan Results — Packets processed: 847 | Fingerprints: 12 | Active probes sent: 2032

  ──────────────────────────────────────────────────────────────────────────────
  MAC Address         IP Address        Vendor                 OS Guess                   Type           Conf.
  ──────────────────────────────────────────────────────────────────────────────
  AA:BB:CC:11:22:33   192.168.1.1       Cisco Systems          Cisco IOS / Network Equip  Router/Gateway 65%
  DD:EE:FF:44:55:66   192.168.1.42      ASRock Incorporation   Windows 10/11              PC             85%
  11:22:33:AA:BB:CC   192.168.1.15      Apple, Inc.            macOS 12+ (Monterey)       PC             85%
  44:55:66:DD:EE:FF   192.168.1.120     Samsung Electronics    Android 10+                Mobile         80%
  ──────────────────────────────────────────────────────────────────────────────
  Total devices: 4
```

### Ejemplo de salida (stress test)

```
  Mode:      STRESS TEST
  Target:    192.168.1.1
  Timeout:   10s

  ⚡    142,837 PPS  │    73.14 Mbps  │  Total:    1,428,370 pkts  │  Elapsed:  10.0s

  ═══════════════════════════════════════════════════
   🔥  STRESS TEST — FINAL REPORT
  ═══════════════════════════════════════════════════

  Target:           192.168.1.1:53
  Duration:         10.02s
  Total Packets:    1,428,370
  Total Data:       131.89 MB

  Avg PPS:          142,552
  Avg Throughput:   73.00 Mbps
  Peak PPS:         158,241
  Peak Throughput:  81.02 Mbps

  ── Sniffer (background monitor) ──
  Pkts captured:    23,847
  Fingerprints:     0
```

---

## 🏗️ Arquitectura

```
            ┌────────────────────────────────────────────┐
            │        WEB UI  (main.py → Uvicorn)         │
            │         ┌──────────────────┐               │
            │         │  FastAPI + WS    │               │
            │         └────────┬─────────┘               │
            └──────────────────┼─────────────────────────┘
                               │
            ┌──────────────────┼─────────────────────────┐
            │  ENGINE          │                          │
            │                  ▼                          │
            │  ┌───────────┐  Observer  ┌──────────────┐ │
            │  │ Sniffer   │──────────▶│AnalysisEngine│ │
            │  │ (passive) │           │  (Factory)    │ │
            │  └───────────┘           └──────┬───────┘ │
            │                                  │         │
            │  ┌───────────────┐               ▼         │
            │  │ActiveScanner  │       ┌──────────────┐ │
            │  │(fire&forget)  │       │ DeviceStore   │ │
            │  └───────────────┘       │ (smart merge) │ │
            │                          └──────────────┘ │
            │  ┌───────────────┐                         │
            │  │StressTester   │                         │
            │  │(raw sockets)  │                         │
            │  └───────────────┘                         │
            └────────────────────────────────────────────┘
                               │
            ┌──────────────────┼─────────────────────────┐
            │  CORE            │                          │
            │  Interfaces │ Models │ Observer │ Factory   │
            │  (zero external dependencies)               │
            └─────────────────────────────────────────────┘
```

**Patrones de diseño:**
- **Observer** — El sniffer notifica al motor de análisis por cada paquete capturado
- **Factory** — Instancia el analizador correcto (ARP/DHCP/TCP) según el protocolo
- **Strategy** — Cada analizador implementa `IPacketAnalyzer.analyze()`
- **Dependency Inversion** — El core define interfaces abstractas; la infra las implementa

---

## ⚖️ Aviso Legal (Disclaimer)

> **⚠️ ADVERTENCIA: USO ÉTICO Y LEGAL EXCLUSIVAMENTE**
>
> Esta herramienta ha sido desarrollada con fines **educativos y de auditoría de seguridad autorizada**.
>
> **Está PROHIBIDO** utilizar NetSleuth para:
> - Escanear redes sin **autorización expresa y por escrito** del propietario.
> - Realizar actividades de reconocimiento en redes ajenas sin consentimiento.
> - Ejecutar **stress tests** o pruebas de carga contra infraestructura ajena.
> - Causar denegación de servicio (**DoS**) intencional en redes de terceros.
> - Cualquier actividad que viole las leyes locales, nacionales o internacionales.
>
> El módulo de **Stress Test** puede causar interrupción del servicio en la red
> local. Úsalo **EXCLUSIVAMENTE** en redes de laboratorio o de tu propiedad.
>
> El autor **NO se hace responsable** del uso indebido de esta herramienta.
> Al usar NetSleuth, aceptas toda la responsabilidad legal por tus acciones.
>
> **Antes de escanear u ejecutar un stress test, obtén siempre permiso por escrito.**

---

## 📄 Licencia

MIT License — consulta el archivo [LICENSE](LICENSE) para más detalles.

---

<p align="center">
  <em>Desarrollado con 🐍 Python y ☕ café por T3R4Nz </em>
</p>
