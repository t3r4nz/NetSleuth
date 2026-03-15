# 🔍 NetSleuth v1.0.0 — Release Notes

<p align="center">
  <img src="https://img.shields.io/badge/release-v1.0.0-brightgreen?style=for-the-badge" alt="Release">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
</p>

**Primera versión estable** de NetSleuth — una herramienta completa de reconocimiento de red con escaneo pasivo/activo, pruebas de estrés y un dashboard web en tiempo real.

---

## 🎯 Highlights

### 🌐 Web Dashboard (Nuevo)
- Interfaz web profesional **dark mode** con TailwindCSS
- Telemetría **en tiempo real** via WebSocket (dispositivos + métricas de stress test)
- **OPSEC modal** para stress test: requiere confirmación explícita (`YES`)
- Botón **Kill Switch** (`⚠ ABORT`) para detener operaciones al instante
- Disponible en `http://localhost:8443` via `sudo python web_main.py`

### 🔥 Stress Test
- Inyección de paquetes UDP a **velocidad máxima** via raw sockets (`IPPROTO_RAW`)
- Alcanza **100,000–200,000+ PPS** (vs ~2,000 PPS con `scapy.send()`)
- Métricas en tiempo real: **PPS, Mbps, Peak PPS, Total Packets**
- Kill switch instantáneo via `threading.Event` (respuesta < 10ms)

### ⚡ Escaneo Activo
- ARP sweep broadcast + TCP SYN probes **fire-and-forget** (`sendp()`/`send()`)
- ~3 segundos para escanear una subred `/24` completa
- El sniffer pasivo captura las respuestas automáticamente

### 🕵️ Motor Pasivo
- Análisis de tráfico ARP, DHCP (Option 55) y TCP/IP fingerprinting
- Identificación de OS: Windows, Linux, macOS, Android, iOS
- Resolución automática de fabricante (MAC vendor lookup)

---

## 📦 Changelog Técnico

### Arquitectura
- Clean Architecture (Hexagonal) con **Inversión de Dependencias**
- Patrones: **Observer**, **Factory**, **Strategy**
- Core domain con **cero dependencias externas**

### Nuevos Módulos
| Módulo | Archivo | Descripción |
|---|---|---|
| Active Scanner | `src/engine/active_scanner.py` | ARP sweep + TCP SYN (fire-and-forget) |
| Stress Tester | `src/engine/stress_tester.py` | Raw socket UDP flood + metrics thread |
| Network Utils | `src/engine/network_utils.py` | Privilege check + interface auto-detect |
| Web Backend | `src/web/app.py` | FastAPI REST + WebSocket |
| Web Frontend | `src/web/templates/index.html` | TailwindCSS SPA dark mode |

### Interfaces (ABCs)
- `IPacketAnalyzer` · `IPacketSource` · `IPacketListener`
- `IActiveScanner` · `IStressTester`
- `IVendorLookup` · `IDeviceStore`

### Concurrencia
- Sniffer, scanner activo, stress tester → hilos daemon con `stop_event`
- Device store → `threading.Lock` para acceso thread-safe
- FastAPI → asyncio event loop (no bloquea el WebSocket)

---

## 🚀 Instalación Rápida (Linux)

```bash
# Clonar
git clone https://github.com/tu-usuario/NetSleuth.git
cd NetSleuth

# Entorno virtual
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt

# CLI — Escaneo pasivo
sudo env/bin/python main.py --timeout 60

# CLI — Escaneo activo
sudo env/bin/python main.py --active -t 30

# CLI — Stress test
sudo env/bin/python main.py --stress-test 192.168.1.1 -t 10

# Web Dashboard
sudo env/bin/python web_main.py
# → http://localhost:8443
```

### Script automático
```bash
chmod +x install.sh && ./install.sh
```

---

## 📋 Requisitos

| Requisito | Versión |
|---|---|
| Python | 3.10+ |
| scapy | ≥ 2.5.0 |
| FastAPI | ≥ 0.104.0 |
| Uvicorn | ≥ 0.24.0 |
| netifaces | ≥ 0.11.0 |
| httpx | ≥ 0.24.0 |
| Privilegios | root / sudo |

---

## ⚖️ Uso Ético

> Esta herramienta es para **uso educativo y auditorías autorizadas exclusivamente**.
> No escanees ni ataques redes sin permiso por escrito del propietario.
> El módulo de stress test puede causar **DoS** — úsalo solo en redes de laboratorio.

---

<p align="center">
  <strong>Full Changelog:</strong> <code>initial commit → v1.0.0</code>
</p>
