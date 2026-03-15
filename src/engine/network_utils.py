"""
NetSleuth — Network Utilities.

Cross-platform helpers for:
    - **Privilege checking** (root on POSIX, Administrator on Windows).
    - **Default interface detection** via scapy's routing table.
    - **Local subnet resolution** (CIDR notation).

These functions are called *before* any capture starts, so errors here
should produce friendly messages and abort early.
"""

from __future__ import annotations

import logging
import os
import platform
import socket
import struct
import sys
from typing import Optional, Tuple

from src.core.exceptions import (
    InsufficientPermissionsError,
    NetworkInterfaceError,
)

logger = logging.getLogger(__name__)

# ANSI helpers for standalone error messages
_RED = "\033[91m"
_YELLOW = "\033[93m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


# ── Privilege Checking ───────────────────────────────────────────────────── #


def check_privileges() -> None:
    """Verify that the current process has raw-socket privileges.

    On POSIX (Linux/macOS) this checks ``os.geteuid() == 0``.
    On Windows this uses ``ctypes`` to query the shell admin flag.

    Raises:
        InsufficientPermissionsError: If the process is unprivileged.
    """
    system = platform.system().lower()

    if system in ("linux", "darwin"):
        if os.geteuid() != 0:  # type: ignore[attr-defined]
            raise InsufficientPermissionsError(
                "NetSleuth requiere privilegios de root para el modo promiscuo "
                "de Scapy. Ejecuta con: sudo python main.py"
            )
    elif system == "windows":
        try:
            import ctypes
            is_admin: bool = ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
            if not is_admin:
                raise InsufficientPermissionsError(
                    "NetSleuth requiere privilegios de Administrador en Windows. "
                    "Ejecuta la terminal como Administrador y asegúrate de tener "
                    "Npcap instalado (https://npcap.com)."
                )
        except AttributeError:
            logger.warning(
                "No se pudo verificar privilegios en Windows: ctypes.windll no disponible."
            )
    else:
        logger.warning(
            "Sistema operativo '%s' no reconocido. No se pudo verificar privilegios.",
            system,
        )


# ── Interface & Subnet Detection ────────────────────────────────────────── #


def detect_default_interface() -> str:
    """Auto-detect the default network interface with internet connectivity.

    Strategy (ordered by reliability):
        1. Use ``scapy.conf.iface`` which resolves from the routing table.
        2. Fall back to ``netifaces.gateways()`` if scapy fails.
        3. Last resort: read ``/proc/net/route`` on Linux.

    Returns:
        Interface name string (e.g., ``"eth0"``, ``"wlan0"``).

    Raises:
        NetworkInterfaceError: If no active interface with a default
            gateway could be found (machine is offline / no bridge adapter).
    """
    # ── Strategy 1: scapy ────────────────────────────────────────────── #
    try:
        from scapy.config import conf as scapy_conf  # type: ignore[import-untyped]

        iface = str(scapy_conf.iface)
        if iface and iface != "lo" and iface != "Loopback Pseudo-Interface 1":
            logger.info("Interfaz detectada vía scapy: %s", iface)
            return iface
    except Exception:
        logger.debug("scapy.conf.iface no disponible, intentando alternativas…")

    # ── Strategy 2: netifaces ────────────────────────────────────────── #
    try:
        import netifaces  # type: ignore[import-untyped]

        gateways = netifaces.gateways()
        default_gw = gateways.get("default") or gateways.get(netifaces.AF_INET)
        if default_gw:
            # default_gw format: {2: ('gateway_ip', 'iface_name')}
            for _af, (gw_ip, iface, *_) in default_gw.items():
                if iface and iface != "lo":
                    logger.info(
                        "Interfaz detectada vía netifaces: %s (gateway %s)",
                        iface,
                        gw_ip,
                    )
                    return iface
    except ImportError:
        logger.debug("netifaces no instalado, intentando /proc/net/route…")
    except Exception:
        logger.debug("netifaces falló, intentando /proc/net/route…")

    # ── Strategy 3: /proc/net/route (Linux only) ─────────────────────── #
    if platform.system().lower() == "linux":
        try:
            iface = _parse_proc_route()
            if iface:
                logger.info("Interfaz detectada vía /proc/net/route: %s", iface)
                return iface
        except Exception:
            logger.debug("/proc/net/route no disponible.")

    # ── All strategies failed — machine is offline ───────────────────── #
    raise NetworkInterfaceError(
        "auto-detect — No se detectó ninguna conexión a internet o subred activa. "
        "Verifica que tu máquina esté conectada a la red o usa el argumento -i <interfaz>."
    )


def get_local_subnet(interface: str) -> str:
    """Resolve the CIDR subnet for a given network interface.

    Args:
        interface: Interface name (e.g., ``"eth0"``).

    Returns:
        CIDR string (e.g., ``"192.168.1.0/24"``).

    Raises:
        NetworkInterfaceError: If the subnet cannot be determined.
    """
    # ── Strategy 1: netifaces (most reliable) ────────────────────────── #
    try:
        import netifaces  # type: ignore[import-untyped]

        addrs = netifaces.ifaddresses(interface)
        ipv4_info = addrs.get(netifaces.AF_INET)
        if ipv4_info:
            entry = ipv4_info[0]
            ip_addr = entry["addr"]
            netmask = entry["netmask"]
            cidr = _netmask_to_cidr(ip_addr, netmask)
            logger.info("Subred detectada vía netifaces: %s", cidr)
            return cidr
    except ImportError:
        logger.debug("netifaces no instalado, intentando scapy…")
    except (ValueError, KeyError):
        logger.debug("netifaces no pudo resolver la subred para %s.", interface)

    # ── Strategy 2: scapy route table ────────────────────────────────── #
    try:
        from scapy.config import conf as scapy_conf  # type: ignore[import-untyped]

        for route in scapy_conf.route.routes:
            # route format: (network, netmask, gateway, iface, output_ip, metric)
            net, mask, gw, iface_name, out_ip, *_ = route
            if iface_name == interface and net != 0 and gw == "0.0.0.0":
                cidr_prefix = _int_to_prefix_len(mask)
                network_str = socket.inet_ntoa(struct.pack("!I", net))
                cidr = f"{network_str}/{cidr_prefix}"
                logger.info("Subred detectada vía scapy routes: %s", cidr)
                return cidr
    except Exception:
        logger.debug("scapy route table no pudo resolver la subred.")

    # ── Fallback: assume /24 from scapy conf ─────────────────────────── #
    try:
        from scapy.config import conf as scapy_conf  # type: ignore[import-untyped]

        # If we can at least get the IP, guess /24
        from scapy.utils import get_if_addr  # type: ignore[import-untyped]

        ip = get_if_addr(interface)
        if ip and ip != "0.0.0.0":
            parts = ip.split(".")
            cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            logger.warning(
                "No se pudo determinar la máscara exacta; asumiendo %s", cidr
            )
            return cidr
    except Exception:
        pass

    raise NetworkInterfaceError(
        f"No se pudo determinar la subred para la interfaz '{interface}'. "
        "Usa el argumento --subnet <CIDR> manualmente."
    )


# ── Private Helpers ──────────────────────────────────────────────────────── #


def _parse_proc_route() -> Optional[str]:
    """Parse ``/proc/net/route`` to find the default gateway interface.

    Returns:
        Interface name, or ``None`` if not found.
    """
    with open("/proc/net/route", "r") as f:
        for line in f.readlines()[1:]:  # skip header
            fields = line.strip().split()
            if len(fields) >= 2 and fields[1] == "00000000":
                return fields[0]
    return None


def _netmask_to_cidr(ip_addr: str, netmask: str) -> str:
    """Convert an IP + netmask pair to CIDR notation.

    Args:
        ip_addr: Dotted-decimal IP (e.g., ``"192.168.1.42"``).
        netmask: Dotted-decimal netmask (e.g., ``"255.255.255.0"``).

    Returns:
        CIDR string (e.g., ``"192.168.1.0/24"``).
    """
    ip_int = struct.unpack("!I", socket.inet_aton(ip_addr))[0]
    mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
    network_int = ip_int & mask_int
    prefix_len = bin(mask_int).count("1")
    network_str = socket.inet_ntoa(struct.pack("!I", network_int))
    return f"{network_str}/{prefix_len}"


def _int_to_prefix_len(mask_int: int) -> int:
    """Convert an integer netmask to a prefix length.

    Args:
        mask_int: Integer representation of the netmask.

    Returns:
        Prefix length (e.g., 24).
    """
    return bin(mask_int).count("1")
