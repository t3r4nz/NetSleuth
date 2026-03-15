"""
NetSleuth — mDNS / SSDP / Port Heuristic Analyzer (Layer 7).

Passive analyzer that extracts **hostnames** and **service labels**
from multicast discovery protocols:

- **mDNS** (UDP 5353): Reads DNS query/response records ending in
  ``.local`` to extract device hostnames (e.g., ``iPhone-de-Juan``).

- **SSDP** (UDP 1900): Parses ``NOTIFY`` and ``M-SEARCH`` responses
  to extract ``Server:`` and ``LOCATION:`` headers, revealing device
  models (e.g., ``Roku/9.4``, ``Samsung TV``).

- **Port heuristics**: Specific well-known ports are used to tag
  services:
    - UDP 19132 → ``Minecraft Bedrock Server``
    - TCP 62078 → ``Apple Device (Sync)``
    - TCP 548   → ``AFP (Apple File Sharing)``
    - TCP 9100  → ``Printer (RAW)``
    - UDP 5353  → ``mDNS``
    - UDP 1900  → ``SSDP/UPnP``

All extraction is wrapped in try/except to handle malformed packets
gracefully without crashing the sniffer thread.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from src.core.interfaces import IPacketAnalyzer
from src.core.models import (
    DeviceFingerprint,
    DeviceType,
    ProtocolType,
    RawPacket,
)

logger = logging.getLogger(__name__)

# ── Port → Service mapping ───────────────────────────────────────────────── #
_PORT_SERVICES: dict[int, tuple[str, str | None]] = {
    # port: (service_label, hostname_override or None)
    19132: ("Minecraft Bedrock", "Minecraft Bedrock Server"),
    62078: ("Apple Sync", "Apple Device (Sync)"),
    548:   ("AFP", None),
    9100:  ("Printer RAW", None),
    3689:  ("iTunes/DAAP", None),
    7000:  ("AirPlay", None),
    7100:  ("AirPlay Mirror", None),
    8008:  ("Chromecast", None),
    8009:  ("Chromecast Control", None),
    5228:  ("Google Play", None),
}

# ── SSDP header extraction ────────────────────────────────────────────────── #
_RE_SERVER = re.compile(r"SERVER:\s*(.+)", re.IGNORECASE)
_RE_LOCATION = re.compile(r"LOCATION:\s*(http\S+)", re.IGNORECASE)
_RE_ST = re.compile(r"ST:\s*(.+)", re.IGNORECASE)
_RE_NT = re.compile(r"NT:\s*(.+)", re.IGNORECASE)


class MdnsSsdpAnalyzer(IPacketAnalyzer):
    """Passive analyzer for mDNS, SSDP, and well-known port heuristics.

    Integrates with the existing Factory/Observer pattern via the
    ``MDNS_SSDP`` protocol type.
    """

    @property
    def supported_protocol(self) -> ProtocolType:
        return ProtocolType.MDNS_SSDP

    def analyze(self, packet: RawPacket) -> Optional[DeviceFingerprint]:
        """Analyze an mDNS/SSDP/port packet for hostname and services.

        Returns a ``DeviceFingerprint`` whose ``details`` field encodes
        extracted hostname and services as metadata that the
        ``AnalysisEngine`` can propagate to the ``NetworkDevice``.
        """
        if packet.protocol != ProtocolType.MDNS_SSDP:
            return None

        hostname: str | None = None
        services: set[str] = set()
        details_parts: list[str] = []

        try:
            # ── mDNS extraction ───────────────────────────────── #
            mdns_name = packet.metadata.get("mdns_hostname")
            if mdns_name and isinstance(mdns_name, str):
                hostname = mdns_name
                services.add("mDNS")
                details_parts.append(f"mDNS hostname: {hostname}")
                logger.info("mDNS hostname for %s: %s", packet.src_mac, hostname)

            # ── SSDP extraction ───────────────────────────────── #
            ssdp_server = packet.metadata.get("ssdp_server")
            if ssdp_server and isinstance(ssdp_server, str):
                services.add("SSDP/UPnP")
                details_parts.append(f"SSDP Server: {ssdp_server}")
                logger.info("SSDP server for %s: %s", packet.src_mac, ssdp_server)

            ssdp_location = packet.metadata.get("ssdp_location")
            if ssdp_location and isinstance(ssdp_location, str):
                details_parts.append(f"SSDP Location: {ssdp_location}")

            # ── Port heuristics ───────────────────────────────── #
            src_port = packet.metadata.get("src_port")
            dst_port = packet.metadata.get("dst_port")

            for port in (src_port, dst_port):
                if port and int(port) in _PORT_SERVICES:
                    svc_label, host_override = _PORT_SERVICES[int(port)]
                    services.add(svc_label)
                    if host_override and hostname is None:
                        hostname = host_override
                    details_parts.append(f"Port {port} → {svc_label}")

        except Exception:
            logger.debug("Error parsing mDNS/SSDP packet from %s", packet.src_mac)
            return None

        if not services and hostname is None:
            return None

        # Encode hostname and services into metadata-style details
        # The analysis engine will use these to update the device.
        detail_str = " | ".join(details_parts) if details_parts else ""

        # Guess device type from services
        device_type = DeviceType.UNKNOWN
        if "AirPlay" in services or "Apple Sync" in services:
            device_type = DeviceType.MOBILE
        elif "Chromecast" in services:
            device_type = DeviceType.TV
        elif "Printer RAW" in services:
            device_type = DeviceType.PRINTER
        elif "Minecraft Bedrock" in services:
            device_type = DeviceType.PC

        return DeviceFingerprint(
            os_guess=hostname or "Unknown",
            device_type=device_type,
            confidence=0.5 if hostname else 0.2,
            method="mDNS/SSDP/Port",
            details=detail_str,
        )


def extract_mdns_hostname(scapy_packet: object) -> str | None:
    """Extract a .local hostname from a DNS layer in a scapy packet.

    Args:
        scapy_packet: Raw scapy packet with potential DNSRR/DNSQR layers.

    Returns:
        Cleaned hostname string or None.
    """
    try:
        from scapy.layers.dns import DNSRR, DNSQR  # type: ignore

        names: list[str] = []

        # Check query records
        if scapy_packet.haslayer(DNSQR):
            qname = scapy_packet[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            if ".local" in qname.lower():
                names.append(qname)

        # Check answer records
        if scapy_packet.haslayer(DNSRR):
            layer = scapy_packet[DNSRR]
            while layer:
                rrname = getattr(layer, "rrname", b"")
                if isinstance(rrname, bytes):
                    rrname = rrname.decode("utf-8", errors="ignore")
                if ".local" in rrname.lower():
                    names.append(rrname)
                layer = getattr(layer, "payload", None)
                if layer and not hasattr(layer, "rrname"):
                    break

        # Clean the best name
        for name in names:
            clean = name.rstrip(".").replace(".local", "").strip()
            # Filter out service names (_tcp, _udp, _services)
            if clean and not clean.startswith("_") and "._" not in clean:
                return clean

    except Exception:
        pass
    return None


def extract_ssdp_info(raw_data: bytes) -> dict[str, str]:
    """Extract Server and Location from SSDP payload bytes.

    Args:
        raw_data: Raw UDP payload bytes.

    Returns:
        Dict with optional keys: "server", "location", "st", "nt"
    """
    result: dict[str, str] = {}
    try:
        text = raw_data.decode("utf-8", errors="ignore")
        m = _RE_SERVER.search(text)
        if m:
            result["server"] = m.group(1).strip()
        m = _RE_LOCATION.search(text)
        if m:
            result["location"] = m.group(1).strip()
        m = _RE_ST.search(text)
        if m:
            result["st"] = m.group(1).strip()
        m = _RE_NT.search(text)
        if m:
            result["nt"] = m.group(1).strip()
    except Exception:
        pass
    return result
