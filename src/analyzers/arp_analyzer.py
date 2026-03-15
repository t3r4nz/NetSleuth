"""
NetSleuth — ARP Packet Analyzer.

Extracts MAC ↔ IP address mappings from ARP request and reply packets.
This is the simplest and most reliable way to discover active devices
on a local network segment.

Filters out poisoned/useless packets where src_ip is ``0.0.0.0`` or
a link-local address (``169.254.x.x``), which would otherwise
contaminate the device table with invalid IPs.
"""

from __future__ import annotations

import logging
from typing import Optional

from src.core.interfaces import IPacketAnalyzer
from src.core.models import (
    DeviceFingerprint,
    DeviceType,
    ProtocolType,
    RawPacket,
)

logger = logging.getLogger(__name__)

# IPs that should NEVER appear as valid device addresses.
_INVALID_IPS = {"0.0.0.0", "255.255.255.255", ""}


def _is_valid_ip(ip: Optional[str]) -> bool:
    """Return True only if *ip* is a usable unicast address.

    Rejects:
    - ``None`` / empty string
    - ``0.0.0.0`` (no IP assigned yet)
    - ``255.255.255.255`` (broadcast)
    - ``169.254.x.x`` (APIPA / link-local, RFC 3927)
    """
    if not ip or ip in _INVALID_IPS:
        return False
    if ip.startswith("169.254."):
        return False
    return True


class ARPAnalyzer(IPacketAnalyzer):
    """Analyzer for ARP (Address Resolution Protocol) packets.

    ARP alone cannot determine the operating system, but it confirms
    device presence with high confidence and provides MAC ↔ IP mapping.

    Packets with invalid source IPs (``0.0.0.0``, ``169.254.x.x``) are
    silently discarded to prevent table poisoning.
    """

    @property
    def supported_protocol(self) -> ProtocolType:
        """This analyzer handles ARP packets."""
        return ProtocolType.ARP

    def analyze(self, packet: RawPacket) -> Optional[DeviceFingerprint]:
        """Analyse an ARP packet to confirm device presence.

        Args:
            packet: A ``RawPacket`` with ``protocol == ProtocolType.ARP``.

        Returns:
            A ``DeviceFingerprint`` with basic presence info, or ``None``
            if the packet contains an invalid source IP.
        """
        if packet.protocol != ProtocolType.ARP:
            return None

        # ── Guard: reject packets with poisoned IPs ──────────────── #
        if not _is_valid_ip(packet.src_ip):
            logger.debug(
                "ARP DROPPED: invalid src_ip=%s from MAC=%s",
                packet.src_ip,
                packet.src_mac,
            )
            return None

        op_code = packet.metadata.get("op", 0)
        op_name = "reply" if op_code == 2 else "request"

        logger.debug(
            "ARP %s: %s (%s) → %s",
            op_name,
            packet.src_mac,
            packet.src_ip or "?",
            packet.dst_ip or "?",
        )

        return DeviceFingerprint(
            os_guess="Unknown (ARP only)",
            device_type=DeviceType.UNKNOWN,
            confidence=0.3,
            method="ARP",
            details=(
                f"ARP {op_name} from {packet.src_mac} "
                f"({packet.src_ip}) → {packet.dst_ip or 'broadcast'}"
            ),
        )
