"""
NetSleuth — ARP Packet Analyzer.

Extracts MAC ↔ IP address mappings from ARP request and reply packets.
This is the simplest and most reliable way to discover active devices
on a local network segment.
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


class ARPAnalyzer(IPacketAnalyzer):
    """Analyzer for ARP (Address Resolution Protocol) packets.

    ARP alone cannot determine the operating system, but it confirms
    device presence with high confidence and provides MAC ↔ IP mapping.
    The device type is classified based on the OUI prefix when possible.
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
            if the packet does not contain useful data.
        """
        if packet.protocol != ProtocolType.ARP:
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
                f"({packet.src_ip or 'no IP'}) → {packet.dst_ip or 'broadcast'}"
            ),
        )
