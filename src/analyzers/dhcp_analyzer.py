"""
NetSleuth — DHCP Packet Analyzer.

Analyses DHCP (Dynamic Host Configuration Protocol) packets, focusing
on **Option 55** (Parameter Request List), which is one of the most
reliable passive OS fingerprinting signals.

Each operating system requests a characteristic set of DHCP options in
a specific order.  By comparing the observed list against a database of
known signatures, we can identify the OS family with moderate-to-high
confidence.

References:
    - RFC 2132 (DHCP Options)
    - Fingerbank (https://fingerbank.org)
    - p0f DHCP signatures
"""

from __future__ import annotations

import logging
from typing import Optional, Sequence

from src.core.interfaces import IPacketAnalyzer
from src.core.models import (
    DeviceFingerprint,
    DeviceType,
    ProtocolType,
    RawPacket,
)

logger = logging.getLogger(__name__)


# ── Known DHCP Option 55 Signatures ──────────────────────────────────────── #
# Keys are tuples of option numbers (the order matters).
# Values are (os_guess, device_type, confidence).

_DHCP_SIGNATURES: dict[tuple[int, ...], tuple[str, DeviceType, float]] = {
    # Windows 10/11
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252): (
        "Windows 10/11",
        DeviceType.PC,
        0.85,
    ),
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249): (
        "Windows 10",
        DeviceType.PC,
        0.80,
    ),
    # Windows 7/8
    (1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43, 252): (
        "Windows 7/8",
        DeviceType.PC,
        0.80,
    ),
    # macOS
    (1, 121, 3, 6, 15, 119, 252, 95, 44, 46): (
        "macOS 12+ (Monterey/Ventura)",
        DeviceType.PC,
        0.85,
    ),
    (1, 3, 6, 15, 119, 95, 252, 44, 46, 47): (
        "macOS (older)",
        DeviceType.PC,
        0.75,
    ),
    # Linux (NetworkManager / systemd-networkd)
    (1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42): (
        "Linux (NetworkManager)",
        DeviceType.PC,
        0.80,
    ),
    (1, 3, 6, 12, 15, 26, 28, 42): (
        "Linux (dhclient)",
        DeviceType.PC,
        0.75,
    ),
    # Android
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 43): (
        "Android 10+",
        DeviceType.MOBILE,
        0.80,
    ),
    (1, 33, 3, 6, 15, 28, 51, 58, 59): (
        "Android (older)",
        DeviceType.MOBILE,
        0.70,
    ),
    # iOS / iPadOS
    (1, 121, 3, 6, 15, 119, 252): (
        "iOS / iPadOS",
        DeviceType.MOBILE,
        0.80,
    ),
    # Smart TVs
    (1, 3, 6, 12, 15, 28, 42): (
        "Smart TV / Media Player",
        DeviceType.TV,
        0.65,
    ),
    # Printers
    (1, 3, 6, 15, 44, 47): (
        "Network Printer",
        DeviceType.PRINTER,
        0.70,
    ),
}


class DHCPAnalyzer(IPacketAnalyzer):
    """Analyzer for DHCP packets — Option 55 fingerprinting.

    Compares the DHCP Parameter Request List against a built-in
    signature database to guess the client's OS and device type.
    """

    @property
    def supported_protocol(self) -> ProtocolType:
        """This analyzer handles DHCP packets."""
        return ProtocolType.DHCP

    def analyze(self, packet: RawPacket) -> Optional[DeviceFingerprint]:
        """Analyse a DHCP packet for OS fingerprinting via Option 55.

        Args:
            packet: A ``RawPacket`` with ``protocol == ProtocolType.DHCP``.

        Returns:
            A ``DeviceFingerprint`` if a signature match is found, or
            a low-confidence generic result.  Returns ``None`` if the
            packet has no Option 55 data.
        """
        if packet.protocol != ProtocolType.DHCP:
            return None

        option_55 = self._extract_option_55(packet)
        if option_55 is None:
            logger.debug("DHCP packet from %s has no Option 55.", packet.src_mac)
            return None

        logger.debug(
            "DHCP Option 55 from %s: %s",
            packet.src_mac,
            list(option_55),
        )

        return self._match_signature(option_55, packet.src_mac)

    # ── Helpers ───────────────────────────────────────────────────────── #

    @staticmethod
    def _extract_option_55(packet: RawPacket) -> Optional[tuple[int, ...]]:
        """Extract DHCP Option 55 (Parameter Request List) from metadata.

        Args:
            packet: Domain packet whose ``metadata`` may contain
                    ``"param_req_list"`` or integer-keyed option 55.

        Returns:
            A tuple of option numbers, or ``None`` if absent.
        """
        raw = packet.metadata.get("param_req_list") or packet.metadata.get("55")
        if raw is None:
            return None

        if isinstance(raw, (list, tuple)):
            return tuple(int(x) for x in raw)
        if isinstance(raw, bytes):
            return tuple(raw)
        return None

    @staticmethod
    def _match_signature(
        option_55: tuple[int, ...], mac: str
    ) -> DeviceFingerprint:
        """Compare an Option 55 list against the known signature database.

        Uses *exact match first*, then falls back to a *subset match*
        with reduced confidence.

        Args:
            option_55: Observed option numbers (order matters).
            mac: Source MAC (for logging).

        Returns:
            A ``DeviceFingerprint`` with the best match or a generic
            "Unknown" result.
        """
        # Exact match
        if option_55 in _DHCP_SIGNATURES:
            os_guess, device_type, confidence = _DHCP_SIGNATURES[option_55]
            logger.info(
                "DHCP exact match for %s → %s (%.0f%%)", mac, os_guess, confidence * 100
            )
            return DeviceFingerprint(
                os_guess=os_guess,
                device_type=device_type,
                confidence=confidence,
                method="DHCP Option 55 (exact)",
                details=f"Option 55: {list(option_55)}",
            )

        # Subset / best overlap match
        best_match: Optional[tuple[str, DeviceType, float]] = None
        best_overlap = 0

        option_set = set(option_55)
        for sig_key, sig_val in _DHCP_SIGNATURES.items():
            overlap = len(option_set & set(sig_key))
            if overlap > best_overlap:
                best_overlap = overlap
                best_match = sig_val

        if best_match is not None and best_overlap >= 4:
            os_guess, device_type, base_confidence = best_match
            adjusted = round(base_confidence * 0.6, 2)
            logger.info(
                "DHCP partial match for %s → %s (%.0f%%, overlap=%d)",
                mac,
                os_guess,
                adjusted * 100,
                best_overlap,
            )
            return DeviceFingerprint(
                os_guess=os_guess,
                device_type=device_type,
                confidence=adjusted,
                method="DHCP Option 55 (partial)",
                details=f"Option 55: {list(option_55)} | overlap={best_overlap}",
            )

        return DeviceFingerprint(
            os_guess="Unknown",
            device_type=DeviceType.UNKNOWN,
            confidence=0.1,
            method="DHCP Option 55 (no match)",
            details=f"Option 55: {list(option_55)}",
        )
