"""
NetSleuth — DHCP Packet Analyzer.

Analyses DHCP (Dynamic Host Configuration Protocol) packets, focusing
on **Option 55** (Parameter Request List), which is one of the most
reliable passive OS fingerprinting signals.

Includes a **Randomized MAC Heuristic**: modern mobile devices
(Android 10+, iOS 14+) use locally-administered MAC addresses to
prevent tracking.  If the second hex character of the MAC is 2, 6,
A, or E, the vendor is overridden with "Randomized MAC (Mobile/IoT)"
and the DHCP fingerprint is trusted over the OUI vendor lookup.

References:
    - RFC 2132 (DHCP Options)
    - Fingerbank (https://fingerbank.org)
    - IEEE 802 locally-administered bit
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
    # ── Windows 10 / 11 ──────────────────────────────────────────────── #
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
    (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121): (
        "Windows 11",
        DeviceType.PC,
        0.80,
    ),
    # ── Windows 7 / 8 ────────────────────────────────────────────────── #
    (1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43, 252): (
        "Windows 7/8",
        DeviceType.PC,
        0.80,
    ),
    (1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43): (
        "Windows 8.1",
        DeviceType.PC,
        0.75,
    ),
    # ── macOS ─────────────────────────────────────────────────────────── #
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
    (1, 121, 3, 6, 15, 119, 252, 95, 44, 46, 101): (
        "macOS 14+ (Sonoma)",
        DeviceType.PC,
        0.85,
    ),
    # ── Linux ─────────────────────────────────────────────────────────── #
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
    (1, 3, 6, 12, 15, 26, 28): (
        "Linux (systemd-networkd)",
        DeviceType.PC,
        0.70,
    ),
    # ── Android ───────────────────────────────────────────────────────── #
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
    (1, 3, 6, 15, 26, 28, 51, 58, 59): (
        "Android 12+",
        DeviceType.MOBILE,
        0.80,
    ),
    (1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114): (
        "Android 13+",
        DeviceType.MOBILE,
        0.85,
    ),
    # ── iOS / iPadOS ──────────────────────────────────────────────────── #
    (1, 121, 3, 6, 15, 119, 252): (
        "iOS / iPadOS",
        DeviceType.MOBILE,
        0.80,
    ),
    (1, 121, 3, 6, 15, 119, 252, 95, 44, 46): (
        "iOS 16+ / iPadOS 16+",
        DeviceType.MOBILE,
        0.85,
    ),
    (1, 3, 6, 15, 119, 252): (
        "iOS (older)",
        DeviceType.MOBILE,
        0.70,
    ),
    # ── Smart TVs / Media ─────────────────────────────────────────────── #
    (1, 3, 6, 12, 15, 28, 42): (
        "Smart TV / Media Player",
        DeviceType.TV,
        0.65,
    ),
    (1, 3, 6, 12, 15, 28, 42, 119): (
        "Smart TV (Samsung/LG)",
        DeviceType.TV,
        0.70,
    ),
    # ── Printers ──────────────────────────────────────────────────────── #
    (1, 3, 6, 15, 44, 47): (
        "Network Printer",
        DeviceType.PRINTER,
        0.70,
    ),
    # ── IoT / Embedded ────────────────────────────────────────────────── #
    (1, 3, 6, 12, 15, 28): (
        "IoT / Embedded Device",
        DeviceType.IOT,
        0.60,
    ),
    (1, 3, 6, 15): (
        "Minimal DHCP Client (IoT)",
        DeviceType.IOT,
        0.50,
    ),
}


# ── Randomized MAC Detection ─────────────────────────────────────────────── #
# IEEE 802: the second hex character of a MAC address encodes two bits:
#   bit 0 (U/L): 1 = Locally Administered (randomized)
#   bit 1 (I/G): 0 = Unicast
# Characters where bit-0 is set AND bit-1 is clear: 2, 6, A, E
_RANDOMIZED_MAC_CHARS = frozenset("26aAeE")


def is_randomized_mac(mac: str) -> bool:
    """Detect if a MAC address is locally-administered (randomized).

    Modern mobile OSes (Android 10+, iOS 14+, Windows 11) randomize
    their MAC per-network.  The second hex character reveals this:
    if it's 2, 6, A, or E, the U/L bit is set → locally administered.

    Args:
        mac: Colon- or dash-separated MAC (e.g., ``"da:a1:19:xx:xx:xx"``).

    Returns:
        ``True`` if the MAC is locally-administered (likely randomized).
    """
    clean = mac.replace(":", "").replace("-", "").replace(".", "")
    if len(clean) < 2:
        return False
    return clean[1] in _RANDOMIZED_MAC_CHARS


class DHCPAnalyzer(IPacketAnalyzer):
    """Analyzer for DHCP packets — Option 55 fingerprinting.

    Compares the DHCP Parameter Request List against a built-in
    signature database to guess the client's OS and device type.

    When the source MAC is detected as randomized (locally-administered),
    the vendor field is flagged as ``"Randomized MAC (Mobile/IoT)"`` and
    the DHCP fingerprint is given priority over OUI vendor lookup.
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

        fp = self._match_signature(option_55, packet.src_mac)

        # ── Randomized MAC heuristic ─────────────────────────── #
        if is_randomized_mac(packet.src_mac):
            logger.info(
                "Randomized MAC detected: %s → overriding vendor.",
                packet.src_mac,
            )
            fp = DeviceFingerprint(
                os_guess=fp.os_guess,
                device_type=fp.device_type,
                confidence=fp.confidence,
                method=fp.method + " [Randomized MAC]",
                details=fp.details + " | vendor_override=Randomized MAC (Mobile/IoT)",
            )

        return fp

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
