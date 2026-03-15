"""
NetSleuth — TCP/IP Stack Fingerprinting Analyzer.

Analyses TCP SYN packets to infer the sender's operating system based
on the characteristic default values of:

- **TTL** (Time To Live)
- **TCP Window Size**
- **TCP Options** (MSS, Window Scale, SACK Permitted, Timestamps, NOP)

These values are set by the OS kernel's TCP/IP stack and differ in
predictable ways across operating systems and versions.

References:
    - p0f v3 signature format
    - Nmap OS detection (``nmap -O``)
    - RFC 793 / 7323 / 1323
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


# ── Known TCP/IP Stack Signatures ────────────────────────────────────────── #
# Each signature is: (initial_ttl, window_size_range, os_guess, device_type)

_TCP_SIGNATURES: list[dict[str, object]] = [
    {
        "ttl": 128,
        "window_min": 8192,
        "window_max": 65535,
        "os_guess": "Windows 10/11 / Server 2016+",
        "device_type": DeviceType.PC,
        "confidence": 0.70,
    },
    {
        "ttl": 128,
        "window_min": 0,
        "window_max": 8191,
        "os_guess": "Windows 7/8 / Server 2008-2012",
        "device_type": DeviceType.PC,
        "confidence": 0.65,
    },
    {
        "ttl": 64,
        "window_min": 5000,
        "window_max": 65535,
        "os_guess": "Linux 4.x-6.x",
        "device_type": DeviceType.PC,
        "confidence": 0.70,
    },
    {
        "ttl": 64,
        "window_min": 0,
        "window_max": 4999,
        "os_guess": "Linux 2.6-3.x / Embedded Linux",
        "device_type": DeviceType.IOT,
        "confidence": 0.55,
    },
    {
        "ttl": 64,
        "window_min": 65535,
        "window_max": 65535,
        "os_guess": "macOS / FreeBSD",
        "device_type": DeviceType.PC,
        "confidence": 0.70,
    },
    {
        "ttl": 255,
        "window_min": 0,
        "window_max": 65535,
        "os_guess": "Cisco IOS / Network Equipment",
        "device_type": DeviceType.ROUTER,
        "confidence": 0.65,
    },
]


class TCPAnalyzer(IPacketAnalyzer):
    """Analyzer for TCP SYN packets — passive OS fingerprinting.

    Only SYN packets (flags == 0x02) are meaningful because they carry
    the initiator's default stack values before any negotiation.
    """

    @property
    def supported_protocol(self) -> ProtocolType:
        """This analyzer handles TCP packets."""
        return ProtocolType.TCP

    def analyze(self, packet: RawPacket) -> Optional[DeviceFingerprint]:
        """Analyse a TCP SYN packet's TTL and Window Size.

        Args:
            packet: A ``RawPacket`` with ``protocol == ProtocolType.TCP``
                    and SYN-only flags.

        Returns:
            A ``DeviceFingerprint`` with OS guess and confidence, or
            ``None`` if the packet metadata is insufficient.
        """
        if packet.protocol != ProtocolType.TCP:
            return None

        ttl = packet.metadata.get("ttl")
        window_size = packet.metadata.get("window_size")

        if ttl is None or window_size is None:
            logger.debug("TCP packet from %s missing TTL/Window metadata.", packet.src_mac)
            return None

        ttl = int(ttl)
        window_size = int(window_size)

        initial_ttl = self._normalize_ttl(ttl)

        logger.debug(
            "TCP SYN from %s: TTL=%d (initial≈%d) Window=%d",
            packet.src_mac,
            ttl,
            initial_ttl,
            window_size,
        )

        return self._match_signature(initial_ttl, window_size, packet.src_mac)

    # ── Helpers ───────────────────────────────────────────────────────── #

    @staticmethod
    def _normalize_ttl(observed_ttl: int) -> int:
        """Estimate the initial TTL from the observed (decremented) value.

        Common initial TTLs are 32, 64, 128, and 255.  We round *up*
        to the nearest known initial value.

        Args:
            observed_ttl: The TTL value seen in the packet after
                          traversing routers.

        Returns:
            The estimated initial TTL.
        """
        for initial in (32, 64, 128, 255):
            if observed_ttl <= initial:
                return initial
        return 255

    @staticmethod
    def _match_signature(
        initial_ttl: int, window_size: int, mac: str
    ) -> DeviceFingerprint:
        """Match observed TTL + Window Size against the signature database.

        Args:
            initial_ttl: Estimated initial TTL.
            window_size: TCP window size from the SYN packet.
            mac: Source MAC address (for logging).

        Returns:
            Best-matching ``DeviceFingerprint``.
        """
        for sig in _TCP_SIGNATURES:
            sig_ttl = sig["ttl"]
            w_min = sig["window_min"]
            w_max = sig["window_max"]

            if initial_ttl == sig_ttl and w_min <= window_size <= w_max:  # type: ignore[operator]
                os_guess: str = sig["os_guess"]  # type: ignore[assignment]
                device_type: DeviceType = sig["device_type"]  # type: ignore[assignment]
                confidence: float = sig["confidence"]  # type: ignore[assignment]

                logger.info(
                    "TCP match for %s: TTL=%d Win=%d → %s (%.0f%%)",
                    mac,
                    initial_ttl,
                    window_size,
                    os_guess,
                    confidence * 100,
                )
                return DeviceFingerprint(
                    os_guess=os_guess,
                    device_type=device_type,
                    confidence=confidence,
                    method="TCP/IP Fingerprint",
                    details=f"TTL={initial_ttl} WindowSize={window_size}",
                )

        return DeviceFingerprint(
            os_guess="Unknown",
            device_type=DeviceType.UNKNOWN,
            confidence=0.1,
            method="TCP/IP Fingerprint (no match)",
            details=f"TTL={initial_ttl} WindowSize={window_size}",
        )
