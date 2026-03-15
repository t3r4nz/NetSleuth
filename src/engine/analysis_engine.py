"""
NetSleuth — Analysis Engine.

Orchestrates the analysis pipeline: receives ``RawPacket`` events from
the sniffer (via the Observer pattern), dispatches each packet to the
appropriate ``IPacketAnalyzer`` (resolved through the Factory), and
upserts discovered devices into the ``IDeviceStore``.

This class implements ``IPacketListener`` so it can be subscribed
directly to the ``PacketCapture`` subject.
"""

from __future__ import annotations

import logging
from typing import Optional

from src.core.analyzer_factory import AnalyzerFactory
from src.core.exceptions import AnalysisError
from src.core.interfaces import IDeviceStore, IPacketListener, IVendorLookup
from src.core.models import (
    DeviceFingerprint,
    NetworkDevice,
    RawPacket,
)

logger = logging.getLogger(__name__)


class AnalysisEngine(IPacketListener):
    """Core analysis orchestrator — consumes packets, produces devices.

    Responsibilities:
        1. Receive a ``RawPacket`` via ``on_packet()``.
        2. Use ``AnalyzerFactory`` to obtain the right analyzer.
        3. Run the analysis and collect a ``DeviceFingerprint``.
        4. Optionally resolve the MAC vendor via ``IVendorLookup``.
        5. Upsert the result into ``IDeviceStore``.

    Args:
        factory: Pre-configured analyzer factory.
        device_store: Where discovered devices are stored.
        vendor_lookup: Optional vendor lookup service.
    """

    def __init__(
        self,
        factory: AnalyzerFactory,
        device_store: IDeviceStore,
        vendor_lookup: Optional[IVendorLookup] = None,
    ) -> None:
        self._factory = factory
        self._device_store = device_store
        self._vendor_lookup = vendor_lookup
        self._packets_processed: int = 0
        self._fingerprints_found: int = 0

    # ── IPacketListener ───────────────────────────────────────────────── #

    def on_packet(self, packet: RawPacket) -> None:
        """Handle an incoming packet from the sniffer.

        This method is called by the ``PacketSubject`` (sniffer) each
        time a relevant packet is captured.

        Args:
            packet: Domain-level raw packet.
        """
        self._packets_processed += 1
        try:
            self._process_packet(packet)
        except AnalysisError as exc:
            logger.error("Analysis error: %s", exc.message)
        except Exception:
            logger.exception("Unexpected error while analysing packet.")

    # ── Internal pipeline ─────────────────────────────────────────────── #

    def _process_packet(self, packet: RawPacket) -> None:
        """Run the full analysis pipeline for a single packet.

        Steps:
            1. Resolve the correct analyzer from the factory.
            2. Run ``analyzer.analyze(packet)``.
            3. If a fingerprint is produced, upsert the device.

        Args:
            packet: The packet to process.

        Raises:
            AnalysisError: If the analyzer itself raises.
        """
        analyzer = self._factory.create(packet.protocol)
        if analyzer is None:
            logger.debug(
                "No analyzer for protocol %s — skipping packet.", packet.protocol.name
            )
            return

        try:
            fingerprint: Optional[DeviceFingerprint] = analyzer.analyze(packet)
        except Exception as exc:
            raise AnalysisError(
                analyzer_name=type(analyzer).__name__, detail=str(exc)
            ) from exc

        if fingerprint is None:
            return

        self._fingerprints_found += 1
        self._upsert_device(packet, fingerprint)

    def _upsert_device(
        self, packet: RawPacket, fingerprint: DeviceFingerprint
    ) -> None:
        """Create or update a ``NetworkDevice`` with a new fingerprint.

        If a device with the same MAC already exists in the store, the
        fingerprint is appended and timestamps are refreshed.  Otherwise
        a new device is created.

        Args:
            packet: Source packet (provides MAC/IP).
            fingerprint: The derived fingerprint.
        """
        mac = packet.src_mac.upper()
        existing = self._device_store.find_by_mac(mac)

        if existing is not None:
            existing.add_fingerprint(fingerprint)
            if packet.src_ip:
                existing.ip_address = packet.src_ip
            self._device_store.upsert(existing)
            logger.info(
                "Updated device %s (%s) — %s confidence=%.2f",
                mac,
                existing.vendor or "Unknown vendor",
                fingerprint.os_guess,
                fingerprint.confidence,
            )
        else:
            vendor = self._resolve_vendor(mac)
            device = NetworkDevice(
                mac_address=mac,
                ip_address=packet.src_ip,
                vendor=vendor,
                fingerprints=[fingerprint],
            )
            self._device_store.upsert(device)
            logger.info(
                "New device discovered: %s (%s) — %s confidence=%.2f",
                mac,
                vendor or "Unknown vendor",
                fingerprint.os_guess,
                fingerprint.confidence,
            )

    def _resolve_vendor(self, mac: str) -> Optional[str]:
        """Resolve the vendor for a MAC address, swallowing errors.

        Args:
            mac: Colon-separated MAC address.

        Returns:
            Vendor name or ``None`` on failure.
        """
        if self._vendor_lookup is None:
            return None
        try:
            return self._vendor_lookup.lookup(mac)
        except Exception:
            logger.warning("Vendor lookup failed for %s.", mac)
            return None

    # ── Metrics ───────────────────────────────────────────────────────── #

    @property
    def packets_processed(self) -> int:
        """Total number of packets that passed through the engine."""
        return self._packets_processed

    @property
    def fingerprints_found(self) -> int:
        """Total number of successful fingerprint extractions."""
        return self._fingerprints_found
