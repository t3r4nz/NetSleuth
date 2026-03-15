"""
NetSleuth — In-Memory Device Store.

Thread-safe device registry that stores discovered ``NetworkDevice``
objects keyed by their MAC address.

This implementation is suitable for a single-session CLI tool.  For
persistence across runs, swap this adapter for a SQLite-backed or
JSON-file-backed implementation of ``IDeviceStore``.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional, Sequence

from src.core.interfaces import IDeviceStore
from src.core.models import NetworkDevice

logger = logging.getLogger(__name__)


class InMemoryDeviceStore(IDeviceStore):
    """Thread-safe, in-memory implementation of ``IDeviceStore``.

    All public methods acquire ``_lock`` before accessing the internal
    dictionary, making it safe to call from both the sniffer thread
    and the main thread simultaneously.
    """

    def __init__(self) -> None:
        self._devices: dict[str, NetworkDevice] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _is_valid_ip(ip: str | None) -> bool:
        """Return True if *ip* is a usable unicast address."""
        if not ip or ip in {"0.0.0.0", "255.255.255.255", ""}:
            return False
        if ip.startswith("169.254."):
            return False
        return True

    def upsert(self, device: NetworkDevice) -> None:
        """Insert a new device or **smart-merge** with an existing one.

        Merge rules:
        - Never overwrite a valid IP with a null/invalid IP.
        - Keep the higher-confidence fingerprint.
        - Preserve the earliest ``first_seen`` timestamp.
        - Always update ``last_seen`` to the latest value.

        Args:
            device: The device to upsert.
        """
        mac_key = device.mac_address.upper()
        with self._lock:
            existing = self._devices.get(mac_key)

            if existing is None:
                # Brand new device — insert directly.
                self._devices[mac_key] = device
                logger.debug("New device %s (%s).", mac_key, device.ip_address)
                return

            # ── Smart merge ──────────────────────────────────── #
            merged = device

            # Preserve valid IP if incoming one is bad.
            if self._is_valid_ip(existing.ip_address) and not self._is_valid_ip(device.ip_address):
                merged = NetworkDevice(
                    mac_address=device.mac_address,
                    ip_address=existing.ip_address,
                    vendor=device.vendor or existing.vendor,
                    fingerprint=device.fingerprint if (device.fingerprint and device.fingerprint.confidence >= (existing.fingerprint.confidence if existing.fingerprint else 0)) else existing.fingerprint,
                    first_seen=min(existing.first_seen, device.first_seen),
                    last_seen=max(existing.last_seen, device.last_seen),
                )
            else:
                merged = NetworkDevice(
                    mac_address=device.mac_address,
                    ip_address=device.ip_address if self._is_valid_ip(device.ip_address) else existing.ip_address,
                    vendor=device.vendor or existing.vendor,
                    fingerprint=device.fingerprint if (device.fingerprint and device.fingerprint.confidence >= (existing.fingerprint.confidence if existing.fingerprint else 0)) else existing.fingerprint,
                    first_seen=min(existing.first_seen, device.first_seen),
                    last_seen=max(existing.last_seen, device.last_seen),
                )

            self._devices[mac_key] = merged
            logger.debug("Merged device %s (%s).", mac_key, merged.ip_address)

    def get_all(self) -> Sequence[NetworkDevice]:
        """Return a snapshot of all discovered devices.

        The returned list is a *copy*, so callers can iterate safely
        without holding the lock.

        Returns:
            List of ``NetworkDevice`` objects, sorted by ``first_seen``.
        """
        with self._lock:
            return sorted(
                self._devices.values(),
                key=lambda d: d.first_seen,
            )

    def find_by_mac(self, mac_address: str) -> Optional[NetworkDevice]:
        """Find a device by its MAC address.

        Args:
            mac_address: Colon-separated MAC (case-insensitive).

        Returns:
            The ``NetworkDevice`` if found, otherwise ``None``.
        """
        mac_key = mac_address.upper()
        with self._lock:
            return self._devices.get(mac_key)

    @property
    def count(self) -> int:
        """Number of unique devices currently stored."""
        with self._lock:
            return len(self._devices)

    def clear(self) -> None:
        """Remove all devices from the store."""
        with self._lock:
            self._devices.clear()
            logger.debug("Device store cleared.")
