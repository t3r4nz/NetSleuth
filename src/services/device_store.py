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

    def upsert(self, device: NetworkDevice) -> None:
        """Insert a new device or replace an existing one (keyed by MAC).

        Args:
            device: The device to upsert.
        """
        mac_key = device.mac_address.upper()
        with self._lock:
            self._devices[mac_key] = device
            logger.debug("Upserted device %s.", mac_key)

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
