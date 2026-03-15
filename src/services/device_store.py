"""
NetSleuth — In-Memory Device Store.

Thread-safe device registry that stores discovered ``NetworkDevice``
objects keyed by their MAC address.

Smart merge rules on ``upsert()``:
- Never overwrite a valid IP with a null/invalid one.
- Preserve the hostname that was set first (unless a new one arrives).
- Union (merge) services sets.
- Keep all fingerprints accumulated over time.
- Preserve earliest ``first_seen``, always update ``last_seen``.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Optional, Sequence

from src.core.interfaces import IDeviceStore
from src.core.models import NetworkDevice

logger = logging.getLogger(__name__)


class InMemoryDeviceStore(IDeviceStore):
    """Thread-safe, in-memory implementation of ``IDeviceStore``."""

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
        - Keep existing hostname unless a non-None hostname arrives.
        - Union services sets.
        - Accumulate all fingerprints.
        - Preserve ``first_seen``, always update ``last_seen``.

        Args:
            device: The device to upsert.
        """
        mac_key = device.mac_address.upper()
        with self._lock:
            existing = self._devices.get(mac_key)

            if existing is None:
                self._devices[mac_key] = device
                logger.debug("New device %s (%s).", mac_key, device.ip_address)
                return

            # ── Smart merge ──────────────────────────────────── #

            # IP: never overwrite valid with invalid
            if self._is_valid_ip(device.ip_address):
                existing.ip_address = device.ip_address
            # else: keep existing IP

            # Vendor: prefer non-None
            if device.vendor:
                existing.vendor = device.vendor

            # Hostname: overwrite None with real value; overwrite old with new
            if device.hostname:
                existing.hostname = device.hostname

            # Services: union
            if device.services:
                existing.services |= device.services

            # Fingerprints: append new ones
            for fp in device.fingerprints:
                existing.fingerprints.append(fp)

            # Timestamps
            existing.first_seen = min(existing.first_seen, device.first_seen)
            existing.last_seen = max(existing.last_seen, device.last_seen, datetime.utcnow())

            self._devices[mac_key] = existing
            logger.debug("Merged device %s (%s).", mac_key, existing.ip_address)

    def get_all(self) -> Sequence[NetworkDevice]:
        """Return a snapshot of all discovered devices sorted by first_seen."""
        with self._lock:
            return sorted(
                self._devices.values(),
                key=lambda d: d.first_seen,
            )

    def find_by_mac(self, mac_address: str) -> Optional[NetworkDevice]:
        """Find a device by its MAC address."""
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
