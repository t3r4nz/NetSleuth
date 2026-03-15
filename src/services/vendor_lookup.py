"""
NetSleuth — MAC Vendor Lookup Service.

Resolves the manufacturer/vendor of a network device from its MAC
address OUI (Organizationally Unique Identifier) using the
`macvendors.com <https://macvendors.com>`_ public API.

Features:
    - **In-memory LRU cache** to avoid redundant HTTP calls.
    - **Rate-limit aware**: respects a configurable delay between requests.
    - **Graceful degradation**: returns ``None`` on failure instead of
      crashing the pipeline.
"""

from __future__ import annotations

import logging
import time
from functools import lru_cache
from typing import Optional

from src.core.exceptions import VendorLookupError
from src.core.interfaces import IVendorLookup

logger = logging.getLogger(__name__)

# Default API endpoint (no key required for basic lookups).
_DEFAULT_API_URL = "https://api.macvendors.com/{mac}"

# Minimum delay between consecutive API calls (seconds).
_MIN_REQUEST_INTERVAL: float = 1.0


class MacVendorLookup(IVendorLookup):
    """Concrete vendor lookup using the macvendors.com REST API.

    Args:
        api_url_template: URL template with a ``{mac}`` placeholder.
        request_interval: Minimum seconds between HTTP requests.

    Example::

        lookup = MacVendorLookup()
        vendor = lookup.lookup("AA:BB:CC:DD:EE:FF")
        # → "Apple, Inc."
    """

    def __init__(
        self,
        api_url_template: str = _DEFAULT_API_URL,
        request_interval: float = _MIN_REQUEST_INTERVAL,
    ) -> None:
        self._api_url_template = api_url_template
        self._request_interval = request_interval
        self._last_request_time: float = 0.0

    def lookup(self, mac_address: str) -> Optional[str]:
        """Look up the vendor for a MAC address.

        Results are cached via ``@lru_cache`` on the normalised OUI
        prefix (first 3 octets).

        Args:
            mac_address: Colon-separated MAC address.

        Returns:
            Vendor name string, or ``None`` if not found or on error.
        """
        oui = self._normalize_oui(mac_address)
        if oui is None:
            return None
        return self._cached_lookup(oui)

    # ── Internal ──────────────────────────────────────────────────────── #

    @staticmethod
    def _normalize_oui(mac_address: str) -> Optional[str]:
        """Extract and normalise the OUI prefix from a MAC address.

        Args:
            mac_address: Full MAC address (``"AA:BB:CC:DD:EE:FF"``).

        Returns:
            The first 3 octets joined by colons (``"AA:BB:CC"``), or
            ``None`` if the format is invalid.
        """
        parts = mac_address.upper().replace("-", ":").split(":")
        if len(parts) < 3:
            logger.warning("Invalid MAC format: %s", mac_address)
            return None
        return ":".join(parts[:3])

    @lru_cache(maxsize=512)
    def _cached_lookup(self, oui: str) -> Optional[str]:
        """HTTP lookup with caching and rate limiting.

        Args:
            oui: Normalised OUI prefix (e.g., ``"AA:BB:CC"``).

        Returns:
            Vendor name or ``None``.
        """
        self._rate_limit()
        url = self._api_url_template.format(mac=oui)
        try:
            import httpx  # Late import — optional dependency

            response = httpx.get(url, timeout=5.0)
            if response.status_code == 200:
                vendor = response.text.strip()
                logger.debug("Vendor for %s: %s", oui, vendor)
                return vendor
            if response.status_code == 404:
                logger.debug("No vendor found for OUI %s.", oui)
                return None
            logger.warning(
                "Vendor API returned status %d for %s.", response.status_code, oui
            )
            return None
        except ImportError:
            logger.warning("httpx is not installed — vendor lookup disabled.")
            return None
        except Exception as exc:
            logger.warning("Vendor lookup HTTP error for %s: %s", oui, exc)
            return None

    def _rate_limit(self) -> None:
        """Sleep if needed to enforce the minimum request interval."""
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self._request_interval:
            time.sleep(self._request_interval - elapsed)
        self._last_request_time = time.monotonic()
