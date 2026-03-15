"""
NetSleuth — CLI Output Formatters.

Provides pluggable formatters that transform a sequence of
``NetworkDevice`` objects into human-readable output for the terminal.

Two built-in formatters:
    - **TableFormatter** — coloured ASCII table (default, uses basic ANSI).
    - **JSONFormatter** — machine-readable JSON output.
"""

from __future__ import annotations

import json
import sys
from abc import ABC, abstractmethod
from io import StringIO
from typing import IO, Sequence

from src.core.models import NetworkDevice


class IOutputFormatter(ABC):
    """Abstract formatter that renders a device list to a text stream."""

    @abstractmethod
    def format(
        self,
        devices: Sequence[NetworkDevice],
        stream: IO[str] | None = None,
    ) -> str:
        """Render devices as a formatted string and optionally write to *stream*.

        Args:
            devices: Devices to render.
            stream: Optional writable text stream (defaults to stdout).

        Returns:
            The formatted output as a string.
        """
        ...


# ── ANSI colour helpers ──────────────────────────────────────────────────── #

_BOLD = "\033[1m"
_CYAN = "\033[96m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_MAGENTA = "\033[95m"
_RESET = "\033[0m"


class TableFormatter(IOutputFormatter):
    """Renders devices as a coloured ASCII table.

    Example output::

        ╔═══════════════════╦═════════════════╦════════════════════╦═══════════╦════════════╗
        ║ MAC Address       ║ IP Address      ║ Vendor             ║ OS Guess  ║ Type       ║
        ╠═══════════════════╬═════════════════╬════════════════════╬═══════════╬════════════╣
        ║ AA:BB:CC:DD:EE:FF ║ 192.168.1.10    ║ Apple, Inc.        ║ macOS 12+ ║ PC         ║
        ╚═══════════════════╩═════════════════╩════════════════════╩═══════════╩════════════╝
    """

    # Column widths
    _COL_MAC = 19
    _COL_IP = 17
    _COL_VENDOR = 22
    _COL_OS = 26
    _COL_TYPE = 14
    _COL_CONFIDENCE = 6

    def format(
        self,
        devices: Sequence[NetworkDevice],
        stream: IO[str] | None = None,
    ) -> str:
        """Render devices as a coloured table.

        Args:
            devices: Devices to display.
            stream: Output stream (defaults to ``sys.stdout``).

        Returns:
            The table as a plain string (without ANSI codes is not
            possible here — but the return value includes them).
        """
        out = stream or sys.stdout
        buf = StringIO()

        if not devices:
            line = f"\n{_YELLOW}  ⚠  No devices discovered yet.{_RESET}\n"
            buf.write(line)
            out.write(line)
            return buf.getvalue()

        # Header
        header = (
            f"\n{_BOLD}{_CYAN}"
            f"{'MAC Address':<{self._COL_MAC}} "
            f"{'IP Address':<{self._COL_IP}} "
            f"{'Vendor':<{self._COL_VENDOR}} "
            f"{'OS Guess':<{self._COL_OS}} "
            f"{'Type':<{self._COL_TYPE}} "
            f"{'Conf.':<{self._COL_CONFIDENCE}}"
            f"{_RESET}\n"
        )
        separator = f"{_CYAN}{'─' * 110}{_RESET}\n"

        buf.write(separator)
        buf.write(header)
        buf.write(separator)

        for device in devices:
            os_guess = device.best_os_guess
            dev_type = device.best_device_type.value
            confidence = ""
            if device.fingerprints:
                best = max(device.fingerprints, key=lambda f: f.confidence)
                confidence = f"{best.confidence:.0%}"

            row = (
                f"{_GREEN}{device.mac_address:<{self._COL_MAC}}{_RESET} "
                f"{device.ip_address or 'N/A':<{self._COL_IP}} "
                f"{_MAGENTA}{(device.vendor or 'Unknown'):<{self._COL_VENDOR}}{_RESET} "
                f"{_YELLOW}{os_guess:<{self._COL_OS}}{_RESET} "
                f"{dev_type:<{self._COL_TYPE}} "
                f"{confidence:<{self._COL_CONFIDENCE}}\n"
            )
            buf.write(row)

        buf.write(separator)
        buf.write(f"  {_BOLD}Total devices: {len(devices)}{_RESET}\n\n")

        out.write(buf.getvalue())
        return buf.getvalue()


class JSONFormatter(IOutputFormatter):
    """Renders devices as pretty-printed JSON."""

    def format(
        self,
        devices: Sequence[NetworkDevice],
        stream: IO[str] | None = None,
    ) -> str:
        """Render devices as a JSON array.

        Args:
            devices: Devices to serialize.
            stream: Output stream (defaults to ``sys.stdout``).

        Returns:
            JSON string.
        """
        out = stream or sys.stdout
        data = [
            {
                "mac_address": d.mac_address,
                "ip_address": d.ip_address,
                "vendor": d.vendor,
                "os_guess": d.best_os_guess,
                "device_type": d.best_device_type.value,
                "fingerprints": [
                    {
                        "os_guess": fp.os_guess,
                        "device_type": fp.device_type.value,
                        "confidence": fp.confidence,
                        "method": fp.method,
                        "details": fp.details,
                    }
                    for fp in d.fingerprints
                ],
                "first_seen": d.first_seen.isoformat(),
                "last_seen": d.last_seen.isoformat(),
            }
            for d in devices
        ]
        text = json.dumps(data, indent=2, ensure_ascii=False)
        out.write(text + "\n")
        return text
