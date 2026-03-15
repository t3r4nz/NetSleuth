#!/usr/bin/env python3
"""
NetSleuth — Unified Entry Point (Web-Only).

Launches the FastAPI web dashboard via Uvicorn.  All network
reconnaissance (passive/active scanning) and stress testing is
controlled exclusively through the browser UI.

Usage::

    # Default (port 8443, all interfaces)
    sudo python main.py

    # Custom port + specific interface + verbose
    sudo python main.py --port 9000 -i eth0 -v

Requirements:
    - Python 3.10+
    - Root / sudo (raw sockets for scapy + stress test)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ── Ensure the project root is in sys.path ────────────────────────────────── #
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ANSI helpers (available before any heavy import)
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_BANNER = rf"""
{_CYAN}{_BOLD}
  ███╗   ██╗███████╗████████╗███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     █████╗  ██║   ██║   ██║   ███████║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
  ██║ ╚████║███████╗   ██║   ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
{_RESET}
  {_GREEN}v1.0.0{_RESET}  {_DIM}Web Dashboard Mode{_RESET}
"""


def _build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser (minimal — web-only)."""
    parser = argparse.ArgumentParser(
        prog="netsleuth",
        description="NetSleuth — Web Dashboard (FastAPI + Uvicorn)",
    )
    parser.add_argument(
        "-i", "--interface",
        type=str, default=None,
        help="Network interface for scanning (auto-detected if omitted).",
    )
    parser.add_argument(
        "--port",
        type=int, default=8443,
        help="HTTP port to bind (default: 8443).",
    )
    parser.add_argument(
        "--host",
        type=str, default="0.0.0.0",
        help="Host address to bind (default: 0.0.0.0).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true", default=False,
        help="Enable debug logging.",
    )
    return parser


def _check_privileges() -> None:
    """Verify root/admin privileges before starting.

    Raw sockets (scapy + stress test) require elevated privileges.
    Fail fast with a clear message instead of crashing later.
    """
    try:
        from src.engine.network_utils import check_privileges
        check_privileges()
    except Exception as exc:
        sys.stderr.write(
            f"\n{_RED}{_BOLD}  ✖  {exc}{_RESET}\n\n"
            f"{_YELLOW}  💡 Ejecuta con: sudo python main.py{_RESET}\n\n"
        )
        sys.exit(1)


def main() -> None:
    """Parse args, check privileges, print banner, and start Uvicorn."""
    parser = _build_parser()
    args = parser.parse_args()

    # ── Privilege gate (before any heavy import) ──────────────────────── #
    _check_privileges()

    # ── Banner ────────────────────────────────────────────────────────── #
    sys.stdout.write(_BANNER)

    url = f"http://127.0.0.1:{args.port}"
    sys.stdout.write(
        f"  {_CYAN}Interface:{_RESET} {_BOLD}{args.interface or 'auto-detect'}{_RESET}\n"
        f"  {_CYAN}Dashboard:{_RESET} {_BOLD}{url}{_RESET}\n"
        f"  {_CYAN}Verbose:{_RESET}   {'Yes' if args.verbose else 'No'}\n\n"
        f"  {_GREEN}NetSleuth UI Iniciada. Abre tu navegador en: {url}{_RESET}\n"
        f"  {_DIM}Presiona Ctrl+C para detener el servidor.{_RESET}\n\n"
    )

    # ── Create app and launch Uvicorn ─────────────────────────────────── #
    import uvicorn  # type: ignore[import-untyped]
    from src.web.app import create_app

    app = create_app(
        interface=args.interface,
        verbose=args.verbose,
    )

    log_level = "debug" if args.verbose else "info"
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=log_level,
        access_log=args.verbose,
    )


if __name__ == "__main__":
    main()
