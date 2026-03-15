#!/usr/bin/env python3
"""
NetSleuth — Web Dashboard Entry Point.

Launches the FastAPI application via Uvicorn, after verifying that
the process has the required root/admin privileges for raw socket
operations (scapy sniffing + stress test raw sockets).

Usage::

    # Default (port 8443)
    sudo python web_main.py

    # Custom port + verbose
    sudo python web_main.py --port 9000 -v

    # Specify network interface
    sudo python web_main.py -i eth0 --port 8443
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ── Ensure project root in sys.path ───────────────────────────────────────── #
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ANSI helpers
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_WEB_BANNER = rf"""
{_CYAN}{_BOLD}
  ███╗   ██╗███████╗████████╗███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     █████╗  ██║   ██║   ██║   ███████║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
  ██║ ╚████║███████╗   ██║   ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
{_RESET}
  {_YELLOW}🌐 Web Dashboard Mode{_RESET}
  {_GREEN}v0.4.0{_RESET}
"""


def _build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for the web entry point."""
    parser = argparse.ArgumentParser(
        prog="netsleuth-web",
        description="NetSleuth — Web Dashboard (FastAPI + Uvicorn)",
    )
    parser.add_argument(
        "-i", "--interface",
        type=str, default=None,
        help="Network interface (auto-detected if omitted).",
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


def main() -> None:
    """Parse args, check privileges, and start the web server."""
    parser = _build_parser()
    args = parser.parse_args()

    # ── Privilege check ───────────────────────────────────────────────── #
    try:
        from src.engine.network_utils import check_privileges
        check_privileges()
    except Exception as exc:
        sys.stderr.write(
            f"\n{_RED}{_BOLD}  ✖  {exc}{_RESET}\n\n"
            f"{_YELLOW}  💡 Ejecuta con: sudo python web_main.py{_RESET}\n\n"
        )
        sys.exit(1)

    # ── Print banner ──────────────────────────────────────────────────── #
    sys.stdout.write(_WEB_BANNER)
    sys.stdout.write(
        f"  {_CYAN}Interface:{_RESET} {_BOLD}{args.interface or 'auto-detect'}{_RESET}\n"
        f"  {_CYAN}Dashboard:{_RESET} {_BOLD}http://{args.host}:{args.port}{_RESET}\n"
        f"  {_CYAN}Verbose:{_RESET}   {'Yes' if args.verbose else 'No'}\n\n"
        f"  {_GREEN}Press Ctrl+C to stop the server.{_RESET}\n\n"
    )

    # ── Create app and run ────────────────────────────────────────────── #
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
