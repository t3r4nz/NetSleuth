#!/usr/bin/env python3
"""
NetSleuth — Unified Entry Point (Web-Only).

Checks root privileges, prints a banner, and starts the FastAPI
web dashboard via Uvicorn on port 8443.

Usage::

    sudo python main.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Ensure the project root is in sys.path ────────────────────────────────── #
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ANSI helpers
_R = "\033[91m"
_G = "\033[92m"
_C = "\033[96m"
_B = "\033[1m"
_D = "\033[2m"
_RST = "\033[0m"

_BANNER = rf"""
{_C}{_B}
  ███╗   ██╗███████╗████████╗███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     █████╗  ██║   ██║   ██║   ███████║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
  ██║ ╚████║███████╗   ██║   ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
{_RST}
  {_G}v1.0.0{_RST}  {_D}Web Dashboard{_RST}
"""

_PORT = 8443
_HOST = "0.0.0.0"


def main() -> None:
    """Check privileges, print banner, start Uvicorn."""

    # ── Privilege gate ────────────────────────────────────────── #
    if os.name == "posix" and os.geteuid() != 0:
        sys.stderr.write(
            f"\n{_R}{_B}  ✖  Se requieren privilegios de root.{_RST}\n"
            f"  {_D}Ejecuta: sudo python main.py{_RST}\n\n"
        )
        sys.exit(1)

    # ── Banner ────────────────────────────────────────────────── #
    sys.stdout.write(_BANNER)
    sys.stdout.write(
        f"  {_G}{_B}NetSleuth Server Running → http://127.0.0.1:{_PORT}{_RST}\n"
        f"  {_D}Presiona Ctrl+C para detener.{_RST}\n\n"
    )

    # ── Start ─────────────────────────────────────────────────── #
    import uvicorn  # type: ignore[import-untyped]
    from src.web.app import create_app

    app = create_app()

    uvicorn.run(
        app,
        host=_HOST,
        port=_PORT,
        log_level="info",
        access_log=False,
    )


if __name__ == "__main__":
    main()
