#!/usr/bin/env python3
"""
NetSleuth — Passive / Active Network Reconnaissance Tool.

Entry point for the CLI application.  Parses command-line arguments,
validates environment (privileges, network), and delegates to the
``CLIController``.

Usage::

    # Passive scan on all interfaces (60 s timeout)
    sudo python main.py --timeout 60

    # Active scan — ARP sweep + TCP SYN probes
    sudo python main.py --active --timeout 30

    # Stress test — measure NIC capacity
    sudo python main.py --stress-test 192.168.1.1 --timeout 10

    # Specify interface and subnet manually
    sudo python main.py -i eth0 --subnet 192.168.1.0/24 --active -t 45

    # JSON output, verbose
    sudo python main.py -i wlan0 -o json -v

Requirements:
    - Python 3.10+
    - scapy  (``pip install scapy``)
    - httpx  (``pip install httpx``) — optional, for vendor lookup
    - netifaces  (``pip install netifaces``) — for subnet auto-detection
    - Root / Administrator privileges for raw packet capture
"""

from __future__ import annotations

import argparse
import sys

# ── Ensure the project root is in sys.path ────────────────────────────────── #
# This allows running ``python main.py`` directly from the NetSleuth/ folder.
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ANSI helpers (available before any heavy import)
_RED = "\033[91m"
_YELLOW = "\033[93m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser.

    Returns:
        Configured ``ArgumentParser`` instance.
    """
    parser = argparse.ArgumentParser(
        prog="netsleuth",
        description=(
            "NetSleuth — Passive / Active Network Reconnaissance Tool.\n"
            "Identifies devices on the local network by analysing MAC addresses,\n"
            "DHCP Option 55, and TCP/IP stack fingerprints.\n\n"
            "Active mode sends ARP broadcasts and TCP SYN probes to force\n"
            "silent devices (firewalls in DROP mode) to reveal their MACs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python main.py --timeout 60               # Passive, 60s\n"
            "  sudo python main.py --active -t 30              # Active, 30s\n"
            "  sudo python main.py -i eth0 --subnet 10.0.0.0/24 --active\n"
            "  sudo python main.py --stress-test 192.168.1.1 -t 10\n"
            "  sudo python main.py -o json -v                  # JSON + verbose\n"
        ),
    )

    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Network interface to capture on (auto-detected if omitted).",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="Scan duration in seconds (default: indefinite, stop with Ctrl+C).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        choices=["table", "json"],
        default="table",
        help="Output format (default: table).",
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        default=True,
        help="Passive mode — listen only, no active probing (default).",
    )
    parser.add_argument(
        "--active",
        action="store_true",
        default=False,
        help=(
            "Active mode — send ARP broadcast sweeps and TCP SYN probes "
            "to force devices to reveal their MACs."
        ),
    )
    parser.add_argument(
        "--subnet",
        type=str,
        default=None,
        help=(
            "Target subnet in CIDR notation (e.g., 192.168.1.0/24). "
            "Auto-detected if omitted."
        ),
    )
    parser.add_argument(
        "--stress-test",
        type=str,
        default=None,
        metavar="TARGET_IP",
        help=(
            "Run a network stress test against TARGET_IP. "
            "Measures max PPS and Mbps of your NIC. "
            "⚠ Can cause DoS — requires explicit confirmation."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose / debug logging.",
    )

    return parser


def _check_privileges_early() -> None:
    """Run a lightweight privilege check before importing heavy modules.

    This prevents the user from waiting for scapy to load only to
    discover they forgot ``sudo``.
    """
    from src.core.exceptions import InsufficientPermissionsError

    try:
        from src.engine.network_utils import check_privileges
        check_privileges()
    except InsufficientPermissionsError as exc:
        sys.stderr.write(
            f"\n{_RED}{_BOLD}  ✖  {exc.message}{_RESET}\n\n"
            f"{_YELLOW}  💡 Tip: ejecuta con 'sudo python main.py' "
            f"o como Administrador en Windows.{_RESET}\n\n"
        )
        sys.exit(1)


def main() -> None:
    """Parse CLI arguments, validate environment, and run the scanner."""
    parser = _build_parser()
    args = parser.parse_args()

    # ── Early privilege gate (before any scapy import) ────────────────── #
    _check_privileges_early()

    # ── Stress test mode ──────────────────────────────────────────────── #
    if args.stress_test:
        from src.cli.controller import CLIController

        controller = CLIController(
            interface=args.interface,
            timeout=args.timeout,
            output_format=args.output,
            passive=True,
            verbose=args.verbose,
            subnet=args.subnet,
            stress_target=args.stress_test,
        )
        controller.run_stress_test()
        return

    # ── Normal scan mode ──────────────────────────────────────────────── #
    passive = not args.active

    # Late import to keep argparse fast (scapy is slow to import).
    from src.cli.controller import CLIController

    controller = CLIController(
        interface=args.interface,
        timeout=args.timeout,
        output_format=args.output,
        passive=passive,
        verbose=args.verbose,
        subnet=args.subnet,
    )
    controller.run()


if __name__ == "__main__":
    main()
