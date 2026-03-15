"""
NetSleuth — CLI Controller.

Wires together all layers of the application:
    Sniffer → AnalysisEngine → DeviceStore → Formatter

Supports three modes:
    - **Passive**: listen-only network monitoring.
    - **Active**: fire-and-forget probes + passive capture.
    - **Stress Test**: high-throughput packet injection + passive capture.

Handles ``Ctrl+C`` for graceful shutdown and prints a final summary.
"""

from __future__ import annotations

import logging
import signal
import sys
import time
from typing import Optional

from src.analyzers.arp_analyzer import ARPAnalyzer
from src.analyzers.dhcp_analyzer import DHCPAnalyzer
from src.analyzers.tcp_analyzer import TCPAnalyzer
from src.cli.formatters import IOutputFormatter, JSONFormatter, TableFormatter
from src.core.analyzer_factory import AnalyzerFactory
from src.core.exceptions import (
    InsufficientPermissionsError,
    NetSleuthError,
    NetworkInterfaceError,
)
from src.core.models import ProtocolType
from src.engine.analysis_engine import AnalysisEngine
from src.engine.sniffer import PacketCapture
from src.services.device_store import InMemoryDeviceStore
from src.services.vendor_lookup import MacVendorLookup

logger = logging.getLogger(__name__)

# ── ANSI helpers ──────────────────────────────────────────────────────────── #
_BOLD = "\033[1m"
_CYAN = "\033[96m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_MAGENTA = "\033[95m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_BG_RED = "\033[41m"
_WHITE = "\033[97m"

_BANNER = rf"""
{_CYAN}{_BOLD}
  ███╗   ██╗███████╗████████╗███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     █████╗  ██║   ██║   ██║   ███████║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
  ██║ ╚████║███████╗   ██║   ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
{_RESET}
  {_YELLOW}Passive / Active Network Reconnaissance Tool{_RESET}
  {_GREEN}v0.3.0 — github.com/netsleuth{_RESET}
"""


class CLIController:
    """Top-level controller that orchestrates a scan session.

    Args:
        interface: Network interface to capture on (``None`` = auto-detect).
        timeout: Maximum scan duration in seconds (``None`` = indefinite).
        output_format: ``"table"`` or ``"json"``.
        passive: If ``True``, only listens (no active probing).
        verbose: Enable debug-level logging.
        subnet: Target subnet in CIDR notation (``None`` = auto-detect).
        stress_target: IP address for stress testing (``None`` = disabled).
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        timeout: Optional[int] = None,
        output_format: str = "table",
        passive: bool = True,
        verbose: bool = False,
        subnet: Optional[str] = None,
        stress_target: Optional[str] = None,
    ) -> None:
        self._timeout = timeout
        self._output_format = output_format
        self._passive = passive
        self._verbose = verbose
        self._stress_target = stress_target
        self._active_scanner_instance = None
        self._stress_tester_instance = None

        # ── Setup logging first so helpers can log ──────────────────── #
        self._setup_logging()

        # ── Auto-detect interface / subnet if not provided ──────────── #
        self._interface = interface
        self._subnet = subnet
        self._resolve_network()

        # ── Build the dependency graph ──────────────────────────────── #
        self._device_store = InMemoryDeviceStore()
        self._vendor_lookup = MacVendorLookup()

        # Factory — register all available analyzers
        self._factory = AnalyzerFactory()
        self._factory.register(ProtocolType.ARP, ARPAnalyzer)
        self._factory.register(ProtocolType.DHCP, DHCPAnalyzer)
        self._factory.register(ProtocolType.TCP, TCPAnalyzer)

        # Analysis engine (Observer listener)
        self._engine = AnalysisEngine(
            factory=self._factory,
            device_store=self._device_store,
            vendor_lookup=self._vendor_lookup,
        )

        # BPF filter — capture ARP, DHCP (port 67/68), and TCP SYN/SYN-ACK/RST
        bpf = (
            "arp or port 67 or port 68 "
            "or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)"
        )

        # Packet capture (Observer subject)
        self._sniffer = PacketCapture(
            interface=self._interface,
            bpf_filter=bpf,
            timeout=self._timeout,
        )

        # Subscribe the analysis engine to the sniffer
        self._sniffer.subscribe(self._engine)

        # Formatter
        self._formatter: IOutputFormatter = (
            JSONFormatter() if output_format == "json" else TableFormatter()
        )

    # ── Public API ────────────────────────────────────────────────────── #

    def run(self) -> None:
        """Execute the full scan lifecycle (passive or active)."""
        self._print_banner()
        self._register_signal_handlers()

        try:
            self._start_scan()
            self._wait_for_completion()
        except InsufficientPermissionsError as exc:
            sys.stderr.write(f"\n{_RED}  ✖  {exc.message}{_RESET}\n")
            sys.exit(1)
        except NetworkInterfaceError as exc:
            sys.stderr.write(f"\n{_RED}  ✖  {exc.message}{_RESET}\n")
            sys.exit(1)
        except NetSleuthError as exc:
            sys.stderr.write(f"\n{_RED}  ✖  {exc.message}{_RESET}\n")
            sys.exit(1)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop_scan()
            self._print_results()

    def run_stress_test(self) -> None:
        """Execute a network stress test with OPSEC safeguards.

        1. Print warning banner.
        2. Require explicit user confirmation ("YES").
        3. Start passive sniffer (background monitor).
        4. Start stress tester.
        5. Wait for timeout or Ctrl+C.
        6. Print final metrics + sniffer stats.
        """
        self._print_banner()

        # ── OPSEC: mandatory user confirmation ────────────────────────── #
        if not self._confirm_stress_test():
            sys.stdout.write(
                f"\n  {_YELLOW}⏹  Stress test cancelled by user.{_RESET}\n\n"
            )
            return

        self._register_signal_handlers()

        try:
            # Start passive sniffer first to monitor the flood
            sys.stdout.write(
                f"\n  {_GREEN}▶  Starting passive sniffer (background monitor)…{_RESET}\n"
            )
            self._sniffer.start()
            time.sleep(0.3)

            # Start the stress tester
            sys.stdout.write(
                f"  {_RED}🔥 Starting stress test → {self._stress_target} "
                f"(duration: {self._timeout or '∞'}s)…{_RESET}\n\n"
            )
            self._start_stress_tester()
            self._wait_for_completion()

        except KeyboardInterrupt:
            pass
        except NetSleuthError as exc:
            sys.stderr.write(f"\n{_RED}  ✖  {exc.message}{_RESET}\n")
        finally:
            self._stop_stress_test()
            self._print_stress_results()

    # ── Internal ──────────────────────────────────────────────────────── #

    def _resolve_network(self) -> None:
        """Auto-detect interface and subnet if the user didn't specify them.

        Raises:
            NetworkInterfaceError: If the machine is offline or no
                interface with a default gateway can be found.
        """
        from src.engine.network_utils import detect_default_interface, get_local_subnet

        if self._interface is None:
            try:
                self._interface = detect_default_interface()
                logger.info("Auto-detected interface: %s", self._interface)
            except NetworkInterfaceError:
                raise

        if not self._passive and self._subnet is None:
            try:
                self._subnet = get_local_subnet(self._interface)
                logger.info("Auto-detected subnet: %s", self._subnet)
            except NetworkInterfaceError:
                raise

    def _setup_logging(self) -> None:
        """Configure logging based on verbosity setting."""
        level = logging.DEBUG if self._verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)-7s] %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )

    def _print_banner(self) -> None:
        """Print the NetSleuth ASCII banner and scan parameters."""
        sys.stdout.write(_BANNER)

        if self._stress_target:
            mode = f"{_BG_RED}{_WHITE}{_BOLD} STRESS TEST {_RESET}"
        elif not self._passive:
            mode = f"{_RED}ACTIVE{_RESET}"
        else:
            mode = f"{_GREEN}PASSIVE{_RESET}"

        sys.stdout.write(
            f"  {_CYAN}Mode:{_RESET}      {mode}\n"
            f"  {_CYAN}Interface:{_RESET} {_BOLD}{self._interface or 'ALL'}{_RESET}\n"
        )
        if self._stress_target:
            sys.stdout.write(
                f"  {_CYAN}Target:{_RESET}    {_BOLD}{_RED}{self._stress_target}{_RESET}\n"
            )
        else:
            sys.stdout.write(
                f"  {_CYAN}Subnet:{_RESET}    {_BOLD}{self._subnet or 'N/A (passive)'}{_RESET}\n"
            )
        sys.stdout.write(
            f"  {_CYAN}Timeout:{_RESET}   {self._timeout or '∞'}s\n"
            f"  {_CYAN}Output:{_RESET}    {self._output_format}\n\n"
        )

    def _confirm_stress_test(self) -> bool:
        """Display an OPSEC warning and require the user to type 'YES'.

        Returns:
            ``True`` if the user confirmed, ``False`` otherwise.
        """
        warning = (
            f"\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ╔══════════════════════════════════════════════════════════════════╗ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║          ⚠   ADVERTENCIA — STRESS TEST / DoS   ⚠              ║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ╠══════════════════════════════════════════════════════════════════╣ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║  Esta prueba inyectará paquetes a velocidad máxima hacia:       ║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║  → {self._stress_target:<62s}║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║                                                                ║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║  Esto PUEDE causar:                                            ║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║    • Denegación de Servicio (DoS) en la red local              ║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║    • Saturación del router / switch                            ║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║    • Pérdida de conectividad para otros dispositivos           ║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║                                                                ║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ║  Úsalo SOLO en redes de tu propiedad y con autorización.       ║ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ╚══════════════════════════════════════════════════════════════════╝ "
            f"{_RESET}\n"
        )
        sys.stdout.write(warning)
        sys.stdout.write(
            f"\n  {_YELLOW}{_BOLD}Escribe 'YES' para confirmar y comenzar: {_RESET}"
        )
        sys.stdout.flush()

        try:
            user_input = input().strip()
        except (EOFError, KeyboardInterrupt):
            return False

        return user_input == "YES"

    def _register_signal_handlers(self) -> None:
        """Register SIGINT/SIGTERM for graceful shutdown."""
        def _handler(signum: int, frame: object) -> None:  # noqa: ANN401
            sys.stdout.write(
                f"\n\n{_YELLOW}  ⏹  Interrupt received — stopping…{_RESET}\n"
            )
            if self._stress_tester_instance is not None:
                self._stop_stress_test()
                self._print_stress_results()
            else:
                self._stop_scan()
                self._print_results()
            sys.exit(0)

        signal.signal(signal.SIGINT, _handler)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _handler)

    def _start_scan(self) -> None:
        """Start the passive sniffer and (optionally) the active scanner."""
        sys.stdout.write(f"  {_GREEN}▶  Starting passive sniffer…{_RESET}\n")
        self._sniffer.start()

        if not self._passive and self._subnet:
            sys.stdout.write(
                f"  {_MAGENTA}⚡ Starting active scanner "
                f"({self._subnet})…{_RESET}\n"
            )
            time.sleep(0.3)
            self._start_active_scanner()

        sys.stdout.write("\n")

    def _start_active_scanner(self) -> None:
        """Instantiate and start the active scanner."""
        from src.engine.active_scanner import ActiveScanner

        self._active_scanner_instance = ActiveScanner(
            interface=self._interface,
            subnet=self._subnet,
        )
        self._active_scanner_instance.start()

    def _start_stress_tester(self) -> None:
        """Instantiate and start the stress tester."""
        from src.engine.stress_tester import StressTester

        self._stress_tester_instance = StressTester(
            target_ip=self._stress_target,
            interface=self._interface,
            duration=self._timeout,
        )
        self._stress_tester_instance.start()

    def _wait_for_completion(self) -> None:
        """Block the main thread until timeout expires or user interrupts."""
        if self._timeout:
            time.sleep(self._timeout)
        else:
            while True:
                time.sleep(1)

    def _stop_scan(self) -> None:
        """Stop the sniffer and active scanner gracefully."""
        if self._active_scanner_instance is not None:
            self._active_scanner_instance.stop()
        self._sniffer.stop()

    def _stop_stress_test(self) -> None:
        """Stop the stress tester and sniffer gracefully."""
        if self._stress_tester_instance is not None:
            self._stress_tester_instance.stop()
        self._sniffer.stop()

    def _print_results(self) -> None:
        """Render discovered devices using the configured formatter."""
        devices = self._device_store.get_all()

        stats_parts = [
            f"Packets processed: {self._engine.packets_processed}",
            f"Fingerprints: {self._engine.fingerprints_found}",
        ]
        if self._active_scanner_instance is not None:
            stats_parts.append(
                f"Active probes sent: {self._active_scanner_instance.packets_sent}"
            )

        sys.stdout.write(
            f"\n  {_BOLD}📊 Scan Results — {' | '.join(stats_parts)}{_RESET}\n"
        )
        self._formatter.format(devices)

    def _print_stress_results(self) -> None:
        """Print the stress test final summary + sniffer stats."""
        if self._stress_tester_instance is None:
            return

        summary = self._stress_tester_instance.get_summary()

        sys.stdout.write(
            f"\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ═══════════════════════════════════════════════════ "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f"   🔥  STRESS TEST — FINAL REPORT                   "
            f"{_RESET}\n"
            f"  {_BG_RED}{_WHITE}{_BOLD}"
            f" ═══════════════════════════════════════════════════ "
            f"{_RESET}\n\n"
        )

        sys.stdout.write(
            f"  {_CYAN}Target:{_RESET}           {_BOLD}{summary['target']}{_RESET}\n"
            f"  {_CYAN}Duration:{_RESET}         {_BOLD}{summary['duration_seconds']}s{_RESET}\n"
            f"  {_CYAN}Total Packets:{_RESET}    {_BOLD}{summary['total_packets']:,}{_RESET}\n"
            f"  {_CYAN}Total Data:{_RESET}       {_BOLD}"
            f"{summary['total_bytes'] / 1_000_000:.2f} MB{_RESET}\n"  # type: ignore[operator]
            f"\n"
            f"  {_GREEN}Avg PPS:{_RESET}          {_BOLD}{summary['avg_pps']:,.0f}{_RESET}\n"
            f"  {_GREEN}Avg Throughput:{_RESET}   {_BOLD}{summary['avg_mbps']:.2f} Mbps{_RESET}\n"
            f"  {_MAGENTA}Peak PPS:{_RESET}         {_BOLD}{summary['peak_pps']:,.0f}{_RESET}\n"
            f"  {_MAGENTA}Peak Throughput:{_RESET}  {_BOLD}{summary['peak_mbps']:.2f} Mbps{_RESET}\n"
        )

        # Sniffer stats (how well it handled the flood)
        sys.stdout.write(
            f"\n  {_DIM}── Sniffer (background monitor) ──{_RESET}\n"
            f"  {_CYAN}Pkts captured:{_RESET}    {self._engine.packets_processed:,}\n"
            f"  {_CYAN}Fingerprints:{_RESET}     {self._engine.fingerprints_found}\n\n"
        )
