"""
NetSleuth — Active Scanner.

Provides active probing capabilities to force silent devices (firewalls
in DROP mode, hosts that never initiate traffic) to reveal their MAC
addresses on the local network.

Architecture Notes
------------------
This module uses **fire-and-forget** sending (``sendp()`` / ``send()``)
instead of ``sr()`` / ``srp()``.  The key insight is that the passive
sniffer (``PacketCapture``) is already running on a separate thread
capturing *all* traffic.  When an active probe forces a device to emit
an ARP reply, SYN-ACK, or RST, the sniffer catches it and pushes it
through the normal ``AnalysisEngine`` pipeline.

This approach:
    - Turns a 5-minute scan into a ~3 second sweep.
    - Avoids blocking on timeouts for non-existent hosts.
    - Keeps the architecture clean (single responsibility).

Concurrency
-----------
All probes run in a **daemon thread** with a ``threading.Event`` for
graceful shutdown.  The sending loop checks ``_stop_event`` between
batches so that ``Ctrl+C`` aborts the scan instantly.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import List, Optional, Sequence

from src.core.interfaces import IActiveScanner

logger = logging.getLogger(__name__)

# Default ports for TCP SYN probing — common services that reveal OS info.
DEFAULT_PROBE_PORTS: List[int] = [22, 80, 135, 139, 443, 445, 3389, 8080]

# Batch size: how many packets to send before checking the stop_event.
_BATCH_SIZE = 16


class ActiveScanner(IActiveScanner):
    """Fire-and-forget active network scanner.

    Sends ARP broadcasts and TCP SYN packets to provoke responses that
    the already-running passive sniffer will capture and analyse.

    Args:
        interface: Network interface to send from.
        subnet: Target subnet in CIDR notation (e.g., ``"192.168.1.0/24"``).
        ports: TCP ports to probe (default: common service ports).
        inter_packet_delay: Seconds between individual packets to avoid
            flooding the network (default: 0.005 = 5 ms).

    Example::

        scanner = ActiveScanner(interface="eth0", subnet="192.168.1.0/24")
        scanner.start()
        # ... sniffer captures the responses ...
        scanner.stop()
    """

    def __init__(
        self,
        interface: str,
        subnet: str,
        ports: Optional[Sequence[int]] = None,
        inter_packet_delay: float = 0.005,
    ) -> None:
        self._interface = interface
        self._subnet = subnet
        self._ports = list(ports) if ports else DEFAULT_PROBE_PORTS
        self._inter_packet_delay = inter_packet_delay

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._packets_sent: int = 0

    # ── IActiveScanner implementation ─────────────────────────────────── #

    def start(self) -> None:
        """Launch the active scanning loop in a background thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Active scanner is already running.")
            return

        self._stop_event.clear()
        self._packets_sent = 0
        self._thread = threading.Thread(
            target=self._scan_loop,
            name="netsleuth-active-scanner",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Active scanner started: interface=%s subnet=%s ports=%s",
            self._interface,
            self._subnet,
            self._ports,
        )

    def stop(self) -> None:
        """Signal the active scanner to stop and wait for thread exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            logger.info(
                "Active scanner stopped. Packets sent: %d", self._packets_sent
            )
            self._thread = None

    # ── Scanning Logic ────────────────────────────────────────────────── #

    def _scan_loop(self) -> None:
        """Main scanning sequence: ARP sweep → TCP SYN probes.

        Each phase checks ``_stop_event`` frequently to allow instant
        abort on Ctrl+C.
        """
        try:
            if not self._stop_event.is_set():
                self._arp_sweep()

            if not self._stop_event.is_set():
                # Small pause between phases to let ARP responses arrive
                time.sleep(0.5)
                self._tcp_syn_probe()

            if not self._stop_event.is_set():
                logger.info(
                    "Active scan complete. Total packets sent: %d",
                    self._packets_sent,
                )
        except Exception:
            logger.exception("Active scanner encountered an error.")

    def _arp_sweep(self) -> None:
        """Send ARP broadcast requests to every host in the subnet.

        Uses ``sendp()`` (layer 2 fire-and-forget) so we don't wait
        for replies — the passive sniffer catches them.
        """
        if self._stop_event.is_set():
            return

        logger.info("🔍 ARP sweep: %s", self._subnet)

        try:
            from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
            from scapy.sendrecv import sendp  # type: ignore[import-untyped]
            from scapy.utils import Net  # type: ignore[import-untyped]

            # Build ARP request: broadcast Ethernet + ARP who-has for entire subnet
            targets = [str(ip) for ip in Net(self._subnet)]

            count = 0
            for target_ip in targets:
                if self._stop_event.is_set():
                    logger.debug("ARP sweep aborted by stop_event.")
                    break

                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
                sendp(pkt, iface=self._interface, verbose=False)
                self._packets_sent += 1
                count += 1

                # Breathe between batches
                if count % _BATCH_SIZE == 0:
                    time.sleep(self._inter_packet_delay * _BATCH_SIZE)

            logger.info("ARP sweep sent %d packets.", count)

        except Exception:
            logger.exception("ARP sweep failed.")

    def _tcp_syn_probe(self) -> None:
        """Send TCP SYN packets to common ports across the subnet.

        Uses ``send()`` (layer 3 fire-and-forget).  Even if the target
        drops the packet, the local router must resolve the destination
        MAC via ARP first — which our sniffer captures.
        """
        if self._stop_event.is_set():
            return

        logger.info(
            "🎯 TCP SYN probe: %s → ports %s", self._subnet, self._ports
        )

        try:
            from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]
            from scapy.sendrecv import send  # type: ignore[import-untyped]
            from scapy.utils import Net  # type: ignore[import-untyped]
            from scapy.volatile import RandShort  # type: ignore[import-untyped]

            targets = [str(ip) for ip in Net(self._subnet)]

            count = 0
            for target_ip in targets:
                if self._stop_event.is_set():
                    logger.debug("TCP SYN probe aborted by stop_event.")
                    break

                for port in self._ports:
                    if self._stop_event.is_set():
                        break

                    pkt = IP(dst=target_ip) / TCP(
                        sport=RandShort(),
                        dport=port,
                        flags="S",
                    )
                    send(pkt, verbose=False)
                    self._packets_sent += 1
                    count += 1

                    # Breathe between batches
                    if count % _BATCH_SIZE == 0:
                        time.sleep(self._inter_packet_delay * _BATCH_SIZE)

            logger.info("TCP SYN probe sent %d packets.", count)

        except Exception:
            logger.exception("TCP SYN probe failed.")

    # ── Metrics ────────────────────────────────────────────────────────── #

    @property
    def packets_sent(self) -> int:
        """Total number of active probe packets sent."""
        return self._packets_sent
