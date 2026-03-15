"""
NetSleuth — Stress Tester.

High-throughput packet injection module for measuring the maximum PPS
(Packets Per Second) and Mbps capacity of a network interface, and for
stress-testing a router under extreme load.

╔══════════════════════════════════════════════════════════════════════╗
║  ⚠  WARNING: This module can cause Denial of Service (DoS).        ║
║  Use ONLY on networks you own and have explicit authorization.      ║
╚══════════════════════════════════════════════════════════════════════╝

Why Raw Sockets Instead of scapy.send()
---------------------------------------
``scapy.send()`` processes each packet through the full scapy stack
(build layers → checksums → system call) achieving ~500-2,000 PPS on
typical hardware.  For a real stress test we need **100,000+ PPS**.

This module uses ``socket.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)``
to bypass scapy entirely.  A pre-built UDP payload is created once
and sent repeatedly via ``socket.sendto()`` — achieving 50,000-200,000+
PPS depending on the NIC and CPU.

Concurrency Model
-----------------
- **Sender thread**: blasts packets in a tight loop, checking
  ``_stop_event`` every ``_REPORT_INTERVAL_PACKETS`` packets.
- **Metrics thread**: every 1 second, reads atomic counters and prints
  a live PPS / Mbps dashboard line to stdout.
- **Main thread**: (in controller.py) waits for timeout or Ctrl+C,
  then calls ``stop()`` which sets the event and joins both threads.
"""

from __future__ import annotations

import logging
import os
import random
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from src.core.interfaces import IStressTester

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

# How often (in packets) the sender checks the stop_event.
_STOP_CHECK_INTERVAL = 1024

# Default target port for UDP flood.
_DEFAULT_PORT = 53

# Default payload size in bytes (UDP data, not counting headers).
_DEFAULT_PAYLOAD_SIZE = 64


@dataclass
class StressMetrics:
    """Live metrics collected during a stress test.

    All counters are updated atomically from the sender thread and
    read from the metrics thread.  On CPython the GIL guarantees
    safe reads/writes of individual integers.
    """

    total_packets: int = 0
    total_bytes: int = 0
    start_time: float = 0.0
    last_report_packets: int = 0
    last_report_bytes: int = 0
    last_report_time: float = 0.0
    peak_pps: float = 0.0
    peak_mbps: float = 0.0


class StressTester(IStressTester):
    """High-performance network stress tester using raw sockets.

    Sends a flood of UDP packets to a target IP to measure the maximum
    throughput of the local NIC and evaluate router resilience.

    Args:
        target_ip: Destination IP address for the packet flood.
        interface: Network interface to bind to (informational; raw
                   sockets use the routing table by default).
        duration: Maximum test duration in seconds (``None`` = until Ctrl+C).
        target_port: Destination UDP port (default: 53).
        payload_size: Size of each UDP payload in bytes (default: 64).

    Example::

        tester = StressTester(target_ip="192.168.1.1", duration=10)
        tester.start()
        # ... metrics print live ...
        tester.stop()
    """

    def __init__(
        self,
        target_ip: str,
        interface: Optional[str] = None,
        duration: Optional[int] = None,
        target_port: int = _DEFAULT_PORT,
        payload_size: int = _DEFAULT_PAYLOAD_SIZE,
    ) -> None:
        self._target_ip = target_ip
        self._interface = interface
        self._duration = duration
        self._target_port = target_port
        self._payload_size = payload_size

        self._stop_event = threading.Event()
        self._sender_thread: Optional[threading.Thread] = None
        self._metrics_thread: Optional[threading.Thread] = None
        self._metrics = StressMetrics()

        # Pre-build the raw packet once (immutable bytes).
        self._raw_packet = self._build_udp_packet()

    # ── IStressTester implementation ──────────────────────────────────── #

    def start(self) -> None:
        """Launch the sender and metrics threads."""
        if self._sender_thread is not None and self._sender_thread.is_alive():
            logger.warning("Stress tester is already running.")
            return

        self._stop_event.clear()
        self._metrics = StressMetrics()
        self._metrics.start_time = time.monotonic()
        self._metrics.last_report_time = self._metrics.start_time

        self._sender_thread = threading.Thread(
            target=self._send_loop,
            name="netsleuth-stress-sender",
            daemon=True,
        )
        self._metrics_thread = threading.Thread(
            target=self._metrics_loop,
            name="netsleuth-stress-metrics",
            daemon=True,
        )

        self._sender_thread.start()
        self._metrics_thread.start()

        logger.info(
            "Stress test started: target=%s:%d payload=%dB duration=%ss",
            self._target_ip,
            self._target_port,
            self._payload_size,
            self._duration or "∞",
        )

    def stop(self) -> None:
        """Signal both threads to stop and wait for completion."""
        self._stop_event.set()
        if self._sender_thread is not None:
            self._sender_thread.join(timeout=3)
        if self._metrics_thread is not None:
            self._metrics_thread.join(timeout=2)
        logger.info("Stress test stopped.")
        self._sender_thread = None
        self._metrics_thread = None

    def get_summary(self) -> dict[str, object]:
        """Return a dict with the final test results.

        Returns:
            Dictionary with total packets, bytes, duration, avg PPS/Mbps,
            and peak PPS/Mbps.
        """
        elapsed = time.monotonic() - self._metrics.start_time if self._metrics.start_time else 0
        avg_pps = self._metrics.total_packets / elapsed if elapsed > 0 else 0
        avg_mbps = (self._metrics.total_bytes * 8 / 1_000_000) / elapsed if elapsed > 0 else 0

        return {
            "target": f"{self._target_ip}:{self._target_port}",
            "duration_seconds": round(elapsed, 2),
            "total_packets": self._metrics.total_packets,
            "total_bytes": self._metrics.total_bytes,
            "avg_pps": round(avg_pps, 0),
            "avg_mbps": round(avg_mbps, 2),
            "peak_pps": round(self._metrics.peak_pps, 0),
            "peak_mbps": round(self._metrics.peak_mbps, 2),
        }

    # ── Packet Construction ───────────────────────────────────────────── #

    def _build_udp_packet(self) -> bytes:
        """Pre-build a raw IP+UDP packet as immutable bytes.

        Constructing the packet once and reusing it in the send loop
        eliminates per-packet overhead entirely.  The IP and UDP
        checksums are set to 0 (the kernel or NIC fills them in for
        raw sockets with ``IPPROTO_RAW``).

        Returns:
            Complete IP+UDP packet as bytes.
        """
        payload = os.urandom(self._payload_size)

        # ── UDP header (8 bytes) ─────────────────────────────────────── #
        src_port = random.randint(1024, 65535)
        udp_length = 8 + len(payload)
        udp_header = struct.pack(
            "!HHHH",
            src_port,           # Source port
            self._target_port,  # Destination port
            udp_length,         # Length
            0,                  # Checksum (0 = let kernel handle)
        )

        # ── IP header (20 bytes, no options) ─────────────────────────── #
        ip_total_length = 20 + udp_length
        ip_id = random.randint(0, 65535)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,               # Version (4) + IHL (5) = 0x45
            0x00,               # DSCP / ECN
            ip_total_length,    # Total length
            ip_id,              # Identification
            0x4000,             # Flags (Don't Fragment) + Fragment Offset
            64,                 # TTL
            socket.IPPROTO_UDP, # Protocol
            0,                  # Header checksum (kernel fills this)
            socket.inet_aton("0.0.0.0"),       # Source IP (kernel fills)
            socket.inet_aton(self._target_ip),  # Destination IP
        )

        return ip_header + udp_header + payload

    # ── Sender Thread ─────────────────────────────────────────────────── #

    def _send_loop(self) -> None:
        """Tight send loop using a raw socket.

        Sends the pre-built packet as fast as possible, checking
        ``_stop_event`` every ``_STOP_CHECK_INTERVAL`` packets for
        instant abort on Ctrl+C.
        """
        packet = self._raw_packet
        packet_size = len(packet)
        dest = (self._target_ip, self._target_port)
        deadline = (
            time.monotonic() + self._duration
            if self._duration
            else float("inf")
        )

        try:
            # AF_INET + SOCK_RAW + IPPROTO_RAW:
            # - We supply the full IP header (IP_HDRINCL is implicit).
            # - The kernel fills in source IP and checksums.
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Set a small send buffer to detect NIC saturation faster.
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            except OSError:
                pass  # Not critical if we can't adjust buffer size

        except PermissionError:
            logger.error(
                "Cannot open raw socket — run as root/Administrator."
            )
            return
        except OSError as exc:
            logger.error("Failed to create raw socket: %s", exc)
            return

        try:
            count = 0
            while not self._stop_event.is_set() and time.monotonic() < deadline:
                try:
                    sock.sendto(packet, dest)
                    count += 1
                    self._metrics.total_packets += 1
                    self._metrics.total_bytes += packet_size

                    # Check stop event periodically (not every packet — too slow)
                    if count % _STOP_CHECK_INTERVAL == 0:
                        time.sleep(0.01)  # Ceder el control al OS obligatoriamente
                        if self._stop_event.is_set():
                            break
                except OSError:
                    # Send buffer full or transient error — skip and continue
                    time.sleep(0.01)  # Ceder el control y evitar 100% de CPU en ráfagas fallidas
                    pass
        finally:
            sock.close()

    # ── Metrics Thread ────────────────────────────────────────────────── #

    def _metrics_loop(self) -> None:
        """Print live PPS and Mbps stats every second.

        Reads the atomic counters from ``_metrics`` and computes
        delta-based throughput for the last interval.
        """
        interval = 1.0
        m = self._metrics

        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=interval)
            if self._stop_event.is_set():
                break

            now = time.monotonic()
            dt = now - m.last_report_time
            if dt <= 0:
                continue

            # Delta since last report
            delta_pkts = m.total_packets - m.last_report_packets
            delta_bytes = m.total_bytes - m.last_report_bytes

            pps = delta_pkts / dt
            mbps = (delta_bytes * 8 / 1_000_000) / dt

            # Track peaks
            if pps > m.peak_pps:
                m.peak_pps = pps
            if mbps > m.peak_mbps:
                m.peak_mbps = mbps

            # Update report baseline
            m.last_report_packets = m.total_packets
            m.last_report_bytes = m.total_bytes
            m.last_report_time = now

            # Elapsed since start
            elapsed = now - m.start_time

            # Live dashboard line (carriage return to overwrite)
            sys.stdout.write(
                f"\r  {_CYAN}⚡{_RESET} "
                f"{_BOLD}{pps:>10,.0f}{_RESET} PPS  │  "
                f"{_BOLD}{mbps:>8,.2f}{_RESET} Mbps  │  "
                f"Total: {_GREEN}{m.total_packets:>12,}{_RESET} pkts  │  "
                f"Elapsed: {_DIM}{elapsed:>6.1f}s{_RESET}  "
            )
            sys.stdout.flush()

        # Final newline after the live line
        sys.stdout.write("\n")
