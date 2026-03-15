"""
NetSleuth — Packet Capture Engine (Sniffer).

Threaded packet capture using ``scapy.sniff()``.  This module implements
both ``IPacketSource`` and ``PacketSubject`` to bridge live network
traffic into the domain layer.

Concurrency model
-----------------
- ``scapy.sniff()`` runs on a **daemon thread** so it does not block
  the main thread.
- A ``threading.Event`` (``_stop_event``) signals the sniffer to stop
  gracefully.
- Each captured packet is converted into a ``RawPacket`` and
  broadcast to all registered ``IPacketListener`` instances via the
  ``PacketSubject.notify()`` mechanism (Observer pattern).
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from src.core.exceptions import (
    InsufficientPermissionsError,
    NetworkInterfaceError,
    SniffingError,
)
from src.core.interfaces import IPacketListener, IPacketSource
from src.core.models import ProtocolType, RawPacket
from src.core.observer import PacketSubject

logger = logging.getLogger(__name__)


class PacketCapture(PacketSubject, IPacketSource):
    """Live network packet capture powered by scapy.

    This class runs ``scapy.sniff()`` in a background thread and
    converts each captured frame into a domain-level ``RawPacket``,
    then notifies all subscribed listeners.

    Args:
        interface: The network interface to listen on (e.g., ``"eth0"``).
                   ``None`` uses scapy's default (all interfaces).
        bpf_filter: Optional BPF filter string (e.g., ``"arp or port 67"``).
        timeout: Maximum capture duration in seconds; ``None`` = indefinite.

    Example::

        sniffer = PacketCapture(interface="eth0", bpf_filter="arp or port 67")
        sniffer.subscribe(my_listener)
        sniffer.start()
        # ... later ...
        sniffer.stop()
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        super().__init__()
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._timeout = timeout
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── IPacketSource implementation ──────────────────────────────────── #

    def start(self) -> None:
        """Start packet capture in a background daemon thread.

        Raises:
            InsufficientPermissionsError: If raw socket access is denied.
            NetworkInterfaceError: If the interface does not exist.
            SniffingError: On any other capture-related error.
        """
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Sniffer is already running.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._sniff_loop,
            name="netsleuth-sniffer",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Sniffer started on interface=%s filter='%s' timeout=%s",
            self._interface or "ALL",
            self._bpf_filter or "",
            self._timeout,
        )

    def stop(self) -> None:
        """Signal the sniffer thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            logger.info("Sniffer stopped.")
            self._thread = None

    def subscribe(self, listener: IPacketListener) -> None:
        """Register a packet listener (delegates to ``PacketSubject``)."""
        super().subscribe(listener)

    def unsubscribe(self, listener: IPacketListener) -> None:
        """Remove a packet listener (delegates to ``PacketSubject``)."""
        super().unsubscribe(listener)

    # ── Internal capture loop ─────────────────────────────────────────── #

    def _sniff_loop(self) -> None:
        """Entry point for the background sniffer thread.

        Wraps ``scapy.sniff()`` and translates low-level OS errors into
        domain-specific exceptions.
        """
        try:
            # Late import so the rest of the codebase can be tested
            # without scapy installed.
            from scapy.all import sniff as scapy_sniff  # type: ignore[import-untyped]

            sniff_kwargs: dict[str, object] = {
                "filter": self._bpf_filter,
                "prn": self._handle_packet,
                "store": False,
                "stop_filter": lambda _pkt: self._stop_event.is_set(),
                "timeout": self._timeout,
            }

            # Only pass iface if explicitly set — None causes
            # ValueError: Interface 'None' not found!
            if self._interface is not None:
                sniff_kwargs["iface"] = self._interface

            scapy_sniff(**sniff_kwargs)
        except PermissionError as exc:
            logger.error("Permission denied: %s", exc)
            raise InsufficientPermissionsError(str(exc)) from exc
        except OSError as exc:
            error_msg = str(exc).lower()
            if "no such device" in error_msg or "no such interface" in error_msg:
                raise NetworkInterfaceError(self._interface or "default") from exc
            raise SniffingError(str(exc)) from exc
        except Exception as exc:
            raise SniffingError(str(exc)) from exc

    def _handle_packet(self, scapy_packet: object) -> None:
        """Callback invoked by scapy for each captured packet.

        Converts the scapy packet into a domain ``RawPacket`` and
        notifies all listeners.

        Args:
            scapy_packet: The raw scapy packet object.
        """
        try:
            raw_packet = self._convert_packet(scapy_packet)
            if raw_packet is not None:
                self.notify(raw_packet)
        except Exception:
            logger.exception("Error converting/dispatching packet.")

    # ── Packet conversion ─────────────────────────────────────────────── #

    @staticmethod
    def _convert_packet(scapy_packet: object) -> Optional[RawPacket]:
        """Convert a scapy packet into a domain-level ``RawPacket``.

        Only packets containing ARP, DHCP (BOOTP), or TCP layers are
        converted; everything else is silently dropped.

        Args:
            scapy_packet: A scapy packet object.

        Returns:
            A ``RawPacket`` or ``None`` if the packet is not interesting.
        """
        # Late imports to keep scapy out of the module-level namespace.
        from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
        from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]
        from scapy.layers.dhcp import BOOTP, DHCP  # type: ignore[import-untyped]

        pkt = scapy_packet  # type alias for readability

        # Determine Ethernet-level MACs (fallback to empty string).
        src_mac = pkt.src if hasattr(pkt, "src") else ""
        dst_mac = pkt.dst if hasattr(pkt, "dst") else ""

        now = datetime.now(tz=timezone.utc)

        # ── ARP ──────────────────────────────────────────────────────── #
        if pkt.haslayer(ARP):
            arp_layer = pkt.getlayer(ARP)
            return RawPacket(
                timestamp=now,
                protocol=ProtocolType.ARP,
                src_mac=arp_layer.hwsrc,
                dst_mac=arp_layer.hwdst,
                src_ip=arp_layer.psrc,
                dst_ip=arp_layer.pdst,
                metadata={"op": arp_layer.op},
            )

        # ── DHCP ─────────────────────────────────────────────────────── #
        if pkt.haslayer(DHCP):
            bootp = pkt.getlayer(BOOTP)
            dhcp_layer = pkt.getlayer(DHCP)
            options: dict[str, object] = {}
            if dhcp_layer and hasattr(dhcp_layer, "options"):
                for opt in dhcp_layer.options:
                    if isinstance(opt, tuple) and len(opt) >= 2:
                        options[str(opt[0])] = opt[1]
            return RawPacket(
                timestamp=now,
                protocol=ProtocolType.DHCP,
                src_mac=bootp.chaddr[:6].hex(":") if bootp else src_mac,
                dst_mac=dst_mac,
                src_ip=pkt[IP].src if pkt.haslayer(IP) else None,
                dst_ip=pkt[IP].dst if pkt.haslayer(IP) else None,
                metadata=options,
            )

        # ── TCP SYN ──────────────────────────────────────────────────── #
        if pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            # Only SYN packets (flags == 0x02) are useful for OS fingerprinting.
            if tcp_layer.flags == 0x02:
                ip_layer = pkt.getlayer(IP)
                return RawPacket(
                    timestamp=now,
                    protocol=ProtocolType.TCP,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    src_ip=ip_layer.src if ip_layer else None,
                    dst_ip=ip_layer.dst if ip_layer else None,
                    metadata={
                        "ttl": ip_layer.ttl if ip_layer else 0,
                        "window_size": tcp_layer.window,
                        "flags": str(tcp_layer.flags),
                        "options": tcp_layer.options,
                    },
                )

        return None
