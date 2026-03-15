"""
NetSleuth — Abstract Interfaces (Ports).

Defines the contracts that the domain expects from the infrastructure
and application layers.  Following the Dependency Inversion Principle,
the core depends only on these abstractions — never on concrete
implementations like scapy or httpx.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, Sequence

from src.core.models import (
    DeviceFingerprint,
    NetworkDevice,
    ProtocolType,
    RawPacket,
)


# ── Packet Analysis ─────────────────────────────────────────────────────── #


class IPacketAnalyzer(ABC):
    """Port: strategy for analysing a specific protocol's packets.

    Each concrete analyzer (ARP, DHCP, TCP) implements this interface.
    The analyzer receives a domain-level ``RawPacket`` and returns an
    optional ``DeviceFingerprint``.
    """

    @property
    @abstractmethod
    def supported_protocol(self) -> ProtocolType:
        """The protocol type this analyzer handles."""
        ...

    @abstractmethod
    def analyze(self, packet: RawPacket) -> Optional[DeviceFingerprint]:
        """Analyse a raw packet and return a fingerprint, if possible.

        Args:
            packet: Domain-level packet to analyse.

        Returns:
            A ``DeviceFingerprint`` if the packet yielded useful data,
            or ``None`` if the packet was not relevant.
        """
        ...


# ── Packet Source (Capture) ──────────────────────────────────────────────── #


class IPacketListener(ABC):
    """Observer callback invoked when a new packet is captured."""

    @abstractmethod
    def on_packet(self, packet: RawPacket) -> None:
        """Handle an incoming captured packet.

        Args:
            packet: The captured packet, already converted to a domain model.
        """
        ...


class IPacketSource(ABC):
    """Port: abstraction over a live packet capture mechanism.

    Concrete implementations wrap scapy, tcpdump, or a PCAP file reader.
    """

    @abstractmethod
    def start(self) -> None:
        """Begin capturing packets (may run in a background thread)."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Signal the capture to stop gracefully."""
        ...

    @abstractmethod
    def subscribe(self, listener: IPacketListener) -> None:
        """Register a listener that will be notified of each new packet.

        Args:
            listener: An object implementing ``IPacketListener``.
        """
        ...

    @abstractmethod
    def unsubscribe(self, listener: IPacketListener) -> None:
        """Remove a previously registered listener.

        Args:
            listener: The listener to remove.
        """
        ...


# ── Active Scanner ───────────────────────────────────────────────────────── #


class IActiveScanner(ABC):
    """Port: active network probing mechanism.

    Concrete implementations send ARP broadcasts, TCP SYN probes,
    or other packets to force silent devices to reveal themselves.
    Responses are captured by the passive ``IPacketSource``.
    """

    @abstractmethod
    def start(self) -> None:
        """Begin sending active probes (runs in a background thread)."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Signal the active scanner to stop gracefully."""
        ...


# ── Stress Tester ────────────────────────────────────────────────────────── #


class IStressTester(ABC):
    """Port: high-throughput packet injection for stress testing.

    Concrete implementations use raw sockets or ``sendpfast()`` to
    measure the maximum PPS/Mbps capacity of a network interface.

    .. warning::
        This can cause Denial of Service (DoS).  Use only on networks
        you own and have explicit authorization to test.
    """

    @abstractmethod
    def start(self) -> None:
        """Begin the stress test (runs in background threads)."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Signal the stress test to stop immediately."""
        ...

    @abstractmethod
    def get_summary(self) -> dict[str, object]:
        """Return a summary of the test results.

        Returns:
            Dict with keys like ``total_packets``, ``avg_pps``,
            ``peak_pps``, ``avg_mbps``, ``peak_mbps``, etc.
        """
        ...


# ── Vendor Lookup ────────────────────────────────────────────────────────── #


class IVendorLookup(ABC):
    """Port: resolve a MAC address OUI to its manufacturer name."""

    @abstractmethod
    def lookup(self, mac_address: str) -> Optional[str]:
        """Look up the vendor for a given MAC address.

        Args:
            mac_address: A colon-separated MAC address (e.g., "AA:BB:CC:DD:EE:FF").

        Returns:
            The vendor/manufacturer name, or ``None`` if not found.
        """
        ...


# ── Device Store ─────────────────────────────────────────────────────────── #


class IDeviceStore(ABC):
    """Port: persistent (or in-memory) device registry."""

    @abstractmethod
    def upsert(self, device: NetworkDevice) -> None:
        """Insert a new device or update an existing one (keyed by MAC).

        Args:
            device: The device to insert or update.
        """
        ...

    @abstractmethod
    def get_all(self) -> Sequence[NetworkDevice]:
        """Return all discovered devices.

        Returns:
            An ordered sequence of ``NetworkDevice`` objects.
        """
        ...

    @abstractmethod
    def find_by_mac(self, mac_address: str) -> Optional[NetworkDevice]:
        """Find a device by its MAC address.

        Args:
            mac_address: Colon-separated MAC address.

        Returns:
            The matching ``NetworkDevice``, or ``None``.
        """
        ...
