"""
NetSleuth — Domain Models.

Immutable data classes representing the core entities of the system.
These models have zero external dependencies and are shared across all layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional


class ProtocolType(Enum):
    """Enumeration of network protocols that NetSleuth can analyse."""

    ARP = auto()
    DHCP = auto()
    TCP = auto()
    UNKNOWN = auto()


class DeviceType(Enum):
    """High-level device classification derived from fingerprinting."""

    PC = "PC"
    MOBILE = "Mobile"
    TV = "Smart TV"
    IOT = "IoT Device"
    ROUTER = "Router/Gateway"
    PRINTER = "Printer"
    UNKNOWN = "Unknown"


@dataclass(frozen=True)
class RawPacket:
    """Lightweight, protocol-agnostic representation of a captured packet.

    Attributes:
        timestamp: UTC time the packet was captured.
        protocol: Detected protocol type.
        src_mac: Source MAC address (colon-separated).
        dst_mac: Destination MAC address (colon-separated).
        src_ip: Source IP address, if available.
        dst_ip: Destination IP address, if available.
        raw_payload: The raw bytes of the interesting layer for deeper analysis.
        metadata: Additional protocol-specific key-value pairs
                  (e.g., DHCP options, TCP flags).
    """

    timestamp: datetime
    protocol: ProtocolType
    src_mac: str
    dst_mac: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    raw_payload: bytes = b""
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class DeviceFingerprint:
    """Result of analysing a single packet or packet group.

    Attributes:
        os_guess: Best-guess operating system string (e.g., "Windows 11", "Linux 5.x").
        device_type: High-level device category.
        confidence: Confidence score from 0.0 (no confidence) to 1.0 (certain).
        method: Name of the analysis method that produced this fingerprint.
        details: Human-readable explanation of how the fingerprint was derived.
    """

    os_guess: str
    device_type: DeviceType
    confidence: float
    method: str
    details: str = ""

    def __post_init__(self) -> None:
        """Validate that confidence is within the expected range."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"Confidence must be between 0.0 and 1.0, got {self.confidence}"
            )


@dataclass
class NetworkDevice:
    """Aggregated representation of a single device discovered on the network.

    This is a *mutable* dataclass because devices are updated incrementally
    as new packets are captured and analysed.

    Attributes:
        mac_address: Device's MAC address (canonical form, uppercase, colon-separated).
        ip_address: Most recently observed IP address.
        vendor: Vendor/manufacturer string resolved from the MAC OUI.
        hostname: DHCP-reported hostname, if available.
        fingerprints: Accumulated fingerprint results from different analyzers.
        first_seen: Timestamp when this device was first observed.
        last_seen: Timestamp of the most recent observation.
    """

    mac_address: str
    ip_address: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    fingerprints: list[DeviceFingerprint] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)

    # -- Computed helpers -------------------------------------------------- #

    @property
    def best_os_guess(self) -> str:
        """Return the OS guess with the highest confidence, or 'Unknown'."""
        if not self.fingerprints:
            return "Unknown"
        best = max(self.fingerprints, key=lambda fp: fp.confidence)
        return best.os_guess

    @property
    def best_device_type(self) -> DeviceType:
        """Return the device type with the highest confidence."""
        if not self.fingerprints:
            return DeviceType.UNKNOWN
        best = max(self.fingerprints, key=lambda fp: fp.confidence)
        return best.device_type

    def add_fingerprint(self, fingerprint: DeviceFingerprint) -> None:
        """Append a new fingerprint and refresh *last_seen*.

        Args:
            fingerprint: The fingerprint to add.
        """
        self.fingerprints.append(fingerprint)
        self.last_seen = datetime.utcnow()
