"""
NetSleuth — Custom Domain Exceptions.

Provides a hierarchy of domain-specific exceptions to ensure robust
error handling across all layers without leaking implementation details.
"""


class NetSleuthError(Exception):
    """Base exception for all NetSleuth errors."""

    def __init__(self, message: str = "An unexpected NetSleuth error occurred.") -> None:
        self.message = message
        super().__init__(self.message)


class InsufficientPermissionsError(NetSleuthError):
    """Raised when the process lacks the required privileges (e.g., raw sockets).

    On Linux/macOS this typically means the tool must run as root.
    On Windows, it requires Administrator privileges and Npcap installed.
    """

    def __init__(self, detail: str = "") -> None:
        msg = (
            "Insufficient permissions to capture packets. "
            "Run as root/Administrator."
        )
        if detail:
            msg += f" Detail: {detail}"
        super().__init__(msg)


class NetworkInterfaceError(NetSleuthError):
    """Raised when the specified network interface is unavailable or invalid."""

    def __init__(self, interface: str) -> None:
        super().__init__(
            f"Network interface '{interface}' is not available or does not exist."
        )
        self.interface = interface


class SniffingError(NetSleuthError):
    """Raised when an unrecoverable error occurs during packet capture."""

    def __init__(self, detail: str = "Unknown sniffing error.") -> None:
        super().__init__(f"Packet capture failed: {detail}")


class AnalysisError(NetSleuthError):
    """Raised when a packet analysis operation fails."""

    def __init__(self, analyzer_name: str, detail: str = "") -> None:
        msg = f"Analysis failed in '{analyzer_name}'."
        if detail:
            msg += f" Detail: {detail}"
        super().__init__(msg)
        self.analyzer_name = analyzer_name


class VendorLookupError(NetSleuthError):
    """Raised when the external MAC vendor API call fails."""

    def __init__(self, mac_address: str, detail: str = "") -> None:
        msg = f"Vendor lookup failed for MAC '{mac_address}'."
        if detail:
            msg += f" Detail: {detail}"
        super().__init__(msg)
        self.mac_address = mac_address
