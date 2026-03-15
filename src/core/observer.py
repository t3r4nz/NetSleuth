"""
NetSleuth — Observer Pattern Implementation.

Provides a reusable Subject mixin and a concrete ``PacketSubject``
that the sniffer inherits to broadcast captured packets to all
registered ``IPacketListener`` instances.

Thread-safety: the listener list is guarded by a ``threading.Lock``
because subscribers may be added/removed from the main thread while
the sniffer thread is iterating over listeners.
"""

from __future__ import annotations

import logging
import threading
from typing import List

from src.core.interfaces import IPacketListener
from src.core.models import RawPacket

logger = logging.getLogger(__name__)


class PacketSubject:
    """Observable mixin that manages a list of packet listeners.

    Any class that captures or produces ``RawPacket`` objects can inherit
    from ``PacketSubject`` to gain publish/subscribe capabilities.

    Example::

        class MySniffer(PacketSubject):
            def _on_capture(self, pkt):
                raw = self._convert(pkt)
                self.notify(raw)

    Attributes:
        _listeners: Internal list of registered listeners.
        _listeners_lock: Lock guarding concurrent access to ``_listeners``.
    """

    def __init__(self) -> None:
        self._listeners: List[IPacketListener] = []
        self._listeners_lock = threading.Lock()

    def subscribe(self, listener: IPacketListener) -> None:
        """Register a listener to be notified on each captured packet.

        Duplicate registrations are silently ignored.

        Args:
            listener: Object implementing ``IPacketListener``.
        """
        with self._listeners_lock:
            if listener not in self._listeners:
                self._listeners.append(listener)
                logger.debug("Listener %s subscribed.", type(listener).__name__)

    def unsubscribe(self, listener: IPacketListener) -> None:
        """Remove a previously registered listener.

        If the listener is not found, the call is a no-op.

        Args:
            listener: The listener to remove.
        """
        with self._listeners_lock:
            try:
                self._listeners.remove(listener)
                logger.debug("Listener %s unsubscribed.", type(listener).__name__)
            except ValueError:
                logger.warning(
                    "Attempted to unsubscribe a listener that was not registered: %s",
                    type(listener).__name__,
                )

    def notify(self, packet: RawPacket) -> None:
        """Broadcast a captured packet to every registered listener.

        Each listener is called within a try/except so that a failing
        listener does not prevent the others from receiving the packet.

        Args:
            packet: The domain-level packet to deliver.
        """
        with self._listeners_lock:
            listeners_snapshot = list(self._listeners)

        for listener in listeners_snapshot:
            try:
                listener.on_packet(packet)
            except Exception:
                logger.exception(
                    "Listener %s raised an exception while handling a packet.",
                    type(listener).__name__,
                )
