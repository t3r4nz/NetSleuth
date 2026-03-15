"""
NetSleuth — Analyzer Factory.

Implements the Factory pattern to instantiate the correct
``IPacketAnalyzer`` for a given ``ProtocolType``.

New analyzers can be registered at runtime via ``register()``,
satisfying the Open/Closed Principle — the factory is open for
extension but closed for modification.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, Optional, Type

from src.core.interfaces import IPacketAnalyzer
from src.core.models import ProtocolType

logger = logging.getLogger(__name__)

# Type alias: a factory callable that creates an IPacketAnalyzer instance.
AnalyzerConstructor = Callable[[], IPacketAnalyzer]


class AnalyzerFactory:
    """Factory that maps ``ProtocolType`` → ``IPacketAnalyzer`` instances.

    Usage::

        factory = AnalyzerFactory()
        factory.register(ProtocolType.ARP, ARPAnalyzer)
        factory.register(ProtocolType.DHCP, DHCPAnalyzer)

        analyzer = factory.create(ProtocolType.ARP)
        if analyzer:
            result = analyzer.analyze(packet)

    The factory stores **constructors** (classes or callables), not live
    instances — each ``create()`` call returns a fresh analyzer.  If you
    prefer singletons, wrap the constructor accordingly.
    """

    def __init__(self) -> None:
        self._registry: Dict[ProtocolType, AnalyzerConstructor] = {}

    def register(
        self,
        protocol: ProtocolType,
        constructor: AnalyzerConstructor,
    ) -> None:
        """Register a constructor for a given protocol type.

        If the protocol is already registered, the previous entry is
        silently overwritten (useful for testing / overriding defaults).

        Args:
            protocol: The protocol this analyzer handles.
            constructor: A callable (typically a class) that returns an
                         ``IPacketAnalyzer`` instance when invoked.
        """
        self._registry[protocol] = constructor
        logger.debug(
            "Registered analyzer '%s' for protocol %s.",
            getattr(constructor, "__name__", str(constructor)),
            protocol.name,
        )

    def create(self, protocol: ProtocolType) -> Optional[IPacketAnalyzer]:
        """Instantiate the analyzer for the given protocol.

        Args:
            protocol: The protocol type to look up.

        Returns:
            A fresh ``IPacketAnalyzer`` instance, or ``None`` if no
            analyzer is registered for the protocol.
        """
        constructor = self._registry.get(protocol)
        if constructor is None:
            logger.warning("No analyzer registered for protocol %s.", protocol.name)
            return None
        return constructor()

    @property
    def registered_protocols(self) -> list[ProtocolType]:
        """List all protocols that have a registered analyzer."""
        return list(self._registry.keys())
