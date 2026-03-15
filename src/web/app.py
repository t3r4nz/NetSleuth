"""
NetSleuth — FastAPI Web Application.

Exposes the core engine (passive/active scanning and stress testing)
through a REST + WebSocket API.  The frontend connects via WebSocket
to ``/ws/live`` and receives real-time device and stress-test metrics.

Architecture
------------
FastAPI is **only a consumer** of the domain interfaces:
    - ``IDeviceStore`` → read discovered devices
    - ``IStressTester`` → start/stop + read metrics
    - ``AnalysisEngine`` → packet/fingerprint counters

No domain logic lives here — this is strictly a *presentation adapter*.

Threading model
---------------
The engine threads (sniffer, active scanner, stress tester) run via
``daemon=True`` threads.  The FastAPI event loop (asyncio, managed
by Uvicorn) never blocks.  WebSocket push loops use
``asyncio.sleep()`` and read thread-safe counters/stores.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.analyzers.arp_analyzer import ARPAnalyzer
from src.analyzers.dhcp_analyzer import DHCPAnalyzer
from src.analyzers.tcp_analyzer import TCPAnalyzer
from src.analyzers.mdns_ssdp_analyzer import MdnsSsdpAnalyzer
from src.core.analyzer_factory import AnalyzerFactory
from src.core.models import ProtocolType
from src.engine.analysis_engine import AnalysisEngine
from src.engine.sniffer import PacketCapture
from src.services.device_store import InMemoryDeviceStore
from src.services.vendor_lookup import MacVendorLookup

logger = logging.getLogger(__name__)

# ── Pydantic request/response models ─────────────────────────────────────── #


class ScanRequest(BaseModel):
    """Request body for starting a scan."""
    mode: str = "passive"          # "passive" | "active"
    interface: Optional[str] = None
    subnet: Optional[str] = None
    timeout: Optional[int] = None


class StressRequest(BaseModel):
    """Request body for starting a stress test."""
    target_ip: str
    duration: Optional[int] = 10


class StatusResponse(BaseModel):
    """Generic status response."""
    status: str
    message: str


# ── Template directory ────────────────────────────────────────────────────── #
_TEMPLATE_DIR = Path(__file__).parent / "templates"


# ── Application factory ──────────────────────────────────────────────────── #


def create_app(
    interface: Optional[str] = None,
    verbose: bool = False,
) -> FastAPI:
    """Build and return a configured FastAPI application.

    Args:
        interface: Network interface to use (auto-detected if ``None``).
        verbose: Enable debug logging.

    Returns:
        A ready-to-serve ``FastAPI`` instance.
    """
    app = FastAPI(
        title="NetSleuth Dashboard",
        version="0.4.0",
        description="Real-time network reconnaissance dashboard",
    )

    # ── Shared state (request-scoped singletons) ──────────────────────── #
    state = _AppState(interface=interface, verbose=verbose)
    app.state.ns = state

    # ── Routes ────────────────────────────────────────────────────────── #

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Serve the SPA dashboard."""
        html_path = _TEMPLATE_DIR / "index.html"
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

    # ── Scan control ──────────────────────────────────────────────────── #

    @app.post("/api/scan/start", response_model=StatusResponse)
    async def start_scan(req: ScanRequest) -> StatusResponse:
        """Start a passive or active scan."""
        if state.scan_active:
            return StatusResponse(status="error", message="Scan already running.")

        try:
            state.start_scan(
                mode=req.mode,
                interface=req.interface,
                subnet=req.subnet,
                timeout=req.timeout,
            )
            return StatusResponse(status="ok", message=f"{req.mode.title()} scan started.")
        except Exception as exc:
            return StatusResponse(status="error", message=str(exc))

    @app.post("/api/scan/stop", response_model=StatusResponse)
    async def stop_scan() -> StatusResponse:
        """Stop the running scan."""
        state.stop_scan()
        return StatusResponse(status="ok", message="Scan stopped.")

    # ── Stress test control ───────────────────────────────────────────── #

    @app.post("/api/stress/start", response_model=StatusResponse)
    async def start_stress(req: StressRequest) -> StatusResponse:
        """Start a stress test (confirmation handled by frontend)."""
        if state.stress_active:
            return StatusResponse(status="error", message="Stress test already running.")

        try:
            state.start_stress(
                target_ip=req.target_ip,
                duration=req.duration,
            )
            return StatusResponse(
                status="ok",
                message=f"Stress test started → {req.target_ip}",
            )
        except Exception as exc:
            return StatusResponse(status="error", message=str(exc))

    @app.post("/api/stress/stop", response_model=StatusResponse)
    async def stop_stress() -> StatusResponse:
        """Emergency stop for stress test."""
        state.stop_stress()
        return StatusResponse(status="ok", message="Stress test stopped.")

    # ── Kill switch (stops everything) ────────────────────────────────── #

    @app.post("/api/kill", response_model=StatusResponse)
    async def kill_all() -> StatusResponse:
        """Emergency abort — stops all running operations."""
        state.kill_all()
        return StatusResponse(status="ok", message="All operations stopped.")

    # ── Device list (REST fallback) ───────────────────────────────────── #

    @app.get("/api/devices")
    async def get_devices() -> list[dict]:
        """Return the current device list as JSON."""
        return state.get_devices_json()

    # ── WebSocket: live telemetry ─────────────────────────────────────── #

    @app.websocket("/ws/live")
    async def ws_live(ws: WebSocket) -> None:
        """Push live device list + stress metrics every 1 second."""
        await ws.accept()
        logger.info("WebSocket client connected.")

        try:
            while True:
                payload = state.build_ws_payload()
                await ws.send_text(json.dumps(payload))
                await asyncio.sleep(1)
        except WebSocketDisconnect:
            logger.info("WebSocket client disconnected.")
        except Exception:
            logger.debug("WebSocket connection closed.")

    return app


# ── Application State Manager ────────────────────────────────────────────── #


class _AppState:
    """Manages the lifecycle of engine components for the web layer.

    Encapsulates the sniffer, analysis engine, active scanner, and
    stress tester — exposing simple start/stop methods and JSON
    serializers for the WebSocket.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        self._verbose = verbose
        self._default_interface = interface

        # Resolved at scan-start time
        self._interface: Optional[str] = interface
        self._subnet: Optional[str] = None

        # Engine components (created on demand)
        self._device_store = InMemoryDeviceStore()
        self._vendor_lookup = MacVendorLookup()
        self._engine: Optional[AnalysisEngine] = None
        self._sniffer: Optional[PacketCapture] = None
        self._active_scanner = None
        self._stress_tester = None

        # Status flags
        self.scan_active = False
        self.stress_active = False

    # ── Scan lifecycle ────────────────────────────────────────────────── #

    def start_scan(
        self,
        mode: str = "passive",
        interface: Optional[str] = None,
        subnet: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Build engine components and start scanning."""
        from src.engine.network_utils import detect_default_interface, get_local_subnet

        self._interface = interface or self._default_interface
        if self._interface is None:
            self._interface = detect_default_interface()

        self._subnet = subnet
        if mode == "active" and self._subnet is None:
            self._subnet = get_local_subnet(self._interface)

        # Fresh stores for new scan
        self._device_store.clear()

        # Factory
        factory = AnalyzerFactory()
        factory.register(ProtocolType.ARP, ARPAnalyzer)
        factory.register(ProtocolType.DHCP, DHCPAnalyzer)
        factory.register(ProtocolType.TCP, TCPAnalyzer)
        factory.register(ProtocolType.MDNS_SSDP, MdnsSsdpAnalyzer)

        # Analysis engine
        self._engine = AnalysisEngine(
            factory=factory,
            device_store=self._device_store,
            vendor_lookup=self._vendor_lookup,
        )

        # BPF filter
        bpf = (
            "arp or port 67 or port 68 "
            "or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0) "
            "or udp port 5353 or udp port 1900 "
            "or udp port 19132 or tcp port 62078"
        )

        # Sniffer
        self._sniffer = PacketCapture(
            interface=self._interface,
            bpf_filter=bpf,
            timeout=timeout,
        )
        self._sniffer.subscribe(self._engine)
        self._sniffer.start()

        # Active scanner
        if mode == "active" and self._subnet:
            import time as _time
            _time.sleep(0.3)
            from src.engine.active_scanner import ActiveScanner
            self._active_scanner = ActiveScanner(
                interface=self._interface,
                subnet=self._subnet,
            )
            self._active_scanner.start()

        self.scan_active = True
        logger.info("Scan started: mode=%s iface=%s subnet=%s", mode, self._interface, self._subnet)

    def stop_scan(self) -> None:
        """Stop the sniffer and active scanner."""
        if self._active_scanner is not None:
            self._active_scanner.stop()
            self._active_scanner = None
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
        self.scan_active = False
        logger.info("Scan stopped.")

    # ── Stress test lifecycle ─────────────────────────────────────────── #

    def start_stress(
        self,
        target_ip: str,
        duration: Optional[int] = 10,
    ) -> None:
        """Start the stress tester (sniffer monitors in background)."""
        from src.engine.network_utils import detect_default_interface
        from src.engine.stress_tester import StressTester

        if self._interface is None:
            self._interface = self._default_interface or detect_default_interface()

        # Start a background sniffer to monitor the flood
        if self._sniffer is None:
            factory = AnalyzerFactory()
            factory.register(ProtocolType.ARP, ARPAnalyzer)
            factory.register(ProtocolType.DHCP, DHCPAnalyzer)
            factory.register(ProtocolType.TCP, TCPAnalyzer)
            factory.register(ProtocolType.MDNS_SSDP, MdnsSsdpAnalyzer)
            self._engine = AnalysisEngine(
                factory=factory,
                device_store=self._device_store,
                vendor_lookup=self._vendor_lookup,
            )
            bpf = (
                "arp or port 67 or port 68 "
                "or (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0) "
                "or udp port 5353 or udp port 1900 "
                "or udp port 19132 or tcp port 62078"
            )
            self._sniffer = PacketCapture(
                interface=self._interface,
                bpf_filter=bpf,
                timeout=duration,
            )
            self._sniffer.subscribe(self._engine)
            self._sniffer.start()

        self._stress_tester = StressTester(
            target_ip=target_ip,
            interface=self._interface,
            duration=duration,
        )
        self._stress_tester.start()
        self.stress_active = True
        logger.info("Stress test started: target=%s duration=%s", target_ip, duration)

    def stop_stress(self) -> None:
        """Stop the stress tester immediately."""
        if self._stress_tester is not None:
            self._stress_tester.stop()
            self._stress_tester = None
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
        self.stress_active = False
        logger.info("Stress test stopped.")

    # ── Kill switch ───────────────────────────────────────────────────── #

    def kill_all(self) -> None:
        """Stop everything immediately."""
        self.stop_stress()
        self.stop_scan()
        logger.warning("KILL SWITCH activated — all operations stopped.")

    # ── Data serializers ──────────────────────────────────────────────── #

    def get_devices_json(self) -> list[dict]:
        """Serialize all devices to JSON-friendly dicts."""
        devices = self._device_store.get_all()
        result = []
        for d in devices:
            best_conf = 0.0
            if d.fingerprints:
                best_conf = max(fp.confidence for fp in d.fingerprints)
            result.append({
                "mac": d.mac_address,
                "ip": d.ip_address or "—",
                "vendor": d.vendor or "Unknown",
                "hostname": d.hostname or "",
                "os": d.best_os_guess,
                "type": d.best_device_type.value,
                "confidence": f"{best_conf * 100:.0f}%",
                "services": d.services_list,
                "first_seen": d.first_seen.strftime("%H:%M:%S"),
                "last_seen": d.last_seen.strftime("%H:%M:%S"),
            })
        return result

    def build_ws_payload(self) -> dict:
        """Build the full WebSocket payload."""
        payload: dict = {
            "scan_active": self.scan_active,
            "stress_active": self.stress_active,
            "devices": self.get_devices_json(),
            "device_count": self._device_store.count,
            "packets_processed": self._engine.packets_processed if self._engine else 0,
            "fingerprints_found": self._engine.fingerprints_found if self._engine else 0,
        }

        # Stress metrics
        if self._stress_tester is not None:
            summary = self._stress_tester.get_summary()
            payload["stress"] = summary
        else:
            payload["stress"] = None

        # Active scanner metrics
        if self._active_scanner is not None:
            payload["active_probes_sent"] = self._active_scanner.packets_sent
        else:
            payload["active_probes_sent"] = 0

        return payload
