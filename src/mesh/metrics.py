"""Prometheus metrics endpoint for the wg-mesh controller.

Exposes ``/metrics`` over HTTP using a lightweight ``asyncio.start_server``
handler — no web framework required.  Each ``MetricsServer`` owns its own
``CollectorRegistry`` and counters, so multiple controller instances never
share mutable state.

The ``prometheus_client`` library is imported lazily — if it is not installed,
``setup()`` returns a no-op stub and the controller operates without
observability.

Usage from the controller::

    from . import metrics
    server = metrics.setup(controller, addr="127.0.0.1", port=9586)
    await server.start()   # non-blocking, runs on the event loop
    ...
    await server.stop()    # graceful shutdown
"""

from abc import ABC, abstractmethod
import asyncio
import logging
from typing import TYPE_CHECKING, Any, Protocol


if TYPE_CHECKING:
    from .mesh import MeshController

logger = logging.getLogger(__name__)

pkt_type_names: dict[int, str] = {1: "announce", 2: "ack", 3: "route_cost"}


class CounterProtocol(Protocol):
    def labels(self, *args: Any, **kwargs: Any) -> CounterProtocol: ...
    def inc(self, amount=1, exemplar: dict = None) -> None: ...


class BaseCounter:
    def labels(self, *_, **__):
        return self

    def inc(self, *_, **__):
        pass


# ---------------------------------------------------------------------------
#  Custom collector — reads live controller state on each scrape
# ---------------------------------------------------------------------------


class MeshCollector:
    """Yields per-scrape gauge families from live ``MeshController`` state.

    Using a custom collector (rather than persistent ``Gauge`` objects) means
    departed peers automatically disappear from the output — no explicit
    ``.remove()`` cleanup required.
    """

    def __init__(self, controller: MeshController) -> None:
        self.controller = controller

    def describe(self):
        return []

    def collect(self):
        from prometheus_client.core import GaugeMetricFamily

        ctrl = self.controller

        # -- scalar gauges ---------------------------------------------------
        from ._version import VERSION_STR

        info = GaugeMetricFamily(
            "wgmesh_info",
            "Static build / identity information (always 1).",
            labels=["version", "node_id", "node_name"],
        )
        info.add_metric(
            [VERSION_STR, str(ctrl.me.node_id), ctrl.me.name],
            1,
        )
        yield info

        peer_count = len(ctrl.known_nodes) - 1  # exclude self
        yield GaugeMetricFamily(
            "wgmesh_peers_total", "Number of known peers.", value=max(peer_count, 0)
        )

        yield GaugeMetricFamily(
            "wgmesh_pending_acks",
            "Number of in-flight reliable sends awaiting ACK.",
            value=len(ctrl.pending_acks),
        )

        yield GaugeMetricFamily(
            "wgmesh_seq_num",
            "Local gossip sequence number.",
            value=ctrl.me.seq_num,
        )

        # Online status (1 = online, 0 = offline)
        is_offline = True
        if monitor := ctrl.daemons.get("online_monitor"):
            is_offline = monitor.is_offline
        yield GaugeMetricFamily(
            "wgmesh_online_status",
            "Whether this node considers itself online (1) or offline (0).",
            value=0 if is_offline else 1,
        )

        # Route table size
        if ctrl.seg6_controller is not None:
            yield GaugeMetricFamily(
                "wgmesh_route_table_entries",
                "Number of SRv6 route table entries.",
                value=ctrl.seg6_controller.route_table_size,
            )

        # -- per-peer gauges -------------------------------------------------
        try:
            loop_time = asyncio.get_event_loop().time()
        except RuntimeError:
            loop_time = 0.0

        rtt = GaugeMetricFamily(
            "wgmesh_peer_rtt_milliseconds",
            "Exponential-decay-weighted link cost (RTT) to each peer, in ms.",
            labels=["peer_id", "peer_name"],
        )
        online = GaugeMetricFamily(
            "wgmesh_peer_online",
            "Whether a peer's link cost is below the unreachable threshold (1=yes).",
            labels=["peer_id", "peer_name"],
        )
        for nid, node in ctrl.known_nodes.items():
            if nid == ctrl.me.node_id:
                continue
            cost = node.get_link_cost(loop_time)
            labels = [str(nid), node.name]
            rtt.add_metric(labels, cost)
            online.add_metric(labels, 1 if cost < 3000 else 0)
        yield rtt
        yield online


# ---------------------------------------------------------------------------
#  Async HTTP server — serves /metrics, owns registry and counters
# ---------------------------------------------------------------------------


class Server(ABC):
    packets_total: CounterProtocol
    packets_dropped_total: CounterProtocol
    reliable_send_total: CounterProtocol
    config_reloads_total: CounterProtocol

    @abstractmethod
    async def start(self) -> None:
        pass

    @abstractmethod
    async def stop(self) -> None:
        pass

class PrometheusMetricsServer(Server):
    """Minimal async HTTP server that serves the ``/metrics`` endpoint."""

    def __init__(self, addr: str, port: int, controller: MeshController) -> None:
        from prometheus_client import Counter, CollectorRegistry

        self.addr = addr
        self.port = port
        self.server: asyncio.Server | None = None

        # Per-instance registry and counters
        self.registry = CollectorRegistry()
        self.collector = MeshCollector(controller)
        self.registry.register(self.collector)

        self.packets_total = Counter(
            "wgmesh_gossip_packets_total",
            "Total gossip packets sent or received.",
            ["type", "direction"],
            registry=self.registry,
        )
        self.packets_dropped_total = Counter(
            "wgmesh_gossip_packets_dropped_total",
            "Gossip packets dropped before processing.",
            ["reason"],
            registry=self.registry,
        )
        self.reliable_send_total = Counter(
            "wgmesh_reliable_send_total",
            "Outcomes of reliable (retried) packet sends.",
            ["outcome"],
            registry=self.registry,
        )
        self.config_reloads_total = Counter(
            "wgmesh_config_reloads_total",
            "Number of config file reloads.",
            registry=self.registry,
        )

    async def start(self) -> None:
        try:
            self.server = await asyncio.start_server(
                self._handle, self.addr, self.port,
            )
            logger.info(f"Metrics endpoint listening on {self.addr}:{self.port}/metrics")
        except OSError as e:
            logger.warning(f"Failed to start metrics server on {self.addr}:{self.port}: {e!r}")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

        try:
            request_line = await reader.readline()
            # Consume remaining headers
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break

            if request_line.startswith(b"GET /metrics"):
                body = generate_latest(self.registry)
                header = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: {CONTENT_TYPE_LATEST}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n"
                )
                writer.write(header.encode() + body)
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except Exception as e:
            logger.warning(f"Failed to handle metrics request: {e!r}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


# ---------------------------------------------------------------------------
#  No-op stub — same interface as MetricsServer but does nothing
# ---------------------------------------------------------------------------

_NOOP = BaseCounter()


class _NoOpServer(Server):
    """Stub returned when prometheus_client is not installed."""

    packets_total = _NOOP
    packets_dropped_total = _NOOP
    reliable_send_total = _NOOP
    config_reloads_total = _NOOP

    async def start(self):
        pass

    async def stop(self):
        pass

_NOOP_SERVER = _NoOpServer()

# ---------------------------------------------------------------------------
#  Setup helper
# ---------------------------------------------------------------------------


def setup(controller: MeshController, addr: str, port: int) -> Server:
    """Create and return a metrics server (or a no-op stub if prometheus_client is missing)."""
    try:
        if not addr or port == 0:
            logger.info("Metrics endpoint disabled")
            return _NOOP_SERVER
        return PrometheusMetricsServer(addr, port, controller)
    except ImportError:
        logger.warning("Required to start metrics server, but Prometheus client library not installed. Metrics will be disabled.")
        return _NOOP_SERVER
