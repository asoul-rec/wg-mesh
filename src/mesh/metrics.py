"""Prometheus metrics endpoint for the wg-mesh controller.

Exposes ``/metrics`` over HTTP using a lightweight ``asyncio.start_server``
handler — no web framework required.  All metric objects live on a dedicated
``CollectorRegistry`` so they never collide with the default process metrics.

Usage from the controller::

    from .metrics import setup_metrics
    server = setup_metrics(controller, port=9586)
    await server.start()   # non-blocking, runs on the event loop
    ...
    await server.stop()    # graceful shutdown
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from prometheus_client import Counter, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
from prometheus_client.core import GaugeMetricFamily

if TYPE_CHECKING:
    from .mesh import MeshController

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Registry — isolated from the default process-level registry
# ---------------------------------------------------------------------------

REGISTRY = CollectorRegistry()

# ---------------------------------------------------------------------------
#  Event-driven counters — incremented at call sites in mesh.py
# ---------------------------------------------------------------------------

PACKETS_TOTAL = Counter(
    "wgmesh_gossip_packets_total",
    "Total gossip packets sent or received.",
    ["type", "direction"],
    registry=REGISTRY,
)

PACKETS_DROPPED_TOTAL = Counter(
    "wgmesh_gossip_packets_dropped_total",
    "Gossip packets dropped before processing.",
    ["reason"],
    registry=REGISTRY,
)

RELIABLE_SEND_TOTAL = Counter(
    "wgmesh_reliable_send_total",
    "Outcomes of reliable (retried) packet sends.",
    ["outcome"],
    registry=REGISTRY,
)

CONFIG_RELOADS_TOTAL = Counter(
    "wgmesh_config_reloads_total",
    "Number of config file reloads.",
    registry=REGISTRY,
)

# Packet type integer → human-readable name
PKT_TYPE_NAMES: dict[int, str] = {1: "announce", 2: "ack", 3: "route_cost"}

# ---------------------------------------------------------------------------
#  Custom collector — reads live controller state on each scrape
# ---------------------------------------------------------------------------


class MeshCollector:
    """Yields per-scrape gauge families from live ``MeshController`` state.

    Using a custom collector (rather than module-level ``Gauge`` objects) means
    departed peers automatically disappear from the output — no explicit
    ``.remove()`` cleanup required.
    """

    def __init__(self, controller: MeshController) -> None:
        self._ctrl = controller

    def describe(self):
        return []

    def collect(self):
        ctrl = self._ctrl

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
            rt_size = len(getattr(ctrl.seg6_controller, "_route_table", {}))
            yield GaugeMetricFamily(
                "wgmesh_route_table_entries",
                "Number of SRv6 route table entries.",
                value=rt_size,
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
#  Async HTTP server — serves /metrics
# ---------------------------------------------------------------------------


class MetricsServer:
    """Minimal async HTTP server that serves the ``/metrics`` endpoint."""

    def __init__(self, port: int, registry: CollectorRegistry) -> None:
        self._port = port
        self._registry = registry
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        if self._port == 0:
            logger.info("Metrics endpoint disabled (port=0)")
            return
        try:
            self._server = await asyncio.start_server(
                self._handle, "0.0.0.0", self._port,
            )
            logger.info(f"Metrics endpoint listening on :{self._port}/metrics")
        except OSError as e:
            logger.warning(f"Failed to start metrics server on port {self._port}: {e}")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await reader.readline()
            # Consume remaining headers
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break

            if request_line.startswith(b"GET /metrics"):
                body = generate_latest(self._registry)
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
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


# ---------------------------------------------------------------------------
#  Setup helper
# ---------------------------------------------------------------------------


def setup_metrics(controller: MeshController, port: int = 9586) -> MetricsServer:
    """Register the live-state collector and return a ready-to-start server."""
    collector = MeshCollector(controller)
    REGISTRY.register(collector)
    return MetricsServer(port, REGISTRY)
