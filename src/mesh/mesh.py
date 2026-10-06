import asyncio
import collections
import json
import logging
import signal
import struct
import time
import typing
from compression import zstd
from typing import Final, TypedDict

from . import metrics
from ._version import *
from .daemons import *
from .linux_net.gre import setup_gre_interface, sync_direct_peers
from .linux_net.seg6 import Seg6Controller
from .linux_net.vrf import VRFTable
from .linux_net.vxlan import setup_vxlan_interface, sync_vxlan_peers
from .linux_net.wg import setup_wg_interface, sync_wg_peers
from .node import LocalNode, Node, load_conf, save_conf
from .utils.algorithm import wrapping_sub
from .utils.crypto import *
from .utils.ip import *
from .utils.version import *

logger = logging.getLogger(__name__)


class MeshProtocol(asyncio.DatagramProtocol):
    controller: MeshController

    def __init__(self, controller: MeshController) -> None:
        self.controller = controller

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.controller.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.controller.handle_packet(data, addr[0])


class MeshPacket:
    OUTER_HEADER_FMT: Final = '!I'
    OUTER_HEADER_LEN: Final = struct.calcsize(OUTER_HEADER_FMT)
    INNER_HEADER_FMT: Final = '!BIIB10s'
    INNER_HEADER_LEN: Final = struct.calcsize(INNER_HEADER_FMT)

    class Error(Exception):
        pass

    @staticmethod
    def pack(
        pkt_type: int, origin_id: int, seq_num: int, pkt_tag: int, payload: bytes, *, target_key: str
    ) -> bytes:
        header_i = struct.pack(MeshPacket.INNER_HEADER_FMT, pkt_type, origin_id, seq_num, pkt_tag, b"\x00" * 10)
        encrypted_data = encrypt_payload(target_key, header_i + payload)
        return struct.pack(MeshPacket.OUTER_HEADER_FMT, VERSION) + encrypted_data

    class UnpackedPacket(TypedDict):
        pkt_type: int
        origin_id: int
        seq_num: int
        pkt_tag: int
        payload: bytes

    @staticmethod
    def unpack(packet: bytes, my_key: str) -> UnpackedPacket:
        # Outer header check
        if len(packet) < MeshPacket.OUTER_HEADER_LEN:
            raise MeshPacket.Error(f"Bad raw packet of length {len(packet)}")
        pkt_version = struct.unpack(MeshPacket.OUTER_HEADER_FMT, packet[:MeshPacket.OUTER_HEADER_LEN])[0]
        if pkt_version >> 8 != VERSION >> 8:
            raise MeshPacket.Error(
                f"Incompatible version {int_to_version(pkt_version)}, current version {VERSION_STR}"
            )
        # Decrypt payload
        try:
            decrypted = decrypt_payload(my_key, packet[MeshPacket.OUTER_HEADER_LEN:])
        except Exception as e:  # noqa: BLE001
            raise MeshPacket.Error(f"Failed to decrypt packet: {e!r}")
        if len(decrypted) < MeshPacket.INNER_HEADER_LEN:
            raise MeshPacket.Error(f"Malformed decrypted packet of length {len(decrypted)}")
        # Unpack payload
        pkt_type, origin_id, seq_num, pkt_tag, _ = struct.unpack(
            MeshPacket.INNER_HEADER_FMT, decrypted[:MeshPacket.INNER_HEADER_LEN]
        )
        return {
            "pkt_type": pkt_type,
            "origin_id": origin_id,
            "seq_num": seq_num,
            "pkt_tag": pkt_tag,
            "payload": decrypted[MeshPacket.INNER_HEADER_LEN:],
        }


class MeshController:
    class DaemonsDict(TypedDict, total=False):
        online_monitor: OnlineMonitor
        keepalive: KeepAlive
        routing: Routing

    STALE_TOLERANCE: Final = 4096
    KEEPALIVE_STATIC_INTERVAL: Final = (600, 1200)
    KEEPALIVE_ROAMING_INTERVAL: Final = (15, 25)
    KEEPALIVE_OFFLINE_INTERVAL: Final = (12, 12)
    MESH_UDP_LISTEN_PORT: Final = 8080

    config_file: str
    dry_run: bool
    known_nodes: dict[int, Node]
    metrics_server: metrics.Server
    me: LocalNode
    transport: asyncio.DatagramTransport | None
    pending_acks: dict[tuple[str, int, int], asyncio.Queue[tuple[int, float]]]
    seg6_controller: Seg6Controller | None
    vrf: VRFTable
    daemons: DaemonsDict
    _send_history: collections.deque[float]
    _announce_task: asyncio.Task[None] | None
    _wg_update_pending: bool
    _wg_task: asyncio.Task[None] | None
    _background_tasks: set[asyncio.Task[None]]

    def __init__(self, config_file: str, dry_run: bool = False) -> None:
        self.config_file = config_file
        self.dry_run = dry_run
        self.known_nodes = {}
        self.transport = None
        self.pending_acks = {}
        self.seg6_controller = None
        self._send_history = collections.deque()
        self._announce_task = None
        self._wg_update_pending = False
        self._wg_task = None
        self.vrf = VRFTable(100)
        self._background_tasks = set()
        # Prepare daemons based on config
        self.load_conf()
        self.metrics_server = metrics.setup_from_str(self, self.me.metrics_endpoint)
        self.daemons = {}
        self._add_online_monitor()
        self._add_keepalive()
        self._add_routing_loop()
        logger.info(f"MeshController starting, version: {VERSION_STR}")

    def load_conf(self) -> None:
        self.me, self.known_nodes = load_conf(self.config_file)
        self.save_conf()
        logger.info(f"Loaded {len(self.known_nodes)} nodes (including self) from {self.config_file}")

    def save_conf(self) -> None:
        save_conf(self.config_file, self.me, self.known_nodes)

    def _add_online_monitor(self) -> None:
        def _online_callback():
            self.bump_my_seq(2 * self.STALE_TOLERANCE)
            self.announce()
            if keepalive := self.daemons.get("keepalive"):
                online_interval = self.KEEPALIVE_STATIC_INTERVAL if self.me.endpoint else self.KEEPALIVE_ROAMING_INTERVAL
                monitor.timeout = online_interval[1] + 3
                keepalive.keepalive_interval = online_interval
                keepalive.keepalive_event.set()
            else:
                monitor.timeout = None  # Never goes offline since we can't decide the threshold

        def _offline_callback():
            monitor.timeout = None
            if keepalive := self.daemons.get("keepalive"):
                keepalive.keepalive_interval = self.KEEPALIVE_OFFLINE_INTERVAL
                keepalive.keepalive_event.set()

        self.daemons["online_monitor"] = monitor = OnlineMonitor(_online_callback, _offline_callback)

    def _add_keepalive(self) -> None:
        self.daemons["keepalive"] = KeepAlive(self.announce, self.KEEPALIVE_OFFLINE_INTERVAL)

    def _add_routing_loop(self) -> None:
        def _get_link_state():
            # Compute route_costs and broadcast to neighbors before updating routes
            self.announce_route_cost()
            return {
                nid: {
                    neighbor_nid: cost
                    for neighbor_str, cost in node.route_cost.items()
                    if (neighbor_nid := int(neighbor_str)) in self.known_nodes
                }
                for nid, node in self.known_nodes.items()
            }

        if self.me.csid is not None:
            def sync_route_callback(rt: dict[int, list[int]]) -> None:
                if seg6_ctrl := self.seg6_controller:
                    seg6_ctrl.sync_routes(rt, flush=False)

            self.daemons["routing"] = Routing(
                me_id=self.me.node_id,
                link_state_callback=_get_link_state,
                sync_route_callback=sync_route_callback,
            )

    async def run(self) -> None:
        def handle_stop():
            logger.warning("Received shutdown signal, initiating graceful exit...")
            stop_event.set()

        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()
        try:
            loop.add_signal_handler(signal.SIGTERM, handle_stop)
            loop.add_signal_handler(signal.SIGINT, handle_stop)
        except NotImplementedError:
            logger.warning("Signal handlers not supported on this platform.")

        my_ip = get_internal_ip(self.me.network, self.me.node_id)
        my_cidr = get_internal_ip(self.me.network, self.me.node_id, cidr="network")

        logger.info(f"Spinning up wg interface on {my_ip}")
        if not self.dry_run:
            self.vrf.up()
            for ext_ip, options in self.me.external_routes.items():
                self.vrf.add_route(ext_ip, options)
            if self.me.wireguard_provider is None:
                setup_wg_interface("wg0", self.me.private_key, my_cidr)
            else:
                setup_wg_interface("wg0", self.me.private_key, my_cidr, provider=self.me.wireguard_provider)
            self.trigger_wg_update()
            if self.me.csid is not None:
                self.seg6_controller = Seg6Controller(self.me.csid)
                self.seg6_controller.setup(self.me.node_id, "wg0", vrf_table=self.vrf, tunnel6_ifname="tun6-mesh")
            if gre_network := self.me.gre_network:
                gre_cidr = get_internal_ip(gre_network, self.me.node_id, cidr="network")
                setup_gre_interface("gre-mesh", gre_cidr)
            if vxlan_network := self.me.vxlan_network:
                vxlan_cidr = get_internal_ip(vxlan_network, self.me.node_id, cidr="network")
                setup_vxlan_interface("vxlan-mesh", vxlan_cidr, "wg0", my_ip)
        await asyncio.sleep(0.1)

        logger.info(f"Binding UDP endpoint on [{my_ip}:{self.MESH_UDP_LISTEN_PORT}]")
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: MeshProtocol(self),
                local_addr=(my_ip, self.MESH_UDP_LISTEN_PORT)
            )
        except Exception as e:  # noqa: BLE001
            logger.error(f"Failed to bind UDP endpoint [{my_ip}:{self.MESH_UDP_LISTEN_PORT}]: {e!r}")
            return
        await asyncio.sleep(0.1)

        await self.metrics_server.start()

        try:
            daemons = typing.cast(dict[str, Daemon], self.daemons)
            self.bump_my_seq()
            self.announce()
            await asyncio.sleep(0.1)
            for d in daemons.values():
                d.start()
            await stop_event.wait()
        finally:
            await self.metrics_server.stop()
            for d in daemons.values():
                d.stop()
            if self._wg_task:
                self._wg_task.cancel()
            if self._announce_task:
                self._announce_task.cancel()
            for task in self._background_tasks:
                task.cancel()
            transport.close()
            logger.info("Graceful shutdown complete.")

    def trigger_wg_update(self) -> None:
        if self.dry_run:
            logger.info("[DRY-RUN] Would update WireGuard")
            return
        self._wg_update_pending = True
        if self._wg_task and not self._wg_task.done():
            return
        self._wg_task = asyncio.create_task(self._async_trigger_wg_update())

    async def _async_trigger_wg_update(self) -> None:
        while self._wg_update_pending:
            self._wg_update_pending = False
            try:
                await sync_wg_peers(
                    "wg0", self.known_nodes, self.me.node_id, self.me.network, csid=self.me.csid, vrf=self.vrf
                )
                peer_keys = self.known_nodes.keys() - {self.me.node_id}
                if gre_network := self.me.gre_network:
                    sync_direct_peers("gre-mesh", peer_keys, gre_network, self.me.network)
                if vxlan_network := self.me.vxlan_network:
                    sync_vxlan_peers("vxlan-mesh", peer_keys, vxlan_network, self.me.network)
                if routing := self.daemons.get("routing"):
                    routing.update_event.set()
            except Exception as e:  # noqa: BLE001
                logger.error(f"Failed to sync wg peers: {e!r}")
            except asyncio.CancelledError:
                logger.info("Sync wg peers cancelled")
                raise

    def bump_my_seq(self, jump: int = 1) -> None:
        self.me.seq_num = (self.me.seq_num + jump) % (1 << 32)
        self.me.timestamp = int(time.time())
        self.save_conf()

    def handle_packet(self, data: bytes, sender_ip: str) -> None:
        logger.debug(f"Received packet from {sender_ip}, length={len(data)}")
        # Notify online monitor after packet decrypted and authenticated successfully
        try:
            pkt = MeshPacket.unpack(data, self.me.pubkey)
            pkt_type, origin_id, seq_num, pkt_tag, payload = (
                pkt["pkt_type"], pkt["origin_id"], pkt["seq_num"], pkt["pkt_tag"], pkt["payload"]
            )
        except MeshPacket.Error as e:
            self.metrics_server.packets_dropped_total.labels(reason="decrypt_fail").inc()
            logger.warning(f"Failed to unpack packet from {sender_ip}: {e}")
            return
        self.metrics_server.packets_total.labels(
            type=metrics.PKT_TYPE_NAMES.get(pkt_type, str(pkt_type)),
            direction="received",
        ).inc()
        try:
            self.daemons["online_monitor"].online_event.set()
        except KeyError:
            pass
        # Dispatch to different handlers
        if pkt_type == 1:
            if origin_id == self.me.node_id:
                # This will not happen for well-behaved neighbors
                logger.warning(f"{sender_ip} sent my announce back to me, dropping")
            else:
                self.process_announce(origin_id, seq_num, pkt_tag, payload, sender_ip)
        elif pkt_type == 2:
            self.process_ack(origin_id, seq_num, sender_ip, pkt_tag)
        elif pkt_type == 3:
            if origin_id == self.me.node_id:
                logger.warning(f"{sender_ip} sent my route cost back to me, dropping")
            else:
                self.process_route_cost(origin_id, seq_num, pkt_tag, payload, sender_ip)

    def process_announce(
        self, origin_id: int, seq_num: int, pkt_tag: int, payload: bytes, sender_ip: str
    ) -> None:
        logger.debug(f"Received announce from {origin_id}, seq_num={seq_num}, sender_ip={sender_ip}")
        my_id = self.me.node_id
        if self.known_nodes.get(my_id) is not self.me.node:
            logger.error("Internal Error: self.known_nodes[self.me.node_id] no longer points to self.me")
            return
        if origin_id == my_id:
            logger.error("Cannot process announce from self")
            return

        def diff(nid, r_seq):
            """Calculates seq distance handling 32-bit wrap-around. >0 means r_seq is newer."""
            if nid not in self.known_nodes:
                return 1  # Unknown node implies sender's knowledge is newer
            l_seq = self.known_nodes[nid].seq_num
            return wrapping_sub(r_seq, l_seq)

        # 1. Flood Control: Drop replayed or slightly older packets (-STALE_TOLERANCE, 0].
        # However, we allow extremely old packets to pass (they represent node amnesia recovery).
        if -self.STALE_TOLERANCE < diff(origin_id, seq_num) <= 0:
            self.metrics_server.packets_dropped_total.labels(reason="stale").inc()
            logger.debug("Dropping stale announce")
            self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)
            return

        try:
            uncompressed = zstd.decompress(payload)
            payload_data = json.loads(uncompressed.decode('utf-8'))
            recv_network = payload_data["network"]
            if recv_network and recv_network != self.me.network:
                self.metrics_server.packets_dropped_total.labels(reason="network_mismatch").inc()
                logger.warning(
                    f"Dropping announce from {sender_ip}: mismatched network ({recv_network} != {self.me.network})"
                )
                return
            recv_dict = {n['node_id']: n for n in payload_data["nodes"]}
        except Exception as e:  # noqa: BLE001
            logger.error(f"Payload parse error from {sender_ip}: {e!r}")
            return

        seq_changed = False
        topology_changed = False
        source_needs_correction = False

        # A. Check if the incoming broadcast is missing any nodes we know about.
        for nid in self.known_nodes:
            if nid not in recv_dict:
                source_needs_correction = True
                break

        # B. Iteratively compare and merge peer records.
        for nid, recv_n in recv_dict.items():
            recv_content = [recv_n.get(k, '') for k in ('name', 'pubkey', 'endpoint')]
            recv_external_ips = recv_n.get('external_ips', [])
            recv_seq = recv_n.get('seq_num', 0)
            recv_ts = recv_n.get('timestamp', 0)

            if recv_ts > time.time() + 60:
                logger.warning(
                    f"Rejecting ghost announce for node {nid}: timestamp is far in the future "
                    f"(+{recv_ts - time.time():.1f}s)."
                )
                continue

            if nid not in self.known_nodes:
                new_node = Node(
                    recv_n["node_id"], *recv_content,
                    seq_num=recv_seq,
                    timestamp=recv_n.get("timestamp", 0),
                    external_ips=recv_external_ips,
                )
                self.known_nodes[nid] = new_node
                topology_changed = True
                continue

            local_n = self.known_nodes[nid]
            seq_diff = diff(nid, recv_seq)

            # UTC Timestamp Veto logic
            time_diff = recv_ts - local_n.timestamp
            if seq_diff > 0 and time_diff <= -120:
                seq_diff = -1
                logger.warning(
                    f"Vetoed ghost seq {recv_seq} for node {nid} "
                    f"(source {origin_id}, timestamp {-time_diff}s older)"
                )
            elif seq_diff <= 0 and time_diff >= 120:
                seq_diff = 1
                logger.warning(
                    f"Obliged amnesia seq {recv_seq} for node {nid} "
                    f"(source {origin_id}, timestamp {time_diff}s newer)"
                )

            local_content = [local_n.name, local_n.pubkey, local_n.endpoint, local_n.external_ips]
            conflict: bool = recv_content + [recv_external_ips] != local_content

            if conflict:
                if seq_diff <= 0 or nid == my_id:
                    source_needs_correction = True
                    if seq_diff == 0 and nid != my_id:
                        # edge case: why same seq num but different content? just forget it.
                        topology_changed = True
                        del self.known_nodes[nid]
                        continue
                else:
                    topology_changed = True
                    local_n.name, local_n.pubkey, local_n.endpoint = recv_content
                    local_n.external_ips = recv_external_ips
                    local_n.timestamp = recv_ts

            if seq_diff <= -self.STALE_TOLERANCE:
                source_needs_correction = True
            if seq_diff > 0:
                local_n.seq_num = recv_seq
                local_n.route_cost = recv_n.get("route_cost", {})
                if not conflict:
                    local_n.timestamp = max(local_n.timestamp, recv_ts)
                seq_changed = True

        # 2. update wg interface and send ACK
        if seq_changed or topology_changed:
            logger.debug("Local mesh state updated, saving config")
            self.save_conf()
            if topology_changed:
                logger.info("Topology mutated, triggering wg update")
                self.trigger_wg_update()
        self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)

        # 3. Broadcast Decision
        origin_id_name = f"<{self.known_nodes[origin_id].name}> " if origin_id in self.known_nodes else ""
        if source_needs_correction:
            logger.info(
                f"Source {origin_id_name}({get_internal_ip(self.me.network, origin_id)}) needs correction. "
                f"Announcing merged state."
            )
            self.bump_my_seq()
            self.announce()
        else:
            logger.info(
                f"Source {origin_id_name}({get_internal_ip(self.me.network, origin_id)}) is consistent. "
                f"Forwarding its raw broadcast."
            )
            self.broadcast(1, origin_id, seq_num, payload, exclude_ip=sender_ip)

    def process_route_cost(
        self, origin_id: int, seq_num: int, pkt_tag: int, payload: bytes, sender_ip: str
    ) -> None:
        logger.debug(f"Received route cost from {origin_id}, seq_num={seq_num}, sender_ip={sender_ip}")
        if origin_id not in self.known_nodes:
            self.announce()
            self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)
            return

        local_n = self.known_nodes[origin_id]
        if wrapping_sub(seq_num, local_n.seq_num) <= 0:
            logger.debug("Dropping stale route cost update")
            self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)
            return
        try:
            route_dict = json.loads(payload.decode('utf-8'))
            self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)
        except Exception as e:  # noqa: BLE001  # do not send ACK for bad packets
            logger.error(f"Route cost payload parse error from {sender_ip}: {e!r}")
            return
        local_n.route_cost = route_dict
        local_n.seq_num = seq_num
        self.save_conf()
        self.broadcast(3, origin_id, seq_num, payload, exclude_ip=sender_ip)

    def process_ack(self, origin_id: int, seq_num: int, sender_ip: str, pkt_tag: int) -> None:
        loop = asyncio.get_running_loop()
        logger.debug(
            f"Received ack from {sender_ip}, origin_id={origin_id}, seq_num={seq_num}, pkt_tag={pkt_tag}"
        )
        task_key = (sender_ip, origin_id, seq_num)
        if task_key in self.pending_acks:
            self.pending_acks[task_key].put_nowait((pkt_tag, loop.time()))

    def send_packet(
        self, target_ip: str, pkt_type: int, origin_id: int, seq_num: int, pkt_tag: int, payload: bytes,
        *, target_key: str,
    ) -> None:
        if not self.transport:
            return
        self.metrics_server.packets_total.labels(
            type=metrics.PKT_TYPE_NAMES.get(pkt_type, str(pkt_type)), direction="sent"
        ).inc()
        packet = MeshPacket.pack(pkt_type, origin_id, seq_num, pkt_tag, payload, target_key=target_key)
        logger.debug(
            f"Sending packet to [{target_ip}:{self.MESH_UDP_LISTEN_PORT}], "
            f"type: {pkt_type}, origin_id: {origin_id}, seq_num: {seq_num}, tag: {pkt_tag}"
        )
        self.transport.sendto(packet, (target_ip, self.MESH_UDP_LISTEN_PORT))

    def send_ack(self, target_ip: str, origin_id: int, seq_num: int, pkt_tag: int) -> None:
        sender_id = get_node_id_from_ip(self.me.network, target_ip)
        if sender_id not in self.known_nodes:
            logger.error(
                f"Cannot send ACK, missing pubkey for immediate sender IP {target_ip} (node {sender_id})"
            )
            return
        target_pubkey = self.known_nodes[sender_id].pubkey
        self.send_packet(target_ip, 2, origin_id, seq_num, pkt_tag, b'', target_key=target_pubkey)

    def announce(self) -> None:
        """
        Announce local mesh updates.
        The broadcast is asynchronously throttled via exponential backoff to prevent network flooding.
        """
        if self._announce_task and not self._announce_task.done():
            return  # self._announce_task will announce the newest state just before finishing
        self._announce_task = asyncio.create_task(self._throttled_announce())

    async def _throttled_announce(self) -> None:
        """Stateless exponential backoff for self-correction broadcasts."""
        loop = asyncio.get_running_loop()
        # Relief throttling based on keepalive interval
        throttle_window = 120
        if keepalive := self.daemons.get("keepalive"):
            throttle_window = min(throttle_window, keepalive.keepalive_interval[1])
        cutoff_time = loop.time() - throttle_window
        while self._send_history and self._send_history[0] < cutoff_time:
            self._send_history.popleft()
        # Exponential backoff
        throttle_count = len(self._send_history)
        if throttle_count > 0:
            sleep_time = min(0.1 * (2 ** throttle_count - 1), 20)
            if sleep_time > 1.0:
                logger.info(f"Throttling self-correction broadcast for {sleep_time:.1f}s")
            await asyncio.sleep(sleep_time)
        # Do broadcast
        self._send_history.append(loop.time())
        self.calculate_route_cost(loop.time())
        self.bump_my_seq()
        logger.info(f"Announcing self-state, seq_num={self.me.seq_num}")
        payload_data = {
            "network": self.me.network,
            "nodes": [node.to_dict() for node in self.known_nodes.values()],
        }
        compressed_payload = zstd.compress(
            json.dumps(payload_data, separators=(",", ":")).encode("utf-8")
        )
        self.broadcast(1, self.me.node_id, self.me.seq_num, compressed_payload)

    def calculate_route_cost(self, curr_time: float) -> None:
        if self.me.csid is not None:
            self.me.route_cost = {
                str(nid): neighbor.get_link_cost(curr_time)
                for nid, neighbor in self.known_nodes.items()
                if nid != self.me.node_id
            }
            logger.debug(f"Calculated route cost: {self.me.route_cost}")

    def announce_route_cost(self) -> None:
        self.calculate_route_cost(asyncio.get_running_loop().time())
        self.bump_my_seq()
        logger.debug(f"Broadcasting route cost, seq_num={self.me.seq_num}")
        payload = json.dumps(self.me.route_cost, separators=(',', ':')).encode('utf-8')
        self.broadcast(3, self.me.node_id, self.me.seq_num, payload)

    def broadcast(
        self, pkt_type: int, origin_id: int, seq_num: int, payload: bytes, *, exclude_ip: str | None = None
    ) -> None:
        for nid, neighbor in self.known_nodes.items():
            if nid == self.me.node_id or nid == origin_id:
                continue
            target_ip = get_internal_ip(self.me.network, nid)
            if exclude_ip and target_ip == exclude_ip:
                continue
            task = asyncio.create_task(
                self.reliable_send(target_ip, pkt_type, origin_id, seq_num, payload, neighbor.pubkey)
            )
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        try:
            self.daemons["keepalive"].keepalive_event.set()
        except KeyError:
            pass

    async def reliable_send(
        self, target_ip: str, pkt_type: int, origin_id: int, seq_num: int, payload: bytes, target_pubkey: str
    ) -> None:
        """
        Sends a packet reliably with up to 3 retry attempts and a 3s timeout for each.
        Uses an asyncio.Queue[tag] to record RTT
        - If tag matches current attempt: RTT is recorded.
        - If tag is stale: Return immediately without recording RTT.
        - On timeout: the attempt is marked as lost.
        """
        task_key = (target_ip, origin_id, seq_num)
        # We use queue as event with tag as value
        ack_queue = asyncio.Queue()
        self.pending_acks[task_key] = ack_queue
        try:
            target_nid = get_node_id_from_ip(self.me.network, target_ip)
            loop = asyncio.get_running_loop()
            for attempt in range(3):
                # Send data after validating current task
                if origin_id not in self.known_nodes or self.known_nodes[origin_id].seq_num != seq_num:
                    logger.debug(f"Aborting reliable_send: seq {seq_num} for node {origin_id} is now stale.")
                    return
                if not self.transport:
                    logger.warning("Transport is not ready, aborting reliable_send")
                    return
                self.send_packet(target_ip, pkt_type, origin_id, seq_num, attempt, payload, target_key=target_pubkey)
                # Process ack
                start_time = loop.time()
                try:
                    recv_tag, recv_time = await asyncio.wait_for(ack_queue.get(), timeout=3.0)
                    if recv_tag == attempt:
                        self.metrics_server.reliable_send_total.labels(outcome="ack_received").inc()
                        logger.debug(f"ACK received for {task_key}, pkt_tag={recv_tag}")
                        if target_nid in self.known_nodes:
                            self.known_nodes[target_nid].record_traffic_stat((start_time, round((recv_time - start_time) * 1000)))
                    else:
                        self.metrics_server.reliable_send_total.labels(outcome="stale_ack").inc()
                        logger.debug(
                            f"Stale ACK received for {task_key}, expected tag {attempt}, got {recv_tag}. "
                            "Aborting further retries."
                        )
                    return
                except TimeoutError:
                    self.metrics_server.reliable_send_total.labels(outcome="timeout").inc()
                    logger.debug(f"Timeout waiting for ACK {task_key}, attempt {attempt + 1}/3")
                    if target_nid in self.known_nodes:
                        self.known_nodes[target_nid].record_traffic_stat((start_time, -1))
                        if self.me.route_cost.get(str(target_nid), 3000) < 3000 and (routing := self.daemons.get("routing")):
                            routing.update_event.set()
            # All attempts failed
            logger.info(
                f"Failed to send packet to [{target_ip}:{self.MESH_UDP_LISTEN_PORT}], "
                f"type: {pkt_type}, origin_id: {origin_id}, seq_num: {seq_num}"
            )
        finally:
            self.pending_acks.pop(task_key, None)
