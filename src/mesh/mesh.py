import argparse
import asyncio
import collections
import compression.zstd as zstd
import heapq
import json
import logging
import random
import signal
import struct
import time

from ._version import *
from .daemons import *
from .linux_net.wg import setup_wg_interface, sync_wg_peers
from .linux_net.gre import setup_gre_interface, sync_direct_peers
from .linux_net.vxlan import setup_vxlan_interface, sync_vxlan_peers
from .linux_net.seg6 import Seg6Controller
from .utils.crypto import *
from .utils.ip import *
from .utils.algorithm import compute_shortest_paths, wrapping_sub
from .node import Node, LocalNode, load_conf, save_conf


class MeshProtocol(asyncio.DatagramProtocol):
    def __init__(self, controller):
        self.controller = controller

    def connection_made(self, transport):
        self.controller.transport = transport

    def datagram_received(self, data, addr):
        self.controller.handle_packet(data, addr[0])


class MeshPacket:
    OUTER_HEADER_FMT = '!I'
    OUTER_HEADER_LEN = struct.calcsize(OUTER_HEADER_FMT)
    INNER_HEADER_FMT = '!BIIB10s'
    INNER_HEADER_LEN = struct.calcsize(INNER_HEADER_FMT)

    class Error(Exception):
        pass

    @staticmethod
    def pack(pkt_type, origin_id, seq_num, pkt_tag, payload, *, target_key):
        raw_data = struct.pack(MeshPacket.INNER_HEADER_FMT, pkt_type, origin_id, seq_num, pkt_tag, b'\x00'*10) + payload
        encrypted_data = encrypt_payload(target_key, raw_data)
        packet = struct.pack(MeshPacket.OUTER_HEADER_FMT, VERSION) + encrypted_data
        return packet

    @staticmethod
    def unpack(packet, my_key):
        # Outer header check
        if len(packet) < MeshPacket.OUTER_HEADER_LEN:
            raise MeshPacket.Error(f"Bad raw packet of length {len(packet)}")
        pkt_version, = struct.unpack(MeshPacket.OUTER_HEADER_FMT, packet[:MeshPacket.OUTER_HEADER_LEN])
        if pkt_version >> 8 != VERSION >> 8:
            raise MeshPacket.Error(f"Incompatible version {int_to_version(pkt_version)}, current version {VERSION_STR}")
        # Decrypt payload
        try:
            decrypted = decrypt_payload(my_key, packet[MeshPacket.OUTER_HEADER_LEN:])
        except Exception as e:
            raise MeshPacket.Error(f"Failed to decrypt packet: {e!r}")
        if len(decrypted) < MeshPacket.INNER_HEADER_LEN:
            raise MeshPacket.Error(f"Malformed decrypted packet of length {len(decrypted)}")
        # Unpack payload
        pkt_type, origin_id, seq_num, pkt_tag, _ = struct.unpack(MeshPacket.INNER_HEADER_FMT, decrypted[:MeshPacket.INNER_HEADER_LEN])
        return {
            "pkt_type": pkt_type,
            "origin_id": origin_id,
            "seq_num": seq_num,
            "pkt_tag": pkt_tag,
            "payload": decrypted[MeshPacket.INNER_HEADER_LEN:],
        }


class MeshController:
    STALE_TOLERANCE = 4096
    KEEPALIVE_STATIC_INTERVAL = (600, 1200)
    KEEPALIVE_ROAMING_INTERVAL = (15, 25)
    KEEPALIVE_OFFLINE_INTERVAL = (12, 12)
    MESH_UDP_LISTEN_PORT = 8080

    me: LocalNode
    known_nodes: dict[int, Node]
    daemons: dict[str, Daemon]

    def __init__(self, config_file, dry_run=False):
        self.config_file = config_file
        self.dry_run = dry_run
        self.known_nodes = {}
        self.me = None
        self.transport = None
        self.pending_acks = {}
        self.seg6_controller = None
        self._send_history = collections.deque()
        self._announce_task = None
        self._wg_update_pending = False
        self._wg_task = None
        self._background_tasks = set()
        # Prepare daemons based on config
        self.load_conf()
        self.daemons = {}
        self._add_online_monitor()
        self._add_keepalive()
        self._add_routing_loop()
        logging.info(f"MeshController starting, version: {VERSION_STR}")

    def load_conf(self):
        self.me, self.known_nodes = load_conf(self.config_file)
        self.save_conf()
        logging.info(f"Loaded {len(self.known_nodes)} nodes (including self) from {self.config_file}")

    def save_conf(self):
        save_conf(self.config_file, self.me, self.known_nodes)

    def _add_online_monitor(self):
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

    def _add_keepalive(self):
        self.daemons["keepalive"] = KeepAlive(self.announce, self.KEEPALIVE_OFFLINE_INTERVAL)

    def _add_routing_loop(self):
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
            self.daemons["routing"] = Routing(
                me_id=self.me.node_id,
                link_state_callback=_get_link_state,
                sync_route_callback=lambda rt: self.seg6_controller.sync_routes(rt, flush=False)
            )

    async def run(self):
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()
        def handle_stop():
            logging.warning("Received shutdown signal, initiating graceful exit...")
            stop_event.set()

        try:
            loop.add_signal_handler(signal.SIGTERM, handle_stop)
            loop.add_signal_handler(signal.SIGINT, handle_stop)
        except NotImplementedError:
            logging.warning("Signal handlers not supported on this platform.")
            pass

        my_ip = get_internal_ip(self.me.network, self.me.node_id)
        my_cidr = get_internal_ip(self.me.network, self.me.node_id, cidr="network")

        logging.info(f"Spinning up wg interface on {my_ip}")
        if not self.dry_run:
            setup_wg_interface("wg0", self.me.private_key, my_cidr, self.me.node_id, csid=self.me.csid)
            self.trigger_wg_update()
            if self.me.csid is not None:
                self.seg6_controller = Seg6Controller(self.me.csid)
                self.seg6_controller.setup(self.me.node_id, "wg0", vrf_table=100, tunnel6_ifname="tun6-mesh")
            if (gre_network := self.me.gre_network):
                gre_cidr = get_internal_ip(gre_network, self.me.node_id, cidr="network")
                setup_gre_interface("gre-mesh", gre_cidr)
            if (vxlan_network := self.me.vxlan_network):
                vxlan_cidr = get_internal_ip(vxlan_network, self.me.node_id, cidr="network")
                setup_vxlan_interface("vxlan-mesh", vxlan_cidr, "wg0", my_ip)
        await asyncio.sleep(1)

        logging.info(f"Binding UDP endpoint on [{my_ip}:{self.MESH_UDP_LISTEN_PORT}]")
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: MeshProtocol(self),
                local_addr=(my_ip, self.MESH_UDP_LISTEN_PORT)
            )
        except Exception as e:
            logging.error(f"Failed to bind UDP endpoint [{my_ip}:{self.MESH_UDP_LISTEN_PORT}]: {e!r}")
            return

        try:
            self.bump_my_seq()
            self.announce()
            for d in self.daemons.values():
                d.start()
            await stop_event.wait()
        finally:
            for d in self.daemons.values():
                d.stop()
            if self._wg_task:
                self._wg_task.cancel()
            for task in self._background_tasks:
                task.cancel()
            transport.close()
            logging.info("Graceful shutdown complete.")


    def trigger_wg_update(self):
        if self.dry_run:
            logging.info(f"[DRY-RUN] Would update WireGuard")
            return
        self._wg_update_pending = True
        if self._wg_task and not self._wg_task.done():
            return
        self._wg_task = asyncio.create_task(self._async_trigger_wg_update())

    async def _async_trigger_wg_update(self):
        while self._wg_update_pending:
            self._wg_update_pending = False
            try:
                await sync_wg_peers("wg0", self.known_nodes, self.me.node_id, self.me.network, csid=self.me.csid)
                peer_keys = self.known_nodes.keys() - {self.me.node_id}
                if (gre_network := self.me.gre_network):
                    sync_direct_peers("gre-mesh", peer_keys, gre_network, self.me.network)
                if (vxlan_network := self.me.vxlan_network):
                    sync_vxlan_peers("vxlan-mesh", peer_keys, vxlan_network, self.me.network)
                if routing := self.daemons.get("routing"):
                    routing.update_event.set()
            except Exception as e:
                logging.error(f"Failed to sync wg peers: {e!r}")
            except asyncio.CancelledError:
                logging.info("Sync wg peers cancelled")
                raise

    def bump_my_seq(self, jump=1):
        self.me.seq_num = (self.me.seq_num + jump) % (1 << 32)
        self.me.timestamp = int(time.time())
        self.save_conf()

    def handle_packet(self, data, sender_ip):
        logging.debug(f"Received packet from {sender_ip}, length={len(data)}")
        # Notify online monitor after packet decrypted and authenticated successfully
        try:
            pkt = MeshPacket.unpack(data, self.me.pubkey)
            pkt_type, origin_id, seq_num, pkt_tag, payload = pkt["pkt_type"], pkt["origin_id"], pkt["seq_num"], pkt["pkt_tag"], pkt["payload"]
        except MeshPacket.Error as e:
            logging.warning(f"Failed to unpack packet from {sender_ip}: {e}")
            return
        try:
            self.daemons["online_monitor"].online_event.set()
        except KeyError:
            pass
        # Dispatch to different handlers
        if pkt_type == 1:
            if origin_id == self.me.node_id:
                # This will not happen for well-behaved neighbors
                logging.warning(f"{sender_ip} sent my announce back to me, dropping")
            else:
                self.process_announce(origin_id, seq_num, pkt_tag, payload, sender_ip)
        elif pkt_type == 2:
            self.process_ack(origin_id, seq_num, sender_ip, pkt_tag)
        elif pkt_type == 3:
            if origin_id == self.me.node_id:
                logging.warning(f"{sender_ip} sent my route cost back to me, dropping")
            else:
                self.process_route_cost(origin_id, seq_num, pkt_tag, payload, sender_ip)

    def process_announce(self, origin_id, seq_num, pkt_tag, payload, sender_ip):
        logging.debug(f"Received announce from {origin_id}, seq_num={seq_num}, sender_ip={sender_ip}")
        my_id = self.me.node_id
        if self.known_nodes.get(my_id) is not self.me.node:
            logging.error("Implementation Error: self.known_nodes[self.me.node_id] is no longer pointing to self.me")
            return
        if origin_id == my_id:
            logging.error("Cannot process announce from self")
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
            logging.debug(f"Dropping stale announce")
            self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)
            return

        try:
            uncompressed = zstd.decompress(payload)
            payload_data = json.loads(uncompressed.decode('utf-8'))
            recv_network = payload_data["network"]
            if recv_network and recv_network != self.me.network:
                logging.warning(f"Dropping announce from {sender_ip}: mismatched network ({recv_network} != {self.me.network})")
                return
            recv_dict = {n['node_id']: n for n in payload_data["nodes"]}
        except Exception as e:
            logging.error(f"Payload parse error from {sender_ip}: {e!r}")
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
            recv_seq = recv_n.get('seq_num', 0)
            recv_ts = recv_n.get('timestamp', 0)

            if recv_ts > time.time() + 60:
                logging.warning(f"Rejecting ghost announce for node {nid}: timestamp is far in the future "
                                f"(+{recv_ts - time.time():.1f}s).")
                continue

            if nid not in self.known_nodes:
                new_node = Node(recv_n['node_id'], *recv_content, seq_num=recv_seq, timestamp=recv_n.get('timestamp', 0))
                self.known_nodes[nid] = new_node
                topology_changed = True
                continue

            local_n = self.known_nodes[nid]
            seq_diff = diff(nid, recv_seq)

            # UTC Timestamp Veto logic
            time_diff = recv_ts - local_n.timestamp
            if seq_diff > 0 and time_diff <= -120:
                seq_diff = -1
                logging.warning(f"Vetoed ghost seq {recv_seq} for node {nid} (source {origin_id}, "
                                f"timestamp {-time_diff}s older)")
            elif seq_diff <= 0 and time_diff >= 120:
                seq_diff = 1
                logging.warning(f"Obliged amnesia seq {recv_seq} for node {nid} (source {origin_id}, "
                                f"timestamp {time_diff}s newer)")

            local_content = [local_n.name, local_n.pubkey, local_n.endpoint]
            conflict = (recv_content != local_content)

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
            logging.debug(f"Local mesh state updated, saving config")
            self.save_conf()
            if topology_changed:
                logging.info(f"Topology mutated, triggering wg update")
                self.trigger_wg_update()
        self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)

        # 3. Broadcast Decision
        origin_id_name = f"<{self.known_nodes[origin_id].name}> " if origin_id in self.known_nodes else ""
        if source_needs_correction:
            logging.info(f"Source {origin_id_name}({get_internal_ip(self.me.network, origin_id)}) needs correction. "
                         f"Announcing merged state.")
            self.bump_my_seq()
            self.announce()
        else:
            logging.info(f"Source {origin_id_name}({get_internal_ip(self.me.network, origin_id)}) is consistent. "
                         f"Forwarding its raw broadcast.")
            self.broadcast(1, origin_id, seq_num, payload, exclude_ip=sender_ip)

    def process_route_cost(self, origin_id, seq_num, pkt_tag, payload, sender_ip):
        logging.debug(f"Received route cost from {origin_id}, seq_num={seq_num}, sender_ip={sender_ip}")
        if origin_id not in self.known_nodes:
            self.announce()
            self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)
            return
            
        local_n = self.known_nodes[origin_id]
        if wrapping_sub(seq_num, local_n.seq_num) <= 0:
            logging.debug(f"Dropping stale route cost update")
            self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)
            return
        try:
            route_dict = json.loads(payload.decode('utf-8'))
            self.send_ack(sender_ip, origin_id, seq_num, pkt_tag)
        except Exception as e:  # do not send ACK for bad packets
            logging.error(f"Route cost payload parse error from {sender_ip}: {e!r}")
            return
        local_n.route_cost = route_dict
        local_n.seq_num = seq_num
        self.save_conf()
        self.broadcast(3, origin_id, seq_num, payload, exclude_ip=sender_ip)

    def process_ack(self, origin_id, seq_num, sender_ip, pkt_tag):
        loop = asyncio.get_running_loop()
        logging.debug(f"Received ack from {sender_ip}, origin_id={origin_id}, seq_num={seq_num}, pkt_tag={pkt_tag}")
        task_key = (sender_ip, origin_id, seq_num)
        if task_key in self.pending_acks:
            self.pending_acks[task_key].put_nowait((pkt_tag, loop.time()))

    def send_packet(self, target_ip, pkt_type, origin_id, seq_num, pkt_tag, payload, *, target_key):
        if not self.transport:
            return
        packet = MeshPacket.pack(pkt_type, origin_id, seq_num, pkt_tag, payload, target_key=target_key)
        logging.debug(f"Sending packet to [{target_ip}:{self.MESH_UDP_LISTEN_PORT}], "
                      f"type: {pkt_type}, origin_id: {origin_id}, seq_num: {seq_num}, tag: {pkt_tag}")
        self.transport.sendto(packet, (target_ip, self.MESH_UDP_LISTEN_PORT))

    def send_ack(self, target_ip, origin_id, seq_num, pkt_tag):
        sender_id = get_node_id_from_ip(self.me.network, target_ip)
        if sender_id not in self.known_nodes:
            logging.error(f"Cannot send ACK, missing pubkey for immediate sender IP {target_ip} (node {sender_id})")
            return
        target_pubkey = self.known_nodes[sender_id].pubkey
        self.send_packet(target_ip, 2, origin_id, seq_num, pkt_tag, b'', target_key=target_pubkey)

    def announce(self):
        """
        Announce local mesh updates.
        The broadcast is asynchronously throttled via exponential backoff to prevent network flooding.
        """
        if self._announce_task and not self._announce_task.done():
            return  # self._announce_task will announce the newest state just before finishing
        self._announce_task = asyncio.create_task(self._throttled_announce())

    async def _throttled_announce(self):
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
                logging.info(f"Throttling self-correction broadcast for {sleep_time:.1f}s")
            await asyncio.sleep(sleep_time)
        # Do broadcast
        self._send_history.append(loop.time())
        self.calculate_route_cost(loop.time())
        self.bump_my_seq()
        logging.info(f"Announcing self-state, seq_num={self.me.seq_num}")
        payload_data = {
            "network": self.me.network,
            "nodes": [node.to_dict() for node in self.known_nodes.values()]
        }
        compressed_payload = zstd.compress(json.dumps(payload_data, separators=(',', ':')).encode('utf-8'))
        self.broadcast(1, self.me.node_id, self.me.seq_num, compressed_payload)

    def calculate_route_cost(self, curr_time):
        if self.me.csid is not None:
            self.me.route_cost = {
                str(nid): neighbor.get_link_cost(curr_time)
                for nid, neighbor in self.known_nodes.items()
                if nid != self.me.node_id
            }
            logging.debug(f"Calculated route cost: {self.me.route_cost}")

    def announce_route_cost(self):
        self.calculate_route_cost(asyncio.get_running_loop().time())
        self.bump_my_seq()
        logging.debug(f"Broadcasting route cost, seq_num={self.me.seq_num}")
        payload = json.dumps(self.me.route_cost, separators=(',', ':')).encode('utf-8')
        self.broadcast(3, self.me.node_id, self.me.seq_num, payload)

    def broadcast(self, pkt_type, origin_id, seq_num, payload, *, exclude_ip=None):
        for nid, neighbor in self.known_nodes.items():
            if nid == self.me.node_id or nid == origin_id:
                continue
            target_ip = get_internal_ip(self.me.network, nid)
            if exclude_ip and target_ip == exclude_ip:
                continue
            task = asyncio.create_task(self.reliable_send(target_ip, pkt_type, origin_id, seq_num, payload, neighbor.pubkey))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        try:
            self.daemons["keepalive"].keepalive_event.set()
        except KeyError:
            pass

    async def reliable_send(self, target_ip, pkt_type, origin_id, seq_num, payload, target_pubkey):
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
                    logging.debug(f"Aborting reliable_send: seq {seq_num} for node {origin_id} is now stale.")
                    return
                if not self.transport:
                    logging.warning(f"Transport is not ready, aborting reliable_send")
                    return
                self.send_packet(target_ip, pkt_type, origin_id, seq_num, attempt, payload, target_key=target_pubkey)
                # Process ack
                start_time = loop.time()
                try:
                    recv_tag, recv_time = await asyncio.wait_for(ack_queue.get(), timeout=3.0)
                    if recv_tag == attempt:
                        logging.debug(f"ACK received for {task_key}, pkt_tag={recv_tag}")
                        if target_nid in self.known_nodes:
                            self.known_nodes[target_nid].record_traffic_stat((start_time, round((recv_time - start_time) * 1000)))
                    else:
                        logging.debug(f"Stale ACK received for {task_key}, expected tag {attempt}, got {recv_tag}. Aborting further retries.")
                    return
                except asyncio.TimeoutError:
                    logging.debug(f"Timeout waiting for ACK {task_key}, attempt {attempt + 1}/3")
                    if target_nid in self.known_nodes:
                        self.known_nodes[target_nid].record_traffic_stat((start_time, -1))
            # All attempts failed
            logging.info(f"Failed to send packet to [{target_ip}:{self.MESH_UDP_LISTEN_PORT}], type: {pkt_type}, origin_id: {origin_id}, seq_num: {seq_num}")
        finally:
            self.pending_acks.pop(task_key, None)
