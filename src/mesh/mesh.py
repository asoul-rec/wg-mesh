import argparse
import asyncio
import collections
import compression.zstd as zstd
import json
import logging
import random
import signal
import struct
import time

from .utils import *
from ._version import *
from .wg import generate_wg_keys, setup_wg_interface, sync_wg_peers
from .crypto import encrypt_payload, decrypt_payload


class Node:
    def __init__(self, node_id, name, pubkey, endpoint="", seq_num=0, timestamp=0):
        self.node_id = int(node_id)
        self.name = name
        self.pubkey = pubkey
        self.endpoint = endpoint
        self.seq_num = seq_num
        self.timestamp = timestamp
        self.last_seen = time.time()

    def to_dict(self):
        return {
            "node_id": self.node_id,
            "name": self.name,
            "pubkey": self.pubkey,
            "endpoint": self.endpoint,
            "seq_num": self.seq_num,
            "timestamp": int(self.timestamp)
        }


class MeshProtocol(asyncio.DatagramProtocol):
    def __init__(self, controller):
        self.controller = controller

    def connection_made(self, transport):
        self.controller.transport = transport

    def datagram_received(self, data, addr):
        self.controller.handle_packet(data, addr[0])


class MeshController:
    STALE_TOLERANCE = 4096
    KEEPALIVE_STATIC_INTERVAL = (600, 1200)
    KEEPALIVE_ROAMING_INTERVAL = (15, 25)
    KEEPALIVE_OFFLINE_INTERVAL = (12, 12)
    MESH_UDP_LISTEN_PORT = 8080

    def __init__(self, config_file, dry_run=False):
        self.config_file = config_file
        self.dry_run = dry_run
        self.known_nodes = {}
        self.me = None
        self.cidr_str = ""
        self.private_key = ""
        self.transport = None
        self.pending_acks = {}
        self._send_history = collections.deque()
        self._broadcast_task = None
        self._wg_update_pending = False
        self._wg_task = None
        self._background_tasks = set()
        self._keepalive_event = asyncio.Event()
        self._keepalive_task = None
        self._inbound_event = asyncio.Event()
        self._online_monitor_task = None
        # active broadcast at start
        self.keepalive_interval = self.KEEPALIVE_OFFLINE_INTERVAL
        self._offline = True
        logging.info(f"MeshController starting, version: {VERSION_STR}")
        self.load_conf()

    def load_conf(self):
        try:
            with open(self.config_file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logging.error(f"Failed to load {self.config_file}: {e!r}")
            raise RuntimeError("Valid configuration file is required.")

        me_cfg = data.get("me", {})
        my_id = me_cfg.get("id")
        if not my_id:
            raise ValueError("Config must contain 'me.id'")

        self.cidr_str = me_cfg.get("cidr", "10.123.234.0/24")
        self.private_key = me_cfg.get("private_key", "")
        my_pubkey = me_cfg.get("public_key", "")

        if not self.private_key or not my_pubkey:
            logging.info("Missing keys in config, generating new ones...")
            self.private_key, my_pubkey = generate_wg_keys()
            if not self.private_key or not my_pubkey:
                raise ValueError("Failed to generate keys")

        self.me = Node(
            my_id, me_cfg.get("name", f"node-{my_id}"), my_pubkey,
            me_cfg.get("endpoint", ""), me_cfg.get("seq_num", 0),
            me_cfg.get("timestamp", int(time.time()))
        )

        peers_cfg = data.get("peers", [])
        for info in peers_cfg:
            try:
                peer_id = info['node_id']
                peer_key = info['pubkey']
            except KeyError:
                # skip peer without required fields
                continue
            self.known_nodes[peer_id] = Node(
                peer_id, info.get("name", f"node-{peer_id}"), peer_key,
                info.get("endpoint", ""), info.get("seq_num", 0),
                info.get("timestamp", 0)
            )

        self.known_nodes[self.me.node_id] = self.me  # must be the same pointer
        self.save_conf()

        logging.info(f"Loaded {len(self.known_nodes)} nodes (including self) from {self.config_file}")

    def save_conf(self):
        try:
            peers_data = [node.to_dict() for node in self.known_nodes.values()]
            data = {
                "me": {
                    "id": self.me.node_id,
                    "name": self.me.name,
                    "cidr": self.cidr_str,
                    "seq_num": self.me.seq_num,
                    "timestamp": int(self.me.timestamp),
                    "private_key": self.private_key,
                    "public_key": self.me.pubkey,
                    "endpoint": self.me.endpoint
                },
                "peers": peers_data
            }
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logging.error(f"Save conf error: {e!r}")

    def trigger_wg_update(self, action="update", node=None):
        if self.dry_run:
            logging.info(f"[DRY-RUN] Would update WireGuard: {action} peer {node.node_id if node else 'all'}")
            return
        self._wg_update_pending = True
        if self._wg_task and not self._wg_task.done():
            return
        self._wg_task = asyncio.create_task(self._async_trigger_wg_update())

    async def _async_trigger_wg_update(self):
        while self._wg_update_pending:
            self._wg_update_pending = False
            try:
                await sync_wg_peers("wg0", self.known_nodes, self.me.node_id, self.cidr_str)
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
        if len(data) < 4:
            logging.warning(f"Bad packet from {sender_ip}, too short")
            return

        pkt_version, = struct.unpack('!I', data[:4])
        if pkt_version > VERSION:
            logging.error(f"Cannot process package: minimal version {int_to_version(pkt_version)}, "
                          f"current version {VERSION_STR}")
            return

        try:
            decrypted = decrypt_payload(self.me.pubkey, data[4:])
        except Exception as e:
            logging.error(f"Failed to decrypt packet from {sender_ip}: {e!r}")
            return

        # Packet decrypted and authenticated successfully
        self._inbound_event.set()

        if len(decrypted) < 9:
            logging.warning(f"Malformed decrypted packet from {sender_ip}")
            return

        pkt_type, origin_id, seq_num = struct.unpack('!BII', decrypted[:9])
        payload_data = decrypted[9:]

        if pkt_type == 1:
            self.process_announce(origin_id, seq_num, payload_data, sender_ip)
        elif pkt_type == 2:
            self.process_ack(origin_id, seq_num, sender_ip)

    def process_announce(self, origin_id, seq_num, payload, sender_ip):
        logging.debug(f"Received announce from {origin_id}, seq_num={seq_num}, sender_ip={sender_ip}")
        my_id = self.me.node_id
        if self.known_nodes.get(my_id) is not self.me:
            logging.error("Implementation Error: self.known_nodes[self.me.node_id] is no longer pointing to self.me")
            return

        def diff(nid, r_seq):
            """Calculates seq distance handling 32-bit wrap-around. >0 means r_seq is newer."""
            if nid not in self.known_nodes:
                return 1  # Unknown node implies sender's knowledge is newer
            l_seq = self.known_nodes[nid].seq_num
            return (r_seq - l_seq + (1 << 31)) % (1 << 32) - (1 << 31)

        # 1. Flood Control: Drop replayed or slightly older packets (-STALE_TOLERANCE, 0].
        # However, we allow extremely old packets to pass (they represent node amnesia recovery).
        if -self.STALE_TOLERANCE < diff(origin_id, seq_num) <= 0:
            logging.debug(f"Dropping stale announce")
            self.send_ack(sender_ip, origin_id, seq_num)
            return

        try:
            uncompressed = zstd.decompress(payload)
            payload_nodes = json.loads(uncompressed.decode('utf-8'))
            recv_dict = {n['node_id']: n for n in payload_nodes}
        except Exception as e:
            logging.error(f"Payload parse error from {sender_ip}: {e!r}")
            return

        changed_local = False
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
                changed_local = True
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
                        del self.known_nodes[nid]
                        changed_local = True
                        continue
                else:
                    local_n.name, local_n.pubkey, local_n.endpoint = recv_content
                    local_n.timestamp = recv_ts

            if seq_diff <= -self.STALE_TOLERANCE:
                source_needs_correction = True
            if seq_diff > 0:
                local_n.seq_num = recv_seq
                if not conflict:
                    local_n.timestamp = max(local_n.timestamp, recv_ts)
                changed_local = True

        # 2. update wg interface and send ACK
        if changed_local:
            logging.debug(f"Local mesh info updated, saving config and triggering wg update")
            self.save_conf()
            self.trigger_wg_update()
        self.send_ack(sender_ip, origin_id, seq_num)

        # 3. Broadcast Decision
        origin_id_name = f"<{self.known_nodes[origin_id].name}> " if origin_id in self.known_nodes else ""
        if source_needs_correction:
            logging.info(f"Source {origin_id_name}({get_internal_ip(self.cidr_str, origin_id)}) needs correction. "
                         f"Broadcasting merged state.")
            self.bump_my_seq()
            self.broadcast_packet(self.me.node_id, self.me.seq_num)
        else:
            logging.info(f"Source {origin_id_name}({get_internal_ip(self.cidr_str, origin_id)}) is consistent. "
                         f"Forwarding its broadcast.")
            self.broadcast_packet(origin_id, seq_num, exclude_ip=sender_ip)

    def process_ack(self, origin_id, seq_num, sender_ip):
        logging.debug(f"Received ack from {origin_id}, seq_num={seq_num}, sender_ip={sender_ip}")
        task_key = (sender_ip, origin_id, seq_num)
        if task_key in self.pending_acks:
            self.pending_acks[task_key].set()

    def send_packet(self, target_ip, pkt_type, origin_id, seq_num, target_pubkey, payload=b""):
        if not self.transport:
            return
        raw_data = struct.pack('!BII', pkt_type, origin_id, seq_num) + payload
        encrypted_data = encrypt_payload(target_pubkey, raw_data)
        packet = struct.pack('!I', MINIMAL_COMPATIBLE_VERSION) + encrypted_data
        logging.debug(f"Sending packet to {target_ip}:{self.MESH_UDP_LISTEN_PORT}, "
                      f"type: {pkt_type}, origin_id: {origin_id}, seq_num: {seq_num}")
        self.transport.sendto(packet, (target_ip, self.MESH_UDP_LISTEN_PORT))

    def send_ack(self, target_ip, origin_id, seq_num):
        sender_id = get_node_id_from_ip(self.cidr_str, target_ip)
        if sender_id not in self.known_nodes:
            logging.error(f"Cannot send ACK, missing pubkey for immediate sender IP {target_ip} (node {sender_id})")
            return
        target_pubkey = self.known_nodes[sender_id].pubkey
        self.send_packet(target_ip, 2, origin_id, seq_num, target_pubkey)

    def broadcast_packet(self, origin_id, seq_num, exclude_ip=None):
        """
        Broadcasts mesh updates. When origin_id == self.me.node_id (self-correction):
        1. The broadcast is asynchronously throttled via exponential backoff to prevent network flooding.
        2. The seq_num/exclude_ip parameters are ignored. The task uses self.me.seq_num and no exclude_ip
           upon execution.
        """
        if origin_id == self.me.node_id:
            if self._broadcast_task and not self._broadcast_task.done():
                return
            self._broadcast_task = asyncio.create_task(self._throttled_self_broadcast())
        else:
            self._send_broadcast_payload(origin_id, seq_num, exclude_ip)

    async def _throttled_self_broadcast(self):
        """Stateless exponential backoff for self-correction broadcasts."""
        loop = asyncio.get_running_loop()
        # relief throttling based on keepalive interval
        throttle_window = min(120, self.keepalive_interval[0])
        cutoff_time = loop.time() - throttle_window
        while self._send_history and self._send_history[0] < cutoff_time:
            self._send_history.popleft()

        throttle_count = len(self._send_history)
        if throttle_count > 0:
            sleep_time = min(0.1 * (2 ** throttle_count - 1), 20)
            if sleep_time > 1.0:
                logging.info(f"Throttling self-correction broadcast for {sleep_time:.1f}s")
            await asyncio.sleep(sleep_time)

        self._send_history.append(loop.time())
        self._send_broadcast_payload(self.me.node_id, self.me.seq_num, exclude_ip=None)

    def _send_broadcast_payload(self, origin_id, seq_num, exclude_ip):
        logging.info(f"Sending broadcast from {origin_id}, seq_num={seq_num}, exclude_ip={exclude_ip}")
        payload_data = [node.to_dict() for node in self.known_nodes.values()]
        compressed_payload = zstd.compress(json.dumps(payload_data).encode('utf-8'))

        for nid, neighbor in self.known_nodes.items():
            if nid == self.me.node_id:
                continue
            target_ip = get_internal_ip(self.cidr_str, neighbor.node_id)
            if target_ip == exclude_ip:
                continue
            task = asyncio.create_task(self.reliable_send(target_ip, 1, origin_id, seq_num, compressed_payload, neighbor.pubkey))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
        self._keepalive_event.set()

    async def _keepalive_loop(self):
        """Keepalive loop: if no broadcast has fired within interval, bump seq and self-broadcast."""
        logging.info(f"Keepalive loop started.")
        try:
            while True:
                self._keepalive_event.clear()
                interval = random.randint(*self.keepalive_interval)
                try:
                    await asyncio.wait_for(self._keepalive_event.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    logging.debug(f"Keepalive ({interval}s) firing broadcast")
                    self.bump_my_seq()
                    self.broadcast_packet(self.me.node_id, self.me.seq_num)
        except Exception as e:
            logging.warning(f"Keepalive loop failed: {e!r}")
            raise
        finally:
            logging.info(f"Keepalive loop terminated.")

    async def _online_monitor_loop(self):
        """Online status monitor: triggers small interval if no valid packets are received from mesh."""
        logging.info(f"Online status monitor started.")
        try:
            while True:
                self._inbound_event.clear()
                # expect to receive packet at least every keepalive_interval[1] + 3 seconds
                timeout = self.keepalive_interval[1] + 3
                logging.debug(f"Online status monitor waiting {timeout}s for packets")
                try:
                    await asyncio.wait_for(self._inbound_event.wait(), timeout=timeout)
                    if self._offline:
                        logging.info("Node is back online.")
                        self._offline = False
                        # Force announce to sync seq num with peers
                        self.bump_my_seq(2 * self.STALE_TOLERANCE)
                        self.broadcast_packet(self.me.node_id, self.me.seq_num)
                        self.keepalive_interval = self.KEEPALIVE_STATIC_INTERVAL if self.me.endpoint else self.KEEPALIVE_ROAMING_INTERVAL
                        self._keepalive_event.set() # Wake up keepalive to revert to normal interval
                except asyncio.TimeoutError:
                    if not self._offline:
                        logging.warning(f"Connection lost! ({timeout}s without packets)")
                        self._offline = True
                        self.keepalive_interval = self.KEEPALIVE_OFFLINE_INTERVAL
                        self._keepalive_event.set() # Wake up keepalive to enforce aggressive broadcast interval
        finally:
            logging.info(f"Online status monitor terminated.")

    async def reliable_send(self, target_ip, pkt_type, origin_id, seq_num, payload, target_pubkey):
        task_key = (target_ip, origin_id, seq_num)
        ack_event = asyncio.Event()
        self.pending_acks[task_key] = ack_event

        raw_data = struct.pack('!BII', pkt_type, origin_id, seq_num) + payload
        encrypted_data = encrypt_payload(target_pubkey, raw_data)
        packet = struct.pack('!I', VERSION) + encrypted_data

        for attempt in range(3):
            if origin_id in self.known_nodes and self.known_nodes[origin_id].seq_num != seq_num:
                logging.debug(f"Aborting reliable_send: seq {seq_num} for node {origin_id} is now stale.")
                break

            if self.transport:
                logging.debug(f"Sending packet to {target_ip}:8080, type: {pkt_type}, origin_id: {origin_id}, seq_num: {seq_num}")
                self.transport.sendto(packet, (target_ip, 8080))
            try:
                await asyncio.wait_for(ack_event.wait(), timeout=3.0)
                logging.debug(f"ACK received for {task_key}")
                break
            except asyncio.TimeoutError:
                logging.debug(f"Timeout waiting for ACK {task_key}, attempt {attempt + 1}/3")

        self.pending_acks.pop(task_key, None)


async def run(config_file, dry_run):
    controller = MeshController(config_file=config_file, dry_run=dry_run)
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

    my_ip = get_internal_ip(controller.cidr_str, controller.me.node_id)

    logging.info(f"Spinning up wg interface on {my_ip}")
    if not controller.dry_run:
        prefix = controller.cidr_str.split('/')[-1]
        setup_wg_interface("wg0", controller.private_key, f"{my_ip}/{prefix}")
        controller.trigger_wg_update()
    await asyncio.sleep(1)

    logging.info(f"Binding UDP endpoint on {my_ip}:8080")
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: MeshProtocol(controller),
            local_addr=(my_ip, 8080)
        )
    except Exception as e:
        logging.error(f"Failed to bind UDP endpoint ({my_ip}, 8080): {e!r}")
        return

    try:
        controller.bump_my_seq()
        controller.broadcast_packet(controller.me.node_id, controller.me.seq_num)
        controller._keepalive_task = asyncio.create_task(controller._keepalive_loop())
        controller._online_monitor_task = asyncio.create_task(controller._online_monitor_loop())
        await stop_event.wait()
    finally:
        if controller._keepalive_task:
            controller._keepalive_task.cancel()
        if controller._online_monitor_task:
            controller._online_monitor_task.cancel()
        if controller._wg_task:
            controller._wg_task.cancel()
        for task in controller._background_tasks:
            task.cancel()
        transport.close()
        logging.info("Graceful shutdown complete.")
