import asyncio
import struct
import time
import json
import logging
import argparse
import signal
import ipaddress
import subprocess
import compression.zstd as zstd

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def version_to_int(v_str):
    parts = [int(x) for x in v_str.split('.')]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def int_to_version(v_int):
    return f"{(v_int >> 24) & 255}.{(v_int >> 16) & 255}.{(v_int >> 8) & 255}.{v_int & 255}"


VERSION_STR = "0.0.1.0"
VERSION = version_to_int(VERSION_STR)
MINIMAL_COMPATIBLE_VERSION = version_to_int("0.0.1.0")


def get_internal_ip(cidr_str, node_id):
    network = ipaddress.IPv4Network(cidr_str, strict=True)
    return str(network[node_id])


def generate_wg_keys():
    """Attempt to call system 'wg' command to generate a keypair."""
    try:
        privkey = subprocess.check_output(["wg", "genkey"], text=True).strip()
        pubkey = subprocess.check_output(["wg", "pubkey"], input=privkey.encode(), text=True).strip()
        return privkey, pubkey
    except Exception as e:
        logging.warning(f"Failed to generate keys via 'wg' command: {e!r}. Using dummy keys.")
        return "DUMMY_PRIVKEY", "DUMMY_PUBKEY"


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

    def __init__(self, config_file, dry_run=False):
        self.config_file = config_file
        self.dry_run = dry_run
        self.known_nodes = {}
        self.me = None
        self.cidr_str = ""
        self.private_key = ""
        self.transport = None
        self.pending_acks = {}
        logging.info(f"MeshController starting, version: {int_to_version(VERSION)}")
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
        raise NotImplementedError("WireGuard execution logic is not implemented yet.")

    def bump_my_seq(self, jump=1):
        self.me.seq_num = (self.me.seq_num + jump) % (1 << 32)
        self.me.timestamp = int(time.time())

    def handle_packet(self, data, sender_ip):
        if len(data) < 13:
            logging.warning(f"Bad packet from {sender_ip}, content {data}")
            return

        pkt_version, pkt_type, origin_id, seq_num = struct.unpack('!IBII', data[:13])
        if pkt_version > VERSION:
            logging.error(f"Cannot process package: minimal version {int_to_version(pkt_version)}, "
                          f"current version {VERSION_STR}")
            return

        if pkt_type == 1:
            self.process_announce(origin_id, seq_num, data[13:], sender_ip)
        elif pkt_type == 2:
            self.process_ack(origin_id, seq_num, sender_ip)

    def process_announce(self, origin_id, seq_num, payload, sender_ip):
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

            if nid not in self.known_nodes:
                new_node = Node(recv_n['node_id'], *recv_content, seq_num=recv_seq, timestamp=recv_n.get('timestamp', 0))
                self.known_nodes[nid] = new_node
                changed_local = True
                continue

            local_n = self.known_nodes[nid]
            d = diff(nid, recv_seq)
            recv_ts = recv_n.get('timestamp', 0)

            # UTC Timestamp Veto logic
            time_diff = recv_ts - local_n.timestamp
            if d > 0 and time_diff <= -120:
                d = -1
                logging.warning(f"Vetoed ghost seq {recv_seq} for node {nid} (timestamp {time_diff}s older)")
            elif d <= 0 and time_diff >= 120:
                d = 1
                logging.warning(f"Obliged amnesia seq {recv_seq} for node {nid} (timestamp {time_diff}s newer)")

            local_content = [local_n.name, local_n.pubkey, local_n.endpoint]
            conflict = (recv_content != local_content)

            if conflict:
                if d <= 0 or nid == my_id:
                    source_needs_correction = True
                    if d == 0 and nid != my_id:
                        # edge case: why same seq num but different content? just forget it.
                        del self.known_nodes[nid]
                        changed_local = True
                        continue
                else:
                    local_n.name, local_n.pubkey, local_n.endpoint = recv_content
                    local_n.timestamp = recv_ts

            if d <= -self.STALE_TOLERANCE:
                source_needs_correction = True
            if d > 0:
                local_n.seq_num = recv_seq
                if not conflict:
                    local_n.timestamp = max(local_n.timestamp, recv_ts)
                changed_local = True

        # Merging complete, send ACK to free the sender's pending task.
        self.send_ack(sender_ip, origin_id, seq_num)

        # 2. Broadcast Decision
        if source_needs_correction:
            logging.info(f"Source {origin_id} needs correction. Broadcasting merged state.")
            self.bump_my_seq()
            self.save_conf()
            self.broadcast_packet(self.me.node_id, self.me.seq_num)
        else:
            if changed_local:
                self.save_conf()
            logging.info(f"Source {origin_id} is consistent. Forwarding its broadcast.")
            self.broadcast_packet(origin_id, seq_num, exclude_ip=sender_ip)

    def process_ack(self, origin_id, seq_num, sender_ip):
        task_key = (sender_ip, origin_id, seq_num)
        if task_key in self.pending_acks:
            self.pending_acks[task_key].set()

    def send_packet(self, target_ip, pkt_type, origin_id, seq_num, payload=b""):
        if not self.transport:
            return
        header = struct.pack('!IBII', MINIMAL_COMPATIBLE_VERSION, pkt_type, origin_id, seq_num)
        self.transport.sendto(header + payload, (target_ip, 8080))

    def send_ack(self, target_ip, origin_id, seq_num):
        self.send_packet(target_ip, 2, origin_id, seq_num)

    def broadcast_packet(self, origin_id, seq_num, exclude_ip=None):
        payload_data = [node.to_dict() for node in self.known_nodes.values()]
        payload_bytes = zstd.compress(json.dumps(payload_data).encode('utf-8'))

        for nid, neighbor in self.known_nodes.items():
            if nid == self.me.node_id: continue

            target_ip = get_internal_ip(self.cidr_str, neighbor.node_id)
            if target_ip == exclude_ip: continue

            asyncio.create_task(self.reliable_send(target_ip, 1, origin_id, seq_num, payload_bytes))

    async def reliable_send(self, target_ip, pkt_type, origin_id, seq_num, payload):
        task_key = (target_ip, origin_id, seq_num)
        ack_event = asyncio.Event()
        self.pending_acks[task_key] = ack_event

        header = struct.pack('!IBII', VERSION, pkt_type, origin_id, seq_num)
        packet = header + payload

        for attempt in range(3):
            if self.transport:
                self.transport.sendto(packet, (target_ip, 8080))

            try:
                await asyncio.wait_for(ack_event.wait(), timeout=3.0)
                logging.debug(f"ACK received for {task_key}")
                break
            except asyncio.TimeoutError:
                logging.debug(f"Timeout waiting for ACK {task_key}, attempt {attempt + 1}/3")

        self.pending_acks.pop(task_key, None)


async def main():
    parser = argparse.ArgumentParser(description="P2P WG Mesh Controller")
    parser.add_argument("--config", type=str, default="config.json", help="Path to config file")
    parser.add_argument("--dry-run", action="store_true", help="Run without executing WG commands")
    args = parser.parse_args()

    controller = MeshController(config_file=args.config, dry_run=args.dry_run)
    loop = asyncio.get_running_loop()

    stop_event = asyncio.Event()
    def handle_stop():
        logging.warning("Received shutdown signal, initiating graceful exit...")
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGTERM, handle_stop)
        loop.add_signal_handler(signal.SIGINT, handle_stop)
    except NotImplementedError:
        pass

    my_ip = get_internal_ip(controller.cidr_str, controller.me.node_id)
    logging.info(f"Binding UDP endpoint on {my_ip}:8080")

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MeshProtocol(controller),
        local_addr=(my_ip, 8080)
    )

    try:
        controller.bump_my_seq()
        controller.broadcast_packet(controller.me.node_id, controller.me.seq_num)
        # Leap increment to prevent silent broadcast rejection (e.g. if node restarted and lost config)
        controller.bump_my_seq(jump=controller.STALE_TOLERANCE * 2)
        controller.save_conf()
        controller.broadcast_packet(controller.me.node_id, controller.me.seq_num)
        await stop_event.wait()
    finally:
        transport.close()
        logging.info("Graceful shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
