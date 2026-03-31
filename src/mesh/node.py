import time
import json
import logging
from .wg import generate_wg_keys

class Node:
    def __init__(self, node_id, name, pubkey, endpoint="", seq_num=0, timestamp=0):
        self.node_id = int(node_id)
        self.name = name
        self.pubkey = pubkey
        self.endpoint = endpoint
        self.seq_num = seq_num
        self.timestamp = timestamp

    def to_dict(self):
        return {
            "node_id": self.node_id,
            "name": self.name,
            "pubkey": self.pubkey,
            "endpoint": self.endpoint,
            "seq_num": self.seq_num,
            "timestamp": self.timestamp
        }

class LocalNode:
    def __init__(self, node, **kwargs):
        super().__setattr__("node", node)
        self.__dict__.update(kwargs)

    def __getattr__(self, name):
        return getattr(self.node, name)

    def __setattr__(self, name, value):
        if hasattr(self.node, name):
            setattr(self.node, name, value)
        else:
            super().__setattr__(name, value)

def load_conf(config_file):
    try:
        with open(config_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        logging.error(f"Failed to load {config_file}: {e!r}")
        raise RuntimeError("Valid configuration file is required.")

    me_cfg = data.get("me", {})
    my_id = me_cfg.get("id")
    if not my_id:
        raise ValueError("Config must contain 'me.id'")

    cidr_str = me_cfg.get("cidr", "10.123.234.0/24")
    private_key = me_cfg.get("private_key", "")
    my_pubkey = me_cfg.get("public_key", "")

    if not private_key or not my_pubkey:
        logging.info("Missing keys in config, generating new ones...")
        private_key, my_pubkey = generate_wg_keys()
        if not private_key or not my_pubkey:
            raise ValueError("Failed to generate keys")

    node_me = Node(
        my_id, me_cfg.get("name", f"node-{my_id}"), my_pubkey,
        me_cfg.get("endpoint", ""), me_cfg.get("seq_num", 0),
        me_cfg.get("timestamp", int(time.time()))
    )
    me = LocalNode(node_me, private_key=private_key, cidr=cidr_str)

    known_nodes = {}
    peers_cfg = data.get("peers", [])
    for info in peers_cfg:
        try:
            peer_id = info['node_id']
            peer_key = info['pubkey']
        except KeyError:
            continue
        known_nodes[peer_id] = Node(
            peer_id, info.get("name", f"node-{peer_id}"), peer_key,
            info.get("endpoint", ""), info.get("seq_num", 0),
            info.get("timestamp", 0)
        )

    known_nodes[me.node_id] = me.node
    return me, known_nodes

def save_conf(config_file, me, known_nodes):
    try:
        peers_data = [node.to_dict() for node in known_nodes.values()]
        data = {
            "me": {
                "id": me.node_id,
                "name": me.name,
                "cidr": me.cidr,
                "seq_num": me.seq_num,
                "timestamp": me.timestamp,
                "private_key": me.private_key,
                "public_key": me.pubkey,
                "endpoint": me.endpoint
            },
            "peers": peers_data
        }
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logging.error(f"Save conf error: {e!r}")
