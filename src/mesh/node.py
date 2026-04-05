import time
import json
import logging
import collections
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional

from .linux_net.wg import generate_wg_keys
from .utils import SRv6CSID


@dataclass
class Node:
    node_id: int
    name: str
    pubkey: str = field(default="", repr=False)
    endpoint: str = ""
    seq_num: int = field(default=0, repr=False)
    timestamp: int = field(default=0, repr=False)
    protected: bool = field(default=False, kw_only=True)
    _protected_fields = {"node_id", "name", "pubkey", "endpoint", "protected", "_initialized"}
    _initialized = False


    def __post_init__(self):
        self._traffic_stats = collections.deque(maxlen=100)
        self._initialized = True

    def record_traffic_stat(self, **kwargs):
        self._traffic_stats.append(kwargs)
        logging.debug(f"Stats for node {self.node_id}: {list(self._traffic_stats)[-10:]}")

    def to_dict(self):
        d = {
            "node_id": self.node_id,
            "name": self.name,
            "pubkey": self.pubkey,
            "seq_num": self.seq_num,
            "timestamp": self.timestamp
        }
        if self.endpoint:
            d["endpoint"] = self.endpoint
        return d

    @contextmanager
    def _force_write(self):
        old_val = self.protected
        super().__setattr__("protected", False)
        try:
            yield
        finally:
            super().__setattr__("protected", old_val)

    def __setattr__(self, field, value):
        if self.protected and field in self._protected_fields and self._initialized:
            raise AttributeError(f"{self}.{field} is read-only")
        super().__setattr__(field, value)


@dataclass(kw_only=True)
class LocalNode:
    node: Node
    private_key: str = field(repr=False)
    network: str
    gre_network: str = ""
    vxlan_network: str = ""
    csid: Optional[SRv6CSID] = None
    _initialized = False

    def __post_init__(self):
        self._initialized = True

    def __getattr__(self, name):
        return getattr(self.node, name)

    def __setattr__(self, name, value):
        if self._initialized and hasattr(self.node, name):
            setattr(self.node, name, value)
        else:
            super().__setattr__(name, value)

    def to_dict(self):
        d = self.node.to_dict()
        d["private_key"] = self.private_key
        d["network"] = self.network
        if self.gre_network:
            d["gre_network"] = self.gre_network
        if self.vxlan_network:
            d["vxlan_network"] = self.vxlan_network
        if self.csid is not None:
            d["srv6"] = {"flavor": "next-csid", **self.csid.to_dict()}
        return d


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

    network_str = me_cfg.get("network", me_cfg.get("cidr", "10.123.234.0/24"))
    gre_network_str = me_cfg.get("gre_network", "")
    vxlan_network_str = me_cfg.get("vxlan_network", "")
    srv6_settings = me_cfg.get("srv6")
    private_key = me_cfg.get("private_key", "")
    my_pubkey = me_cfg.get("public_key", "")

    if not private_key or not my_pubkey:
        logging.info("Missing keys in config, generating new ones...")
        private_key, my_pubkey = generate_wg_keys()
        if not private_key or not my_pubkey:
            raise ValueError("Failed to generate keys")

    csid = None
    if srv6_settings is not None:
        srv6_settings = srv6_settings.copy()
        flavor = srv6_settings.pop("flavor", "")
        if flavor == "next-csid":
            csid = SRv6CSID(**srv6_settings)
        else:
            raise ValueError(f"Unknown SRv6 flavor: {flavor}")

    node_me = Node(
        my_id, me_cfg.get("name", f"node-{my_id}"), my_pubkey,
        me_cfg.get("endpoint", ""), me_cfg.get("seq_num", 0),
        me_cfg.get("timestamp", int(time.time())),
        protected=True
    )
    me = LocalNode(
        node=node_me,
        private_key=private_key,
        network=network_str,
        gre_network=gre_network_str,
        vxlan_network=vxlan_network_str,
        csid=csid
    )

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
        me_dict = me.to_dict()
        # compatibility with old configs
        me_dict["id"] = me_dict.pop("node_id")
        me_dict["public_key"] = me_dict.pop("pubkey")
        # reorder keys
        for key in [
            "id", "name", "private_key", "public_key", "endpoint", "network",
            "srv6", "gre_network", "vxlan_network", "seq_num", "timestamp"
        ]:
            if key in me_dict:
                me_dict[key] = me_dict.pop(key)
        data = {
            "me": me_dict,
            "peers": [node.to_dict() for node in known_nodes.values()]
        }
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logging.error(f"Save conf error: {e!r}")
