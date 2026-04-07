import collections
import json
import logging
import math
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from itertools import pairwise
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
    route_cost: dict[str, int] = field(default_factory=dict, repr=False)
    protected: bool = field(default=False, kw_only=True)
    _protected_fields = {"node_id", "name", "pubkey", "endpoint", "protected", "_initialized"}
    _initialized = False

    def __post_init__(self):
        self._traffic_stats = collections.deque(maxlen=100)
        self._initialized = True

    def record_traffic_stat(self, item: tuple[float, int]):
        self._traffic_stats.append(item)
        logging.debug(f"Stats for node {self.node_id}: {list(self._traffic_stats)[-10:]}")

    def get_link_cost(self, curr_time: float) -> int:
        """
        Compute a weighted-average RTT cost for this peer link using exponential time decay.

        Each sample is assigned a weight by integrating the exponential decay PDF
        ``f(t) = ln(2)/HALF_LIFE * 2^(-(curr_time - t)/HALF_LIFE)`` over the interval
        from the previous midpoint to the next midpoint between consecutive samples
        (sorted newest-first). Because the PDF integrates to 1 over ``(-inf, curr_time]``,
        the weights naturally sum to 1 when all history is covered.

        Individual weights are capped at ``WEIGHT_CAP`` to prevent any single sample
        from dominating. If the oldest sample still leaves unassigned weight, the
        result is rescaled to normalize over the covered portion. Lost packets
        (``rtt < 0``) are substituted with ``LOST_PENALTY`` ms.

        :param curr_time: The current monotonic time (``loop.time()``).
        :return: The weighted link cost in milliseconds, minimum 1.
        """
        LOST_PENALTY = 3000
        HALF_LIFE = 20
        WEIGHT_CAP = 0.2
        if not self._traffic_stats:
            return LOST_PENALTY
        decay = -math.log(2) / HALF_LIFE
        cost = 0
        sorted_stats = sorted(self._traffic_stats, reverse=True)
        weight_left = 1
        for (t_i, rtt_i), (t_prev, _) in pairwise(sorted_stats):
            rtt_i = rtt_i if rtt_i > 0 else LOST_PENALTY
            if weight_left < 0.01:
                cost += weight_left * rtt_i
                break
            weight = weight_left - math.e ** (decay * (curr_time - (t_prev + t_i) / 2))
            weight = WEIGHT_CAP if weight > WEIGHT_CAP else weight
            cost += weight * rtt_i
            weight_left -= weight
        else:  # reach the final item but has significant weight_left
            rtt_i = sorted_stats[-1][1]
            rtt_i = rtt_i if rtt_i > 0 else LOST_PENALTY
            weight = WEIGHT_CAP if weight_left > WEIGHT_CAP else weight_left
            cost += weight * rtt_i
            cost /= 1 - (weight_left - weight)
        cost = 1 if cost < 1 else cost
        return round(cost)

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
        if self.route_cost:
            d["route_cost"] = self.route_cost
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
        if self.protected and field in type(self)._protected_fields and self._initialized:
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
        my_id, me_cfg.get("name", f"node-{my_id}"),
        pubkey=my_pubkey,
        endpoint=me_cfg.get("endpoint", ""),
        seq_num=me_cfg.get("seq_num", 0),
        timestamp=me_cfg.get("timestamp", int(time.time())),
        route_cost=me_cfg.get("route_cost", {}),
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
            peer_id, info.get("name", f"node-{peer_id}"),
            pubkey=peer_key,
            endpoint=info.get("endpoint", ""),
            seq_num=info.get("seq_num", 0),
            timestamp=info.get("timestamp", 0),
            route_cost=info.get("route_cost", {})
        )
        if (cost := node_me.route_cost.get(str(peer_id), 3000)) < 3000:
            known_nodes[peer_id].record_traffic_stat((0, cost))

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
            "srv6", "gre_network", "vxlan_network", "route_cost", "seq_num", "timestamp"
        ]:
            if key in me_dict:
                me_dict[key] = me_dict.pop(key)
        # dump data
        data = {
            "me": me_dict,
            "peers": [node.to_dict() for node in known_nodes.values()]
        }
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logging.error(f"Save conf error: {e!r}")
