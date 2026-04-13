import ipaddress
from typing import Optional, Literal


__all__ = [
    "get_internal_ip",
    "get_node_id_from_ip",
]


def get_internal_ip(network_addr, node_id, *, cidr: Optional[Literal["network", "host"]]=None):
    network = ipaddress.ip_network(network_addr, strict=True)
    if cidr is None:
        return str(network[node_id])
    elif cidr == "network":
        return f"{network[node_id]}/{network.prefixlen}"
    elif cidr == "host":
        return f"{network[node_id]}/{network.max_prefixlen}"
    else:
        raise ValueError(f"Unknown cidr type: {cidr!r}")


def get_node_id_from_ip(network_addr, ip_str):
    network = ipaddress.ip_network(network_addr, strict=True)
    ip = ipaddress.ip_address(ip_str)
    return int(ip) - int(network.network_address)
