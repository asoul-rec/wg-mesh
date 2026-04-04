import ipaddress
from typing import Optional, Literal

__all__ = [
    "version_to_int",
    "int_to_version",
    "get_internal_ip",
    "get_node_id_from_ip",
]


def version_to_int(v_str):
    parts = [int(x) for x in v_str.split('.')]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def int_to_version(v_int):
    return f"{(v_int >> 24) & 255}.{(v_int >> 16) & 255}.{(v_int >> 8) & 255}.{v_int & 255}"


def get_internal_ip(network_addr, node_id, cidr: Optional[Literal["network", "host"]]=None):
    network = ipaddress.IPv4Network(network_addr, strict=True)
    if cidr is None:
        return str(network[node_id])
    elif cidr == "network":
        return f"{network[node_id]}/{network.prefixlen}"
    elif cidr == "host":
        return f"{network[node_id]}/{network.max_prefixlen}"
    else:
        raise ValueError(f"Unknown cidr type: {cidr!r}")


def get_node_id_from_ip(network_addr, ip_str):
    network = ipaddress.IPv4Network(network_addr, strict=True)
    ip = ipaddress.IPv4Address(ip_str)
    return int(ip) - int(network.network_address)
