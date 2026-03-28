import ipaddress

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


def get_internal_ip(cidr_str, node_id):
    network = ipaddress.IPv4Network(cidr_str, strict=True)
    return str(network[node_id])


def get_node_id_from_ip(cidr_str, ip_str):
    network = ipaddress.IPv4Network(cidr_str, strict=True)
    ip = ipaddress.IPv4Address(ip_str)
    return int(ip) - int(network.network_address)
