import ipaddress
from typing import Optional, Literal

__all__ = [
    "version_to_int",
    "int_to_version",
    "get_internal_ip",
    "get_node_id_from_ip",
    "SRv6CSID",
]


def version_to_int(v_str):
    parts = [int(x) for x in v_str.split('.')]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def int_to_version(v_int):
    return f"{(v_int >> 24) & 255}.{(v_int >> 16) & 255}.{(v_int >> 8) & 255}.{v_int & 255}"


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

class SRv6CSID:
    """
    Utility class to manage SRv6 Compressed SIDs (CSID) geometries for NEXT-CSID flavors.

    This abstracts away the bitwise manipulations required to construct Locator Blocks
    and Node Function addresses for segment routing over IPv6.
    """

    def __init__(self, *, nflen: int, locator_block: int = None, lblen: int = None,
                 locator_block_address: str = None):
        """
        Initialize the SRv6 CSID geometry. Accepts either a combination of ``locator_block`` and ``lblen``,
        or a CIDR-style ``locator_block_address``.

        :param nflen: The length of the Node Function (NF) identifier in bits.
        :param locator_block: The integer value of the Locator Block.
        :param lblen: The bit length of the Locator Block (LB).
        :param locator_block_address: The IPv6 network address denoting the locator block,
                                      e.g. 'fd00::/8'. Overrides locator_block and lblen.
        :raises ValueError: If the provided bit lengths are invalid, unaligned, or incompatible.
        """
        if (locator_block is None or lblen is None) and locator_block_address is None:
            raise ValueError("Must provide either locator_block and lblen, or locator_block_address.")
        if locator_block_address is not None:
            if not (locator_block is None and lblen is None):
                raise ValueError("Must provide either locator_block and lblen, or locator_block_address.")
            locator_addr = ipaddress.IPv6Network(locator_block_address)
            lblen = locator_addr.prefixlen
            locator_block = int(locator_addr.network_address) >> (128 - lblen)
        if lblen < 0 or nflen < 0 or lblen + nflen > 128 or lblen & 7 or nflen & 7:
            raise ValueError(f"Invalid lblen or nflen: {lblen}, {nflen}. "
                             "Must be non-negative, sum <= 128, and both divisible by 8.")
        if not 0 < locator_block < 1 << lblen:
            raise ValueError(f"Locator block {locator_block} is invalid for Locator-Block length {lblen}.")
        self._lblen = lblen
        self._nflen = nflen
        self._locator_block = locator_block
        self._locator_block_address = str(ipaddress.IPv6Network((locator_block << (128 - lblen), lblen)))

    @property
    def locator_block_address(self):
        return self._locator_block_address

    @property
    def lblen(self):
        return self._lblen

    @property
    def nflen(self):
        return self._nflen

    def get_node_function_address(self, node_function_id: int, *, cidr: Optional[Literal["network", "host"]]=None):
        """
        Construct a CSID-assigned IPv6 address for a specific Node Function ID.

        :param node_function_id: The ID of the node to construct the address for.
        :param cidr: Whether to append a CIDR suffix corresponding to the 'network' (LB+NF)
                     or 'host' (full 128-bit) prefix lengths.
        :return: The formatted IPv6 address string.
        """
        node_function_id = int(node_function_id)
        if not 0 < node_function_id < 1 << self._nflen:
            raise ValueError(f"Node function ID {node_function_id} is invalid for Locator-Node Function length {self._nflen}.")
        net_int = self._locator_block << self._nflen | node_function_id
        net_int <<= 128 - self._lblen - self._nflen
        net = ipaddress.IPv6Network((net_int, self._lblen + self._nflen))
        if cidr is None:
            return str(net.network_address)
        elif cidr == "network":
            return str(net)
        elif cidr == "host":
            return f"{net.network_address}/{net.max_prefixlen}"
        else:
            raise ValueError(f"Unknown cidr type: {cidr!r}")

    def get_srv6_address(self, hops_id: list[int]):
        """
        Build a full SRv6 destination address encoding a list of NEXT-CSID hops.

        The hops are packed sequentially into the address following the locator block.

        :param hops_id: A list of Node Function IDs representing the segment routing path hops.
        :return: The generated SRv6 IPv6 address encapsulating the hops.
        :raises ValueError: If the hops exceed the remaining bits in the 128-bit address.
        """
        padding = 128 - self._lblen - self._nflen * len(hops_id)
        if padding < 0:
            raise ValueError(f"Too many hops for SRv6 CSID lblen={self._lblen}, nflen={self._nflen}, hops={len(hops_id)}")
        addr_int = self._locator_block
        for hid in hops_id:
            if not 0 < hid < 1 << self._nflen:
                raise ValueError(f"Invalid hop ID: {hid}")
            addr_int <<= self._nflen
            addr_int |= hid
        addr_int <<= padding
        return str(ipaddress.IPv6Address(addr_int))

    def to_dict(self, locator_block: Literal["address", "block"] = "address"):
        match locator_block:
            case "address":
                d = {"locator_block_address": self._locator_block_address}
            case "block":
                d = {"locator_block": self._locator_block, "lblen": self._lblen}
            case _:
                raise ValueError(f"Unknown locator_block type: {locator_block!r}")
        d["nflen"] = self._nflen
        return d
