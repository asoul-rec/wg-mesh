import ipaddress
import logging
from subprocess import CalledProcessError
from typing import Optional, Union, Literal

from .proc import run, log_called_process_error
from .vrf import VRFTable
from ..utils import SRv6CSID, get_internal_ip


def setup_seg6_csid(
    node_id: int, masquerade_iface: str = "", *,
    csid: SRv6CSID,
    vrf_table: Union[VRFTable, int] = -1,
    tunnel6_ifname: Optional[str] = None,
    decapsulation_mode: Literal["DT46", "ip6tnl"] = "ip6tnl"
):
    """
    Configure SRv6 Compressed SID (CSID) routing for this node.

    Sets up the NEXT-CSID End behavior to process SRv6 traffic. It configures the ``seg6local``
    route to forward the segment routing headers and optionally binds the decapsulated
    traffic into a specific VRF or IPv6 tunnel interface.

    :param node_id: The ID of the current node to embed into the local Node Function address.
    :param masquerade_iface: An interface to masquerade outgoing SRv6 traffic via nftables.
    :param csid: The SRv6 CSID geometry object containing the locator block and nflen.
    :param vrf_table: The VRF routing table to bind decapsulated inner payloads to. Disable VRF if negative (default).
    :param tunnel6_ifname: Optional interface name to create an external (collect metadata mode)
                           ip6tnl decap interface. If provided, the tunnel is bound to the VRF master.
    :param decapsulation_mode: The decapsulation mode to use. DT46 will use seg6local End.DT46,
                               and ip6tnl will rely on the kernel's automatic decap.
    """
    if isinstance(vrf_table, VRFTable):
        has_vrf = True
    elif vrf_table > 0:
        vrf_table = VRFTable(table_id=vrf_table)
        has_vrf = True
    else:
        has_vrf = False
    # Do setup
    try:
        # Masquerade forwarded traffic from wg and back to wg to avoid dropping
        if masquerade_iface:
            nft_rule = """
            table ip6 srv6 {{
                map srv6_paths {{
                    type ipv6_addr : ipv6_addr
                }}
                chain raw_prerouting {{
                    type filter hook prerouting priority raw; policy accept;
                    iif "{iface}" ip6 daddr {node_addr} ip6 saddr set ip6 saddr & {node_mask} | {lb_addr} ip6 daddr set {local_addr} accept
                    iif "{iface}" ip6 saddr {lb_net} ip6 daddr {node_net} notrack accept
                    iif "{iface}" ip6 saddr {lb_net} counter drop
                }}
                chain forward {{
                    type filter hook forward priority filter; policy accept;
                    ip6 saddr {lb_net} counter
                }}
                chain mangle_output {{
                    type filter hook output priority mangle; policy accept;
                    oif "{iface}" ip6 daddr {lb_net} ip6 daddr set ip6 daddr map @srv6_paths accept
                    oif "{iface}" ip6 daddr {lb_net} counter accept
                }}
                chain mangle_postrouting {{
                    type filter hook postrouting priority mangle; policy accept;
                    oif "{iface}" ip6 saddr {lb_net} ip6 daddr {lb_net} ip6 saddr set ip6 saddr & {node_mask} | {node_addr}
                }}
            }}
            """.format(
                iface=masquerade_iface,
                lb_net=csid.locator_block_address,
                lb_addr=get_internal_ip(csid.locator_block_address, 0),
                node_addr=csid.get_node_function_address(node_id, cidr=None),
                node_net=csid.get_node_function_address(node_id, cidr="network"),
                node_mask=ipaddress.ip_network(csid.get_node_function_address(node_id, cidr="network")).hostmask,
                local_addr=get_internal_ip(csid.locator_block_address, node_id)
            )
            logging.debug(f"Creating nft srv6 table: {nft_rule}")
            run(["nft", "-f", "-"], input=nft_rule.encode())
        run(["ip", "route", "add", "local", csid.get_node_function_address(node_id, cidr="network"), "encap", "seg6local",
             "action", "End", "flavors", "next-csid", "lblen", str(csid.lblen), "nflen", str(csid.nflen), "dev", "lo"])
        if tunnel6_ifname is not None:
            run(["ip", "link", "add", tunnel6_ifname, "type", "ip6tnl", "external"])
            run(["ip", "link", "set", tunnel6_ifname, "mtu", "1380"])
            run(["ip", "link", "set", tunnel6_ifname, "up"])
            run(["ip", "addr", "add", csid.get_node_function_address(node_id, cidr="host"), "dev", "lo"])
        if has_vrf:
            vrf_table.up()
            if decapsulation_mode == "ip6tnl":
                if tunnel6_ifname is not None:
                    run(["ip", "link", "set", tunnel6_ifname, "master", str(vrf_table.ifname)])
                else:
                    logging.warning("ip6tnl decapsulation mode requires a external tunnel6 interface for VRF binding.")
            elif decapsulation_mode == "DT46":
                run(["ip", "route", "add", "local", csid.get_node_function_address(node_id, cidr="host"), "encap", "seg6local",
                     "action", "End.DT46", "vrftable", str(vrf_table.table_id), "dev", "lo"])
        else:
            if decapsulation_mode == "DT46":
                logging.warning("DT46 decapsulation mode requires a VRF table.")
    except CalledProcessError as e:
        log_called_process_error(logging.warning, e)
    except Exception as e:
        logging.warning(f"Failed to setup SRv6 CSID: {e!r}")
    else:
        logging.info(f"SRv6 CSID setup successfully")

def sync_seg6_routes(csid: SRv6CSID, route_table: dict[int, list[int]], flush: bool = False):
    nft_commands = ["flush set ip6 srv6 srv6_paths"] if flush else []
    for nid, hops in route_table.items():
        key = get_internal_ip(csid.locator_block_address, nid)
        value = csid.get_srv6_address(hops)
        nft_commands.append(f"destroy element ip6 srv6 srv6_paths {{ {key} }}")
        nft_commands.append(f"add element ip6 srv6 srv6_paths {{ {key} : {value} }}")
    if not nft_commands:
        return
    nft_commands_str = "\n".join(nft_commands)
    logging.debug(f"Updating nftables map:\n{nft_commands_str}")
    try:
        run(["nft", "-f", "-"], input=nft_commands_str.encode())
    except CalledProcessError as e:
        log_called_process_error(logging.warning, e)
    except Exception as e:
        logging.warning(f"Failed to sync SRv6 routes: {e!r}")
    else:
        logging.info(f"SRv6 routes synced successfully ({len(route_table)} routes updated)")
