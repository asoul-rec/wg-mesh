import ipaddress
import logging
import typing
from subprocess import CalledProcessError
from typing import Literal, overload

from ...utils.ip import get_internal_ip
from ..proc import log_called_process_error, run
from ..vrf import VRFTable
from .csid import SRv6CSID

logger = logging.getLogger(__name__.rsplit(".", 1)[0])


def setup_seg6_csid(
    node_id: int, ifname: str, *,
    csid: SRv6CSID,
    vrf_table: VRFTable | int = -1,
    tunnel6_ifname: str | None = None,
    decapsulation_mode: Literal["DT46", "ip6tnl"] = "ip6tnl"
):
    """
    Configure SRv6 Compressed SID (CSID) routing for this node.

    Sets up the NEXT-CSID End behavior to process SRv6 traffic. It configures the ``seg6local``
    route to forward the segment routing headers and optionally binds the decapsulated
    traffic into a specific VRF or IPv6 tunnel interface.

    :param node_id: The ID of the current node to embed into the local Node Function address.
    :param ifname: An interface to masquerade outgoing SRv6 traffic via nftables.
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
        nft_rule = """
destroy table ip6 srv6
table ip6 srv6 {{
    map srv6_paths {{
        type ipv6_addr : ipv6_addr
    }}
    chain raw_prerouting {{
        type filter hook prerouting priority raw; policy accept;
        iif "{ifname}" ip6 daddr {node_addr} ip6 saddr set ip6 saddr & {node_mask} | {lb_addr} ip6 daddr set {local_addr} accept
        iif "{ifname}" ip6 saddr {lb_net} ip6 daddr {node_net} notrack accept
        iif "{ifname}" ip6 saddr {lb_net} counter drop
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        ip6 saddr {lb_net} counter
    }}
    chain mangle_output {{
        type filter hook output priority mangle; policy accept;
        oif "{ifname}" ip6 daddr {lb_net} jump set_route
    }}
    chain set_route {{
        ip6 daddr set ip6 daddr map @srv6_paths counter accept
        counter comment "No route"
    }}
    chain mangle_postrouting {{
        type filter hook postrouting priority mangle; policy accept;
        oif "{ifname}" ip6 saddr {lb_net} ip6 daddr {lb_net} ip6 saddr set ip6 saddr & {node_mask} | {node_addr}
    }}
}}
        """.format(
            ifname=ifname,
            lb_net=csid.locator_block_address,
            lb_addr=get_internal_ip(csid.locator_block_address, 0),
            node_addr=csid.get_node_function_address(node_id, cidr=None),
            node_net=csid.get_node_function_address(node_id, cidr="network"),
            node_mask=ipaddress.ip_network(csid.get_node_function_address(node_id, cidr="network")).hostmask,
            local_addr=get_internal_ip(csid.locator_block_address, node_id)
        )
        logger.debug(f"Creating nft srv6 table: {nft_rule}")
        run(["nft", "-f", "-"], input=nft_rule.encode())
        run(["ip", "addr", "add", get_internal_ip(csid.locator_block_address, node_id, cidr="network"), "dev", ifname])
        run(["ip", "route", "add", "local", csid.get_node_function_address(node_id, cidr="network"), "encap", "seg6local",
             "action", "End", "flavors", "next-csid", "lblen", str(csid.lblen), "nflen", str(csid.nflen), "dev", "lo"])
        if tunnel6_ifname is not None:
            run(["ip", "link", "add", tunnel6_ifname, "type", "ip6tnl", "external"])
            run(["ip", "link", "set", tunnel6_ifname, "mtu", "1380"])
            run(["ip", "link", "set", tunnel6_ifname, "up"])
            run(["ip", "addr", "add", csid.get_node_function_address(node_id, cidr="host"), "dev", "lo"])
        if has_vrf:
            vrf_table = typing.cast(VRFTable, vrf_table)
            vrf_table.up()
            if decapsulation_mode == "ip6tnl":
                if tunnel6_ifname is not None:
                    run(["ip", "link", "set", tunnel6_ifname, "master", str(vrf_table.ifname)])
                else:
                    logger.warning("ip6tnl decapsulation mode requires a external tunnel6 interface for VRF binding.")
            elif decapsulation_mode == "DT46":
                run(["ip", "route", "add", "local", csid.get_node_function_address(node_id, cidr="host"), "encap", "seg6local",
                     "action", "End.DT46", "vrftable", str(vrf_table.table_id), "dev", "lo"])
        else:
            if decapsulation_mode == "DT46":
                logger.warning("DT46 decapsulation mode requires a VRF table.")
        if csid.extra_options and csid.extra_options.get("enable_sticky_ipv4_flow"):
            if tunnel6_ifname is not None:
                set_sticky_ipv4_flow(tunnel6_ifname=tunnel6_ifname, enable=True)
            else:
                logger.warning("Sticky IPv4 flow requires an external tunnel6 interface.")
                set_sticky_ipv4_flow(enable=False)
        else:
            set_sticky_ipv4_flow(enable=False)
    except CalledProcessError as e:
        log_called_process_error(logger.warning, e)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Failed to setup SRv6 CSID: {e!r}")
    else:
        logger.info("SRv6 CSID setup successfully")

def sync_seg6_routes(
    csid: SRv6CSID, *,
    add: dict[int, list[int]] | None = None,
    replace: dict[int, list[int]] | None = None,
    delete: set[int] | None = None,
    flush: bool = False
):
    try:
        add = {} if add is None else add
        replace = {} if replace is None else replace
        delete = set() if delete is None else delete
        add.update(replace)
        delete |= replace.keys()

        nft_commands = ["flush map ip6 srv6 srv6_paths"] if flush else []
        if delete and not flush:
            for nid in delete:
                key = get_internal_ip(csid.locator_block_address, nid)
                nft_commands.append(f"delete element ip6 srv6 srv6_paths {{ {key} }}")
        for nid, hops in add.items():
            key = get_internal_ip(csid.locator_block_address, nid)
            value = csid.get_srv6_address(hops)
            nft_commands.append(f"add element ip6 srv6 srv6_paths {{ {key} : {value} }}")
        if not nft_commands:
            return
        nft_commands_str = "\n".join(nft_commands)
        logger.debug(f"Updating nftables map:\n{nft_commands_str}")
        run(["nft", "-f", "-"], input=nft_commands_str.encode())
    except CalledProcessError as e:
        log_called_process_error(logger.warning, e)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Failed to sync SRv6 routes: {e!r}")
    else:
        logger.info("SRv6 routes synced successfully")

@overload
def set_sticky_ipv4_flow(*, enable: Literal[False], tunnel6_ifname: str | None = None) -> None: ...


@overload
def set_sticky_ipv4_flow(
    *, enable: Literal[True] = True, tunnel6_ifname: str, mark_prefix: int = 0x42, timeout: int = 2
) -> None: ...


def set_sticky_ipv4_flow(
    *, enable: bool = True, tunnel6_ifname: str | None = None, mark_prefix: int = 0x42, timeout: int = 2
) -> None:
    operation = {False: "disable", True: "enable"}[enable]
    try:
        nft_rule = """
flush chain ip6 srv6 set_route
destroy chain ip6 srv6 sticky_route
destroy map ip6 srv6 sticky_dst
destroy table ip sticky_flow
        """
        if enable:
            if tunnel6_ifname is None:
                logger.error("Sticky IPv4 flow requires an external tunnel6 interface.")
                return
            mark_prefix = int(mark_prefix)
            if not 0x00 <= mark_prefix <= 0xFF:
                raise ValueError("mark_prefix must be between 0 and 255")
            mark_mask = mark_prefix << 24
            nft_rule += f"""
table ip6 srv6 {{
    map sticky_dst {{
        type mark : ipv6_addr
        flags dynamic, timeout
        timeout {timeout + 5}s
    }}
    chain set_route {{
        meta mark & 0xFF000000 == {mark_mask:#x} jump sticky_route comment "tunneled traffic"
        ip6 daddr set ip6 daddr map @srv6_paths counter accept comment "raw v6 traffic"
        counter comment "No route"
    }}
    chain sticky_route {{
        ip6 daddr set meta mark map @sticky_dst update @sticky_dst {{ meta mark : :: }} accept
        ip6 daddr set ip6 daddr map @srv6_paths update @sticky_dst {{ meta mark : ip6 daddr }} accept
    }}
}}

table ip sticky_flow {{
    map socket_idx {{
        type inet_proto . ipv4_addr . inet_service . ipv4_addr . inet_service : mark
        flags dynamic, timeout
        timeout {timeout}s
    }}
    chain prerouting {{
        type filter hook prerouting priority filter;
        iifname {tunnel6_ifname} meta l4proto . ip daddr . th dport . ip saddr . th sport @socket_idx update @socket_idx {{ meta l4proto . ip daddr . th dport . ip saddr . th sport : 0 }} counter
    }}
    chain postrouting {{
        type filter hook postrouting priority filter;
        oifname {tunnel6_ifname} meta l4proto {{ tcp, udp }} jump outbound_pkt 
    }}
    chain outbound_pkt {{
        meta mark set meta l4proto . ip saddr . th sport . ip daddr . th dport map @socket_idx return
        meta mark set {mark_mask:#x} | numgen inc mod 0x01000000
        update @socket_idx {{ meta l4proto . ip saddr . th sport . ip daddr . th dport : meta mark }}
    }}
}}
            """
        else:
            nft_rule += f"""
table ip6 srv6 {{
    chain set_route {{
        ip6 daddr set ip6 daddr map @srv6_paths counter accept
        counter comment "No route"
    }}
}}
            """  # noqa: F541
        logger.debug(f"Updating nft srv6 table to {operation} sticky IPv4 flow: {nft_rule}")
        run(["nft", "-f", "-"], input=nft_rule.encode())
    except CalledProcessError as e:
        log_called_process_error(logger.warning, e)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Failed to {operation} sticky IPv4 flow: {e!r}")
    else:
        if enable:
            logger.info(f"Sticky IPv4 flow enabled on {tunnel6_ifname}")
        else:
            logger.info("Sticky IPv4 flow disabled")
