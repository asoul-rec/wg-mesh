import logging
from subprocess import CalledProcessError
from typing import Optional, Union, Literal

from .proc import run, log_called_process_error
from .vrf import VRFTable
from ..utils import SRv6CSID


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
            table ip6 nat {{
                chain srv6masq {{
                    type nat hook postrouting priority srcnat; policy accept;
                    iif "{iface}" oif "{iface}" ip6 saddr {lb_addr} ip6 daddr {lb_addr} masquerade
                }}
            }}
            """.format(iface=masquerade_iface, lb_addr=csid.locator_block_address)
            logging.debug(f"Creating nft srv6masq chain: {nft_rule}")
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
