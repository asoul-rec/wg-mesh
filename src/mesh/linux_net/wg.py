import asyncio
import copy
import logging
import subprocess
from typing import Optional

from ..utils.ip import get_internal_ip
from .seg6 import SRv6CSID
from .proc import run, run_async


__all__ = [
    "generate_wg_keys",
    "setup_wg_interface",
    "sync_wg_peers",
]


def generate_wg_keys():
    """Attempt to call system 'wg' command to generate a keypair."""
    try:
        logging.debug("Exec: $ wg genkey | wg pubkey")
        privkey = subprocess.check_output(["wg", "genkey"], text=True).strip()
        pubkey = subprocess.check_output(["wg", "pubkey"], input=privkey.encode(), text=True).strip()
        return privkey, pubkey
    except Exception as e:
        logging.error(f"Failed to generate keys via 'wg' command: {e!r}")
        return None, None


def setup_wg_interface(iface_name: str, private_key: str, cidr: str, listen_port: int = 51820):
    """init wg interface, equivalent to wg-quick up"""
    try:
        run(["ip", "link", "add", "dev", iface_name, "type", "wireguard"], check=False)
        run(["wg", "set", iface_name, "private-key", "/dev/stdin", "listen-port", str(listen_port)], input=private_key.encode())
        run(["ip", "address", "replace", cidr, "dev", iface_name])
        run(["ip", "link", "set", "up", "dev", iface_name])
        logging.info(f"Interface {iface_name} setup successful with IP {cidr}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to setup wireguard {iface_name}. {e} stdout: {e.output.decode()} stderr: {e.stderr.decode()}")
        raise

_sync_wg_peers_running = False

async def sync_wg_peers(iface_name: str, known_nodes_dict, my_node_id: int, network_addr: str, csid: Optional[SRv6CSID]=None, vrf=None):
    """Incrementally sync WireGuard peers. Only one instance may run at a time."""
    global _sync_wg_peers_running
    if _sync_wg_peers_running:
        raise RuntimeError("sync_wg_peers is already running concurrently!")
    _sync_wg_peers_running = True

    try:
        known_nodes = copy.deepcopy(known_nodes_dict)
        # get current peers on the interface
        try:
            _, stdout, _ = await run_async(["wg", "show", iface_name, "peers"])
            current_peers = set(stdout.decode().strip().splitlines())
        except Exception:
            current_peers = set()

        expected_peers = set()
        expected_encap_routes = {}

        # 1. upsert expected peers
        for nid, node in known_nodes.items():
            if nid == my_node_id:
                continue
            expected_peers.add(node.pubkey)
            allowed_ips = [get_internal_ip(network_addr, nid, cidr="host")]
            if csid is not None:  # Allow segment routing
                allowed_ips.append(csid.get_node_function_address(nid, cidr="network"))
                # External IPs mapped via CSID locator encap route
                encap_dst = get_internal_ip(csid.locator_block_address, nid, cidr=None)
                for ext_ip in node.external_ips:
                    expected_encap_routes[ext_ip] = encap_dst

            cmd = ["wg", "set", iface_name, "peer", node.pubkey, "allowed-ips", ','.join(allowed_ips)]
            if node.endpoint:
                cmd.extend(["endpoint", node.endpoint])
            try:
                rc, _, stderr = await run_async(cmd, timeout=2.0)
                if rc != 0:
                    logging.warning(f"wg set error for peer {node.node_id}: {stderr.decode().strip()}")
            except asyncio.TimeoutError:
                logging.error(f"wg set timed out for peer {node.node_id} (endpoint: {node.endpoint})")
            except Exception as e:
                logging.error(f"wg set failed for peer {node.node_id}: {e!r}")

        # 2. remove stale peers
        for pubkey in current_peers - expected_peers:
            try:
                await run_async(["wg", "set", iface_name, "peer", pubkey, "remove"], timeout=2.0)
                logging.info(f"Removed stale peer {pubkey} from {iface_name}")
            except asyncio.TimeoutError:
                logging.warning(f"wg remove timed out for stale peer {pubkey}")
            except Exception as e:
                logging.warning(f"Failed to remove stale peer {pubkey}: {e!r}")

        # 3. sync VRF external encapsulated routes logically bypassing wg keys
        if vrf is not None and csid is not None:
            try:
                vrf.sync_encap_routes(expected_encap_routes, "tun6-mesh")
            except Exception as e:
                logging.error(f"Failed to sync external routes via VRF: {e!r}")
    finally:
        _sync_wg_peers_running = False
