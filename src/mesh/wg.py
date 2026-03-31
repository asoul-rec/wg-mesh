import logging
import subprocess
import os
import asyncio
import copy
import shlex

from .utils import get_internal_ip


__all__ = [
    "generate_wg_keys",
    "setup_wg_interface",
    "sync_wg_peers",
]


def _run(cmd, **kwargs):
    """Wrapper around subprocess.run that logs the command at DEBUG level."""
    logging.debug(f"Exec: $ {shlex.join(cmd)}")
    return subprocess.run(cmd, **kwargs)


async def _run_async(cmd, timeout=None):
    """Run a subprocess with optional timeout, ensuring zombie reap on any exit path."""
    logging.debug(f"Exec async: $ {shlex.join(cmd)}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        if timeout is not None:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        else:
            stdout, stderr = await proc.communicate()
        return proc.returncode, stdout, stderr
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except OSError:
                pass


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


def setup_wg_interface(iface_name, private_key_str, internal_ip, node_id, listen_port=51820, vxlan_cidr=""):
    """init wg / vxlan interface, equivalent to wg-quick up"""
    try:
        # 1. create private key temp file
        # For security reasons, wg does not accept private key directly from parameters
        # Use /dev/shm to ensure the file is only in memory
        key_path = f"/dev/shm/{iface_name}_priv"
        with open(key_path, "w") as f:
            f.write(private_key_str + "\n")
        os.chmod(key_path, 0o600)

        # 2. create wg interface (if already exists, ignore the error)
        _run(["ip", "link", "add", "dev", iface_name, "type", "wireguard"], stderr=subprocess.DEVNULL)

        # 3. bind private key and port
        _run(["wg", "set", iface_name, "private-key", key_path, "listen-port", str(listen_port)], check=True)

        # 4. set ip and bring up interface
        _run(["ip", "address", "replace", internal_ip, "dev", iface_name], check=True)
        _run(["ip", "link", "set", "up", "dev", iface_name], check=True)

        os.remove(key_path)
        logging.info(f"Interface {iface_name} setup successful with IP {internal_ip}")

        # --- VXLAN POC START ---
        if vxlan_cidr:
            vxlan_ip = get_internal_ip(vxlan_cidr, node_id)
            vxlan_ip_cidr = f"{vxlan_ip}/{vxlan_cidr.split('/')[-1]}"
            try:
                _run(["ip", "link", "add", "vxlan0", "type", "vxlan", "id", "100",
                      "local", str(internal_ip.split('/')[0]), "dstport", "4789", "dev", iface_name])
                _run(["ip", "link", "set", "vxlan0", "up"])
                _run(["ip", "addr", "add", str(vxlan_ip_cidr), "dev", "vxlan0"])
                logging.info(f"VXLAN PoC overlay vxlan0 setup successful with IP {vxlan_ip_cidr}")
            except Exception as e:
                logging.warning(f"Failed to setup VXLAN overlay: {e!r}")
        # --- VXLAN POC END ---

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to setup interface {iface_name}: {e!r}")
        raise

_sync_wg_peers_running = False

async def sync_wg_peers(iface_name, known_nodes_dict, my_node_id, cidr_str):
    """Incrementally sync WireGuard peers. Only one instance may run at a time."""
    global _sync_wg_peers_running
    if _sync_wg_peers_running:
        raise RuntimeError("sync_wg_peers is already running concurrently!")
    _sync_wg_peers_running = True

    try:
        known_nodes = copy.deepcopy(known_nodes_dict)

        # get current peers on the interface
        try:
            _, stdout, _ = await _run_async(["wg", "show", iface_name, "peers"])
            current_peers = set(stdout.decode().strip().splitlines())
        except Exception:
            current_peers = set()

        expected_peers = set()

        # 1. upsert expected peers
        for nid, node in known_nodes.items():
            if nid == my_node_id:
                continue
            expected_peers.add(node.pubkey)
            allowed_ip = f"{get_internal_ip(cidr_str, node.node_id)}/32"

            # --- VXLAN POC START ---
            wgip = allowed_ip.split('/')[0]
            try:
                # Deliberately blind delete first to scrub duplicates, then append
                rc, stdout, stderr = await _run_async(["bridge", "fdb", "delete", "00:00:00:00:00:00", "dev", "vxlan0", "dst", wgip])
                logging.debug(f"delete rc: {rc}, stdout: {stdout.decode().strip()}, stderr: {stderr.decode().strip()}")
                rc, stdout, stderr = await _run_async(["bridge", "fdb", "append", "00:00:00:00:00:00", "dev", "vxlan0", "dst", wgip])
                logging.debug(f"append rc: {rc}, stdout: {stdout.decode().strip()}, stderr: {stderr.decode().strip()}")
            except Exception as e:
                logging.debug(f"VXLAN FDB sync error for {wgip}: {e!r}")
            # --- VXLAN POC END ---

            cmd = ["wg", "set", iface_name, "peer", node.pubkey, "allowed-ips", allowed_ip]
            if node.endpoint:
                cmd.extend(["endpoint", node.endpoint])
            try:
                rc, _, stderr = await _run_async(cmd, timeout=2.0)
                if rc != 0:
                    logging.warning(f"wg set error for peer {node.node_id}: {stderr.decode().strip()}")
            except asyncio.TimeoutError:
                logging.error(f"wg set timed out for peer {node.node_id} (endpoint: {node.endpoint})")
            except Exception as e:
                logging.error(f"wg set failed for peer {node.node_id}: {e!r}")

        # 2. remove stale peers
        for pubkey in current_peers - expected_peers:
            try:
                await _run_async(["wg", "set", iface_name, "peer", pubkey, "remove"], timeout=2.0)
                logging.info(f"Removed stale peer {pubkey} from {iface_name}")
            except asyncio.TimeoutError:
                logging.warning(f"wg remove timed out for stale peer {pubkey}")
            except Exception as e:
                logging.warning(f"Failed to remove stale peer {pubkey}: {e!r}")
    finally:
        _sync_wg_peers_running = False
