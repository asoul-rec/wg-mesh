import logging
from subprocess import CalledProcessError

from .proc import run, log_called_process_error
from ..utils import get_internal_ip


def setup_vxlan_interface(
    iface_name, cidr, underlay_iface, underlay_addr, vxlan_id=1, dstport=4789
):
    try:
        run(["ip", "link", "add", iface_name, "type", "vxlan", "id", str(vxlan_id),
             "dstport", str(dstport), "local", underlay_addr, "dev", underlay_iface])
        run(["ip", "link", "set", iface_name, "up"])
        run(["ip", "addr", "add", cidr, "dev", iface_name])
    except CalledProcessError as e:
        log_called_process_error(logging.warning, e)
    except Exception as e:
        logging.warning(f"Failed to setup VXLAN interface: {e!r}")
    else:
        logging.info(f"VXLAN interface {iface_name} setup successful with {cidr}")

def sync_vxlan_peers(iface_name, peers_id, network_addr, underlay_network_addr):
    try:
        for nid in peers_id:
            run(["bridge", "fdb", "delete", "00:00:00:00:00:00", "dev", iface_name,
                  "dst", get_internal_ip(underlay_network_addr, nid)], check=False)
            run(["bridge", "fdb", "append", "00:00:00:00:00:00", "dev", iface_name,
                  "dst", get_internal_ip(underlay_network_addr, nid)])
    except CalledProcessError as e:
        log_called_process_error(logging.warning, e)
    except Exception as e:
        logging.warning(f"Failed to sync VXLAN peers: {e!r}")
    else:
        logging.info(f"VXLAN peers synced successfully")
