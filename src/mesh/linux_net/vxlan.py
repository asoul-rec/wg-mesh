import logging
from subprocess import CalledProcessError

from ..utils.ip import get_internal_ip
from .proc import log_called_process_error, run

logger = logging.getLogger(__name__)


def setup_vxlan_interface(
    iface_name, cidr, underlay_iface, underlay_addr, vxlan_id=1, dstport=4789
):
    try:
        run(["ip", "link", "add", iface_name, "type", "vxlan", "id", str(vxlan_id),
             "dstport", str(dstport), "local", underlay_addr, "dev", underlay_iface])
        run(["ip", "link", "set", iface_name, "up"])
        run(["ip", "addr", "add", cidr, "dev", iface_name])
    except CalledProcessError as e:
        log_called_process_error(logger.warning, e)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Failed to setup VXLAN interface: {e!r}")
    else:
        logger.info(f"VXLAN interface {iface_name} setup successful with {cidr}")

def sync_vxlan_peers(iface_name, peers_id, network_addr, underlay_network_addr):
    try:
        for nid in peers_id:
            run(["bridge", "fdb", "delete", "00:00:00:00:00:00", "dev", iface_name,
                  "dst", get_internal_ip(underlay_network_addr, nid)], check=False)
            run(["bridge", "fdb", "append", "00:00:00:00:00:00", "dev", iface_name,
                  "dst", get_internal_ip(underlay_network_addr, nid)])
    except CalledProcessError as e:
        log_called_process_error(logger.warning, e)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Failed to sync VXLAN peers: {e!r}")
    else:
        logger.info("VXLAN peers synced successfully")
