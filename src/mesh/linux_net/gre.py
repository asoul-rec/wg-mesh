import logging
from subprocess import CalledProcessError

from .proc import run, log_called_process_error
from ..utils.ip import get_internal_ip


def setup_gre_interface(iface_name, cidr):
    try:
        run(["ip", "link", "add", iface_name, "type", "gre", "external"])
        run(["ip", "link", "set", iface_name, "mtu", "1392"])
        run(["ip", "link", "set", iface_name, "up"])
        run(["ip", "addr", "add", cidr, "dev", iface_name])
    except CalledProcessError as e:
        log_called_process_error(logging.warning, e)
    except Exception as e:
        logging.warning(f"Failed to setup GRE interface: {e!r}")
    else:
        logging.info(f"GRE interface {iface_name} setup successfully with {cidr}")

def sync_direct_peers(iface_name, peers_id, network_addr, underlay_network_addr):
    try:
        run(["ip", "route", "flush", "dev", iface_name])
        for nid in peers_id:
            run(["ip", "route", "add", get_internal_ip(network_addr, nid, cidr="host"),
                  "encap", "ip", "dst", get_internal_ip(underlay_network_addr, nid), "dev", iface_name])
    except CalledProcessError as e:
        log_called_process_error(logging.warning, e)
    except Exception as e:
        logging.warning(f"Failed to sync direct peers: {e!r}")
    else:
        logging.info(f"Direct peers synced successfully")
