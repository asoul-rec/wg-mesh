import logging
from subprocess import CalledProcessError

from .proc import _run, _run_async
from ..utils import get_internal_ip


def setup_gre_interface(iface_name, cidr):
    try:
        _run(["ip", "link", "add", iface_name, "type", "gre", "external"])
        _run(["ip", "link", "set", iface_name, "mtu", "1392"])
        _run(["ip", "link", "set", iface_name, "up"])
        _run(["ip", "addr", "add", cidr, "dev", iface_name])
    except CalledProcessError as e:
        logging.warning(f"{e} stdout: {e.output.decode()} stderr: {e.stderr.decode()}")
    except Exception as e:
        logging.warning(f"Failed to setup GRE interface: {e!r}")
    else:
        logging.info(f"GRE interface {iface_name} setup successfully with {cidr}")

def sync_direct_peers(iface_name, peers_id, network_addr, underlay_network_addr):
    try:
        _run(["ip", "route", "flush", "dev", iface_name])
        for nid in peers_id:
            _run(["ip", "route", "add", get_internal_ip(network_addr, nid, cidr="host"),
                  "encap", "ip", "dst", get_internal_ip(underlay_network_addr, nid), "dev", iface_name])
    except CalledProcessError as e:
        logging.warning(f"{e} stdout: {e.output.decode()} stderr: {e.stderr.decode()}")
    except Exception as e:
        logging.warning(f"Failed to sync direct peers: {e!r}")
    else:
        logging.info(f"Direct peers synced successfully")
