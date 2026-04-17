import itertools
import logging
from subprocess import CalledProcessError
from typing import Optional

from .proc import run, log_called_process_error


class VRFTable:
    """
    A controller for Linux Virtual Routing and Forwarding (VRF) interfaces.

    This class manages the lifecycle and routing rules of a VRF interface using
    ``iproute2`` commands. It keeps track of the interface state (up/down).
    """

    def __init__(self, table_id: int, ifname: Optional[str] = None):
        """
        Initialize the VRFTable controller.

        :param table_id: The routing table ID to associate with the VRF.
        :param ifname: The name for the VRF interface. Defaults to "vrf<table_id>".
        """
        self.table_id = table_id
        self.state = None
        self._encap_route_cache = {}
        if ifname is None:
            self.ifname = f"vrf{table_id}"
        else:
            self.ifname = ifname

    @staticmethod
    def _try_run(cmd, msg_fail, msg_success):
        try:
            run(cmd)
        except CalledProcessError as e:
            log_called_process_error(logging.warning, e)
        except Exception as e:
            logging.warning(msg_fail + repr(e))
        else:
            logging.info(msg_success)
            return True
        return False

    def setup(self):
        """
        Create the VRF interface and assign it to the routing table.

        Transitions the state to 'down' upon successful creation.
        """
        success = self._try_run(
            ["ip", "link", "add", self.ifname, "type", "vrf", "table", str(self.table_id)],
            f"Failed to setup VRF interface {self.ifname}: ",
            f"VRF interface {self.ifname} setup successfully"
        )
        if success:
            self.state = "down"

    def up(self):
        """
        Bring the VRF interface up. If it doesn't exist yet, it is created first.

        Transitions the state to 'up'.
        """
        if self.state is None:
            self.setup()
        if self.state == "down":
            success = self._try_run(
                ["ip", "link", "set", self.ifname, "up"],
                f"Failed to bring up VRF interface {self.ifname}: ",
                f"VRF interface {self.ifname} is up"
            )
            if success:
                self.state = "up"

    def down(self):
        """
        Bring the VRF interface down.

        Transitions the state to 'down'.
        """
        if self.state == "up":
            success = self._try_run(
                ["ip", "link", "set", self.ifname, "down"],
                f"Failed to bring down VRF interface {self.ifname}: ",
                f"VRF interface {self.ifname} is down"
            )
            if success:
                self.state = "down"

    def add_route(self, network_addr: str, route_options: Optional[dict]):
        """
        Add a route to the VRF routing table.

        :param network_addr: The destination network address (e.g., '10.0.0.0/24').
        :param route_options: Dictionary storing route details or None.
        """
        if route_options is None:
            self._try_run(
                ["ip", "addr", "add", network_addr, "dev", self.ifname],
                f"Failed to add address {network_addr} to {self.ifname}: ",
                f"Address {network_addr} added to {self.ifname}"
            )
            return

        if dev := route_options.get("dev"):
            self._try_run(
                ["ip", "link", "set", "dev", dev, "master", self.ifname],
                f"Failed to set {dev} master to {self.ifname}: ",
                f"Device {dev} is now slave to {self.ifname}"
            )

        cmd = ["ip", "route", "add", network_addr, "vrf", self.ifname]
        cmd += itertools.chain.from_iterable(route_options.items())
        self._try_run(
            cmd,
            f"Failed to add route {network_addr} to VRF {self.ifname}: ",
            f"Route {network_addr} added to VRF {self.ifname}"
        )

    def add_encap_route(self, network_addr: str, encap_dst: str, dev: str):
        """
        Add an IPv6 encapsulated route to the VRF routing table.

        :param network_addr: The destination network address (e.g., '10.0.0.0/24').
        :param encap_dst: The IPv6 destination for encapsulation.
        :param dev: The exit device for the route.
        """
        self._try_run(
            ["ip", "route", "add", network_addr, "encap", "ip6", "dst", encap_dst, "dev", dev, "table", str(self.table_id)],
            f"Failed to add encap route {network_addr} to table {self.table_id}: ",
            f"Encap route {network_addr} added to VRF interface {self.ifname}"
        )

    def del_route(self, network_addr: str, dev: str):
        """
        Delete a route from the VRF routing table.

        :param network_addr: The destination network address.
        :param dev: The exit device for the route.
        """
        self._try_run(
            ["ip", "route", "del", network_addr, "dev", dev, "table", str(self.table_id)],
            f"Failed to delete route {network_addr} from table {self.table_id}: ",
            f"Route {network_addr} deleted from VRF interface {self.ifname}"
        )

    def replace_encap_route(self, network_addr: str, encap_dst: str, dev: str):
        """
        Replace an IPv6 encapsulated route in the VRF routing table.
        """
        self._try_run(
            ["ip", "route", "replace", network_addr, "encap", "ip6", "dst", encap_dst, "dev", dev, "table", str(self.table_id)],
            f"Failed to replace encap route {network_addr} to table {self.table_id}: ",
            f"Encap route {network_addr} replaced on VRF interface {self.ifname}"
        )

    def sync_encap_routes(self, expected_encap_routes: dict[str, str], dev: str):
        old_keys, new_keys = self._encap_route_cache.keys(), expected_encap_routes.keys()
        for net in old_keys - new_keys:
            self.del_route(net, dev)
        for net in new_keys - old_keys:
            self.add_encap_route(net, expected_encap_routes[net], dev)
        for net in old_keys & new_keys:
            if expected_encap_routes[net] != self._encap_route_cache[net]:
                self.replace_encap_route(net, expected_encap_routes[net], dev)
        self._encap_route_cache = expected_encap_routes
