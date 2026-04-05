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

    def add_route(self, network_addr: str, dev: str):
        """
        Add a route to the VRF routing table.

        :param network_addr: The destination network address (e.g., '10.0.0.0/24').
        :param dev: The exit device for the route.
        """
        self._try_run(
            ["ip", "route", "add", network_addr, "dev", dev, "table", str(self.table_id)],
            f"Failed to add route {network_addr} to table {self.table_id}: ",
            f"Route {network_addr} added to VRF interface {self.ifname}"
        )
