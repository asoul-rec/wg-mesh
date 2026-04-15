import asyncio
import logging
import random

from .utils.algorithm import compute_shortest_paths


__all__ = [
    "Daemon",
    "OnlineMonitor",
    "KeepAlive",
    "Routing",
]


class Daemon:
    def __init__(self, name=None):
        self._task = None
        self._name = name if name is not None else self.__class__.__name__

    def start(self):
        def _done_callback(t):
            try:
                self._task = None
                if t.cancelled() or (e := t.exception()) is None:
                    logging.info(f"{self._name} loop terminated.")
                else:
                    logging.warning(f"{self._name} loop failed: {e!r}")
            except BaseException as e:
                logging.error(f"Error in {self._name} loop done callback: {e!r}")
                raise

        if self._task is None:
            self._task = asyncio.create_task(self.run())
            self._task.add_done_callback(_done_callback)

    def stop(self):
        if self._task is not None:
            self._task.cancel()

    async def run(self):
        logging.info(f"{self._name} loop started")
        while True:
            await self._loop()

    @property
    def is_running(self):
        return self._task is not None

    async def _loop(self):
        raise NotImplementedError


class OnlineMonitor(Daemon):
    def __init__(self, online_callback, offline_callback, timeout=None):
        """Online status monitor: triggers small interval if no valid packets are received from mesh."""
        super().__init__()
        self.timeout = timeout
        self.online_callback = online_callback
        self.offline_callback = offline_callback
        self.is_offline = True
        self.online_event = asyncio.Event()

    async def _loop(self):
        self.online_event.clear()
        try:
            await asyncio.wait_for(self.online_event.wait(), timeout=self.timeout)
            if self.is_offline:
                logging.info("Node is back online.")
                self.is_offline = False
                self.online_callback()
        except asyncio.TimeoutError:
            if not self.is_offline:
                logging.warning(f"Connection lost! ({self.timeout}s without packets)")
                self.is_offline = True
                self.offline_callback()


class KeepAlive(Daemon):
    """Keepalive: if no broadcast has fired within interval, bump seq and self-broadcast."""
    def __init__(self, callback, keepalive_interval):
        super().__init__()
        self.callback = callback
        self.keepalive_interval = keepalive_interval
        self.keepalive_event = asyncio.Event()

    async def _loop(self):
        self.keepalive_event.clear()
        interval = random.uniform(*self.keepalive_interval)
        try:
            await asyncio.wait_for(self.keepalive_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            logging.debug(f"Keepalive ({interval:.3f}s) firing broadcast")
            self.callback()


class Routing(Daemon):
    """Routing supervisor: periodically computes shortest paths and updates routes."""
    def __init__(self, me_id, link_state_callback, sync_route_callback):
        super().__init__()
        self.me_id = me_id
        self.link_state_callback = link_state_callback
        self.sync_route_callback = sync_route_callback
        self.update_event = asyncio.Event()

    async def _loop(self):
        self.update_event.clear()
        try:
            await asyncio.sleep(3)
            await asyncio.wait_for(self.update_event.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            pass
        link_state = self.link_state_callback()
        route_table, distances = compute_shortest_paths(link_state, self.me_id)
        if route_table:
            logging.debug(f"Update routing {route_table=}, {distances=}")
            try:
                self.sync_route_callback(route_table)
            except Exception as e:
                logging.warning(f"Failed to sync routes: {e!r}")
