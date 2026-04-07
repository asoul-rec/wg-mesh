from .linux_net.seg6 import setup_seg6_csid, sync_seg6_routes
from .utils import SRv6CSID


class Seg6Controller:
    """
    SRv6 CSID controller.
    """
    def __init__(self, csid: SRv6CSID):
        self.csid = csid
        self._route_table_cache = {}

    def setup(self, *args, **kwargs):
        setup_seg6_csid(*args, **kwargs, csid=self.csid)

    def sync_routes(self, route_table: dict[int, list[int]], flush: bool = False):
        if not flush:
            old_keys, new_keys = self._route_table_cache.keys(), route_table.keys()
            kwargs = {
                "delete": old_keys - new_keys,
                "add": {k: route_table[k] for k in new_keys - old_keys},
                "replace": {
                    k: new_value for k in old_keys & new_keys
                    if (new_value := route_table[k]) != self._route_table_cache[k]
                }
            }
        else:
            kwargs = {"add": route_table}
        sync_seg6_routes(self.csid, **kwargs, flush=flush)
        self._route_table_cache = route_table
