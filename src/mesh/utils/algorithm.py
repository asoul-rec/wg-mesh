import heapq
import math
from itertools import pairwise


__all__ = [
    "wrapping_sub",
    "compute_shortest_paths",
    "LinkCostSummary",
]


def wrapping_sub(a: int, b: int, max_val: int = 1 << 32) -> int:
    """
    Compute the wrapping difference between two integers.

    :param a: The first integer.
    :param b: The second integer.
    :param max_val: The maximum value.
    :return: The wrapping difference between a and b.
    """
    return (a - b + (max_val >> 1)) % max_val - (max_val >> 1)


def compute_shortest_paths(link_state, me_id, no_route_val=3000):
    distances = {nid: no_route_val for nid in link_state}
    distances[me_id] = 0
    predecessors = {nid: None for nid in link_state}
    pq = [(0, me_id)]
    visited = set()
    while pq:
        current_dist, current_node = heapq.heappop(pq)
        if current_node in visited:
            continue
        visited.add(current_node)
        if current_node not in link_state:
            continue

        for neighbor, edge_weight in link_state[current_node].items():
            edge_weight = 1 if edge_weight < 1 else edge_weight
            edge_weight = no_route_val if edge_weight > no_route_val else edge_weight
            new_dist = current_dist + edge_weight
            if new_dist < distances[neighbor]:
                distances[neighbor] = new_dist
                predecessors[neighbor] = current_node
                heapq.heappush(pq, (new_dist, neighbor))

    route_table = {}
    for target_nid in link_state:
        if target_nid == me_id or distances[target_nid] == no_route_val:
            continue
        path = []
        curr = target_nid
        while curr != me_id:
            path.append(curr)
            curr = predecessors[curr]
        route_table[target_nid] = path[::-1]
    return route_table


class LinkCostSummary:
    @staticmethod
    def exponential_decay_integral(
        stats: list[tuple[float, int]], curr_time: float, *,
        lost_penalty: int = 6000,
        half_life: int = 20,
        weight_cap: float = 0.2
    ) -> int:
        """
        Compute a weighted-average RTT cost for this peer link using exponential time decay.

        Each sample is assigned a weight by integrating the exponential decay PDF
        ``f(t) = ln(2)/HALF_LIFE * 2^(-(curr_time - t)/HALF_LIFE)`` over the interval
        from the previous midpoint to the next midpoint between consecutive samples
        (sorted newest-first). Because the PDF integrates to 1 over ``(-inf, curr_time]``,
        the weights naturally sum to 1 when all history is covered.

        Individual weights are capped at ``WEIGHT_CAP`` to prevent any single sample
        from dominating. If the oldest sample still leaves unassigned weight, the
        result is rescaled to normalize over the covered portion. Lost packets
        (``rtt < 0``) are substituted with ``LOST_PENALTY`` ms.

        :param curr_time: The current monotonic time (``loop.time()``).
        :return: The weighted link cost in milliseconds, minimum 1.
        """
        if not stats:
            return lost_penalty
        decay = -math.log(2) / half_life
        cost = 0
        sorted_stats = sorted(stats, reverse=True)
        weight_left = 1
        for (t_i, rtt_i), (t_prev, _) in pairwise(sorted_stats):
            rtt_i = rtt_i if rtt_i > 0 else lost_penalty
            if weight_left < 0.01:
                cost += weight_left * rtt_i
                break
            weight = weight_left - math.e ** (decay * (curr_time - (t_prev + t_i) / 2))
            weight = weight_cap if weight > weight_cap else weight
            cost += weight * rtt_i
            weight_left -= weight
        else:  # reach the final item but has significant weight_left
            rtt_i = sorted_stats[-1][1]
            rtt_i = rtt_i if rtt_i > 0 else lost_penalty
            weight = weight_cap if weight_left > weight_cap else weight_left
            cost += weight * rtt_i
            cost /= 1 - (weight_left - weight)
        cost = 1 if cost < 1 else cost
        return round(cost)
