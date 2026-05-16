"""Tests for mesh.utils.algorithm — the numerical backbone of the mesh protocol.

Covers:
- ``wrapping_sub``: signed 32-bit sequence number comparison (used by gossip
  stale-detection and conflict resolution).
- ``compute_shortest_paths``: Dijkstra's algorithm over the link-state graph
  (used by the Routing daemon to build SRv6 hop lists).
- ``LinkCostSummary.exponential_decay_integral``: time-weighted RTT averaging
  (used to convert raw ACK samples into a single link cost metric).
"""

import pytest
from mesh.utils.algorithm import wrapping_sub, compute_shortest_paths, LinkCostSummary


# ═══════════════════════════════════════════════════════════════════════════
#  wrapping_sub — signed distance on a 32-bit ring
# ═══════════════════════════════════════════════════════════════════════════

class TestWrappingSub:
    """``wrapping_sub(a, b)`` returns the signed distance from *b* to *a* on
    a 32-bit ring.  Positive means *a* is newer; negative means *a* is older.

    This is the same idea as TCP sequence number comparison (RFC 1323 §4).
    Getting this wrong would silently break gossip stale-detection.
    """

    MAX = 1 << 32          # 4294967296
    HALF = 1 << 31         # 2147483648 — the signed ambiguity point

    # --- basic arithmetic ---------------------------------------------------

    def test_positive_when_a_is_ahead(self):
        assert wrapping_sub(5, 3) == 2
        assert wrapping_sub(100, 1) == 99

    def test_negative_when_a_is_behind(self):
        assert wrapping_sub(3, 5) == -2
        assert wrapping_sub(1, 100) == -99

    def test_zero_when_equal(self):
        assert wrapping_sub(0, 0) == 0
        assert wrapping_sub(42, 42) == 0
        assert wrapping_sub(self.MAX - 1, self.MAX - 1) == 0

    # --- wrap-around across the u32 boundary --------------------------------

    def test_forward_wrap(self):
        """``a`` just past 0 while ``b`` is near MAX → ``a`` is newer."""
        assert wrapping_sub(0, self.MAX - 1) == 1
        assert wrapping_sub(1, self.MAX - 1) == 2
        assert wrapping_sub(100, self.MAX - 100) == 200

    def test_backward_wrap(self):
        """``a`` near MAX while ``b`` just past 0 → ``a`` is older."""
        assert wrapping_sub(self.MAX - 1, 0) == -1
        assert wrapping_sub(self.MAX - 1, 1) == -2
        assert wrapping_sub(self.MAX - 100, 100) == -200

    # --- symmetry and boundary properties -----------------------------------

    def test_antisymmetry(self):
        """``wrapping_sub(a, b) == -wrapping_sub(b, a)`` everywhere except at
        exactly HALF distance, where both directions map to ``-HALF`` (the
        two's-complement minimum has no positive counterpart).
        """
        pairs = [(5, 3), (0, self.MAX - 1), (1000, 500), (100, self.MAX - 100)]
        for a, b in pairs:
            assert wrapping_sub(a, b) == -wrapping_sub(b, a), f"failed for ({a}, {b})"

    def test_half_range_ambiguity(self):
        """At exactly HALF distance, both directions yield ``-HALF``.

        This is analogous to ``-2^31`` in two's complement — it has no
        positive counterpart.  In practice this never matters because
        STALE_TOLERANCE (4096) is far smaller than HALF (2^31).
        """
        assert wrapping_sub(0, self.HALF) == -self.HALF
        assert wrapping_sub(self.HALF, 0) == -self.HALF

    # --- interaction with the gossip stale-detection window -----------------

    def test_stale_window_boundaries(self):
        """Verify the gossip stale-detection predicate:

            ``-STALE_TOLERANCE < diff <= 0``  →  drop (stale replay)

        Boundary cases matter:
        - ``diff == 0``  →  in window (drop, it's a duplicate)
        - ``diff == -1``  →  in window (slightly old, drop)
        - ``diff == -STALE_TOLERANCE``  →  NOT in window (amnesia recovery)
        - ``diff == -STALE_TOLERANCE + 1``  →  in window (barely stale, drop)
        - ``diff == 1``  →  NOT in window (newer, accept)
        """
        STALE_TOLERANCE = 4096

        # diff == 0 → drop
        diff = wrapping_sub(5000, 5000)
        assert -STALE_TOLERANCE < diff <= 0

        # diff == -1 → drop
        diff = wrapping_sub(4999, 5000)
        assert -STALE_TOLERANCE < diff <= 0

        # diff == -4095 → drop (barely inside window)
        diff = wrapping_sub(905, 5000)
        assert diff == -4095
        assert -STALE_TOLERANCE < diff <= 0

        # diff == -4096 → NOT in window (amnesia territory)
        diff = wrapping_sub(904, 5000)
        assert diff == -4096
        assert not (-STALE_TOLERANCE < diff <= 0)

        # diff == +1 → NOT in window (newer, accept)
        diff = wrapping_sub(5001, 5000)
        assert diff == 1
        assert not (-STALE_TOLERANCE < diff <= 0)

    def test_stale_window_across_wrap(self):
        """The stale window must work correctly when sequence numbers wrap
        around the u32 boundary.
        """
        STALE_TOLERANCE = 4096

        # local_seq = 100, recv_seq near MAX → diff ≈ -200, still in window
        diff = wrapping_sub(self.MAX - 100, 100)
        assert diff == -200
        assert -STALE_TOLERANCE < diff <= 0

        # local_seq = 100, recv_seq much further back → outside window (amnesia)
        diff = wrapping_sub(self.MAX - 5000, 100)
        assert diff == -5100
        assert not (-STALE_TOLERANCE < diff <= 0)


# ═══════════════════════════════════════════════════════════════════════════
#  compute_shortest_paths — Dijkstra over the gossip link-state graph
# ═══════════════════════════════════════════════════════════════════════════

class TestComputeShortestPaths:
    """``compute_shortest_paths(link_state, me_id)`` runs Dijkstra and returns
    ``(route_table, distances)`` where ``route_table[target] = [hop, ...]``
    is the ordered path from me to the target.

    The link-state graph is built from gossip-propagated ``route_cost`` dicts:
    ``{node_id: {neighbor_id: cost_ms, ...}, ...}``.
    """

    def test_direct_neighbors(self):
        """Two directly connected nodes → single-hop paths."""
        link_state = {
            1: {2: 10},
            2: {1: 10},
        }
        rt, dist = compute_shortest_paths(link_state, me_id=1)
        assert rt[2] == [2]
        assert dist[2] == 10

    def test_multihop_shorter_than_direct(self):
        """When the indirect path A→B→C is cheaper than A→C, Dijkstra must
        pick the multi-hop route.  This is the core reason SRv6 exists in
        this project — WireGuard only does point-to-point.
        """
        link_state = {
            1: {2: 10, 3: 2000},
            2: {1: 10, 3: 10},
            3: {1: 2000, 2: 10},
        }
        rt, dist = compute_shortest_paths(link_state, me_id=1)
        # Path to 3 should go through 2 (cost 20) instead of direct (cost 2000)
        assert rt[3] == [2, 3]
        assert dist[3] == 20

    def test_disconnected_node(self):
        """An unreachable node should NOT appear in route_table."""
        link_state = {
            1: {2: 10},
            2: {1: 10},
            3: {},           # node 3 has no links
        }
        rt, dist = compute_shortest_paths(link_state, me_id=1)
        assert 3 not in rt
        assert dist[3] == 3000   # no_route_val

    def test_single_node(self):
        """A mesh with only one node → empty route table."""
        rt, dist = compute_shortest_paths({1: {}}, me_id=1)
        assert rt == {}
        assert dist[1] == 0

    def test_edge_weight_clamp_below_one(self):
        """Weights below 1 are clamped to 1 to prevent zero-cost loops."""
        link_state = {
            1: {2: 0},
            2: {1: -5},
        }
        _, dist = compute_shortest_paths(link_state, me_id=1)
        assert dist[2] == 1   # 0 → clamped to 1

    def test_edge_weight_clamp_above_max(self):
        """Weights above no_route_val (3000) are clamped to 3000, which makes
        the link effectively unreachable (total cost == no_route_val).
        """
        link_state = {
            1: {2: 5000},
            2: {1: 5000},
        }
        rt, dist = compute_shortest_paths(link_state, me_id=1)
        # Cost 5000 → clamped to 3000 → total == no_route_val → excluded
        assert 2 not in rt

    def test_complex_diamond_topology(self):
        """Diamond graph:  1 → 2 → 4
                           1 → 3 → 4
        with different costs on each path.
        """
        link_state = {
            1: {2: 100, 3: 50},
            2: {1: 100, 4: 100},
            3: {1: 50, 4: 10},
            4: {2: 100, 3: 10},
        }
        rt, dist = compute_shortest_paths(link_state, me_id=1)
        # Best path to 4: 1→3→4 (cost 60) vs 1→2→4 (cost 200)
        assert rt[4] == [3, 4]
        assert dist[4] == 60


# ═══════════════════════════════════════════════════════════════════════════
#  LinkCostSummary — exponential-decay-weighted RTT averaging
# ═══════════════════════════════════════════════════════════════════════════

class TestLinkCostSummary:
    """``LinkCostSummary.exponential_decay_integral(stats, curr_time)``
    computes a weighted-average RTT with a 20-second half-life.

    - Lost packets (rtt < 0) are penalised at 6000 ms.
    - Individual sample weights are capped at 0.2.
    - Return value is always >= 1.
    """

    edi = staticmethod(LinkCostSummary.exponential_decay_integral)

    def test_empty_returns_lost_penalty(self):
        """No samples → assume the link is dead → return lost_penalty."""
        assert self.edi([], curr_time=100) == 6000

    def test_single_sample(self):
        """A single good sample should produce a cost equal to that RTT."""
        cost = self.edi([(100, 42)], curr_time=100)
        assert cost == 42

    def test_all_lost_approaches_penalty(self):
        """If every packet was lost, cost should be heavily penalised."""
        stats = [(float(t), -1) for t in range(90, 100)]
        cost = self.edi(stats, curr_time=100)
        assert cost >= 3000

    def test_recent_good_reduces_cost(self):
        """Adding recent low-RTT samples should pull the cost well below
        the all-lost penalty (6000 ms).  The weight_cap (0.2) prevents
        any single sample from dominating, so 5 good samples can't fully
        override 10 lost ones — but the exponential decay gives them
        enough weight to cut the cost roughly in half.
        """
        all_lost = [(float(t), -1) for t in range(90, 100)]
        mixed = (
            [(float(t), -1) for t in range(60, 70)]      # old: all lost
            + [(float(t), 5) for t in range(95, 100)]     # recent: 5 ms
        )
        cost_lost = self.edi(all_lost, curr_time=100)
        cost_mixed = self.edi(mixed, curr_time=100)
        # Recent good samples must reduce cost below the all-lost baseline
        assert cost_mixed < cost_lost
        # Cost should drop meaningfully — at least 30% reduction
        assert cost_mixed < cost_lost * 0.7

    def test_weight_cap_limits_outlier(self):
        """A single extreme outlier should not dominate the cost because
        each sample's weight is capped at 0.2.
        """
        stats = (
            [(99.0, 50000)]                                # outlier: 50 s
            + [(float(t), 10) for t in range(80, 99)]      # normal: 10 ms
        )
        cost = self.edi(stats, curr_time=100)
        # Without the cap, the outlier would push cost to ~50000.
        # With cap, it's limited to 0.2 × 50000 = 10000 contribution,
        # diluted by many 10 ms samples.
        assert cost < 5000

    def test_minimum_cost_is_one(self):
        """Cost should never drop below 1, even for sub-millisecond RTTs."""
        stats = [(100.0, 0), (99.0, 0)]
        cost = self.edi(stats, curr_time=100)
        assert cost >= 1
