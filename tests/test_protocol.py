"""Tests for MeshController.process_announce — the gossip merge engine.

This is the most complex single method in the codebase.  It implements
five interacting concerns:

  1. **Flood control** — drop packets whose origin seq_num falls within
     ``(-STALE_TOLERANCE, 0]`` of the local record (prevents replayed
     announces from re-triggering convergence).
  2. **UTC timestamp veto** — override seq_num comparison when timestamps
     diverge by ≥120 s (catches ghost-seq attacks from nodes with stale
     clocks and recovers amnesia-reset nodes whose seq dropped to 0).
  3. **Conflict resolution** — if content (name, pubkey, endpoint) differs
     at the same seq_num, delete the peer rather than guess which is right.
  4. **Self-protection** — never accept external updates about our own
     node; instead, flag the source for correction.
  5. **Broadcast decision** — either forward the original packet (consistent
     state) or re-announce merged state (correction needed).

Tests mock only the async I/O surface (send_ack, announce, broadcast) and
let the actual gossip logic run against a real config file on disk.

Requires Python ≥3.14 (``compression.zstd``).
"""

import json
import time
from unittest.mock import Mock

import compression.zstd as zstd
import pytest

from mesh.mesh import MeshController
from mesh.node import Node
from conftest import TEST_KEYS


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

NETWORK = "10.123.234.0/24"


def make_announce_payload(network: str, node_dicts: list[dict]) -> bytes:
    """Build a zstd-compressed announce payload identical to what
    ``_throttled_announce`` produces on the wire.
    """
    data = {"network": network, "nodes": node_dicts}
    return zstd.compress(json.dumps(data, separators=(',', ':')).encode())


def node_dict(node_id: int, name: str, pubkey: str, *, endpoint: str = "",
              seq_num: int = 0, timestamp: int | None = None,
              **extra) -> dict:
    """Shorthand for building the per-node dict inside an announce payload."""
    d = {
        "node_id": node_id,
        "name": name,
        "pubkey": pubkey,
        "seq_num": seq_num,
        "timestamp": timestamp if timestamp is not None else int(time.time()),
    }
    if endpoint:
        d["endpoint"] = endpoint
    d.update(extra)
    return d


# ---------------------------------------------------------------------------
#  Fixture: a 2-node MeshController ready for process_announce calls
# ---------------------------------------------------------------------------

@pytest.fixture
def ctrl(config_file):
    """Create a ``MeshController(dry_run=True)`` backed by a real temp
    config, then stub out the three async methods that would need a
    running event loop.  Everything else — including ``save_conf``,
    ``bump_my_seq``, and the entire gossip merge logic — runs un-mocked.

    Initial state (from ``sample_config`` in conftest.py):

    ========  ===========  ========  =========================
    node_id   name         seq_num   pubkey
    ========  ===========  ========  =========================
    1 (me)    test-node-1  100       TEST_KEYS[1]["public_key"]
    2 (peer)  test-node-2  50        TEST_KEYS[2]["public_key"]
    ========  ===========  ========  =========================
    """
    c = MeshController(config_file, dry_run=True)
    c.send_ack = Mock()
    c.announce = Mock()
    c.broadcast = Mock()
    return c


# ═══════════════════════════════════════════════════════════════════════════
#  process_announce
# ═══════════════════════════════════════════════════════════════════════════

class TestProcessAnnounce:
    """Each test constructs a zstd-compressed announce payload and feeds
    it to ``process_announce``, then asserts on the resulting state
    changes and I/O decisions (mock calls).
    """

    # --- Flood control --------------------------------------------------------

    def test_stale_packet_dropped(self, ctrl):
        """An announce whose origin seq_num matches the local record
        (diff == 0, which falls inside ``(-STALE_TOLERANCE, 0]``) must be
        ACK'd and dropped — no state change, no broadcast.
        """
        payload = make_announce_payload(NETWORK, [
            node_dict(1, "test-node-1", TEST_KEYS[1]["public_key"], seq_num=100),
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"],
                      endpoint="172.20.123.2:51820", seq_num=50),
        ])
        ctrl.process_announce(
            origin_id=2, seq_num=50, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.2",
        )
        # ACK is sent even for stale packets (avoids retry storms)
        ctrl.send_ack.assert_called_once()
        # But the packet is dropped: no forwarding, no correction
        ctrl.broadcast.assert_not_called()
        ctrl.announce.assert_not_called()

    def test_amnesia_recovery_not_dropped(self, ctrl):
        """When the origin's seq_num is *far* behind the local record
        (diff ≤ -STALE_TOLERANCE), the packet bypasses flood control.
        This allows a node that reset to seq 0 to rejoin the mesh.

        The boundary is strict-less-than: diff == -4096 passes, but
        diff == -4095 is still dropped (tested in test_algorithm.py).
        """
        # Node 2 local seq = 50.  Incoming at exactly -STALE_TOLERANCE:
        #   (50 - 4096) mod 2^32 = 4294963250
        #   wrapping_sub(4294963250, 50) == -4096  →  NOT in (-4096, 0]
        amnesia_seq = (50 - 4096) % (1 << 32)
        payload = make_announce_payload(NETWORK, [
            node_dict(1, "test-node-1", TEST_KEYS[1]["public_key"], seq_num=100),
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"],
                      endpoint="172.20.123.2:51820", seq_num=amnesia_seq),
        ])
        ctrl.process_announce(
            origin_id=2, seq_num=amnesia_seq, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.2",
        )
        # Packet was NOT dropped — the merge logic ran and flagged correction
        # (seq_diff <= -STALE_TOLERANCE triggers source_needs_correction)
        ctrl.send_ack.assert_called_once()
        ctrl.announce.assert_called_once()

    # --- New node discovery ---------------------------------------------------

    def test_new_node_added(self, ctrl):
        """When the payload includes a node not in our ``known_nodes``,
        it should be added (topology_changed=True) and the raw broadcast
        should be forwarded to other peers.
        """
        now = int(time.time())
        payload = make_announce_payload(NETWORK, [
            node_dict(1, "test-node-1", TEST_KEYS[1]["public_key"],
                      seq_num=100, timestamp=now),
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"],
                      endpoint="172.20.123.2:51820", seq_num=51, timestamp=now),
            # Brand new node 3
            node_dict(3, "test-node-3", TEST_KEYS[3]["public_key"],
                      seq_num=10, timestamp=now),
        ])
        ctrl.process_announce(
            origin_id=2, seq_num=51, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.2",
        )
        assert 3 in ctrl.known_nodes
        assert ctrl.known_nodes[3].name == "test-node-3"
        assert ctrl.known_nodes[3].pubkey == TEST_KEYS[3]["public_key"]

    # --- Timestamp-based veto / amnesia override ------------------------------

    def test_future_timestamp_rejected(self, ctrl):
        """A node whose timestamp is >60 s in the future must be skipped
        (not added or updated).  This prevents clock-skew attacks from
        poisoning the mesh state.

        Note: the 60 s threshold is generous — NTP-synced clocks rarely
        drift more than a few seconds.
        """
        now = int(time.time())
        payload = make_announce_payload(NETWORK, [
            node_dict(1, "test-node-1", TEST_KEYS[1]["public_key"],
                      seq_num=100, timestamp=now),
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"],
                      endpoint="172.20.123.2:51820", seq_num=51, timestamp=now),
            # Ghost node with timestamp 5 minutes in the future
            node_dict(3, "ghost-node", TEST_KEYS[3]["public_key"],
                      seq_num=999, timestamp=now + 300),
        ])
        ctrl.process_announce(
            origin_id=2, seq_num=51, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.2",
        )
        # Node 3 should NOT be added — its timestamp is suspicious
        assert 3 not in ctrl.known_nodes

    def test_ghost_seq_vetoed(self, ctrl):
        """If a node's incoming seq_num is newer but its timestamp is
        ≥120 s older than the local record, the update is vetoed.

        This catches the "ghost seq" scenario: a node with a stale clock
        pushes a high seq_num, which would otherwise win the comparison
        and overwrite legitimate state.

        After veto, the packet is still forwarded — other nodes decide
        for themselves based on their own timestamps.
        """
        now = int(time.time())
        ctrl.known_nodes[2].timestamp = now

        # Incoming: higher seq (9999 > 50) but 200 s older timestamp
        payload = make_announce_payload(NETWORK, [
            node_dict(1, "test-node-1", TEST_KEYS[1]["public_key"],
                      seq_num=100, timestamp=now),
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"],
                      endpoint="172.20.123.2:51820", seq_num=9999,
                      timestamp=now - 200),
        ])
        old_seq = ctrl.known_nodes[2].seq_num  # 50
        ctrl.process_announce(
            origin_id=2, seq_num=9999, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.2",
        )
        # The seq update should be vetoed — local seq stays at 50
        assert ctrl.known_nodes[2].seq_num == old_seq

    # --- Self-protection ------------------------------------------------------

    def test_conflict_about_self_triggers_correction(self, ctrl):
        """If the incoming payload claims different content for our own
        node (nid == my_id), we must NOT update our record and must
        trigger a correction broadcast (bump_my_seq + announce).

        This is the primary defence against identity hijacking in the
        gossip protocol — a node is always authoritative about itself.
        """
        now = int(time.time())
        payload = make_announce_payload(NETWORK, [
            # Wrong pubkey for node 1 (us!)
            node_dict(1, "test-node-1", "WRONG-PUBKEY-FOR-NODE-1",
                      seq_num=200, timestamp=now),
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"],
                      endpoint="172.20.123.2:51820", seq_num=51, timestamp=now),
        ])
        ctrl.process_announce(
            origin_id=2, seq_num=51, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.2",
        )
        # Our pubkey must NOT change
        assert ctrl.known_nodes[1].pubkey == TEST_KEYS[1]["public_key"]
        # Correction broadcast must be triggered
        ctrl.announce.assert_called_once()

    # --- Conflict resolution --------------------------------------------------

    def test_same_seq_different_content_deletes_node(self, ctrl):
        """If a peer has the same seq_num as our local record but
        different content (endpoint, name, or pubkey), the ambiguity
        is unresolvable — the code deletes the node entirely, forcing
        re-discovery on the next announce cycle.

        This is an intentional last-resort mechanism: rather than guess
        which version is correct, forget the node and let convergence
        re-establish it from the authoritative source.

        Origin must be a *different* node to pass the stale check.
        """
        now = int(time.time())
        # Add node 3 as the origin so its seq passes the stale check
        ctrl.known_nodes[3] = Node(
            3, "test-node-3", pubkey=TEST_KEYS[3]["public_key"], seq_num=10,
        )
        payload = make_announce_payload(NETWORK, [
            node_dict(1, "test-node-1", TEST_KEYS[1]["public_key"],
                      seq_num=100, timestamp=now),
            # Node 2: same seq (50) but different endpoint → conflict
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"],
                      endpoint="1.2.3.4:51820", seq_num=50, timestamp=now),
            node_dict(3, "test-node-3", TEST_KEYS[3]["public_key"],
                      seq_num=11, timestamp=now),
        ])
        ctrl.process_announce(
            origin_id=3, seq_num=11, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.3",
        )
        # Node 2 should be deleted due to same-seq content conflict
        assert 2 not in ctrl.known_nodes

    # --- Network mismatch -----------------------------------------------------

    def test_network_mismatch_dropped(self, ctrl):
        """An announce payload whose ``network`` field differs from ours
        must be silently dropped — no ACK, no broadcast, no state change.

        This prevents cross-mesh contamination when multiple overlays
        share the same WireGuard transport.
        """
        payload = make_announce_payload("10.99.99.0/24", [
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"], seq_num=51),
        ])
        ctrl.process_announce(
            origin_id=2, seq_num=51, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.2",
        )
        # Everything is silent — the packet is discarded before merge
        ctrl.send_ack.assert_not_called()
        ctrl.broadcast.assert_not_called()
        ctrl.announce.assert_not_called()

    # --- Consistent forwarding ------------------------------------------------

    def test_consistent_announce_forwarded(self, ctrl):
        """When incoming state is consistent with local state (all nodes
        present, no content conflicts, newer seq), the raw broadcast
        should be forwarded to other peers — not re-announced.

        Forwarding the raw packet instead of re-announcing preserves the
        original origin_id and seq_num, which is essential for the stale-
        detection window to work correctly across multiple hops.
        """
        now = int(time.time())
        payload = make_announce_payload(NETWORK, [
            node_dict(1, "test-node-1", TEST_KEYS[1]["public_key"],
                      seq_num=100, timestamp=now),
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"],
                      endpoint="172.20.123.2:51820", seq_num=200, timestamp=now),
        ])
        ctrl.process_announce(
            origin_id=2, seq_num=200, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.2",
        )
        # Local seq for node 2 should be updated
        assert ctrl.known_nodes[2].seq_num == 200
        # No correction needed → forward raw broadcast
        ctrl.broadcast.assert_called_once()
        ctrl.announce.assert_not_called()

    # --- Missing-node correction ----------------------------------------------

    def test_missing_node_triggers_correction(self, ctrl):
        """If we know about a node that the sender doesn't include in
        its announce payload, we trigger a correction broadcast so the
        sender can learn about the missing node.

        This is the primary mechanism for disseminating knowledge about
        late-joining nodes: when the joiner announces to any single peer,
        that peer re-announces to everyone with the merged state.
        """
        now = int(time.time())
        # We know about node 3, but the sender doesn't
        ctrl.known_nodes[3] = Node(
            3, "test-node-3", pubkey=TEST_KEYS[3]["public_key"], seq_num=10,
        )
        payload = make_announce_payload(NETWORK, [
            node_dict(1, "test-node-1", TEST_KEYS[1]["public_key"],
                      seq_num=100, timestamp=now),
            node_dict(2, "test-node-2", TEST_KEYS[2]["public_key"],
                      endpoint="172.20.123.2:51820", seq_num=51, timestamp=now),
            # Node 3 is NOT in this payload
        ])
        ctrl.process_announce(
            origin_id=2, seq_num=51, pkt_tag=0,
            payload=payload, sender_ip="10.123.234.2",
        )
        # Source is missing node 3 → correction needed
        ctrl.announce.assert_called_once()
        # Correction replaces forwarding — raw broadcast is NOT sent
        ctrl.broadcast.assert_not_called()
