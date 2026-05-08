"""Tests for mesh.node — data model and configuration persistence.

Covers:
- ``Node.protected``: field-level write protection with ``_force_write``
  context-manager bypass (prevents gossip-sourced data from silently
  overwriting locally-authoritative fields like ``pubkey``).
- ``get_internal_ip`` / ``get_node_id_from_ip``: address arithmetic that
  maps ``(network_cidr, node_id)`` ↔ IP, used by every outgoing packet.
- ``SRv6CSID``: Compressed-SID address construction (Locator Block + Node
  Function), verified against hand-computed addresses from the production
  container configs.
- ``load_conf`` / ``save_conf`` round-trip: ensures serialisation preserves
  all fields and survives the key-renaming dance (``id`` ↔ ``node_id``,
  ``public_key`` ↔ ``pubkey``).
"""

import json

import pytest

from mesh.node import Node, load_conf, save_conf
from mesh.utils.ip import get_internal_ip, get_node_id_from_ip
from mesh.linux_net.seg6.csid import SRv6CSID

from conftest import TEST_KEYS


# ═══════════════════════════════════════════════════════════════════════════
#  Node — protected-field enforcement
# ═══════════════════════════════════════════════════════════════════════════

class TestNodeProtection:
    """The ``protected`` flag prevents gossip-received updates from
    clobbering locally-authoritative fields (node_id, name, pubkey,
    endpoint, external_ips).  Only ``seq_num``, ``timestamp``, and
    ``route_cost`` can be written freely on a protected node.
    """

    def test_protected_field_raises(self):
        """Writing to a protected field on a protected node must raise."""
        node = Node(1, "n1", pubkey="key", protected=True)
        with pytest.raises(AttributeError, match="read-only"):
            node.pubkey = "evil-key"

    def test_unprotected_field_writable(self):
        """Fields outside the protected set (seq_num, timestamp, route_cost)
        must always be writable, even when protected=True.
        """
        node = Node(1, "n1", protected=True)
        node.seq_num = 999
        assert node.seq_num == 999
        node.timestamp = 123456
        assert node.timestamp == 123456

    def test_unprotected_node_writable(self):
        """With protected=False, all fields are writable."""
        node = Node(1, "n1", pubkey="old")
        node.pubkey = "new"
        assert node.pubkey == "new"

    def test_force_write_bypass(self):
        """The ``_force_write`` context manager temporarily drops
        protection so that LocalNode.__post_init__ can set external_ips.
        """
        node = Node(1, "n1", pubkey="key", protected=True)
        with node._force_write():
            node.pubkey = "override"
        assert node.pubkey == "override"
        # Protection is restored after exiting the context
        with pytest.raises(AttributeError, match="read-only"):
            node.pubkey = "another"

    def test_force_write_restores_on_exception(self):
        """Protection must be restored even if the body raises."""
        node = Node(1, "n1", protected=True)
        with pytest.raises(ZeroDivisionError):
            with node._force_write():
                _ = 1 / 0
        # Protection is restored despite the exception
        with pytest.raises(AttributeError, match="read-only"):
            node.name = "should-fail"


# ═══════════════════════════════════════════════════════════════════════════
#  get_internal_ip / get_node_id_from_ip — address arithmetic
# ═══════════════════════════════════════════════════════════════════════════

class TestInternalIp:
    """These functions convert between ``(network_cidr, node_id)`` and IP
    strings.  Every packet send/receive path depends on them.
    """

    NET = "10.123.234.0/24"

    def test_bare_ip(self):
        """Node 1 in 10.123.234.0/24 → 10.123.234.1 (no CIDR suffix)."""
        assert get_internal_ip(self.NET, 1) == "10.123.234.1"
        assert get_internal_ip(self.NET, 254) == "10.123.234.254"

    def test_network_cidr(self):
        """cidr='network' appends the network prefix length."""
        assert get_internal_ip(self.NET, 5) == "10.123.234.5"
        assert get_internal_ip(self.NET, 5, cidr="network") == "10.123.234.5/24"

    def test_host_cidr(self):
        """cidr='host' appends /32 (single-host route)."""
        assert get_internal_ip(self.NET, 5, cidr="host") == "10.123.234.5/32"

    def test_round_trip_with_node_id(self):
        """get_node_id_from_ip(net, get_internal_ip(net, n)) == n."""
        for nid in [1, 2, 42, 254]:
            ip = get_internal_ip(self.NET, nid)
            assert get_node_id_from_ip(self.NET, ip) == nid


# ═══════════════════════════════════════════════════════════════════════════
#  SRv6CSID — Compressed-SID address construction
# ═══════════════════════════════════════════════════════════════════════════

class TestSRv6CSID:
    """SRv6 NEXT-CSID packs the Locator Block (LB) and Node Function (NF)
    into the high bits of an IPv6 address.  These tests verify the
    address geometry against hand-computed values.

    With ``locator_block_address='fd00::/8'`` and ``nflen=8`` (the
    production config used by all five container nodes):

      LB  = 0xfd  (8 bits)
      NF  = node_id (8 bits)
      Remaining 112 bits = padding / further CSID hops

    So node 1's locator address is::

      (0xfd << 8 | 0x01) << 112 = fd01::

    A 2-hop SRv6 path [3, 5] packs both NFs after the LB::

      (0xfd << 16 | 0x03 << 8 | 0x05) << 104 = fd03:500::
    """

    @pytest.fixture
    def csid(self):
        """Matches the production container SRv6 config."""
        return SRv6CSID(locator_block_address="fd00::/8", nflen=8)

    def test_locator_block_address(self, csid):
        assert csid.locator_block_address == "fd00::/8"

    def test_lblen_nflen(self, csid):
        assert csid.lblen == 8
        assert csid.nflen == 8

    def test_node_function_address(self, csid):
        """Verify addresses for nodes 1–5 match hand-computed values."""
        assert csid.get_node_function_address(1) == "fd01::"
        assert csid.get_node_function_address(2) == "fd02::"
        assert csid.get_node_function_address(3) == "fd03::"
        assert csid.get_node_function_address(5) == "fd05::"

    def test_node_function_with_cidr(self, csid):
        """cidr='network' appends /(LB+NF) = /16."""
        assert csid.get_node_function_address(2, cidr="network") == "fd02::/16"
        assert csid.get_node_function_address(2, cidr="host") == "fd02::/128"

    def test_srv6_multihop_address(self, csid):
        """A 2-hop path [3, 5] produces fd03:500:: and a 3-hop path
        [2, 3, 5] produces fd02:305:: — both verified by manual
        bit-shifting.
        """
        assert csid.get_srv6_address([3, 5]) == "fd03:500::"
        assert csid.get_srv6_address([2, 3, 5]) == "fd02:305::"

    def test_srv6_single_hop(self, csid):
        """Single hop [2] → fd02:: (same as the node function address)."""
        assert csid.get_srv6_address([2]) == "fd02::"

    def test_invalid_node_function_id(self, csid):
        """Node function ID 0 or >= 256 (2^nflen) must raise."""
        with pytest.raises(ValueError, match="invalid"):
            csid.get_node_function_address(0)
        with pytest.raises(ValueError, match="invalid"):
            csid.get_node_function_address(256)

    def test_constructor_from_block_and_lblen(self):
        """Alternative constructor using integer locator_block + lblen."""
        csid = SRv6CSID(locator_block=0xfd, lblen=8, nflen=8)
        assert csid.get_node_function_address(1) == "fd01::"


# ═══════════════════════════════════════════════════════════════════════════
#  load_conf / save_conf — configuration round-trip
# ═══════════════════════════════════════════════════════════════════════════

class TestConfigRoundTrip:
    """Ensures the JSON config survives a load→save→reload cycle,
    including the key-renaming dance (``id`` ↔ ``node_id``,
    ``public_key`` ↔ ``pubkey``).
    """

    def test_load_save_reload(self, config_file):
        """load_conf → save_conf → load_conf must recover the same state."""
        me1, nodes1 = load_conf(config_file)
        save_conf(config_file, me1, nodes1)
        me2, nodes2 = load_conf(config_file)

        assert me1.node_id == me2.node_id
        assert me1.name == me2.name
        assert me1.pubkey == me2.pubkey
        assert me1.network == me2.network
        assert me1.private_key == me2.private_key
        assert len(nodes1) == len(nodes2)

    def test_missing_id_raises(self, tmp_path):
        """A config without 'me.id' must raise ValueError."""
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"me": {"name": "no-id"}}))
        with pytest.raises(ValueError, match="id"):
            load_conf(str(bad))

    def test_peer_without_pubkey_skipped(self, tmp_path):
        """A peer entry lacking 'pubkey' should be silently skipped."""
        cfg = {
            "me": {
                "id": 99,
                "network": "10.0.0.0/24",
                "private_key": TEST_KEYS[1]["private_key"],
                "public_key": TEST_KEYS[1]["public_key"],
            },
            "peers": [
                {"node_id": 100, "name": "no-key-peer"},
            ],
        }
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps(cfg))
        me, nodes = load_conf(str(path))
        # Only 'me' should be in known_nodes; the bad peer is skipped
        assert 100 not in nodes
