"""Container integration tests — mesh convergence and overlay connectivity.

These tests require Docker with ``NET_ADMIN`` capability and are excluded
from the default pytest run (``-m 'not container'``).  Run them via::

    just test-container

The test harness:
  1. Copies the 5 seed configs into ``runtime_conf/`` (writable by nodes).
  2. Brings up a 5-node Docker Compose cluster on two bridge networks.
  3. Waits for gossip convergence (~20 s).
  4. Exec's into each container to verify overlay state.
  5. Tears down and cleans up.

Topology (from compose.yml)::

                  main network: 172.20.123.0/24
                 ┌───┬───┬───┬───┬───┐
                 │ 1 │ 2 │ 3 │ 4 │ 5 │
                 └───┴───┴───┴───┴───┘
                  extra network: 172.20.124.0/24
                 ┌───┬───┬───┬───┬───┐
                 │ 1 │ 2 │ 3 │ 4 │ 5 │
                 └───┴───┴───┴───┴───┘
                 WireGuard overlay: 10.123.234.0/24
                 (formed dynamically via gossip)

Edge cases baked into the seed configs:
  - Node 1: uses ``cidr`` (legacy key) instead of ``network``
  - Node 2: has both ``cidr`` and ``network`` (``network`` wins)
  - Node 3: starts with seq_num=4294967290 (near u32 MAX → wraps around)
  - Node 5: joins late (5 s sleep), has stale endpoint for node 1
            (``random-not-existing-domain:51820``)
"""

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest


COMPOSE_DIR = Path(__file__).parent
CONF_DIR = COMPOSE_DIR / "conf"
RUNTIME_CONF = COMPOSE_DIR / "runtime_conf"
# Node 5 has a built-in 5 s delay; add margin for gossip convergence
CONVERGENCE_WAIT = 20


def docker_exec(service: str, cmd: str, *, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a shell command inside a running compose service container."""
    return subprocess.run(
        ["docker", "compose", "exec", "-T", service, "sh", "-c", cmd],
        cwd=COMPOSE_DIR, capture_output=True, text=True, timeout=timeout,
    )


def read_container_config(service: str) -> dict:
    """Read and parse the JSON config from inside a running container."""
    result = docker_exec(service, "cat /app/config.json")
    assert result.returncode == 0, f"Failed to read config from {service}: {result.stderr}"
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
#  Module-scoped fixture: start/stop the Docker Compose cluster once
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mesh_cluster():
    """Bring up the 5-node mesh cluster and wait for convergence.

    Copies seed configs into ``runtime_conf/`` so that each node's
    ``save_conf`` writes to its own mutable copy without touching
    the checked-in originals under ``conf/``.
    """
    # Prepare writable config copies
    if RUNTIME_CONF.exists():
        shutil.rmtree(RUNTIME_CONF)
    RUNTIME_CONF.mkdir()
    for f in sorted(CONF_DIR.glob("*.json")):
        shutil.copy(f, RUNTIME_CONF / f.name)

    # Build and start
    subprocess.run(
        ["docker", "compose", "up", "--build", "-d"],
        cwd=COMPOSE_DIR, check=True, timeout=180,
    )
    time.sleep(CONVERGENCE_WAIT)
    yield

    # Tear down
    subprocess.run(
        ["docker", "compose", "down", "-v"],
        cwd=COMPOSE_DIR, check=True, timeout=60,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  Convergence
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.container
class TestConvergence:
    """Verify that all five nodes converge to a complete mesh view."""

    def test_all_nodes_discovered(self, mesh_cluster):
        """After convergence, every node's saved config should list all
        5 nodes in the 'peers' array (which includes self due to the
        ``save_conf`` format — ``known_nodes`` contains ``me.node``).
        """
        for i in range(1, 6):
            config = read_container_config(f"node{i}")
            peer_ids = {p["node_id"] for p in config["peers"]}
            assert peer_ids == {1, 2, 3, 4, 5}, (
                f"Node {i} is missing peers: expected {{1..5}}, got {peer_ids}"
            )

    def test_overlay_ping(self, mesh_cluster):
        """Every node should be able to ping every other node over the
        WireGuard overlay (10.123.234.0/24).  This verifies that gossip
        correctly distributed WG pubkeys and that ``sync_wg_peers``
        configured the tunnels.
        """
        for src in range(1, 6):
            for dst in range(1, 6):
                if src == dst:
                    continue
                dst_ip = f"10.123.234.{dst}"
                result = docker_exec(f"node{src}", f"ping -c 1 -W 5 {dst_ip}")
                assert result.returncode == 0, (
                    f"node{src} → {dst_ip} (node{dst}) failed:\n{result.stderr}"
                )


# ═══════════════════════════════════════════════════════════════════════════
#  Edge cases baked into the seed configs
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.container
class TestEdgeCases:

    def test_seq_wrap_around(self, mesh_cluster):
        """Node 3 starts with seq_num=4294967290 (6 below u32 MAX).
        After several keepalive cycles, the seq must have wrapped past 0.
        All other nodes should still track node 3 despite the wrap.

        This is a regression test for the ``wrapping_sub`` arithmetic —
        a naive ``a - b`` comparison would treat the wrapped seq as
        massively stale.
        """
        for i in [1, 2, 4, 5]:
            config = read_container_config(f"node{i}")
            peers = {p["node_id"]: p for p in config["peers"]}
            assert 3 in peers, f"Node {i} lost track of node 3 after seq wrap"

    def test_stale_endpoint_corrected(self, mesh_cluster):
        """Node 5's seed config has node 1's endpoint as
        ``random-not-existing-domain:51820``.  After gossip convergence,
        node 5 should learn node 1's actual endpoint from the mesh.
        """
        config = read_container_config("node5")
        peers = {p["node_id"]: p for p in config["peers"]}
        assert 1 in peers
        ep = peers[1].get("endpoint", "")
        assert "random-not-existing-domain" not in ep, (
            f"Node 5 still has stale endpoint for node 1: {ep}"
        )

    def test_external_ips_propagated(self, mesh_cluster):
        """Node 1 and node 3 declare ``external_routes`` in their configs,
        which ``LocalNode.__post_init__`` converts to ``external_ips``.
        After gossip, node 4 (which starts knowing only node 3) should
        see node 1's ``external_ips`` — proving multi-hop gossip
        propagation works.
        """
        config = read_container_config("node4")
        peers = {p["node_id"]: p for p in config["peers"]}
        assert 1 in peers
        ext_ips = peers[1].get("external_ips", [])
        assert len(ext_ips) > 0, (
            "Node 4 should have learned node 1's external_ips via gossip"
        )

    def test_legacy_cidr_key_accepted(self, mesh_cluster):
        """Node 1's config uses ``cidr`` instead of ``network``.
        ``load_conf`` should accept both keys.  After ``save_conf``,
        the key is normalised to ``network``.
        """
        config = read_container_config("node1")
        me = config["me"]
        # After save_conf, the key should be normalised to 'network'
        assert "network" in me
        # Node 1 should have all peers
        peer_ids = {p["node_id"] for p in config["peers"]}
        assert peer_ids == {1, 2, 3, 4, 5}
