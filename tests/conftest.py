"""Shared fixtures for the wg-mesh test suite.

Provides pre-generated WireGuard key material and reusable config
templates so that unit tests never shell out to the ``wg`` binary.
"""

import json
import time

import pytest

# ---------------------------------------------------------------------------
# Pre-generated WireGuard keys (test-only, taken from container_tests/conf/).
# Using fixed keys avoids calling ``wg genkey`` during tests, which would
# require the wireguard-tools package to be installed on the CI runner.
# ---------------------------------------------------------------------------
TEST_KEYS = {
    1: {
        "private_key": "AOQ5yUTeHxshA49Hqo+EaI21lItgKEGvyXP7GLxFCl4=",
        "public_key": "KDrEX85VNrZhEeKdeRH6kh9BbzosLprrgYHfwNtt+gk=",
    },
    2: {
        "private_key": "EJjkjdfbMLeXRKosb+nC0sZCfI8xyjlGDg6StIfroVM=",
        "public_key": "ldWMAMxO7xo9z0DU/u98kIK1b1fh4LDzdLKff+QV+3c=",
    },
    3: {
        "private_key": "KJoNrU8bVYcbsF+jqP39SC9QQUarXh2Wzypay/HSL2A=",
        "public_key": "wBsmLhwCrR1o0bwZPwi0m0uZzkxnTwdhKmd2ZALTWHg=",
    },
    4: {
        "private_key": "aJtwOTlu0JZXDRJihhNjKvfcT/rz8ySbYt7bPc259ms=",
        "public_key": "lGogn8FU9sNtuJb+9fwSekysFib4N8+4gjXDdCCAMyE=",
    },
    5: {
        "private_key": "OESTipNQy393z5TVlPTrodYczChbycE4px/FGd/eHFM=",
        "public_key": "+F0amf0jOei7x3vyeH3FxaYsKZ9M7KsRu6eNDwG0rU0=",
    },
}


@pytest.fixture
def sample_config():
    """Return a minimal valid config dict for a 2-node mesh (node 1 + node 2).

    Uses pre-generated keys so that ``load_conf`` never invokes ``wg genkey``.
    Suitable for ``MeshController(path, dry_run=True)`` instantiation.
    """
    now = int(time.time())
    return {
        "me": {
            "id": 1,
            "name": "test-node-1",
            "network": "10.123.234.0/24",
            "private_key": TEST_KEYS[1]["private_key"],
            "public_key": TEST_KEYS[1]["public_key"],
            "seq_num": 100,
            "timestamp": now,
        },
        "peers": [
            {
                "node_id": 2,
                "name": "test-node-2",
                "pubkey": TEST_KEYS[2]["public_key"],
                "endpoint": "172.20.123.2:51820",
                "seq_num": 50,
                "timestamp": now,
            },
        ],
    }


@pytest.fixture
def config_file(sample_config, tmp_path):
    """Write ``sample_config`` to a temporary JSON file and return its path.

    The file is writable so that ``save_conf`` can update it during tests.
    """
    path = tmp_path / "config.json"
    path.write_text(json.dumps(sample_config))
    return str(path)
