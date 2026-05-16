"""Tests for the mesh control-plane cryptography layer.

Covers:
- ``encrypt_payload`` / ``decrypt_payload``: symmetric CTR-mode cipher with
  HMAC-SHA256 integrity.  The key is derived from ``SHA-256(pubkey)``.
- ``MeshPacket.pack`` / ``MeshPacket.unpack``: wire-format serialisation
  including the 4-byte version header, encryption envelope, and inner
  header (type, origin_id, seq_num, pkt_tag).

These tests exercise the application-layer crypto only.  The outer WireGuard
tunnel (which provides forward secrecy) is not covered here.
"""

import struct

import pytest

from mesh.utils.crypto import encrypt_payload, decrypt_payload
from mesh.mesh import MeshPacket
from mesh._version import VERSION
from mesh.utils.version import version_to_int, int_to_version


# ═══════════════════════════════════════════════════════════════════════════
#  encrypt_payload / decrypt_payload
# ═══════════════════════════════════════════════════════════════════════════

class TestEncryptDecrypt:
    """Round-trip and tamper-detection tests for the SHA-256-CTR + HMAC
    envelope used on every gossip packet.
    """

    KEY = "test-public-key-string"

    def test_round_trip(self):
        """decrypt(encrypt(data)) must recover the original plaintext."""
        plaintext = b"hello mesh control plane"
        ct = encrypt_payload(self.KEY, plaintext)
        assert decrypt_payload(self.KEY, ct) == plaintext

    def test_empty_payload(self):
        """An empty payload should round-trip without error."""
        ct = encrypt_payload(self.KEY, b"")
        assert decrypt_payload(self.KEY, ct) == b""

    def test_large_payload(self):
        """Payloads exceeding one SHA-256 block (32 bytes) must still work,
        exercising the multi-block CTR counter increment.
        """
        plaintext = b"A" * 1000
        ct = encrypt_payload(self.KEY, plaintext)
        assert decrypt_payload(self.KEY, ct) == plaintext

    def test_wrong_key_rejected(self):
        """Decryption with the wrong key must fail MAC verification."""
        ct = encrypt_payload(self.KEY, b"secret")
        with pytest.raises(ValueError, match="MAC"):
            decrypt_payload("wrong-key", ct)

    def test_tampered_ciphertext_rejected(self):
        """Flipping a bit in the ciphertext must fail MAC verification."""
        ct = encrypt_payload(self.KEY, b"important data")
        tampered = bytearray(ct)
        tampered[40] ^= 0xFF       # byte 40 is inside the ciphertext
        with pytest.raises(ValueError, match="MAC"):
            decrypt_payload(self.KEY, bytes(tampered))

    def test_tampered_mac_rejected(self):
        """Flipping a bit in the MAC prefix must fail verification."""
        ct = encrypt_payload(self.KEY, b"data")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF        # byte 0 is inside the HMAC tag
        with pytest.raises(ValueError, match="MAC"):
            decrypt_payload(self.KEY, bytes(tampered))

    def test_nonce_randomness(self):
        """Two encryptions of the same plaintext must produce different
        ciphertext (the 8-byte nonce is random each time).
        """
        plaintext = b"same input"
        ct1 = encrypt_payload(self.KEY, plaintext)
        ct2 = encrypt_payload(self.KEY, plaintext)
        assert ct1 != ct2

    def test_truncated_payload_rejected(self):
        """A payload shorter than the minimum envelope (32-byte MAC + 8-byte
        nonce) must be rejected.
        """
        with pytest.raises(ValueError, match="too short"):
            decrypt_payload(self.KEY, b"short")


# ═══════════════════════════════════════════════════════════════════════════
#  MeshPacket — wire-format pack / unpack
# ═══════════════════════════════════════════════════════════════════════════

class TestMeshPacket:
    """Tests for the outer protocol framing: version header + encrypted inner
    header (pkt_type, origin_id, seq_num, pkt_tag) + payload.
    """

    KEY = "recipient-pubkey"

    def test_round_trip(self):
        """pack → unpack must recover all header fields and payload."""
        payload = b"gossip data"
        pkt = MeshPacket.pack(
            pkt_type=1, origin_id=42, seq_num=9999, pkt_tag=2,
            payload=payload, target_key=self.KEY,
        )
        result = MeshPacket.unpack(pkt, self.KEY)
        assert result["pkt_type"] == 1
        assert result["origin_id"] == 42
        assert result["seq_num"] == 9999
        assert result["pkt_tag"] == 2
        assert result["payload"] == payload

    def test_wrong_key_raises(self):
        """Unpacking with the wrong key must raise ``MeshPacket.Error``."""
        pkt = MeshPacket.pack(1, 1, 1, 0, b"", target_key=self.KEY)
        with pytest.raises(MeshPacket.Error, match="decrypt"):
            MeshPacket.unpack(pkt, "wrong-key")

    def test_incompatible_version_raises(self):
        """A packet with a different major/minor version must be rejected.

        The version check compares the top 3 bytes (``>> 8``), allowing
        patch-level differences (the lowest byte).
        """
        pkt = MeshPacket.pack(1, 1, 1, 0, b"data", target_key=self.KEY)
        # Overwrite the 4-byte version header with an incompatible version
        bad_version = version_to_int("99.0.0.0")
        bad_pkt = struct.pack("!I", bad_version) + pkt[4:]
        with pytest.raises(MeshPacket.Error, match="Incompatible"):
            MeshPacket.unpack(bad_pkt, self.KEY)

    def test_patch_version_accepted(self):
        """A packet whose version differs only in the patch byte should be
        accepted (the top 3 bytes still match).
        """
        payload = b"cross-version"
        pkt = MeshPacket.pack(1, 1, 1, 0, payload, target_key=self.KEY)

        # Replace version with same major.minor.micro but different patch
        current_str = int_to_version(VERSION)
        parts = [int(x) for x in current_str.split(".")]
        parts[3] = (parts[3] + 1) % 256
        tweaked = version_to_int(".".join(str(p) for p in parts))
        pkt = struct.pack("!I", tweaked) + pkt[4:]

        result = MeshPacket.unpack(pkt, self.KEY)
        assert result["payload"] == payload

    def test_truncated_packet_raises(self):
        """A packet shorter than the outer header must raise an error."""
        with pytest.raises(MeshPacket.Error, match="Bad raw packet"):
            MeshPacket.unpack(b"\x00\x01", self.KEY)
