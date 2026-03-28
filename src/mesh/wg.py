import logging
import subprocess

__all__ = [
    "generate_wg_keys",
]

def generate_wg_keys():
    """Attempt to call system 'wg' command to generate a keypair."""
    try:
        privkey = subprocess.check_output(["wg", "genkey"], text=True).strip()
        pubkey = subprocess.check_output(["wg", "pubkey"], input=privkey.encode(), text=True).strip()
        return privkey, pubkey
    except Exception as e:
        logging.error(f"Failed to generate keys via 'wg' command: {e!r}")
        return None, None
