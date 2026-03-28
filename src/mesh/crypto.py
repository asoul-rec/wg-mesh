import hashlib
import hmac
import os

__all__ = [
    "encrypt_payload",
    "decrypt_payload",
]


def encrypt_payload(pubkey: str, payload: bytes) -> bytes:
    nonce = os.urandom(8)
    key = hashlib.sha256(pubkey.encode('utf-8')).digest()

    out = bytearray(len(payload))
    counter = 0
    stream = b""
    while len(stream) < len(payload):
        counter_bytes = counter.to_bytes(4, 'big')
        stream += hashlib.sha256(key + nonce + counter_bytes).digest()
        counter += 1

    for i in range(len(payload)):
        out[i] = payload[i] ^ stream[i]

    encrypted = nonce + bytes(out)
    mac = hmac.new(key, encrypted, hashlib.sha256).digest()
    return mac + encrypted


def decrypt_payload(pubkey: str, data: bytes) -> bytes:
    if len(data) < 40:
        raise ValueError("Payload too short for encryption envelope")
    mac, encrypted = data[:32], data[32:]
    key = hashlib.sha256(pubkey.encode('utf-8')).digest()

    expected_mac = hmac.new(key, encrypted, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("MAC verification failed")

    nonce, ciphertext = encrypted[:8], encrypted[8:]

    out = bytearray(len(ciphertext))
    counter = 0
    stream = b""
    while len(stream) < len(ciphertext):
        counter_bytes = counter.to_bytes(4, 'big')
        stream += hashlib.sha256(key + nonce + counter_bytes).digest()
        counter += 1

    for i in range(len(ciphertext)):
        out[i] = ciphertext[i] ^ stream[i]

    return bytes(out)
