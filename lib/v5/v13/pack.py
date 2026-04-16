"""v13.2 cryptographic helpers for the encrypted-VM bootstrap.

Two primitives are used at runtime:

  master_key = scrypt(password, salt, N, r, p, dklen=64)
  keystream  = SHA-256 counter-mode expansion over (master_key, nonce)
  payload    = plaintext XOR keystream

The build side of this module packs the VM source and program bytes
into ciphertext blobs using the same primitives with a fixed
build-time password. At runtime the bootstrap (see `bootstrap.py`)
reproduces the keystream from the user's password guess.
"""
from __future__ import annotations
import hashlib
import os


SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64


def derive_master(password: bytes, salt: bytes) -> bytes:
    """Return the master key for (password, salt). Matches bootstrap."""
    return hashlib.scrypt(
        password, salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN,
    )


def keystream(master: bytes, nonce: bytes, n: int) -> bytes:
    """SHA-256 counter-mode KS. Matches bootstrap exactly."""
    out = bytearray()
    i = 0
    while len(out) < n:
        h = hashlib.sha256()
        h.update(master)
        h.update(nonce)
        h.update(i.to_bytes(4, "big"))
        out += h.digest()
        i += 1
    return bytes(out[:n])


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(plaintext: bytes, master: bytes, nonce: bytes) -> bytes:
    return xor(plaintext, keystream(master, nonce, len(plaintext)))


def random_nonce() -> bytes:
    return os.urandom(16)


def random_salt() -> bytes:
    return os.urandom(16)
