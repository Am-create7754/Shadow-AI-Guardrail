"""Authenticated encryption for data at rest (AES-256-GCM).

* The configured key is never used directly: a purpose-specific 256-bit key is
  derived with HKDF-SHA256, so the same master key can safely serve other
  purposes later without key reuse.
* Every encryption uses a fresh random 96-bit nonce (``os.urandom``); the nonce
  is stored in front of the ciphertext. With random nonces AES-GCM stays safe
  for well over 2^32 messages per key, far beyond this application's volume.
* Associated data binds a ciphertext to its record (e.g. the approval id), so
  a ciphertext copied onto another row fails to decrypt.
* The key lives in configuration / the key directory, never in the database
  next to the ciphertext.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_BYTES = 12
FORMAT_VERSION = b"\x01"


class DecryptionError(ValueError):
    """Ciphertext was modified, truncated, bound to other data, or the key is wrong."""


class Aead:
    def __init__(self, master_key: bytes, purpose: str) -> None:
        if len(master_key) < 32:
            raise ValueError("master key must be at least 32 bytes")
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"guardrail-aead-v1",
            info=purpose.encode(),
        ).derive(master_key)
        self._aead = AESGCM(derived)

    def __repr__(self) -> str:
        return "Aead()"

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        return FORMAT_VERSION + nonce + self._aead.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, blob: bytes, associated_data: bytes) -> bytes:
        if len(blob) < 1 + NONCE_BYTES + 16 or blob[:1] != FORMAT_VERSION:
            raise DecryptionError("ciphertext is malformed")
        nonce, ciphertext = blob[1 : 1 + NONCE_BYTES], blob[1 + NONCE_BYTES :]
        try:
            return self._aead.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as exc:
            raise DecryptionError("ciphertext failed authentication") from exc
