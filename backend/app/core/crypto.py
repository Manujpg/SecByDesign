"""Verschlüsselung von Geheimnissen in der Datenbank (SR-02, SR-06).

TOTP-Secrets werden mit AES-256-GCM verschlüsselt gespeichert:

    gespeichert = Version (1 Byte) || Nonce (12 Byte) || Ciphertext + Tag (16 Byte)

- Schlüssel: per HKDF-SHA256 aus ``APP_SECRET_KEY`` abgeleitet, mit eigenem Kontext je
  Verwendungszweck. Der Rohschlüssel wird so nie direkt für AES verwendet.
- Associated Data: die Nutzer-ID. Ein in der Datenbank zwischen zwei Konten
  vertauschtes Secret lässt sich dadurch nicht entschlüsseln.
- Version: erlaubt später einen Schlüsselwechsel, ohne alte Einträge unlesbar zu machen.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings

_VERSION = 1
_NONCE_BYTES = 12


class DecryptionError(Exception):
    """Ciphertext manipuliert, falscher Schlüssel oder falsche Zuordnung."""


@lru_cache
def _derive(purpose: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"praxistermin",
        info=b"praxistermin/" + purpose,
    ).derive(get_settings().secret_key_bytes())


def encrypt(plaintext: bytes, *, purpose: bytes, associated_data: bytes) -> bytes:
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(_derive(purpose)).encrypt(nonce, plaintext, associated_data)
    return bytes([_VERSION]) + nonce + ciphertext


def decrypt(blob: bytes, *, purpose: bytes, associated_data: bytes) -> bytes:
    if len(blob) < 1 + _NONCE_BYTES + 16 or blob[0] != _VERSION:
        raise DecryptionError
    nonce, ciphertext = blob[1 : 1 + _NONCE_BYTES], blob[1 + _NONCE_BYTES :]
    try:
        return AESGCM(_derive(purpose)).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise DecryptionError from exc


def keyed_hash(value: str, *, purpose: bytes) -> str:
    """HMAC-SHA256 mit abgeleitetem Schlüssel, z. B. für Recovery-Codes."""
    return hmac.new(_derive(purpose), value.encode(), hashlib.sha256).hexdigest()
