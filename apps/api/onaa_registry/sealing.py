"""Encryption at rest for pilot message bodies (AES-256-GCM, versioned key).

A stored body looks like ``enc:<version>:<base64url(nonce || ciphertext+tag)>``. The conversation id and message
id are bound as associated data, so a ciphertext copied to another row does not open. A database dump alone does
not reveal message text; the running server, which holds the key, can still read it (it has to, to show the inbox
to the member's assistant). Without ONAA_MESSAGE_KEY, bodies are stored as plain text (local development).
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc:"


class SealError(Exception):
    pass


def _key(b64: str) -> bytes:
    raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    if len(raw) != 32:
        raise SealError("ONAA_MESSAGE_KEY must be 32 bytes, base64url-encoded")
    return raw


def _keys(settings) -> dict[int, bytes]:
    out: dict[int, bytes] = {}
    if getattr(settings, "message_key", None):
        out[settings.message_key_version] = _key(settings.message_key)
        if settings.message_key_previous and settings.message_key_version > 1:
            out[settings.message_key_version - 1] = _key(settings.message_key_previous)
    return out


def new_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def seal(settings, text: str | None, aad: str) -> str | None:
    if text is None or not getattr(settings, "message_key", None):
        return text
    version = settings.message_key_version
    nonce = os.urandom(12)
    ct = AESGCM(_key(settings.message_key)).encrypt(nonce, text.encode(), aad.encode())
    return f"{PREFIX}{version}:" + base64.urlsafe_b64encode(nonce + ct).decode().rstrip("=")


def unseal(settings, stored: str | None, aad: str) -> str | None:
    """Plain text back. Rows written before a key was set are returned as they are."""
    if stored is None or not stored.startswith(PREFIX):
        return stored
    try:
        version_s, body = stored[len(PREFIX):].split(":", 1)
        key = _keys(settings).get(int(version_s))
        if key is None:
            raise SealError(f"no key for version {version_s}")
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        return AESGCM(key).decrypt(raw[:12], raw[12:], aad.encode()).decode()
    except SealError:
        raise
    except Exception as exc:  # noqa: BLE001 - tampered or truncated: never fall back to showing ciphertext
        raise SealError("message body does not open") from exc
