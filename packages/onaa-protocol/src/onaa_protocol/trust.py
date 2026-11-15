"""Issuer key manifest and purpose-bound verification (CERT-011, ONAA attestation key management procedure).

Relying parties pin the issuer's ROOT public key, never a URL. The root key signs an *issuer manifest*: a
JWKS whose keys each carry one purpose (the JWS ``typ`` they may sign), a status and a validity window::

    {"manifest_version": "0.1.0", "issuer_id": "...", "issued_at": ..., "next_update": ..., "test_only": true,
     "keys": [{<public Ed25519 JWK>, "onaa_purpose": "onaa-attestation+jws", "onaa_status": "active",
               "not_before": ..., "not_after": ...}],
     "signature": {"protected": ..., "signature": ...}}       # typ onaa-issuer-jwks+jws, root kid

Rules enforced here (key management doc sections 2-4 and 9):

* one key, one purpose: a kid is accepted only for the ``typ`` its manifest entry names;
* ``test-`` kids and ``test_only`` manifests are rejected unless the caller allows TEST-ONLY material;
* ``next`` and ``revoked`` keys never verify; a key verifies only objects signed inside its window;
* a manifest past its ``next_update`` is stale and fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jose
from .envelope import format_ts, parse_ts, utcnow
from .errors import AttestationError, ProtocolError, SignatureError

TYP_ISSUER_MANIFEST = "onaa-issuer-jwks+jws"
MANIFEST_VERSION = "0.1.0"
PURPOSES = (jose.TYP_ATTESTATION, jose.TYP_ATTESTATION_STATUS, "onaa-log-checkpoint+jws")
KEY_STATUSES = ("next", "active", "retired", "revoked")
TEST_KID_PREFIX = "test-"
_KEY_META = ("onaa_purpose", "onaa_status", "not_before", "not_after")


def manifest_key(jwk: dict[str, Any], purpose: str, *, status: str = "active", not_before: datetime,
                 not_after: datetime | None = None) -> dict[str, Any]:
    if purpose not in PURPOSES or status not in KEY_STATUSES:
        raise ValueError("unknown key purpose or status")
    if "d" in jwk:
        raise ValueError("manifest keys must be public")
    out = dict(jwk, onaa_purpose=purpose, onaa_status=status, not_before=format_ts(not_before))
    if not_after is not None:
        out["not_after"] = format_ts(not_after)
    return out


def build_manifest(issuer_id: str, keys: list[dict[str, Any]], *, issued_at: datetime, next_update: datetime,
                   test_only: bool = True) -> dict[str, Any]:
    return {"manifest_version": MANIFEST_VERSION, "issuer_id": issuer_id, "issued_at": format_ts(issued_at),
            "next_update": format_ts(next_update), "test_only": test_only, "keys": keys}


def sign_manifest(manifest: dict[str, Any], root: jose.Signer) -> dict[str, Any]:
    manifest["signature"] = jose.sign_detached({k: v for k, v in manifest.items() if k != "signature"}, root,
                                               TYP_ISSUER_MANIFEST)
    return manifest


@dataclass(frozen=True)
class _Key:
    kid: str
    purpose: str
    status: str
    not_before: datetime
    not_after: datetime | None
    jwk: dict[str, Any]


@dataclass(frozen=True)
class TrustedIssuer:
    """A verified manifest. Use :meth:`lookup` to get a purpose- and time-bound key lookup."""

    issuer_id: str
    test_only: bool
    next_update: datetime
    keys: dict[str, _Key]
    allow_test_only: bool

    def lookup(self, purpose: str, signed_at: datetime | None = None):
        def find(kid: str) -> Ed25519PublicKey:
            k = self.keys.get(kid)
            if k is None:
                raise SignatureError("key_not_found", "kid not in the issuer manifest")
            if k.purpose != purpose:
                raise SignatureError("key_not_found", "kid is not assigned to this object type")
            if k.status == "revoked":
                raise SignatureError("key_revoked", "issuer key is revoked")
            if k.status == "next":
                raise SignatureError("key_not_found", "issuer key is not in use yet")
            if signed_at is not None and (signed_at < k.not_before
                                          or (k.not_after is not None and signed_at > k.not_after)):
                raise SignatureError("key_not_found", "object was signed outside the key's validity window")
            return jose.public_key_from_jwk(k.jwk)
        return find

    def jwks(self, purpose: str) -> dict[str, Any]:
        """Plain JWKS of the usable keys for ``purpose`` (no window check; prefer :meth:`lookup`)."""
        return {"keys": [{k: v for k, v in key.jwk.items()} for key in self.keys.values()
                         if key.purpose == purpose and key.status in ("active", "retired")]}


def verify_manifest(manifest: Any, root_jwk: dict[str, Any], *, now: datetime | None = None,
                    allow_test_only: bool = False) -> TrustedIssuer:
    """Verify an issuer manifest against the pinned root public key. Fails closed (AttestationError codes)."""
    if not isinstance(manifest, dict) or set(manifest) != {"manifest_version", "issuer_id", "issued_at",
                                                           "next_update", "test_only", "keys", "signature"}:
        raise AttestationError("manifest_invalid", "issuer manifest has unexpected members")
    if manifest["manifest_version"] != MANIFEST_VERSION or not isinstance(manifest["issuer_id"], str) \
            or not isinstance(manifest["test_only"], bool) or not isinstance(manifest["keys"], list):
        raise AttestationError("manifest_invalid", "issuer manifest fields are invalid")
    root_kid = root_jwk.get("kid") if isinstance(root_jwk, dict) else None
    if not isinstance(root_kid, str):
        raise AttestationError("manifest_invalid", "pinned root key needs a kid")
    root_key = jose.public_key_from_jwk(root_jwk)

    def root_lookup(kid: str) -> Ed25519PublicKey:
        if kid != root_kid:
            raise SignatureError("key_not_found", "manifest is not signed by the pinned root key")
        return root_key

    jose.verify_detached({k: v for k, v in manifest.items() if k != "signature"}, manifest["signature"],
                         root_lookup, TYP_ISSUER_MANIFEST)
    if (manifest["test_only"] or root_kid.startswith(TEST_KID_PREFIX)) and not allow_test_only:
        raise AttestationError("attestation_test_only", "TEST-ONLY issuer manifest; not valid outside tests")
    now = now or utcnow()
    try:
        issued, next_update = parse_ts(manifest["issued_at"], "issued_at"), parse_ts(manifest["next_update"],
                                                                                     "next_update")
    except ProtocolError as exc:
        raise AttestationError("manifest_invalid", exc.message) from exc
    if now < issued:
        raise AttestationError("manifest_invalid", "issuer manifest is not valid yet")
    if now > next_update:
        raise AttestationError("manifest_stale", "issuer manifest is past its next_update; fetch it again")
    try:
        jose.validate_jwks({"keys": [{k: v for k, v in e.items() if k not in _KEY_META}
                                     for e in manifest["keys"] if isinstance(e, dict)]})
    except SignatureError as exc:
        raise AttestationError("manifest_invalid", exc.message) from exc
    keys: dict[str, _Key] = {}
    for e in manifest["keys"]:
        if not isinstance(e, dict) or e.get("onaa_purpose") not in PURPOSES or e.get("onaa_status") not in KEY_STATUSES:
            raise AttestationError("manifest_invalid", "manifest key needs onaa_purpose and onaa_status")
        kid = e["kid"]
        if kid in keys:
            raise AttestationError("manifest_invalid", "duplicate kid in manifest")
        if kid.startswith(TEST_KID_PREFIX) and not allow_test_only:
            raise AttestationError("attestation_test_only", "manifest lists a test- key")
        try:
            nb = parse_ts(e["not_before"], "not_before")
            na = parse_ts(e["not_after"], "not_after") if "not_after" in e else None
        except (KeyError, ProtocolError) as exc:
            raise AttestationError("manifest_invalid", "manifest key validity is malformed") from exc
        keys[kid] = _Key(kid, e["onaa_purpose"], e["onaa_status"], nb, na,
                         {k: v for k, v in e.items() if k not in _KEY_META})
    return TrustedIssuer(manifest["issuer_id"], manifest["test_only"], next_update, keys, allow_test_only)
