"""JWS (RFC 7515) with detached payload over JCS (RFC 8785), Ed25519 only (RFC 8037 / RFC 9864).

All cryptography is done by the ``cryptography`` package; this module only builds the signing input
and JOSE headers. See docs/ADR/ADR-002-onaa-protocol-signing.md and spec section 9.

Signature object (same JSON shape as A2A 1.0 ``AgentCardSignature``)::

    {"protected": BASE64URL(UTF8(JSON(header))), "signature": BASE64URL(sig)}

Signing input::

    ASCII(protected) || "." || BASE64URL(JCS(payload_without_signature_member))
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .errors import SignatureError
from .jcs import CanonicalizationError, canonicalize

ALG = "EdDSA"                      # emitted (RFC 8037; widest library support)
ACCEPTED_ALGS = ("EdDSA", "Ed25519")  # "Ed25519" is the RFC 9864 fully-specified identifier
TYP_ENVELOPE = "onaa-envelope+jws"
TYP_ATTESTATION = "onaa-attestation+jws"
TYP_ATTESTATION_STATUS = "onaa-attestation-status+jws"
FORBIDDEN_HEADER_PARAMS = ("jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256", "crit", "b64", "zip", "enc")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_KID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Strict unpadded base64url: rejects padding, foreign characters and non-canonical encodings.

    Non-zero unused low bits in the final character decode to the same bytes as the canonical form, which
    would make signatures malleable (two byte-different envelopes, one signature). The re-encode check
    accepts only the canonical spelling (v0.1.1 errata, spec section 9.5).
    """
    if not isinstance(text, str) or not _B64URL_RE.match(text) or len(text) % 4 == 1:
        raise ValueError("not unpadded base64url")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - regex already filters
        raise ValueError("not base64url") from exc
    if b64url_encode(data) != text:
        raise ValueError("non-canonical base64url")
    return data


def _no_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate member in JSON object")
        out[k] = v
    return out


# ------------------------------------------------------------------ keys


def public_jwk(key: Ed25519PublicKey | Ed25519PrivateKey, kid: str) -> dict[str, str]:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw), "kid": kid, "use": "sig", "alg": ALG}


def private_jwk(key: Ed25519PrivateKey, kid: str) -> dict[str, str]:
    """Private JWK (adds ``d``). Only for TEST-ONLY vectors; never publish or commit a real key."""
    jwk = public_jwk(key, kid)
    jwk["d"] = b64url_encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    return jwk


def public_key_from_jwk(jwk: Any) -> Ed25519PublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise SignatureError("key_not_found", "JWK is not an OKP/Ed25519 key")
    if jwk.get("use") not in (None, "sig") or jwk.get("alg") not in (None, *ACCEPTED_ALGS):
        raise SignatureError("key_not_found", "JWK is not usable for EdDSA signatures")
    try:
        raw = b64url_decode(jwk.get("x", ""))
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise SignatureError("key_not_found", "JWK 'x' is not a 32-byte base64url Ed25519 key") from exc


def private_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.from_private_bytes(b64url_decode(jwk["d"]))
    if public_jwk(key, "x")["x"] != jwk.get("x", public_jwk(key, "x")["x"]):
        raise ValueError("JWK 'd' does not match 'x'")
    return key


def derive_test_only_key(label: str) -> Ed25519PrivateKey:
    """Deterministic TEST-ONLY key: seed = SHA-256("ONAA-TEST-ONLY-KEY:" + label).

    Anyone can derive these keys. They exist only so test vectors are reproducible.
    Verifiers outside tests MUST NOT trust them (spec section 9.6).
    """
    seed = hashlib.sha256(("ONAA-TEST-ONLY-KEY:" + label).encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url) of an OKP key."""
    members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64url_encode(hashlib.sha256(canonicalize(members)).digest())


def validate_jwks(jwks: Any) -> dict[str, dict[str, Any]]:
    """Return {kid: jwk} for the usable Ed25519 signing keys of a JWKS (RFC 7517)."""
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise SignatureError("jwks_unavailable", "JWKS must be an object with a 'keys' array")
    out: dict[str, dict[str, Any]] = {}
    for jwk in jwks["keys"]:
        if not isinstance(jwk, dict) or "d" in jwk:
            raise SignatureError("jwks_unavailable", "JWKS entries must be public JWK objects")
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not _KID_RE.match(kid):
            raise SignatureError("jwks_unavailable", "every JWK needs a 'kid' matching [A-Za-z0-9._:-]{1,128}")
        if kid in out:
            raise SignatureError("jwks_unavailable", "duplicate kid in JWKS")
        if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            public_key_from_jwk(jwk)
            out[kid] = jwk
    return out


# ------------------------------------------------------------------ sign / verify


@dataclass(frozen=True)
class Signer:
    """A private key plus the ``kid`` under which its public key is published in the signer's JWKS."""

    private_key: Ed25519PrivateKey  # gitleaks:allow (type annotation, not a secret)
    kid: str

    def public_jwk(self) -> dict[str, str]:
        return public_jwk(self.private_key, self.kid)


def signing_input(protected_b64: str, payload: Any) -> bytes:
    try:
        canon = canonicalize(payload)
    except CanonicalizationError as exc:
        raise SignatureError("signature_invalid", f"payload cannot be canonicalized: {exc}") from exc
    return protected_b64.encode("ascii") + b"." + b64url_encode(canon).encode("ascii")


def sign_detached(payload: Any, signer: Signer, typ: str) -> dict[str, str]:
    if not _KID_RE.match(signer.kid):
        raise ValueError("kid must match [A-Za-z0-9._:-]{1,128}")
    header = {"alg": ALG, "kid": signer.kid, "typ": typ}
    protected = b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    sig = signer.private_key.sign(signing_input(protected, payload))
    return {"protected": protected, "signature": b64url_encode(sig)}


def parse_protected(sig_obj: Any, typ: str) -> dict[str, Any]:
    if not isinstance(sig_obj, dict) or set(sig_obj) != {"protected", "signature"}:
        raise SignatureError("signature_header_invalid", "signature must be exactly {protected, signature}")
    try:
        header = json.loads(b64url_decode(sig_obj["protected"]), object_pairs_hook=_no_duplicate_members)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise SignatureError("signature_header_invalid", "protected header is not base64url JSON") from exc
    if not isinstance(header, dict):
        raise SignatureError("signature_header_invalid", "protected header must be a JSON object")
    if header.get("alg") not in ACCEPTED_ALGS:
        raise SignatureError("signature_alg_unsupported", "alg not accepted")
    if any(p in header for p in FORBIDDEN_HEADER_PARAMS):
        raise SignatureError("signature_header_invalid", "header carries a forbidden parameter (jku/jwk/x5*/crit/b64)")
    if header.get("typ") != typ:
        raise SignatureError("signature_header_invalid", f"typ must be {typ!r}")
    if not isinstance(header.get("kid"), str) or not _KID_RE.match(header["kid"]):
        raise SignatureError("signature_header_invalid", "kid missing or malformed")
    return header


KeyLookup = Callable[[str], Ed25519PublicKey]


def verify_detached(payload: Any, sig_obj: Any, lookup: KeyLookup, typ: str) -> dict[str, Any]:
    """Verify; returns the protected header. ``lookup(kid)`` raises SignatureError if the key is unknown."""
    header = parse_protected(sig_obj, typ)
    key = lookup(header["kid"])
    try:
        sig = b64url_decode(sig_obj["signature"])
    except ValueError as exc:
        raise SignatureError("signature_invalid", "signature is not base64url") from exc
    if len(sig) != 64:
        raise SignatureError("signature_invalid", "Ed25519 signatures are 64 bytes")
    try:
        key.verify(sig, signing_input(sig_obj["protected"], payload))
    except InvalidSignature as exc:
        raise SignatureError("signature_invalid", "signature does not verify") from exc
    return header


def verify_compact(jws: str, key: Ed25519PublicKey) -> bytes:
    """Verify a compact JWS with attached payload (used only for the RFC 8037 A.4 known-answer test)."""
    protected, payload, sig = jws.split(".")
    header = json.loads(b64url_decode(protected))
    if header.get("alg") not in ACCEPTED_ALGS:
        raise SignatureError("signature_alg_unsupported", "alg")
    try:
        key.verify(b64url_decode(sig), (protected + "." + payload).encode("ascii"))
    except InvalidSignature as exc:
        raise SignatureError("signature_invalid", "signature does not verify") from exc
    return b64url_decode(payload)
