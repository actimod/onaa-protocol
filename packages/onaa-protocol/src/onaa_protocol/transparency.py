"""Append-only Merkle transparency log for attestation events (CERT-011).

Hashing and proofs follow RFC 9162 (Certificate Transparency 2.0) section 2.1:

* leaf hash  = SHA-256(0x00 || leaf_bytes)
* node hash  = SHA-256(0x01 || left || right)
* the empty tree hashes to SHA-256("")

A leaf is the JCS (RFC 8785) form of one log entry, so anyone can recompute it from the published JSON.
A checkpoint (signed tree head) commits to ``tree_size`` and ``root_hash`` and is signed with the log key
(JWS ``typ`` ``onaa-log-checkpoint+jws``, per the ONAA attestation key management procedure). Inclusion proofs
show an entry is in a checkpoint; consistency proofs show a later checkpoint only appended to an earlier one,
so the log operator cannot silently rewrite or drop history.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from . import jose
from .envelope import format_ts
from .jcs import canonicalize

TYP_CHECKPOINT = "onaa-log-checkpoint+jws"
CHECKPOINT_VERSION = "0.1.0"
ENTRY_VERSION = "0.1.0"
EVENTS = ("issue", "renew", "suspend", "reinstate", "revoke", "expire", "key_event")


class ProofError(ValueError):
    """A Merkle proof or checkpoint did not verify."""


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_bytes(entry: dict[str, Any]) -> bytes:
    return canonicalize(entry)


def leaf_hash(leaf: bytes) -> bytes:
    return _h(b"\x00" + leaf)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root_from_hashes(hashes: list[bytes]) -> bytes:
    """Merkle Tree Hash over already-hashed leaves (RFC 9162 section 2.1.1)."""
    if not hashes:
        return _h(b"")
    level = list(hashes)
    # Iterative form of the recursive definition: pair left to right, carry an odd last node up unchanged.
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def _subtree(hashes: list[bytes]) -> bytes:
    return root_from_hashes(hashes)


def inclusion_proof(hashes: list[bytes], index: int) -> list[bytes]:
    """Audit path for leaf ``index`` in the tree over ``hashes`` (RFC 9162 section 2.1.3.1)."""
    n = len(hashes)
    if not 0 <= index < n:
        raise ValueError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(hashes[:k], index) + [_subtree(hashes[k:])]
    return inclusion_proof(hashes[k:], index - k) + [_subtree(hashes[:k])]


def verify_inclusion(leaf_h: bytes, index: int, tree_size: int, proof: list[bytes], root: bytes) -> None:
    """RFC 9162 section 2.1.3.2. Raises ProofError."""
    if not 0 <= index < tree_size:
        raise ProofError("leaf index out of range")
    fn, sn, r = index, tree_size - 1, leaf_h
    for p in proof:
        if sn == 0:
            raise ProofError("inclusion proof too long")
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ProofError("inclusion proof too short")
    if r != root:
        raise ProofError("inclusion proof does not match the root")


def consistency_proof(hashes: list[bytes], first: int) -> list[bytes]:
    """Proof that the tree of size ``first`` is a prefix of the tree over ``hashes`` (RFC 9162 2.1.4.1)."""
    n = len(hashes)
    if not 0 < first <= n:
        raise ValueError("first tree size out of range")
    if first == n:
        return []
    return _subproof(first, hashes, True)


def _subproof(m: int, hashes: list[bytes], b: bool) -> list[bytes]:
    n = len(hashes)
    if m == n:
        return [] if b else [_subtree(hashes)]
    k = _split(n)
    if m <= k:
        return _subproof(m, hashes[:k], b) + [_subtree(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [_subtree(hashes[:k])]


def verify_consistency(first: int, second: int, proof: list[bytes], first_root: bytes, second_root: bytes) -> None:
    """RFC 9162 section 2.1.4.2. Raises ProofError."""
    if not 0 < first <= second:
        raise ProofError("tree sizes out of order")
    if first == second:
        if proof:
            raise ProofError("proof must be empty for equal tree sizes")
        if first_root != second_root:
            raise ProofError("roots differ for the same tree size")
        return
    if not proof:
        raise ProofError("empty consistency proof")
    path = list(proof)
    if first & (first - 1) == 0:  # first is an exact power of two: its root is the implicit first node
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            raise ProofError("consistency proof too long")
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ProofError("consistency proof too short")
    if fr != first_root or sr != second_root:
        raise ProofError("consistency proof does not match the roots")


# ------------------------------------------------------------------ entries and checkpoints


def build_entry(*, event: str, attestation_id: str, subject_id: str, level: str, status: str,
                at: datetime, reason: str | None = None, attestation_sha256: str | None = None,
                test_only: bool = True) -> dict[str, Any]:
    if event not in EVENTS:
        raise ValueError(f"unknown log event {event}")
    entry: dict[str, Any] = {"entry_version": ENTRY_VERSION, "event": event, "attestation_id": attestation_id,
                             "subject_id": subject_id, "level": level, "status": status, "at": format_ts(at),
                             "test_only": test_only}
    if reason:
        entry["reason"] = reason[:500]
    if attestation_sha256:
        entry["attestation_sha256"] = attestation_sha256
    return entry


def attestation_digest(att: dict[str, Any]) -> str:
    """``sha256:<hex>`` of the JCS form of a signed attestation (signature included)."""
    return "sha256:" + hashlib.sha256(canonicalize(att)).hexdigest()


def b64(h: bytes) -> str:
    return jose.b64url_encode(h)


def unb64(s: str) -> bytes:
    try:
        raw = jose.b64url_decode(s)
    except ValueError as exc:
        raise ProofError("hash is not base64url") from exc
    if len(raw) != 32:
        raise ProofError("hash must be 32 bytes")
    return raw


def build_checkpoint(log_id: str, tree_size: int, root: bytes, timestamp: datetime,
                     *, test_only: bool = True) -> dict[str, Any]:
    return {"checkpoint_version": CHECKPOINT_VERSION, "log_id": log_id, "tree_size": tree_size,
            "root_hash": b64(root), "timestamp": format_ts(timestamp), "test_only": test_only}


def sign_checkpoint(cp: dict[str, Any], signer: jose.Signer) -> dict[str, Any]:
    cp["signature"] = jose.sign_detached({k: v for k, v in cp.items() if k != "signature"}, signer, TYP_CHECKPOINT)
    return cp


def verify_checkpoint(cp: Any, lookup: jose.KeyLookup) -> dict[str, Any]:
    """Check shape and signature of a checkpoint; returns the protected header. Raises ProofError/SignatureError."""
    need = {"checkpoint_version", "log_id", "tree_size", "root_hash", "timestamp", "test_only", "signature"}
    if not isinstance(cp, dict) or set(cp) != need:
        raise ProofError("checkpoint has unexpected members")
    if cp["checkpoint_version"] != CHECKPOINT_VERSION or not isinstance(cp["tree_size"], int) \
            or isinstance(cp["tree_size"], bool) or cp["tree_size"] < 0 or not isinstance(cp["test_only"], bool):
        raise ProofError("checkpoint fields are invalid")
    unb64(cp["root_hash"])
    return jose.verify_detached({k: v for k, v in cp.items() if k != "signature"}, cp["signature"], lookup,
                                TYP_CHECKPOINT)
