"""CERT-011: Merkle transparency log proofs and the root-signed issuer manifest."""

from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest

from onaa_protocol import jose, trust
from onaa_protocol import transparency as tl
from onaa_protocol.attestation import (
    build_attestation,
    build_status_record,
    sign_attestation,
    sign_status_record,
    verify_attestation,
)
from onaa_protocol.envelope import parse_ts, utcnow
from onaa_protocol.errors import AttestationError, SignatureError


def leaves(n: int) -> list[bytes]:
    return [tl.leaf_hash(f"entry-{i}".encode()) for i in range(n)]


def test_known_answers_rfc9162_shape():
    assert tl.root_from_hashes([]) == hashlib.sha256(b"").digest()
    a, b, c = leaves(3)
    assert tl.root_from_hashes([a]) == a
    assert tl.root_from_hashes([a, b]) == tl.node_hash(a, b)
    # n=3 splits 2 + 1: the odd leaf is carried up, not duplicated (no CVE-2012-2459 style ambiguity)
    assert tl.root_from_hashes([a, b, c]) == tl.node_hash(tl.node_hash(a, b), c)
    assert tl.leaf_hash(b"x") != tl.node_hash(b"", b"x"[:0] + b"x")  # domain separation


@pytest.mark.parametrize("n", range(1, 18))
def test_inclusion_proofs_verify_for_every_leaf(n):
    hs = leaves(n)
    root = tl.root_from_hashes(hs)
    for i in range(n):
        proof = tl.inclusion_proof(hs, i)
        tl.verify_inclusion(hs[i], i, n, proof, root)
        with pytest.raises(tl.ProofError):
            tl.verify_inclusion(tl.leaf_hash(b"forged"), i, n, proof, root)
        if proof:
            with pytest.raises(tl.ProofError):
                tl.verify_inclusion(hs[i], i, n, proof[:-1], root)
            with pytest.raises(tl.ProofError):
                tl.verify_inclusion(hs[i], i, n, proof + [proof[0]], root)
    with pytest.raises(tl.ProofError):
        tl.verify_inclusion(hs[0], n, n, [], root)


@pytest.mark.parametrize("second", range(1, 18))
def test_consistency_proofs_verify_for_every_prefix(second):
    hs = leaves(second)
    second_root = tl.root_from_hashes(hs)
    for first in range(1, second + 1):
        first_root = tl.root_from_hashes(hs[:first])
        proof = tl.consistency_proof(hs, first)
        tl.verify_consistency(first, second, proof, first_root, second_root)
        if first < second:
            # A rewritten history (one old leaf changed) must not verify against the new root.
            tampered = list(hs)
            tampered[0] = tl.leaf_hash(b"rewritten")
            bad_root = tl.root_from_hashes(tampered[:first])
            with pytest.raises(tl.ProofError):
                tl.verify_consistency(first, second, proof, bad_root, second_root)
            with pytest.raises(tl.ProofError):
                tl.verify_consistency(first, second, [], first_root, second_root)


def test_checkpoint_sign_and_verify():
    signer = jose.Signer(jose.derive_test_only_key("log"), "test-log-1")
    cp = tl.sign_checkpoint(tl.build_checkpoint("onaa-staging", 3, tl.root_from_hashes(leaves(3)), utcnow()), signer)
    pub = signer.private_key.public_key()
    tl.verify_checkpoint(cp, lambda kid: pub)
    cp["tree_size"] = 4
    with pytest.raises(SignatureError):
        tl.verify_checkpoint(cp, lambda kid: pub)


# ------------------------------------------------------------------ issuer manifest


def keyset(now):
    root = jose.Signer(jose.derive_test_only_key("root"), "test-root-1")
    att = jose.Signer(jose.derive_test_only_key("att"), "test-att-1")
    st = jose.Signer(jose.derive_test_only_key("status"), "test-status-1")
    log = jose.Signer(jose.derive_test_only_key("logk"), "test-log-1")
    nb = now - timedelta(days=30)
    keys = [trust.manifest_key(att.public_jwk(), jose.TYP_ATTESTATION, not_before=nb),
            trust.manifest_key(st.public_jwk(), jose.TYP_ATTESTATION_STATUS, not_before=nb),
            trust.manifest_key(log.public_jwk(), tl.TYP_CHECKPOINT, not_before=nb)]
    return root, att, st, log, keys


def signed_manifest(now, keys, root, **kw):
    m = trust.build_manifest("onaa-registry-staging", keys, issued_at=now - timedelta(hours=1),
                             next_update=now + timedelta(days=7), **kw)
    return trust.sign_manifest(m, root)


def attestation(att_signer, now, issuer="onaa-registry-staging"):
    a = build_attestation(id_="att_1", issuer={"id": issuer, "jwks_uri": "https://reg.example/.well-known/onaa/issuer-jwks.json"},
                          subject={"subject_type": "agent", "subject_id": "agt_1"}, level="protocol_certified",
                          scope={"roles": ["seller_agent"]}, criteria_version="0.1", issued_at=now - timedelta(days=1),
                          expires_at=now + timedelta(days=300), status_url="https://reg.example/v1/attestations/att_1/status",
                          evidence=[{"type": "conformance_report", "sha256": "sha256:" + "0" * 64}])
    return sign_attestation(a, att_signer)


def test_manifest_binds_purpose_and_rejects_test_keys_in_production():
    now = utcnow()
    root, att, st, log, keys = keyset(now)
    m = signed_manifest(now, keys, root)
    with pytest.raises(AttestationError) as e:
        trust.verify_manifest(m, root.public_jwk(), now=now)
    assert e.value.code == "attestation_test_only"
    issuer = trust.verify_manifest(m, root.public_jwk(), now=now, allow_test_only=True)
    a = attestation(att, now)
    rec = sign_status_record(build_status_record("att_1", "onaa-registry-staging", "active", now,
                                                 now + timedelta(days=7)), st)
    res = verify_attestation(a, issuer_manifest=issuer, status_record=rec, now=now, allow_test_only=True)
    assert res.status == "active"
    # Cross-purpose: an attestation signed with the status key is refused (one key, one purpose).
    wrong = attestation(st, now)
    with pytest.raises(SignatureError):
        verify_attestation(wrong, issuer_manifest=issuer, now=now, allow_test_only=True)
    # Status record signed with the attestation key is refused too.
    rec2 = sign_status_record(build_status_record("att_1", "onaa-registry-staging", "active", now,
                                                  now + timedelta(days=7)), att)
    with pytest.raises(SignatureError):
        verify_attestation(a, issuer_manifest=issuer, status_record=rec2, now=now, allow_test_only=True)


def test_manifest_stale_wrong_root_and_revoked_or_retired_keys():
    now = utcnow()
    root, att, st, log, keys = keyset(now)
    m = signed_manifest(now, keys, root)
    with pytest.raises(AttestationError) as e:
        trust.verify_manifest(m, root.public_jwk(), now=now + timedelta(days=8), allow_test_only=True)
    assert e.value.code == "manifest_stale"
    other = jose.Signer(jose.derive_test_only_key("other-root"), "test-root-1")
    with pytest.raises(SignatureError):
        trust.verify_manifest(m, other.public_jwk(), now=now, allow_test_only=True)
    tampered = dict(m, next_update="2099-01-01T00:00:00Z")
    with pytest.raises(SignatureError):
        trust.verify_manifest(tampered, root.public_jwk(), now=now, allow_test_only=True)

    # Revoked attestation key: nothing it signed verifies.
    revoked = [dict(keys[0], onaa_status="revoked")] + keys[1:]
    issuer = trust.verify_manifest(signed_manifest(now, revoked, root), root.public_jwk(), now=now,
                                   allow_test_only=True)
    with pytest.raises(SignatureError) as se:
        verify_attestation(attestation(att, now), issuer_manifest=issuer, now=now, allow_test_only=True)
    assert se.value.code == "key_revoked"

    # Rotation: a retired key still verifies what it signed before not_after, but not later.
    retired_at = now - timedelta(hours=12)
    retired = [trust.manifest_key(att.public_jwk(), jose.TYP_ATTESTATION, status="retired",
                                  not_before=now - timedelta(days=30), not_after=retired_at)] + keys[1:]
    issuer = trust.verify_manifest(signed_manifest(now, retired, root), root.public_jwk(), now=now,
                                   allow_test_only=True)
    old = attestation(att, now)  # issued now - 1 day, before retirement
    assert verify_attestation(old, issuer_manifest=issuer, now=now, allow_test_only=True).status == "active"
    new = build_attestation(id_="att_2", issuer=old["issuer"], subject=old["subject"], level=old["level"],
                            scope=old["scope"], criteria_version="0.1", issued_at=now - timedelta(hours=1),
                            expires_at=now + timedelta(days=30), status_url=old["status_url"], evidence=old["evidence"])
    with pytest.raises(SignatureError):
        verify_attestation(sign_attestation(new, att), issuer_manifest=issuer, now=now, allow_test_only=True)


def test_status_record_past_next_update_fails_closed():
    now = utcnow()
    root, att, st, log, keys = keyset(now)
    issuer = trust.verify_manifest(signed_manifest(now, keys, root), root.public_jwk(), now=now, allow_test_only=True)
    rec = sign_status_record(build_status_record("att_1", "onaa-registry-staging", "active", now - timedelta(days=8),
                                                 now - timedelta(days=1)), st)
    with pytest.raises(AttestationError) as e:
        verify_attestation(attestation(att, now), issuer_manifest=issuer, status_record=rec, now=now,
                           allow_test_only=True)
    assert e.value.code == "attestation_status_stale"
    assert parse_ts(rec["next_update"], "x") < now


def test_manifest_rejects_private_material():
    now = utcnow()
    root, att, st, log, keys = keyset(now)
    with pytest.raises(ValueError):
        trust.manifest_key(jose.private_jwk(att.private_key, "test-att-1"), jose.TYP_ATTESTATION, not_before=now)
    leaked = [dict(keys[0], d="AAAA")] + keys[1:]
    with pytest.raises(AttestationError):
        trust.verify_manifest(signed_manifest(now, leaked, root), root.public_jwk(), now=now, allow_test_only=True)
