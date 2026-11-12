"""Attestations (offline verification, status records) and registry trust levels."""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from onaa_protocol import AttestationError, build_attestation, trust_levels, validate_record, verify_attestation
from onaa_protocol.errors import ProtocolError
from onaa_protocol.vectors import T0, attestations, jwks, registry_records


def test_build_refuses_real_issuance():
    with pytest.raises(ValueError, match="TEST-ONLY"):
        build_attestation(id_="a", issuer={"id": "i", "jwks_uri": "https://i.example.com/j"},
                          subject={"subject_type": "agent", "subject_id": "agt_1"}, level="protocol_certified",
                          scope={}, criteria_version="0.1", issued_at=T0, expires_at=T0 + timedelta(days=1),
                          status_url="https://i.example.com/s", evidence=[], test_only=False)


def test_valid_attestation_result():
    case = attestations()["cases"][0]
    res = verify_attestation(case["attestation"], jwks("issuer"), trusted_issuers={"onaa-test-issuer"},
                             now=T0 + timedelta(days=1), allow_test_only=True)
    assert (res.level, res.status, res.test_only) == ("protocol_certified", "active", True)


def test_issuer_keys_never_come_from_the_attestation():
    att = copy.deepcopy(attestations()["cases"][0]["attestation"])
    att["issuer"]["jwks_uri"] = "https://attacker.example.com/jwks.json"   # covered by signature
    with pytest.raises(Exception) as e:
        verify_attestation(att, jwks("issuer"), trusted_issuers={"onaa-test-issuer"}, now=T0, allow_test_only=True)
    assert getattr(e.value, "code", "") == "signature_invalid"


def test_status_record_and_suspended_status():
    d = attestations()
    revoked = next(c for c in d["cases"] if c["name"] == "revoked-by-status-record")
    suspended = next(c for c in d["cases"] if c["name"] == "suspended")
    with pytest.raises(AttestationError) as e:
        verify_attestation(revoked["attestation"], jwks("issuer"), trusted_issuers={"onaa-test-issuer"},
                           now=T0 + timedelta(days=2), status_record=revoked["status_record"], allow_test_only=True)
    assert e.value.code == "attestation_revoked"
    with pytest.raises(AttestationError):
        verify_attestation(suspended["attestation"], jwks("issuer"), trusted_issuers={"onaa-test-issuer"},
                           now=T0 + timedelta(days=2), allow_test_only=True)


def test_trust_levels_are_independent():
    d = registry_records()
    for c in d["cases"]:
        lv = trust_levels(c["record"], now=T0 + timedelta(minutes=2))
        assert lv == c["expected"], c["name"]
        assert lv["listing_tier"] == "free"


def test_record_validation_rejects_bad_status():
    rec = copy.deepcopy(registry_records()["cases"][0]["record"])
    rec["status"] = "verified"            # not a registry lifecycle value; never coerce
    with pytest.raises(ProtocolError):
        validate_record(rec)
