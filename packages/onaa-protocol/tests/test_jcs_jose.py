"""JCS (RFC 8785) and JWS/EdDSA (RFC 7515/8037) building blocks."""

from __future__ import annotations

import json

import pytest

from onaa_protocol import jose
from onaa_protocol.errors import SignatureError
from onaa_protocol.jcs import CanonicalizationError, canonicalize
from onaa_protocol.vectors import RFC8037_A4_JWS, RFC8037_D, RFC8037_X


def test_rfc8037_known_answer():
    key = jose.public_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X})
    assert jose.verify_compact(RFC8037_A4_JWS, key) == b"Example of Ed25519 signing"
    priv = jose.private_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "d": RFC8037_D, "x": RFC8037_X})
    # Ed25519 is deterministic: re-signing the RFC input reproduces the RFC signature.
    protected, payload, sig = RFC8037_A4_JWS.split(".")
    assert jose.b64url_encode(priv.sign(f"{protected}.{payload}".encode())) == sig


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 2**53, -(2**53), {1: "x"}, object()])
def test_jcs_rejects_non_ijson(value):
    with pytest.raises(CanonicalizationError):
        canonicalize(value)


def test_jcs_rejects_lone_surrogate():
    with pytest.raises(CanonicalizationError):
        canonicalize(json.loads('"\\ud800"'))


def test_jcs_is_compact_sorted_utf8():
    assert canonicalize({"b": 1, "a": [True, None, "x\ny"]}) == b'{"a":[true,null,"x\\ny"],"b":1}'
    assert canonicalize({"k": chr(0x1F)}) == b'{"k":"\\u001f"}'


def test_sign_verify_roundtrip_and_tamper():
    s = jose.Signer(jose.derive_test_only_key("unit"), "unit-1")
    payload = {"a": 1, "b": [1, 2]}
    sig = jose.sign_detached(payload, s, jose.TYP_ENVELOPE)
    key = s.private_key.public_key()
    header = jose.verify_detached(payload, sig, lambda kid: key, jose.TYP_ENVELOPE)
    assert header == {"alg": "EdDSA", "kid": "unit-1", "typ": jose.TYP_ENVELOPE}
    with pytest.raises(SignatureError) as e:
        jose.verify_detached({"a": 2, "b": [1, 2]}, sig, lambda kid: key, jose.TYP_ENVELOPE)
    assert e.value.code == "signature_invalid"
    with pytest.raises(SignatureError) as e:
        jose.verify_detached(payload, sig, lambda kid: key, jose.TYP_ATTESTATION)
    assert e.value.code == "signature_header_invalid"
    with pytest.raises(SignatureError) as e:
        jose.verify_detached(payload, dict(sig, header={}), lambda kid: key, jose.TYP_ENVELOPE)
    assert e.value.code == "signature_header_invalid"


def test_derived_test_keys_are_deterministic_and_distinct():
    a = jose.public_jwk(jose.derive_test_only_key("x"), "k")
    assert a == jose.public_jwk(jose.derive_test_only_key("x"), "k")
    assert a["x"] != jose.public_jwk(jose.derive_test_only_key("y"), "k")["x"]


@pytest.mark.parametrize("bad", ["a=", "a+b", "a/b", "abcde", "é"])
def test_b64url_is_strict(bad):
    with pytest.raises(ValueError):
        jose.b64url_decode(bad)


def test_jwks_validation():
    pub = jose.public_jwk(jose.derive_test_only_key("x"), "k1")
    assert set(jose.validate_jwks({"keys": [pub]})) == {"k1"}
    with pytest.raises(SignatureError):
        jose.validate_jwks({"keys": [pub, pub]})                                  # duplicate kid
    with pytest.raises(SignatureError):
        jose.validate_jwks({"keys": [jose.private_jwk(jose.derive_test_only_key("x"), "k2")]})  # private
    with pytest.raises(SignatureError):
        jose.validate_jwks({"keys": [dict(pub, kid="bad kid!")]})
    assert jose.validate_jwks({"keys": [{"kty": "RSA", "kid": "r", "n": "x", "e": "AQAB"}]}) == {}
    assert len(jose.jwk_thumbprint(pub)) == 43
