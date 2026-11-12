"""Endpoint Verified is a paid tier; listing/search stay free. Founding Cohort gets it free."""

from __future__ import annotations

from dataclasses import replace

import pytest
from conftest import AGENT, SERVICE, admin_headers, make_operator, verify_listing
from fastapi.testclient import TestClient

from onaa_registry.main import create_app


@pytest.fixture
def gated(settings, fetcher, txt):
    with TestClient(create_app(replace(settings, require_verification_entitlement=True, founding_cohort_size=2),
                               fetcher, txt)) as c:
        yield c


def test_listing_and_search_stay_free_but_verification_is_gated(gated):
    op_id, h = make_operator(gated)
    aid = gated.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    assert gated.get("/v1/agents").json()["total"] == 1
    r = gated.post(f"/v1/agents/{aid}/verify-domain", headers=h)
    assert r.status_code == 402 and "free and searchable" in r.json()["detail"]


def test_founding_cohort_unlocks_agent_verification(gated, fetcher):
    op_id, h = make_operator(gated)
    aid = gated.post("/v1/agents", json=AGENT, headers=h).json()["id"]
    r = gated.post(f"/v1/admin/operators/{op_id}/founding-cohort", headers=admin_headers(), json={"grant": True})
    assert r.status_code == 200 and r.json()["founding_cohort_active"] is True
    verify_listing(gated, fetcher, "agents", aid, h)
    # Cohort membership is not a trust signal by itself and implies nothing else.
    trust = gated.get(f"/v1/agents/{aid}/trust").json()
    assert trust["endpoint_control_verified"] is True and trust["operator_identity_verified"] is False


def test_founding_cohort_does_not_cover_service_providers(gated):
    op_id, h = make_operator(gated)
    gated.post(f"/v1/admin/operators/{op_id}/founding-cohort", headers=admin_headers(), json={"grant": True})
    sid = gated.post("/v1/services", json=SERVICE, headers=h).json()["id"]
    assert gated.post(f"/v1/services/{sid}/verify-domain", headers=h).status_code == 402


def test_cohort_cap_and_revoke(gated):
    ids = [make_operator(gated, f"Op {i}")[0] for i in range(3)]
    grant = {"grant": True}
    assert gated.post(f"/v1/admin/operators/{ids[0]}/founding-cohort", headers=admin_headers(), json=grant).is_success
    assert gated.post(f"/v1/admin/operators/{ids[1]}/founding-cohort", headers=admin_headers(), json=grant).is_success
    r = gated.post(f"/v1/admin/operators/{ids[2]}/founding-cohort", headers=admin_headers(), json=grant)
    assert r.status_code == 409
    r = gated.post(f"/v1/admin/operators/{ids[0]}/founding-cohort", headers=admin_headers(), json={"grant": False})
    assert r.json()["founding_cohort_active"] is False
    # Revoking does not silently reopen a seat.
    r = gated.post(f"/v1/admin/operators/{ids[2]}/founding-cohort", headers=admin_headers(), json=grant)
    assert r.status_code == 409


def test_approved_endpoint_verified_application_unlocks_listing(gated, fetcher):
    op_id, h = make_operator(gated)
    sid = gated.post("/v1/services", json=SERVICE, headers=h).json()["id"]
    app_ = gated.post("/v1/certifications/applications", headers=h,
                      json={"listing_id": sid, "scheme": "endpoint_verified"}).json()
    assert app_["status"] == "submitted"
    assert gated.post(f"/v1/services/{sid}/verify-domain", headers=h).status_code == 402  # applying != paying
    gated.post(f"/v1/admin/certifications/{app_['id']}/decision", headers=admin_headers(),
               json={"decision": "approve", "reason": "fee received out of band (sandbox)"})
    verify_listing(gated, fetcher, "services", sid, h)
    rec = gated.get(f"/v1/services/{sid}").json()
    # The entitlement itself is not displayed as a certification.
    assert rec["trust"]["endpoint_control_verified"] is True and rec["trust"]["certifications"] == []


def test_operators_cannot_grant_themselves(gated):
    op_id, h = make_operator(gated)
    r = gated.post(f"/v1/admin/operators/{op_id}/founding-cohort", headers=h, json={"grant": True})
    assert r.status_code == 403
