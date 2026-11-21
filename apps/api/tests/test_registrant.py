"""Trust levels for registered listings (founder decision 2026-11-17). The store-specific parts of this file (email
verification for stores, store-stated details, store lookups and re-checks) went with the store directory."""

from __future__ import annotations

from onaa_registry import registrant


def test_trust_level_order():
    lv = registrant.trust_level
    assert lv(operator_id=None, lifecycle_status="discovered", endpoint_verified=False) == "discovered_unverified"
    assert lv(operator_id="op", lifecycle_status="claim_pending", endpoint_verified=False) == "discovered_unverified"
    assert lv(operator_id="op", lifecycle_status="registered", endpoint_verified=False) == "operator_registered"
    assert lv(operator_id="op", lifecycle_status="registered", endpoint_verified=False,
              owner_confirmed_via="published_email") == "operator_confirmed_by_email"
    assert lv(operator_id="op", lifecycle_status="endpoint_verified", endpoint_verified=True,
              owner_confirmed_via="published_email") == "operator_endpoint_verified"
    assert lv(operator_id="op", lifecycle_status="certified", endpoint_verified=True, certified=True) == "certified"
