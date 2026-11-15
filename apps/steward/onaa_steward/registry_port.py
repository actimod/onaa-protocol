"""The steward's only connection to the Registry: public reads plus Policy Service requests.

It holds a steward token, not an admin token, so it cannot change registry state except through
`POST /v1/policy/requests`, where the registry's policy code decides.
"""

from __future__ import annotations

from typing import Any

import httpx


class PolicyDenied(Exception):
    def __init__(self, decision: dict[str, Any]):
        super().__init__(f"policy {decision.get('decision')}: {decision.get('decision_reason')}")
        self.decision = decision


class RegistryPort:
    def __init__(self, client: httpx.Client, steward_token: str | None):
        self.client = client
        self._auth = {"Authorization": f"Bearer {steward_token}"} if steward_token else {}

    # ---- reads (public API)
    def get_listing(self, listing_id: str) -> dict[str, Any]:
        kind = "services" if listing_id.startswith(("svc_", "hst_")) else "agents"
        r = self.client.get(f"/v1/{kind}/{listing_id}")
        r.raise_for_status()
        return r.json()

    def search(self, kind: str = "agents", **params: Any) -> list[dict[str, Any]]:
        r = self.client.get(f"/v1/{kind}", params=params)
        r.raise_for_status()
        return r.json().get("items", [])

    def incidents(self, listing_id: str | None = None, state: str | None = None) -> list[dict[str, Any]]:
        params = {k: v for k, v in {"listing_id": listing_id, "state": state}.items() if v}
        r = self.client.get("/v1/incidents", params=params)
        r.raise_for_status()
        return r.json()["items"]

    # ---- writes (Policy Service only)
    def request(self, action: str, subject_id: str | None = None, params: dict | None = None,
                rationale: str | None = None) -> dict[str, Any]:
        r = self.client.post("/v1/policy/requests", headers=self._auth,
                             json={"action": action, "subject_id": subject_id, "params": params or {},
                                   "rationale": rationale})
        r.raise_for_status()
        return r.json()

    def apply(self, action: str, subject_id: str | None = None, params: dict | None = None,
              rationale: str | None = None) -> dict[str, Any]:
        """Request an AUTO action and return its result; raise PolicyDenied if it was not applied."""
        d = self.request(action, subject_id, params, rationale)
        if d.get("decision") != "applied":
            raise PolicyDenied(d)
        return d.get("result") or {}
