from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

Kind = Literal["agents", "services"]
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "testserver"}


class OnaaError(Exception):
    """Non-2xx response from the Registry."""

    def __init__(self, status_code: int, detail: Any, body: Any = None):
        super().__init__(f"HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail
        self.body = body


@dataclass
class Page:
    items: list[dict]
    total: int
    limit: int
    offset: int


def _params(filters: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for key, value in filters.items():
        if value is None or value is False:
            continue
        key = "status" if key == "status_" else key
        if isinstance(value, list | tuple | set):
            out.extend((key, str(v)) for v in value)
        elif value is True:
            out.append((key, "true"))
        else:
            out.append((key, str(value)))
    return out


class OnaaClient:
    """Synchronous client for the ONAA Registry API (v1).

    >>> reg = OnaaClient("https://registry.example", api_key=os.environ["ONAA_API_KEY"])
    >>> sellers = reg.search_agents(role="seller_agent", capability="commerce.quote.issue", region="US")

    The API key is sent only over HTTPS (plain HTTP is allowed for localhost development).
    Never hard-code keys; load them from your secret store.
    """

    def __init__(self, base_url: str, api_key: str | None = None, *, timeout: float = 10.0,
                 http_client: httpx.Client | None = None):
        parts = urlsplit(base_url)
        if parts.scheme not in ("https", "http"):
            raise ValueError("base_url must be http(s)")
        if api_key and parts.scheme != "https" and (parts.hostname or "") not in _LOCAL_HOSTS:
            raise ValueError("refusing to send an API key over plain HTTP to a non-local host")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._http = http_client or httpx.Client(timeout=timeout)
        self._owns_http = http_client is None

    # ---- plumbing ----
    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> OnaaClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _request(self, method: str, path: str, *, json: Any = None, params: Any = None,
                 auth: bool = False, ok: tuple[int, ...] = (200, 201, 204)) -> Any:
        headers = {"Accept": "application/json", "User-Agent": "onaa-sdk-python/0.1.0"}
        if auth:
            if not self.api_key:
                raise ValueError("this call needs an operator api_key")
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = self._http.request(method, self.base_url + path, json=json, params=params, headers=headers)
        if resp.status_code not in ok:
            try:
                body = resp.json()
            except ValueError:
                body = resp.text
            detail = body.get("detail", body.get("error", body)) if isinstance(body, dict) else body
            raise OnaaError(resp.status_code, detail, body)
        if resp.status_code == 204 or not resp.content:
            return None
        return resp.json()

    # ---- meta ----
    def health(self) -> dict:
        return self._request("GET", "/v1/health")

    def discovery_metadata(self) -> dict:
        return self._request("GET", "/.well-known/onaa-registry.json")

    # ---- operators ----
    def create_operator(self, display_name: str, operator_type: Literal["individual", "organization"], *,
                        accept_terms_version: str, country: str | None = None,
                        website_url: str | None = None) -> dict:
        """Create an operator account. Returns {'operator': ..., 'api_key': ...}; the key is shown once.

        The returned key is also set on this client.
        """
        body = {"display_name": display_name, "operator_type": operator_type,
                "accept_terms_version": accept_terms_version}
        if country:
            body["country"] = country
        if website_url:
            body["website_url"] = website_url
        data = self._request("POST", "/v1/operators", json=body)
        self.api_key = data["api_key"]
        return data

    def me(self) -> dict:
        return self._request("GET", "/v1/operators/me", auth=True)

    def update_profile(self, **fields) -> dict:
        """Optional operator linkage, e.g. a self-registered agent attaching an organisation profile later."""
        return self._request("PATCH", "/v1/operators/me", auth=True, json=fields)

    # ---- agent self-registration (no human signup) ----
    def current_terms_version(self) -> str:
        return self.discovery_metadata()["onboarding"]["terms_version"]

    def start_self_registration(self, listing: dict, *, kind: Literal["agent", "service"] = "agent",
                                method: Literal["well_known", "dns_txt"] = "well_known",
                                accept_terms_version: str | None = None) -> dict:
        """Step 1. Returns the challenge: token (to publish), registration_secret (keep private), challenge_url
        or dns_record_name. Nothing is listed until step 2 succeeds."""
        tv = accept_terms_version or self.current_terms_version()
        return self._request("POST", "/v1/self-register",
                             json={"accept_terms_version": tv, "method": method, kind: listing})

    def complete_self_registration(self, registration_id: str, registration_secret: str, *,
                                   set_key: bool = True) -> dict:
        """Step 2. On success returns {'operator', 'api_key', 'listing', 'next_steps'} and sets api_key on this
        client. Raises OnaaError(422) with body['error'] while the proof is not visible yet."""
        data = self._request("POST", f"/v1/self-register/{registration_id}/complete",
                             json={"registration_secret": registration_secret})
        if set_key:
            self.api_key = data["api_key"]
        return data

    def self_register(self, listing: dict, publish: Callable[[dict], None], *,
                      kind: Literal["agent", "service"] = "agent",
                      method: Literal["well_known", "dns_txt"] = "well_known",
                      accept_terms_version: str | None = None, attempts: int = 3,
                      retry_delay: float = 2.0) -> dict:
        """Register this agent end to end in one call.

        `publish(challenge)` must make the token visible on the agent's own host: serve challenge['token'] at
        challenge['challenge_url'] (well_known) or set the TXT record challenge['dns_record_name'] (dns_txt).
        The proof is retried up to `attempts` times (the server allows 10) to absorb propagation delay.
        Always passing the current terms version is the caller's acceptance of those terms.
        """
        chl = self.start_self_registration(listing, kind=kind, method=method,
                                           accept_terms_version=accept_terms_version)
        publish(chl)
        for i in range(max(1, attempts)):
            try:
                return self.complete_self_registration(chl["registration_id"], chl["registration_secret"])
            except OnaaError as exc:
                if exc.status_code != 422 or i == attempts - 1:
                    raise
                time.sleep(retry_delay)
        raise AssertionError("unreachable")

    def rotate_key(self) -> str:
        data = self._request("POST", "/v1/operators/me/keys/rotate", auth=True)
        self.api_key = data["api_key"]
        return self.api_key

    # ---- listings ----
    def register_agent(self, *, display_name: str, roles: list[str], agent_card_url: str, **fields) -> dict:
        return self._request("POST", "/v1/agents", auth=True, json={
            "display_name": display_name, "roles": roles, "agent_card_url": agent_card_url, **fields})

    def register_service(self, *, display_name: str, service_type: str, endpoint_url: str, **fields) -> dict:
        return self._request("POST", "/v1/services", auth=True, json={
            "display_name": display_name, "service_type": service_type, "endpoint_url": endpoint_url, **fields})

    def update(self, kind: Kind, listing_id: str, **fields) -> dict:
        return self._request("PATCH", f"/v1/{kind}/{listing_id}", auth=True, json=fields)

    def delete(self, kind: Kind, listing_id: str) -> None:
        self._request("DELETE", f"/v1/{kind}/{listing_id}", auth=True)

    def get(self, kind: Kind, listing_id: str) -> dict:
        return self._request("GET", f"/v1/{kind}/{listing_id}")

    def trust(self, kind: Kind, listing_id: str) -> dict:
        return self._request("GET", f"/v1/{kind}/{listing_id}/trust")

    def claim_agent(self, listing_id: str) -> dict:
        return self._request("POST", f"/v1/agents/{listing_id}/claim", auth=True)

    def refresh_card(self, listing_id: str) -> dict:
        return self._request("POST", f"/v1/agents/{listing_id}/refresh-card", auth=True)

    # ---- search ----
    def search(self, kind: Kind, *, limit: int = 20, offset: int = 0, **filters) -> Page:
        """Filters: q, role, capability, region, currency, protocol, language, category,
        type (services), verified_only, certified_only, claimed_only, status_. Lists repeat the parameter."""
        data = self._request("GET", f"/v1/{kind}", params=_params({**filters, "limit": limit, "offset": offset}))
        return Page(items=data["items"], total=data["total"], limit=data["limit"], offset=data["offset"])

    def search_agents(self, **filters) -> Page:
        return self.search("agents", **filters)

    def search_services(self, **filters) -> Page:
        return self.search("services", **filters)

    def iter_search(self, kind: Kind, *, page_size: int = 50, max_items: int | None = None,
                    **filters) -> Iterator[dict]:
        offset, seen = 0, 0
        while True:
            page = self.search(kind, limit=page_size, offset=offset, **filters)
            for item in page.items:
                yield item
                seen += 1
                if max_items is not None and seen >= max_items:
                    return
            offset += len(page.items)
            if not page.items or offset >= page.total:
                return

    # ---- verification ----
    def start_verification(self, kind: Kind, listing_id: str,
                           method: Literal["well_known", "dns_txt"] = "well_known") -> dict:
        """Returns the challenge (token shown once, plus challenge_url or dns_record_name)."""
        return self._request("POST", f"/v1/{kind}/{listing_id}/verify-domain", auth=True, json={"method": method})

    def complete_verification(self, kind: Kind, listing_id: str, challenge_id: str) -> dict:
        """Raises OnaaError(422) with body['error'] (e.g. token_mismatch) if the proof is not found yet."""
        return self._request("POST", f"/v1/{kind}/{listing_id}/verification-complete", auth=True,
                             json={"challenge_id": challenge_id})

    # ---- certification / trust ----
    def apply_certification(self, listing_id: str, scheme: str, *, evidence_urls: list[str] | None = None,
                            notes: str | None = None) -> dict:
        body: dict[str, Any] = {"listing_id": listing_id, "scheme": scheme, "evidence_urls": evidence_urls or []}
        if notes:
            body["notes"] = notes
        return self._request("POST", "/v1/certifications/applications", auth=True, json=body)

    def get_certification_application(self, application_id: str) -> dict:
        return self._request("GET", f"/v1/certifications/{application_id}", auth=True)

    def report(self, subject_id: str, category: str, description: str, *,
               evidence_urls: list[str] | None = None) -> dict:
        return self._request("POST", "/v1/reports", auth=bool(self.api_key), json={
            "subject_id": subject_id, "category": category, "description": description,
            "evidence_urls": evidence_urls or []})
