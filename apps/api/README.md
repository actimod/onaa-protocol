# ONAA Registry API (MVP)

Central **discovery, registration and trust metadata** for ONAA (Open Network for AI Agents).
The Registry is a control plane only: buyers, sellers and service providers transact **directly** over
their own A2A/HTTPS endpoints. The Registry never relays commerce messages, holds funds, or hosts seller data.

Status: development build. Not deployed anywhere; no production credentials exist.

## Run locally

```bash
cd apps/api
pip install -e '.[dev]'
pytest                                   # contract + security tests (no network)
uvicorn --factory onaa_registry.main:create_app --reload   # http://localhost:8000/docs
```

### Database and migrations (ENG-007)

SQLite (default) creates tables automatically for local development. Any server database (PostgreSQL) uses
Alembic and never auto-creates tables unless `ONAA_AUTO_CREATE_SCHEMA=1`:

```bash
pip install -e '.[dev,postgres]'
export ONAA_DATABASE_URL='postgresql+psycopg://onaa@localhost:5432/onaa_dev'
alembic upgrade head                      # apply migrations
alembic revision --autogenerate -m "..."  # after changing models.py; review the generated file
```

`tests/test_migrations.py` fails if migrations drift from `models.py`. To run the whole suite on PostgreSQL:
`ONAA_TEST_DATABASE_URL='postgresql+psycopg://user@host:5432/onaa_test' pytest` (the database is wiped per test).

Environment variables (all optional; see `onaa_registry/config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `ONAA_DATABASE_URL` | `sqlite:///./onaa_dev.db` | SQLAlchemy URL. PostgreSQL: `postgresql+psycopg://...` (install the `postgres` extra). |
| `ONAA_AUTO_CREATE_SCHEMA` | `1` for SQLite, else `0` | Create tables at startup instead of using migrations. |
| `ONAA_ADMIN_TOKEN` | unset | Enables admin endpoints (discovery import, suspension, certification decisions). Unset = admin API returns 404. |
| `ONAA_TERMS_VERSION` | `draft-0.2` | Terms version operators must accept at signup. |
| `ONAA_CHALLENGE_TTL_SECONDS` | `86400` | Domain challenge lifetime. |
| `ONAA_WRITE_RATE_LIMIT` | `60` | Write requests per client IP per minute (in-process). `0` disables. |
| `ONAA_VERIFICATION_VALID_DAYS` | `90` | Endpoint-control proof lifetime; owners re-verify before expiry. |
| `ONAA_MAX_LISTINGS_PER_OPERATOR` | `50` | Non-deleted listings (incl. claims) per operator. |
| `ONAA_OPERATOR_WRITE_LIMIT` | `120` | Authenticated write requests per operator per minute. |
| `ONAA_TRUSTED_PROXY_HOPS` | `0` | Reverse proxies in front of the API; >0 reads the client IP from `X-Forwarded-For`. |
| `ONAA_REQUIRE_VERIFICATION_ENTITLEMENT` | `1` | Endpoint verification needs an entitlement. `0` only for local dev/tests. |
| `ONAA_FOUNDING_COHORT_SIZE` | `50` | Founding Cohort seats (agent operators). |
| `ONAA_PUBLIC_BASE_URL` | `http://localhost:8000` | Used in discovery metadata links. |

Regenerate the OpenAPI snapshot after changing routes or schemas (a test fails if it is stale):

```bash
python scripts/export_openapi.py         # writes ../../specs/openapi.json
```

## Endpoints (blueprint section 19)

| Method | Path | Auth |
|---|---|---|
| GET | `/v1/health`, `/v1/specs`, `/.well-known/onaa-registry.json` (includes `onboarding`), `/llms.txt` | public |
| POST | `/v1/self-register`, `/v1/self-register/{id}/complete` | public: agent self-registration (key once) |
| POST | `/v1/operators` | public (returns API key once) |
| GET/PATCH/DELETE | `/v1/operators/me` ; POST `/v1/operators/me/keys/rotate` | operator |
| GET | `/v1/agents?q=&role=&capability=&region=&currency=&protocol=&language=&category=&verified_only=&certified_only=&claimed_only=&status=&limit=&offset=` | public |
| GET | `/v1/agents/{id}`, `/v1/agents/{id}/trust` | public |
| POST / PATCH / DELETE | `/v1/agents`, `/v1/agents/{id}` | operator (owner) |
| POST | `/v1/agents/{id}/claim` (discovered only), `/v1/agents/{id}/refresh-card` | operator |
| POST | `/v1/agents/{id}/verify-domain`, `/v1/agents/{id}/verification-complete` | operator (owner) |
| GET | `/v1/services?type=escrow&region=US&currency=USD...` and `/v1/services/{id}[/trust]` | public |
| POST / PATCH / DELETE | `/v1/services`, `/v1/services/{id}` (+ verify-domain, verification-complete) | operator (owner) |
| POST / GET | `/v1/certifications/applications`, `/v1/certifications/{id}` | operator |
| POST | `/v1/reports` | public or operator |
| POST | `/v1/admin/discovered`, `/v1/admin/discovered/services`, `/v1/admin/listings/{id}/suspend`, `/v1/admin/certifications/{id}/decision` | admin token |

Multi-valued filters accept repeats or commas (`region=US,KR`). A listing with region `GLOBAL` matches any region filter.

## Agent self-registration

An AI agent can join with no human signup form, but it always registers **for its operator** (the person or
organisation responsible for it), and the operator is the party bound by the terms. Plain-text instructions for LLM
agents are served at `GET /llms.txt` and as JSON under `onboarding` in `/.well-known/onaa-registry.json`, both built
from `ONAA_PUBLIC_BASE_URL`.

0. `GET /v1/terms` returns the current terms `version`, the `sha256` of the exact text, a short summary and the full
   text (`GET /v1/terms.md` serves the text alone). Texts are bundled in `onaa_registry/terms/<version>.md`;
   `ONAA_TERMS_VERSION` must name a bundled text or the app refuses to start.
   The terms are a draft and have not been reviewed by a lawyer.
1. `POST /v1/self-register` with `{"accept_terms_version": "<current>", "confirm_operator_authority": true,
   "accept_terms_sha256": "<optional, must match>", "operator_contact": "<optional private email or https URL>",
   "method": "well_known"|"dns_txt", "agent": {AgentCreate}}` (or `"service": {ServiceCreate}`).
   `confirm_operator_authority` must be `true`. The payload is fully validated but nothing is listed.
   The response has `token`, a private `registration_secret` and `challenge_url` / `dns_record_name`.
2. The agent publishes the token on its own host (same paths as endpoint verification, no redirects).
3. `POST /v1/self-register/{id}/complete` with `{"registration_secret": ...}`. ONAA creates an agent identity
   (`operator_type: "agent"`), an agent-scoped `onaa_sk_` key (shown once, SHA-256 stored) and the listing.

The secret exists because the challenge URL and token become public once published; without it anyone watching the
host could finish the signup and take the key. The signup proof is an anti-abuse gate only: the listing starts
`registered` with `endpoint_control_verified: false` and `trust.registration_method: "agent_self_registration"`.
Endpoint Verified stays a separate, paid tier. A discovered copy of the same Agent Card is retired
(`status_reason: claimed_via_self_registration:<id>`). Operator linkage is optional and later: `PATCH
/v1/operators/me` can set `operator_type` to `individual`/`organization`, name, country and website (needed before
paid operator verification); it does not verify anything by itself.

Acceptance evidence is stored on the operator row: `terms_version`, `terms_sha256`, `terms_accepted_at` and
`terms_acceptance_method` (`agent_on_behalf_of_operator` or `operator_account`). `operator_contact` is private: it
is never in registry records or audit details. Withdrawal is `DELETE` on the listing or `DELETE /v1/operators/me`;
a rightful owner who did not authorise a registration reports it with category `unauthorized_registration`.

Abuse limits (env): `ONAA_SELF_REGISTRATION_TTL_SECONDS` (3600), `ONAA_SELF_REGISTRATION_PER_IP_PER_HOUR` (10),
`ONAA_SELF_REGISTRATION_PENDING_PER_HOST` (3), `ONAA_SELF_REGISTRATION_AGENTS_PER_HOST` (3), plus 10 proof
attempts, the IP write limit, per-identity listing quota and write budget, and the host lock held by a verified
owner. `ONAA_SELF_REGISTRATION_ENABLED=0` turns the flow off (404). No raw IPs are stored.

Clients: `OnaaClient.self_register(listing, publish, accept_terms_version=..., confirm_operator_authority=True)`
in the Python SDK does all three steps in one call (it never accepts terms by itself); the MCP server adds
`get_terms`, `self_register_start` and `self_register_complete` with `--enable-self-registration --key-file`.

## Discovery imports

`POST /v1/admin/discovered` (agents with a public Agent Card) and `POST /v1/admin/discovered/services`
(providers with official docs; `endpoint_url` optional) create `discovered` listings: `operator_id: null`,
`claimed: false`, `trust.registration_method: "discovery_import"` and a provenance note saying ONAA observed them
and they are not registered or endorsed. Search shows them by default; `claimed_only=true` hides them. When the
provider self-registers on the same host and service type (or the same Agent Card), the discovered copy is retired.
`scripts/import_discovered.py SEED` validates a seed file offline; `--apply` posts it with `ONAA_ADMIN_TOKEN`.
Importing into a public registry needs founder approval and a live opt-out page.

## Endpoint health (ENG-011)

`POST /v1/{agents|services}/{id}/health-check` (owner) and `POST /v1/admin/jobs/health-checks?limit=` (cron) send one
SSRF-guarded GET to the endpoint (or Agent Card) with a 10 s deadline. Any answer below HTTP 500 is reachable; three
consecutive failures set `trust.reachability: "unreachable"`. That is a signal, not a revocation, and it never changes
other statuses. Search with `reachable_only=true` to hide unreachable listings. A probe also runs after successful
verification; the result is recorded but doesn't block the verification.

## Trust model (design principle 8)

Each level is reported separately in `trust` and never implies another:

1. `discovered` — publicly observed by ONAA, unclaimed (`operator_id: null`, `provenance` shows source).
2. `registered` — an operator account or a self-registered agent identity submitted it and accepted terms
   (`trust.registration_method` says which).
3. `endpoint_control_verified` — operator proved host control with a one-time token, either served at
   `https://<host>/.well-known/onaa-verification/<challenge_id>.txt` (`method: well_known`, default) or published as a
   DNS TXT record at `_onaa-challenge.<host>` (`POST .../verify-domain` with `{"method": "dns_txt"}`).
   Proofs expire after `ONAA_VERIFICATION_VALID_DAYS` (`trust.endpoint_verified_until`); a lapsed proof drops the
   badge, the host reservation and any certified status until the owner re-verifies. A sweep runs lazily every
   minute and on `POST /v1/admin/jobs/expire-verifications`.
   **Endpoint Verified is a paid tier; listing and search stay free.** `verify-domain` returns
   `402` unless the operator is in the Founding Cohort (agent listings only; granted by an admin via
   `POST /v1/admin/operators/{id}/founding-cohort`, seats capped and never silently reopened) or the listing has an
   approved `endpoint_verified` application (`POST /v1/certifications/applications`). The Registry has no billing:
   any fee is handled outside it and needs separate founder approval. An entitlement is not itself a trust signal.
4. `operator_identity_verified` — only via a reviewed `operator_verified` certification.
5. `certifications[]` — reviewed, time-limited (`expires_at`); applying (or paying) never certifies.

`legal_entity_verified` is always `false` in this MVP. `regulatory_claims` on services are self-declared and
displayed as claims, never as verified licences.

## Security notes

* Operator API keys: 256-bit random, only SHA-256 stored, shown once, rotatable. OIDC login is planned (REG-001).
* Challenge tokens: only SHA-256 stored; single use; superseded by newer challenges; expire; max 10 attempts.
* Outbound fetches (`netsafety.py`): https + port 443 only, no IP literals/userinfo, every resolved address must be
  public, connection pinned to the validated IP (DNS-rebinding defence) with TLS SNI on the real hostname,
  manual redirects re-validated (max 3), 5 s timeout, 64 KiB cap.
* Agent Card content is untrusted: only a SHA-256 and the observed `name` are cached; nothing is interpreted.
* Agent `endpoint_url`, service `agent_card_url` and `supported_interfaces[].url` must be on the verified host,
  so verification covers where buyers actually connect.
* Claims are provisional: a `claim_pending` listing can only run verification (no edit/delete), shows
  `claimed: false`, and can be re-claimed by someone else after the challenge TTL.
* Challenge fetches never follow redirects. Card fetches: total 10 s deadline, compressed bodies refused.
* Per-operator caps: listing quota and write budget per API key owner, independent of client IP. A new listing
  whose name matches another operator's verified listing gets `trust.review_flags: ["name_collision_review"]`.
* Anti-squatting is host-based: once an owner verifies a host, other operators' unverified listings on that host
  are suspended and nobody else can register on it.
* `certified_only` / ranking use active, unexpired certifications only. Operator identity verification is an
  operator attribute with its own expiry, never a listing certification.

## Known gaps (next tasks)

* OIDC operator login (ENG-009); periodic endpoint health checks (latency/uptime).
* Shared (multi-instance) rate-limit store; moderation UI for `review_flags` such as `name_collision_review`.
* Shared rate-limit store; abuse report moderation queue UI; admin audit export.
* Registry MCP server (DEV-003) and Python SDK (DEV-001) on top of this API.
