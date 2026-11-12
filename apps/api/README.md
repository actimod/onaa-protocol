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
| `ONAA_TERMS_VERSION` | `draft-0.1` | Terms version operators must accept at signup. |
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
| GET | `/v1/health`, `/v1/specs`, `/.well-known/onaa-registry.json` | public |
| POST | `/v1/operators` | public (returns API key once) |
| GET/DELETE | `/v1/operators/me` ; POST `/v1/operators/me/keys/rotate` | operator |
| GET | `/v1/agents?q=&role=&capability=&region=&currency=&protocol=&language=&category=&verified_only=&certified_only=&claimed_only=&status=&limit=&offset=` | public |
| GET | `/v1/agents/{id}`, `/v1/agents/{id}/trust` | public |
| POST / PATCH / DELETE | `/v1/agents`, `/v1/agents/{id}` | operator (owner) |
| POST | `/v1/agents/{id}/claim` (discovered only), `/v1/agents/{id}/refresh-card` | operator |
| POST | `/v1/agents/{id}/verify-domain`, `/v1/agents/{id}/verification-complete` | operator (owner) |
| GET | `/v1/services?type=escrow&region=US&currency=USD...` and `/v1/services/{id}[/trust]` | public |
| POST / PATCH / DELETE | `/v1/services`, `/v1/services/{id}` (+ verify-domain, verification-complete) | operator (owner) |
| POST / GET | `/v1/certifications/applications`, `/v1/certifications/{id}` | operator |
| POST | `/v1/reports` | public or operator |
| POST | `/v1/admin/discovered`, `/v1/admin/listings/{id}/suspend`, `/v1/admin/certifications/{id}/decision` | admin token |

Multi-valued filters accept repeats or commas (`region=US,KR`). A listing with region `GLOBAL` matches any region filter.

## Endpoint health (ENG-011)

`POST /v1/{agents|services}/{id}/health-check` (owner) and `POST /v1/admin/jobs/health-checks?limit=` (cron) send one
SSRF-guarded GET to the endpoint (or Agent Card) with a 10 s deadline. Any answer below HTTP 500 is reachable; three
consecutive failures set `trust.reachability: "unreachable"`. That is a signal, not a revocation, and it never changes
other statuses. Search with `reachable_only=true` to hide unreachable listings. A probe also runs after successful
verification; the result is recorded but doesn't block the verification.

## Trust model (design principle 8)

Each level is reported separately in `trust` and never implies another:

1. `discovered` — publicly observed by ONAA, unclaimed (`operator_id: null`, `provenance` shows source).
2. `registered` — an operator account submitted it and accepted terms.
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
