# ADR-001: Registry API stack and MVP auth

Date: 2026-11-12 · Status: Accepted for MVP (reversible) · Owner: registry-backend

## Context
Blueprint section 10 asks for FastAPI (Python) or TypeScript, managed PostgreSQL, and PostgreSQL FTS before any
dedicated search engine. P0 needs register/search/verify for agents and services with contract tests.

## Decision
* **Python 3.11+ / FastAPI 0.115 / Pydantic 2 / SQLAlchemy 2.0** in `apps/api/`.
* SQLite for local dev and tests; schema is portable to PostgreSQL. Multi-valued facets (role, capability,
  region, currency, protocol, language, category) live in a `listing_facets` table so filters are plain SQL on both.
* One `listings` table for agent / service / hosting, discriminated by `listing_type`.
* **MVP operator auth = random API keys (SHA-256 stored, shown once, rotatable).** OIDC (REG-001) is deferred; see
  the project's internal decision record.
* Domain-control proof = HTTPS well-known challenge first; DNS TXT next.
* `specs/openapi.json` is exported from the app and checked by a test to prevent drift.

## Consequences
* Alembic migrations are required before any shared staging DB (currently `create_all`).
* In-process rate limiting is single-instance only.
* Swapping to PostgreSQL FTS/trigram ranking is a later, contained change in `routes/listings.py::search`.
