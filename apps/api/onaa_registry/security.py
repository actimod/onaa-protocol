from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_session
from .models import ApiKey, Operator

KEY_PREFIX = "onaa_sk_"
_bearer = HTTPBearer(auto_error=False)


def sha256_hex(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def issue_api_key() -> tuple[str, str, str]:
    """Return (plaintext, sha256, display prefix). Plaintext is shown once and never stored."""
    plaintext = KEY_PREFIX + secrets.token_urlsafe(32)
    return plaintext, sha256_hex(plaintext), plaintext[: len(KEY_PREFIX) + 4]


def current_operator(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_session),
) -> Operator:
    if creds is None or not creds.credentials.startswith(KEY_PREFIX):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "operator API key required",
                            headers={"WWW-Authenticate": "Bearer"})
    key = session.scalar(select(ApiKey).where(ApiKey.key_hash == sha256_hex(creds.credentials)))
    if key is None or key.revoked_at is not None or key.operator.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or revoked API key",
                            headers={"WWW-Authenticate": "Bearer"})
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        # Per-operator write budget, independent of client IP (Sybil / shared-proxy resistance).
        request.app.state.operator_limiter.check(f"op:{key.operator_id}")
    return key.operator


def optional_operator(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_session),
) -> Operator | None:
    if creds is None:
        return None
    return current_operator(request, creds, session)


def require_admin(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    expected = request.app.state.settings.admin_token
    if not expected:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "admin API disabled")
    if creds is None or not hmac.compare_digest(creds.credentials.encode(), expected.encode()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin token required")
    return "admin"


class RateLimiter:
    """In-process sliding-window limiter for write endpoints (MVP; replace with shared store at scale)."""

    def __init__(self, per_minute: int, window_seconds: int = 60):
        self.per_minute = per_minute  # max hits per window (the window is 60 s unless overridden)
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        if self.per_minute <= 0:
            return
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.per_minute:
                raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded",
                                    headers={"Retry-After": str(self.window)})
            q.append(now)
            if len(self._hits) > 10_000:  # bound memory: drop idle clients
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
                    del self._hits[k]


def client_ip(request: Request) -> str:
    """Socket peer, or the address added by the Nth trusted proxy when ONAA_TRUSTED_PROXY_HOPS > 0."""
    peer = request.client.host if request.client else "unknown"
    hops = request.app.state.settings.trusted_proxy_hops
    if hops <= 0:
        return peer
    chain = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    # The last `hops` entries were appended by our own proxies; the one before them is the client.
    return chain[-hops] if len(chain) >= hops else peer


def write_limit(request: Request) -> None:
    request.app.state.rate_limiter.check(client_ip(request))
