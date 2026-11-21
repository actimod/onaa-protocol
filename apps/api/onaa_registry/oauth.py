"""OAuth 2.1 sign-in for the pilot MCP connector (the standard MCP remote-server authorization).

One public connector URL for everyone, ``<base>/pilot/mcp``, with nothing secret in it. An MCP host (ChatGPT,
Claude, Claude Code...) that gets 401 from it reads the protected-resource metadata (RFC 9728), finds this
authorization server (RFC 8414), registers itself (RFC 7591) and runs the authorization-code flow with PKCE (S256).
The person signs in on our page with their email and a one-time code we email them; a first sign-in also picks a
nickname and creates the member (and their Agent Card). The email is only a sign-in key: we keep an HMAC of it,
never the address, and it is not an identity check.

Tokens: access tokens (``onaa_at_...``, 1 hour) go in the Authorization header; refresh tokens (``onaa_rt_...``,
180 days) rotate on every use, and reusing an old one revokes that whole sign-in. Only SHA-256 hashes of codes and
tokens are stored. "Sign out everywhere" revokes every token of the member (and the old personal token URL).

Public, no sign-in: the directory, Agent Cards and the A2A door that outside agents write to.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import smtplib
import threading
import time
from email.message import EmailMessage
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import anyio
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import hosting, member_terms
from .db import get_session
from .logic import audit
from .models import PilotMember, PilotOAuthClient, PilotOAuthLogin, PilotOAuthToken
from .models import utcnow as now
from .security import RateLimiter, client_ip, sha256_hex

log = logging.getLogger("onaa.oauth")

SCOPE = "pilot"
RESOURCE_PATH = "/pilot/mcp"
RESOURCE_PATHS = (RESOURCE_PATH, "/mcp")  # /mcp needs sign-in when ONAA_MCP_LOGIN=1; both names reach one server
ACCESS_PREFIX, REFRESH_PREFIX = "onaa_at_", "onaa_rt_"
LOGIN_TTL = dt.timedelta(minutes=15)
CODE_TTL = dt.timedelta(minutes=5)
MAX_OTP_ATTEMPTS = 5
MAX_WRONG_CODES_PER_DAY = 10  # per email, across sign-ins (each new code resets MAX_OTP_ATTEMPTS)
MIN_SECRET_LEN = 32
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$")
_LOOPBACK = ("localhost", "127.0.0.1", "[::1]", "::1")


def enabled(settings) -> bool:
    secret = settings.oauth_secret
    return bool(settings.pilot_enabled and secret and len(secret) >= MIN_SECRET_LEN)


def _on(request: Request) -> None:
    if not enabled(request.app.state.settings):
        raise HTTPException(404, "Not Found")


def _base(settings) -> str:
    return settings.public_base_url.rstrip("/")


def resource_url(settings, path: str = RESOURCE_PATH) -> str:
    return _base(settings) + path


def resource_metadata_url(settings, path: str = RESOURCE_PATH) -> str:
    return _base(settings) + "/.well-known/oauth-protected-resource" + path


def _resource_ok(settings, resource: str | None) -> bool:
    return not resource or resource.rstrip("/") in {resource_url(settings, p) for p in RESOURCE_PATHS}


def _aware(t: dt.datetime | None) -> dt.datetime | None:
    return t if t is None or t.tzinfo else t.replace(tzinfo=dt.UTC)


def email_hash(settings, email: str) -> str:
    return hmac.new(settings.oauth_secret.encode(), b"email:" + email.strip().lower().encode(),
                    hashlib.sha256).hexdigest()


def _limiter(request: Request, name: str, per_window: int, window: int) -> RateLimiter:
    state = request.app.state
    attr = f"oauth_{name}_limiter"
    lim = getattr(state, attr, None)
    if lim is None:
        lim = RateLimiter(per_window, window_seconds=window)
        setattr(state, attr, lim)
    return lim


# A sign-in is bound to the browser that opened /oauth/authorize: that response sets this cookie, and every later
# step (email, code, Google start/callback, nickname) requires it. Without it, anyone could open a sign-in for their
# own app and send someone the "Continue with Google" link, skipping the page that names the app (review 2026-11-19).
LOGIN_COOKIE = "onaa_signin"


def _login_binding(settings, login_id: str) -> str:
    return hmac.new((settings.oauth_secret or "").encode(), ("browser:" + login_id).encode(),
                    hashlib.sha256).hexdigest()


def _bind_browser(response, settings, login: PilotOAuthLogin):
    response.set_cookie(LOGIN_COOKIE, _login_binding(settings, login.id), max_age=int(LOGIN_TTL.total_seconds()),
                        path="/oauth", httponly=True, samesite="lax",
                        secure=str(settings.public_base_url or "").startswith("https://"))
    return response


def _browser_ok(request: Request, settings, login: PilotOAuthLogin) -> bool:
    if login.scope == VERIFY_SCOPE:  # the Google check link proves nothing alone; the email must match the member
        return True
    return hmac.compare_digest(request.cookies.get(LOGIN_COOKIE, ""), _login_binding(settings, login.id))


WRONG_SIGNIN = ("This sign-in was started in another browser or has expired. Go back to your app and connect again "
                "from this browser.")


# --------------------------------------------------------------------------- tokens

def member_for_bearer(session: Session, token: str | None) -> PilotMember | None:
    """The active member behind a bearer: an OAuth access token, or a personal token URL's token (pilot_...)."""
    if not token:
        return None
    if token.startswith(ACCESS_PREFIX):
        row = session.scalar(select(PilotOAuthToken).where(PilotOAuthToken.token_hash == sha256_hex(token),
                                                           PilotOAuthToken.kind == "access"))
        if row is None or row.revoked_at is not None or _aware(row.expires_at) <= now():
            return None
        m = session.get(PilotMember, row.member_id)
    elif token.startswith("pilot_"):
        m = session.scalar(select(PilotMember).where(PilotMember.token_hash == sha256_hex(token)))
    else:
        return None
    return m if m is not None and m.status == "active" else None


def _issue(session: Session, settings, member_id: str, client_id: str, family: str) -> dict[str, Any]:
    access, refresh = ACCESS_PREFIX + secrets.token_urlsafe(32), REFRESH_PREFIX + secrets.token_urlsafe(32)
    t = now()
    session.add(PilotOAuthToken(token_hash=sha256_hex(access), kind="access", member_id=member_id,
                                client_id=client_id, family=family, scope=SCOPE,
                                expires_at=t + dt.timedelta(seconds=settings.oauth_access_ttl_seconds)))
    session.add(PilotOAuthToken(token_hash=sha256_hex(refresh), kind="refresh", member_id=member_id,
                                client_id=client_id, family=family, scope=SCOPE,
                                expires_at=t + dt.timedelta(days=settings.oauth_refresh_ttl_days)))
    return {"access_token": access, "token_type": "Bearer", "expires_in": settings.oauth_access_ttl_seconds,
            "refresh_token": refresh, "scope": SCOPE}


def _revoke_family(session: Session, family: str) -> None:
    session.execute(update(PilotOAuthToken).where(PilotOAuthToken.family == family,
                                                  PilotOAuthToken.revoked_at.is_(None)).values(revoked_at=now()))


def sign_out_everywhere(session: Session, member: PilotMember) -> int:
    """Revoke every OAuth token of the member and retire the personal token URL. Returns tokens revoked."""
    n = session.execute(update(PilotOAuthToken).where(PilotOAuthToken.member_id == member.id,
                                                      PilotOAuthToken.revoked_at.is_(None))
                        .values(revoked_at=now())).rowcount or 0
    member.token_hash = sha256_hex("retired:" + secrets.token_urlsafe(32))
    # an authorization code handed out in the last few minutes must not turn into new tokens afterwards
    session.execute(update(PilotOAuthLogin).where(PilotOAuthLogin.member_id == member.id,
                                                  PilotOAuthLogin.status == "authorized").values(status="used"))
    audit(session, "pilot", None, "pilot.signed_out_everywhere", member.id, tokens=n)
    return n


# --------------------------------------------------------------------------- email

CODE_SUBJECT = "Your ONAA sign-in code: {code}"
CODE_BODY = ("Your ONAA sign-in code is {code}\n\nIt works for 15 minutes, once. If you did not try to sign in, "
             "ignore this email.\n\nONAA uses this address only to sign you in.")


class ZohoMailer:
    """Zoho Mail REST API sender (the free Zoho Mail plan has no SMTP). Keeps the short-lived access token and the
    account id in memory; never logs either."""

    def __init__(self, settings, http: httpx.Client | None = None):
        self.s, self.http = settings, http or httpx.Client(timeout=20)
        self._token: str | None = None
        self._token_until = 0.0
        self._account: str | None = None
        self._lock = threading.Lock()

    def _auth(self) -> dict[str, str]:
        with self._lock:
            if self._token is None or time.monotonic() > self._token_until:
                r = self.http.post(self.s.zoho_accounts_host.rstrip("/") + "/oauth/v2/token", data={
                    "refresh_token": self.s.zoho_refresh_token, "client_id": self.s.zoho_client_id,
                    "client_secret": self.s.zoho_client_secret, "grant_type": "refresh_token"})
                tok = r.json() if r.content else {}
                if "access_token" not in tok:
                    raise RuntimeError(f"zoho token refresh failed: {str(tok.get('error'))[:60]}")
                self._token = tok["access_token"]
                self._token_until = time.monotonic() + max(60, int(tok.get("expires_in", 3600)) - 300)
            return {"Authorization": "Zoho-oauthtoken " + self._token}

    def _account_id(self) -> str:
        if self._account is None:
            r = self.http.get(self.s.zoho_mail_api.rstrip("/") + "/api/accounts", headers=self._auth())
            want = (self.s.mail_from or "").split("<")[-1].strip(" >").lower()
            accounts = (r.json() or {}).get("data") or []
            match = [a for a in accounts if str(a.get("primaryEmailAddress", "")).lower() == want]
            if not match:
                raise RuntimeError("ONAA_MAIL_FROM is not a mailbox of this Zoho account")
            self._account = str(match[0]["accountId"])
        return self._account

    def send(self, to: str, subject: str, text: str) -> None:
        r = self.http.post(f"{self.s.zoho_mail_api.rstrip('/')}/api/accounts/{self._account_id()}/messages",
                           headers=self._auth(), json={"fromAddress": self.s.mail_from, "toAddress": to,
                                                       "subject": subject, "content": text, "mailFormat": "plaintext"})
        status = ((r.json() if r.content else {}) or {}).get("status") or {}
        if r.status_code != 200 or status.get("code") != 200:
            raise RuntimeError(f"zoho send failed: {r.status_code} {str(status.get('description'))[:80]}")


_zoho: dict[int, ZohoMailer] = {}


def send_code(settings, email: str, code: str) -> None:
    backend = settings.mail_backend
    if backend == "dev-log":  # local development only: the code ends up in the server log
        log.warning("DEV sign-in code for %s: %s", email, code)
        return
    subject, text = CODE_SUBJECT.format(code=code), CODE_BODY.format(code=code)
    if backend == "zoho":
        if not (settings.zoho_client_id and settings.zoho_client_secret and settings.zoho_refresh_token
                and settings.mail_from):
            raise RuntimeError("zoho mail is not configured")
        mailer = _zoho.get(id(settings))
        if mailer is None:
            mailer = _zoho[id(settings)] = ZohoMailer(settings)
        mailer.send(email, subject, text)
        return
    if backend != "smtp" or not (settings.smtp_host and settings.mail_from):
        raise RuntimeError("sign-in email is not configured")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = settings.mail_from, email, subject
    msg.set_content(text)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password or "")
        smtp.send_message(msg)


# --------------------------------------------------------------------------- pages

_CSS = ("body{font-family:system-ui,-apple-system,sans-serif;background:#f6f7f9;color:#1b1f24;margin:0}"
        "main{max-width:420px;margin:48px auto;background:#fff;border:1px solid #e3e6ea;border-radius:12px;"
        "padding:28px}h1{font-size:20px;margin:0 0 6px}p{line-height:1.5;color:#4a525c;font-size:14px}"
        "label{display:block;font-size:13px;margin:14px 0 4px;color:#1b1f24}input{width:100%;box-sizing:border-box;"
        "padding:10px;border:1px solid #c9ced4;border-radius:8px;font-size:15px}button{margin-top:18px;width:100%;"
        "padding:11px;border:0;border-radius:8px;background:#1f5eff;color:#fff;font-size:15px;cursor:pointer}"
        ".err{color:#b42318}.small{font-size:12px;color:#6b737d}")


def _origin(url: str) -> str:
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}" if u.scheme in ("http", "https") and u.netloc else ""


def _page(title: str, body: str, status: int = 200, also_form_to: str = "") -> HTMLResponse:
    # form-action also limits where a form's response may redirect, so the code step must allow the app's
    # return address (browsers otherwise stop the final redirect and the sign-in appears to hang)
    form_to = " " + _origin(also_form_to) if _origin(also_form_to) else ""
    doc = (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
           f"content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title><style>{_CSS}</style>"
           f"</head><body><main>{body}</main></body></html>")
    return HTMLResponse(doc, status_code=status, headers={
        "Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": f"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'{form_to}; "
                                   "frame-ancestors 'none'"})


def google_enabled(settings) -> bool:
    return bool(getattr(settings, "google_client_id", None) and getattr(settings, "google_client_secret", None))


# Shown next to every button that finishes a sign-in; _finish records the acceptance as "oauth_signin", so the
# person agrees on this page themselves (decision 2026-11-20, for the ChatGPT / Claude directory reviews).
TERMS_NOTICE = ("<p class=small>By continuing, you agree to ONAA's <a href='" + member_terms.PATH + "' "
                "target=_blank rel=noopener>Member Terms and Privacy Notice</a>.</p>")


def _google_button(login: PilotOAuthLogin, google: bool) -> str:
    if not google:
        return ""
    return ("<p><a href='/oauth/google/start?login_id=" + html.escape(login.id) + "' style='display:block;"
            "text-align:center;padding:11px;border:1px solid #c9ced4;border-radius:8px;color:#1b1f24;"
            "text-decoration:none;font-size:15px'>Continue with Google</a></p>"
            "<p class=small style='text-align:center'>or get a code by email</p>")


def _email_form(login: PilotOAuthLogin, client: PilotOAuthClient, error: str = "",
                google: bool = False) -> HTMLResponse:
    e = f"<p class=err>{html.escape(error)}</p>" if error else ""
    return _page("Sign in to ONAA", (
        "<h1>Sign in to ONAA</h1>" +
        (f"<p>The app at <b>{html.escape(client.name)}</b> wants to use your ONAA inbox and messages (ONAA checked "
         "that this request comes from that website's published app identity).</p>" if client.id.startswith(CIMD_PREFIX)
         else f"<p>An app that calls itself <b>{html.escape(client.name)}</b> wants to use your ONAA inbox and "
              "messages.</p>") +
        f"<p class=small>After you sign in, ONAA sends you back to <b>{html.escape(_host_of(login.redirect_uri))}</b>. "
        "Continue only if you started this from your own AI app.</p>" + e +
        _google_button(login, google) +
        "<form method=post action='/oauth/authorize/email'>"
        f"<input type=hidden name=login_id value='{html.escape(login.id)}'>"
        "<label for=email>Email</label><input id=email name=email type=email required autocomplete=email>"
        "<label for=nickname>Nickname (first time only)</label>"
        "<input id=nickname name=nickname maxlength=40 autocomplete=nickname>"
        "<button type=submit>Email me a code</button></form>" + TERMS_NOTICE +
        "<p class=small>We use your email only to sign you in. We keep a fingerprint of it, not the address, and "
        "never show it to anyone.</p>"))


def _host_of(uri: str) -> str:
    try:
        return urlsplit(uri).hostname or uri
    except ValueError:
        return uri


def _code_form(login: PilotOAuthLogin, error: str = "") -> HTMLResponse:
    e = f"<p class=err>{html.escape(error)}</p>" if error else ""
    return _page("Enter your code", (
        "<h1>Check your email</h1><p>If this email can sign in to ONAA, we sent it a 6-digit code. Enter it "
        "here, in this window.</p>" + e +
        "<form method=post action='/oauth/authorize/code'>"
        f"<input type=hidden name=login_id value='{html.escape(login.id)}'>"
        "<label for=code>Code</label><input id=code name=code inputmode=numeric pattern='[0-9]{6}' maxlength=6 "
        "required autocomplete=one-time-code><button type=submit>Sign in</button></form>"),
        also_form_to=login.redirect_uri)


def _error_page(msg: str, status: int = 400) -> HTMLResponse:
    return _page("Sign-in problem", f"<h1>Sign-in problem</h1><p class=err>{html.escape(msg)}</p>", status)


async def _form(request: Request) -> dict[str, str]:
    body = (await request.body())[:16384].decode("utf-8", "replace")
    return {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}


# --------------------------------------------------------------------------- routes

router = APIRouter(include_in_schema=False, dependencies=[Depends(_on)])


def _resource_metadata(request: Request, path: str) -> JSONResponse:
    s = request.app.state.settings
    return JSONResponse({"resource": resource_url(s, path), "authorization_servers": [_base(s)],
                         "scopes_supported": [SCOPE], "bearer_methods_supported": ["header"],
                         "resource_name": "ONAA: agent search, your inbox and messages"})


@router.get("/.well-known/oauth-protected-resource" + RESOURCE_PATH)
def protected_resource(request: Request):
    return _resource_metadata(request, RESOURCE_PATH)


@router.get("/.well-known/oauth-protected-resource/mcp")
def protected_resource_mcp(request: Request):
    return _resource_metadata(request, "/mcp")


@router.get("/.well-known/oauth-protected-resource")
def protected_resource_root(request: Request):
    return _resource_metadata(request, "/mcp" if getattr(request.app.state.settings, "mcp_login", False)
                              else RESOURCE_PATH)


@router.get("/.well-known/oauth-authorization-server")
def authorization_server(request: Request):
    b = _base(request.app.state.settings)
    return {"issuer": b, "authorization_endpoint": b + "/oauth/authorize", "token_endpoint": b + "/oauth/token",
            "registration_endpoint": b + "/oauth/register", "revocation_endpoint": b + "/oauth/revoke",
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"], "scopes_supported": [SCOPE],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "revocation_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "authorization_response_iss_parameter_supported": True,
            "client_id_metadata_document_supported": True}


def _redirect_ok(uri: Any) -> bool:
    if not isinstance(uri, str) or len(uri) > 2048 or "#" in uri:
        return False
    try:
        p = urlsplit(uri)
        host = (p.hostname or "").lower()
    except ValueError:
        return False
    if p.scheme == "https" and host:
        return True
    return p.scheme == "http" and host in _LOOPBACK


def _oauth_error(error: str, desc: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": desc}, status_code=status,
                        headers={"Cache-Control": "no-store"})


# Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document): the client_id is an https URL the app
# publishes (Claude does this). We fetch it at /authorize through the SSRF-safe fetcher (public IPs only, pinned, no
# redirects, size-capped), check it names itself, and keep a row keyed by a hash of the URL. The consent page names
# the URL's host, never the self-asserted client_name.
CIMD_PREFIX = "cm_"
CIMD_REFRESH = dt.timedelta(hours=1)
CIMD_MAX_URL = 512


def cimd_id(url: str) -> str:
    return CIMD_PREFIX + sha256_hex(url)[:40]


def _is_cimd_url(client_id: str) -> bool:
    if not client_id.startswith("https://") or len(client_id) > CIMD_MAX_URL:
        return False
    p = urlsplit(client_id)
    return bool(p.hostname) and p.path not in ("", "/") and not p.fragment and not p.username and not p.port


# Copies of the published client metadata of the big MCP hosts (fetched 2026-11-19), used only when their site
# answers our fetch with an error (their bot shields can block server IPs) and we hold no earlier copy. The live
# document always wins when we can read it.
KNOWN_CIMD: dict[str, dict[str, Any]] = {
    "https://claude.ai/oauth/mcp-oauth-client-metadata": {
        "client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata",
        "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"], "token_endpoint_auth_method": "none"},
    "https://chatgpt.com/oauth/client.json": {
        "client_id": "https://chatgpt.com/oauth/client.json",
        "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"]},
}


def _public_client_ok(doc: dict) -> bool:
    """The client can use token_endpoint_auth_method "none" (PKCE). ChatGPT's document names private_key_jwt as its
    preference but lists "none" in token_endpoint_auth_methods_supported, and then uses the method both sides
    support, so the plural list decides when it is there."""
    methods = doc.get("token_endpoint_auth_methods_supported")
    if isinstance(methods, list):
        return "none" in methods
    return (doc.get("token_endpoint_auth_method") or "none") == "none"


def _fetch_cimd(request: Request, session: Session, url: str) -> PilotOAuthClient | None:
    cid = cimd_id(url)
    client = session.get(PilotOAuthClient, cid)
    if client is not None and now() - _aware(client.created_at) < CIMD_REFRESH:
        return client
    from .netsafety import FetchError, UnsafeURLError

    try:
        res = request.app.state.fetcher.fetch(url, allow_redirects=False)
        if res.status_code != 200 or len(res.body) > 16384:
            raise FetchError(f"http_{res.status_code}")
        doc = json.loads(res.body)
    except (FetchError, UnsafeURLError, ValueError) as exc:
        log.warning("client metadata document fetch failed for %s: %s %s", urlsplit(url).hostname,
                    type(exc).__name__, getattr(exc, "category", ""))
        if client is not None:
            return client  # keep a known client working through a transient failure
        doc = KNOWN_CIMD.get(url)  # a well-known app whose site turned our fetch away (bot shield)
        if doc is None:
            return None
    if not isinstance(doc, dict) or doc.get("client_id") != url:
        log.warning("client metadata document from %s does not name itself", urlsplit(url).hostname)
        return None
    uris = doc.get("redirect_uris")
    if not isinstance(uris, list) or not 1 <= len(uris) <= 20 or not all(_redirect_ok(u) for u in uris):
        return None
    if not _public_client_ok(doc):
        return None  # we only take public (PKCE) clients this way
    host = urlsplit(url).hostname or "unknown"
    if client is None:
        client = PilotOAuthClient(id=cid, name=host[:100], redirect_uris=uris)
        session.add(client)
    else:
        client.name, client.redirect_uris, client.created_at = host[:100], uris, now()
    session.flush()
    return client


def _redirect_allowed(uri: str | None, allowed: list) -> bool:
    """Exact match, except loopback redirect URIs match with any port (RFC 8252 7.3; native apps like Claude Code)."""
    if not uri:
        return False
    if uri in allowed:
        return True
    try:
        p = urlsplit(uri)
        if p.scheme != "http" or (p.hostname or "").lower() not in ("localhost", "127.0.0.1", "::1"):
            return False
        for a in allowed:
            q = urlsplit(a)
            if (q.scheme, (q.hostname or "").lower(), q.path, q.query) == (
                    p.scheme, (p.hostname or "").lower(), p.path, p.query):
                return True
    except ValueError:
        return False
    return False


@router.post("/oauth/register", status_code=201)
async def register(request: Request, session: Session = Depends(get_session)):
    """RFC 7591 dynamic client registration (open, as MCP hosts expect)."""
    _limiter(request, "register", 20, 3600).check("reg:" + client_ip(request))
    try:
        body = await request.json()
    except ValueError:
        return _oauth_error("invalid_client_metadata", "body must be JSON")
    if not isinstance(body, dict):
        return _oauth_error("invalid_client_metadata", "body must be a JSON object")
    uris = body.get("redirect_uris")
    if not isinstance(uris, list) or not 1 <= len(uris) <= 10 or not all(_redirect_ok(u) for u in uris):
        return _oauth_error("invalid_redirect_uri", "redirect_uris: 1-10 https URLs (http only for localhost)")
    method = body.get("token_endpoint_auth_method") or "none"
    if method not in ("none", "client_secret_post", "client_secret_basic"):
        return _oauth_error("invalid_client_metadata", "unsupported token_endpoint_auth_method")
    grants = body.get("grant_types") or ["authorization_code", "refresh_token"]
    if not isinstance(grants, list) or not set(grants) <= {"authorization_code", "refresh_token"}:
        return _oauth_error("invalid_client_metadata", "grant_types: authorization_code, refresh_token")
    name = str(body.get("client_name") or "MCP client")
    name = "".join(ch for ch in name if ch >= " ")[:100] or "MCP client"
    client = PilotOAuthClient(id="oc_" + secrets.token_urlsafe(24), name=name, redirect_uris=uris)
    out: dict[str, Any] = {"client_id": client.id, "client_name": name, "redirect_uris": uris,
                           "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                           "token_endpoint_auth_method": method,
                           "client_id_issued_at": int(now().timestamp())}
    if method != "none":
        secret = secrets.token_urlsafe(32)
        client.secret_hash = sha256_hex(secret)
        out["client_secret"], out["client_secret_expires_at"] = secret, 0
    session.add(client)
    return JSONResponse(out, status_code=201, headers={"Cache-Control": "no-store"})


@router.get("/oauth/authorize")
def authorize(request: Request, session: Session = Depends(get_session)):
    q = request.query_params
    settings = request.app.state.settings
    raw_id = q.get("client_id") or ""
    if _is_cimd_url(raw_id):
        _limiter(request, "cimd", 30, 60).check("cimd:" + client_ip(request))
        client = _fetch_cimd(request, session, raw_id)
    else:
        client = session.get(PilotOAuthClient, raw_id)
    redirect_uri = q.get("redirect_uri") or (client.redirect_uris[0] if client and len(client.redirect_uris) == 1
                                             else None)
    if client is None or not _redirect_allowed(redirect_uri, client.redirect_uris):
        return _error_page("This app is not registered with ONAA, or its return address does not match.")
    state = q.get("state")

    def back(error: str, desc: str) -> RedirectResponse:
        params = {"error": error, "error_description": desc, "iss": _base(settings)}
        if state:
            params["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(redirect_uri + sep + urlencode(params), status_code=302)

    if q.get("response_type") != "code":
        return back("unsupported_response_type", "response_type must be code")
    challenge = q.get("code_challenge") or ""
    if q.get("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", challenge):
        return back("invalid_request", "PKCE with code_challenge_method=S256 is required")
    resource = q.get("resource")
    if not _resource_ok(settings, resource):
        return back("invalid_target", "unknown resource")
    scopes = set((q.get("scope") or SCOPE).split())
    if SCOPE not in scopes and scopes - {"openid", "profile", "email", "offline_access"}:
        return back("invalid_scope", f"scope must be {SCOPE}")
    login = PilotOAuthLogin(id="ol_" + secrets.token_urlsafe(24), client_id=client.id, redirect_uri=redirect_uri,
                            state=(state or None) and state[:512], code_challenge=challenge, scope=SCOPE,
                            expires_at=now() + LOGIN_TTL)
    session.add(login)
    return _bind_browser(_email_form(login, client, google=google_enabled(settings)), settings, login)


def _open_login(session: Session, login_id: str, want: tuple[str, ...],
                allow_verify: bool = False) -> PilotOAuthLogin | None:
    login = session.get(PilotOAuthLogin, login_id or "")
    if login is None or login.status not in want or _aware(login.expires_at) <= now():
        return None
    if login.scope == VERIFY_SCOPE and not allow_verify:  # a Google check link never becomes an app sign-in
        return None
    return login


# --------------------------------------------------------------------------- Google check for a signed-in member
# Operators of server agents must have signed in with Google. A member who connected with an emailed code gets a
# one-time link instead of having to disconnect and reconnect the connector: signing in with Google there, with
# the same email, marks the member Google-verified. The link proves nothing by itself; only a Google account
# whose email matches the member's does.

VERIFY_SCOPE = "google_verify"
VERIFY_CLIENT = "onaa-google-verify"
VERIFY_TTL = dt.timedelta(minutes=15)


def google_verify_link(session: Session, settings, member: PilotMember) -> str | None:
    """A one-time link (15 minutes) that confirms this member with Google, or None when Google is off."""
    if not google_enabled(settings):
        return None
    login = PilotOAuthLogin(id="ol_" + secrets.token_urlsafe(24), client_id=VERIFY_CLIENT, redirect_uri="",
                            code_challenge="", scope=VERIFY_SCOPE, member_id=member.id,
                            expires_at=now() + VERIFY_TTL)
    session.add(login)
    return _base(settings) + "/oauth/google/start?login_id=" + login.id


def _finish_verify(session: Session, login: PilotOAuthLogin) -> HTMLResponse:
    member = session.get(PilotMember, login.member_id or "")
    login.status = "used"
    if member is None or member.status != "active":
        session.commit()
        return _error_page("This account is disabled.", 403)
    if not login.email_hash or not hmac.compare_digest(login.email_hash, member.email_hash or ""):
        session.commit()
        return _error_page("That Google account uses a different email from your ONAA sign-in. Ask your AI app "
                           "for a new link and choose the Google account with the same email.", 403)
    member.google_verified_at = now()
    audit(session, "pilot", None, "pilot.google_verified", member.id, via="verify_link")
    session.commit()
    return _page("Google sign-in confirmed", "<h1>Google sign-in confirmed</h1><p>Go back to your AI app and ask it "
                 "to try again. Your connector stays as it is.</p>")


@router.post("/oauth/authorize/email")
async def authorize_email(request: Request, session: Session = Depends(get_session)):
    f = await _form(request)
    settings = request.app.state.settings
    g = google_enabled(settings)
    login = _open_login(session, f.get("login_id", ""), ("started", "code_sent"))
    if login is None:
        return _error_page("This sign-in expired. Go back to your app and connect again.")
    if not _browser_ok(request, settings, login):
        return _error_page(WRONG_SIGNIN, 403)
    client = session.get(PilotOAuthClient, login.client_id)
    email = (f.get("email") or "").strip()
    if not _EMAIL_RE.match(email):
        return _email_form(login, client, "Enter a valid email address.", google=g)
    eh = email_hash(settings, email)
    # Decision 2026-11-19 (review): one address cannot use up everyone's mail allowance (per address, under a
    # quarter of the hourly total), the total is charged only for mail actually sent, and the answer is the same
    # whether or not the email has an account (no "no account yet" or "first time here" tells).
    try:
        _limiter(request, "send_ip", max(1, settings.mail_per_hour // 4), 3600).check("ip:" + client_ip(request))
    except HTTPException:
        return _email_form(login, client, "Too many sign-ins from here. Try again later.", google=g)
    try:
        _limiter(request, "send_email", 3, 600).check("em:" + eh)
    except HTTPException:
        return _email_form(login, client, "Too many codes for this address. Wait 10 minutes and try again.", google=g)
    member = session.scalar(select(PilotMember).where(PilotMember.email_hash == eh))
    nickname = "".join(ch for ch in (f.get("nickname") or "") if ch >= " ").strip()[:40] or None
    if member is None and not settings.pilot_open_signup:  # invite-only: no mail, the same answer
        login.email_hash, login.nickname, login.status = eh, nickname, "code_sent"
        login.otp_hash, login.otp_attempts = sha256_hex(login.id + ":" + secrets.token_urlsafe(16)), 0
        return _code_form(login)
    try:  # stay inside the mail provider's hourly allowance (Zoho Mail: 50-500 external mails an hour)
        _limiter(request, "send_all", settings.mail_per_hour, 3600).check("all")
    except HTTPException:
        return _email_form(login, client, "Too many sign-ins right now. Try again in a few minutes.", google=g)
    code = f"{secrets.randbelow(10**6):06d}"
    login.email_hash, login.nickname = eh, nickname
    login.otp_hash, login.otp_attempts, login.status = sha256_hex(login.id + ":" + code), 0, "code_sent"
    try:
        # off the event loop: a slow mail provider (up to 20 s) must not stall every other request
        await anyio.to_thread.run_sync(send_code, settings, email, code)
    except Exception as exc:  # noqa: BLE001 - never show mail server details
        log.error("sign-in email failed (%s)", type(exc).__name__)  # the text can carry the address
        session.rollback()
        return _email_form(login, client, "We could not send the email right now. Try again in a minute.", google=g)
    return _code_form(login)


def _new_member(session: Session, settings, nickname: str, eh: str) -> PilotMember:
    m = PilotMember(nickname=nickname, contact="", token_hash=sha256_hex("oauth-only:" + secrets.token_urlsafe(32)),
                    a2a_enabled=True, email_hash=eh,
                    check_every_minutes=settings.pilot_default_check_minutes or None)
    session.add(m)
    session.flush()
    if hosting.enabled(settings):
        hosting.sync_listing(session, settings, m)  # Agent Card listed in the directory at once
    audit(session, "pilot", None, "pilot.member_joined", m.id, via="oauth")
    return m


@router.post("/oauth/authorize/code")
async def authorize_code(request: Request, session: Session = Depends(get_session)):
    f = await _form(request)
    settings = request.app.state.settings
    login = _open_login(session, f.get("login_id", ""), ("code_sent",))
    if login is None:
        return _error_page("This sign-in expired. Go back to your app and connect again.")
    if not _browser_ok(request, settings, login):
        return _error_page(WRONG_SIGNIN, 403)
    code = (f.get("code") or "").strip()
    if login.otp_attempts >= MAX_OTP_ATTEMPTS:
        return _error_page("Too many wrong codes. Go back to your app and connect again.")
    wrong = _limiter(request, "otp_wrong_email", MAX_WRONG_CODES_PER_DAY, 86400)
    if wrong.remaining("em:" + (login.email_hash or "")) <= 0:  # spans sign-ins: new codes do not reset it
        return _error_page("Too many wrong codes for this address today. Try again tomorrow, or use Google.")
    if not hmac.compare_digest(sha256_hex(login.id + ":" + code), login.otp_hash or ""):
        try:
            wrong.check("em:" + (login.email_hash or ""))
        except HTTPException:
            pass
        login.otp_attempts += 1
        session.commit()
        return _code_form(login, "That code is not right. Check the newest email.")
    if not login.nickname and session.scalar(select(PilotMember.id).where(
            PilotMember.email_hash == login.email_hash)) is None:
        login.status, login.otp_hash = "code_ok", None  # new member: the nickname comes after the code
        session.commit()
        return _nickname_form(login)
    return _finish(session, settings, login, login.nickname)


def _finish(session: Session, settings, login: PilotOAuthLogin, nickname: str | None):
    """The person is who they say (code or Google): find or create the member, send the app its code."""
    member = session.scalar(select(PilotMember).where(PilotMember.email_hash == login.email_hash))
    if member is None:
        member = _new_member(session, settings, nickname or "member", login.email_hash)
    elif member.status != "active":
        return _error_page("This account is disabled.", 403)
    if login.status == "google_ok":  # an operator of server agents must have signed in with Google
        member.google_verified_at = now()
    if not member_terms.accepted(member):  # agreed on the sign-in page (TERMS_NOTICE)
        member_terms.record(session, member, "oauth_signin")
    auth_code = secrets.token_urlsafe(32)
    login.member_id, login.code_hash, login.otp_hash = member.id, sha256_hex(auth_code), None
    login.status, login.expires_at = "authorized", now() + CODE_TTL
    audit(session, "pilot", None, "pilot.oauth_authorized", member.id, client=login.client_id)
    params = {"code": auth_code, "iss": _base(settings)}
    if login.state:
        params["state"] = login.state
    sep = "&" if "?" in login.redirect_uri else "?"
    return RedirectResponse(login.redirect_uri + sep + urlencode(params), status_code=302,
                            headers={"Cache-Control": "no-store"})


# --------------------------------------------------------------------------- Continue with Google (OIDC)

GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"


def google_redirect_uri(settings) -> str:
    return _base(settings) + "/oauth/google/callback"


def _google_verifier(settings, login: PilotOAuthLogin) -> str:
    # PKCE verifier for our own leg to Google, derived so nothing extra is stored
    return hmac.new((settings.oauth_secret or "").encode(), ("google:" + login.id).encode(), hashlib.sha256).hexdigest()


def google_userinfo(settings, code: str, verifier: str) -> dict[str, Any]:
    """Exchange Google's code (server to server, with our client secret) and read the signed-in account."""
    with httpx.Client(timeout=15) as http:
        r = http.post(GOOGLE_TOKEN, data={"grant_type": "authorization_code", "code": code,
                                          "client_id": settings.google_client_id,
                                          "client_secret": settings.google_client_secret,
                                          "redirect_uri": google_redirect_uri(settings), "code_verifier": verifier})
        r.raise_for_status()
        u = http.get(GOOGLE_USERINFO, headers={"Authorization": "Bearer " + r.json()["access_token"]})
        u.raise_for_status()
        return u.json()


def _nickname_form(login: PilotOAuthLogin, suggested: str = "", error: str = "") -> HTMLResponse:
    e = f"<p class=err>{html.escape(error)}</p>" if error else ""
    return _page("Pick a nickname", (
        "<h1>Welcome to ONAA</h1><p>Pick a nickname. Others see it next to your address; it does not have to be "
        "unique.</p>" + e +
        "<form method=post action='/oauth/google/nickname'>"
        f"<input type=hidden name=login_id value='{html.escape(login.id)}'>"
        "<label for=nickname>Nickname</label>"
        f"<input id=nickname name=nickname maxlength=40 required value='{html.escape(suggested)}'>"
        "<button type=submit>Continue</button></form>" + TERMS_NOTICE), also_form_to=login.redirect_uri)


@router.get("/oauth/google/start")
def google_start(request: Request, session: Session = Depends(get_session)):
    settings = request.app.state.settings
    if not google_enabled(settings):
        return _error_page("Google sign-in is not available. Use the email code instead.", 404)
    login = _open_login(session, request.query_params.get("login_id", ""), ("started", "code_sent", "google_sent"),
                        allow_verify=True)
    if login is None:
        return _error_page("This sign-in expired. Go back to your app and connect again.")
    if not _browser_ok(request, settings, login):
        return _error_page(WRONG_SIGNIN, 403)
    _limiter(request, "google_ip", 30, 600).check("ip:" + client_ip(request))
    nonce = secrets.token_urlsafe(24)
    login.otp_hash, login.otp_attempts, login.status = sha256_hex("google:" + nonce), 0, "google_sent"
    verifier = _google_verifier(settings, login)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    params = {"client_id": settings.google_client_id, "redirect_uri": google_redirect_uri(settings),
              "response_type": "code", "scope": "openid email profile", "state": login.id + "." + nonce,
              "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account"}
    return RedirectResponse(GOOGLE_AUTH + "?" + urlencode(params), status_code=302,
                            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@router.get("/oauth/google/callback")
def google_callback(request: Request, session: Session = Depends(get_session)):
    settings = request.app.state.settings
    q = request.query_params
    login_id, _, nonce = (q.get("state") or "").partition(".")
    login = _open_login(session, login_id, ("google_sent",), allow_verify=True) if google_enabled(settings) else None
    if login is None or not nonce or not hmac.compare_digest(sha256_hex("google:" + nonce), login.otp_hash or ""):
        return _error_page("This sign-in expired. Go back to your app and connect again.")
    if not _browser_ok(request, settings, login):
        return _error_page(WRONG_SIGNIN, 403)
    login.otp_hash = None  # one use
    if q.get("error") or not q.get("code"):
        login.status = "started"
        session.commit()
        return _error_page("Google sign-in was cancelled. Go back to your app and connect again.")
    try:
        info = google_userinfo(settings, q["code"], _google_verifier(settings, login))
    except Exception:  # noqa: BLE001 - never show provider details
        log.exception("google sign-in failed")
        session.commit()
        return _error_page("Google sign-in did not work. Go back to your app and try again, or use the email code.")
    email = str(info.get("email") or "").strip()
    if not info.get("sub") or not email or info.get("email_verified") is not True:
        session.commit()
        return _error_page("That Google account has no verified email. Use the email code instead.")
    login.email_hash, login.status = email_hash(settings, email), "google_ok"
    if login.scope == VERIFY_SCOPE:
        return _finish_verify(session, login)
    member = session.scalar(select(PilotMember).where(PilotMember.email_hash == login.email_hash))
    if member is None:
        if not settings.pilot_open_signup:
            session.commit()
            return _error_page("ONAA is invite-only right now and this account has no membership yet.", 403)
        suggested = "".join(ch for ch in str(info.get("given_name") or info.get("name") or "") if ch >= " ")[:40]
        session.commit()
        return _nickname_form(login, suggested.strip())
    return _finish(session, settings, login, None)


@router.post("/oauth/google/nickname")
async def google_nickname(request: Request, session: Session = Depends(get_session)):
    f = await _form(request)
    settings = request.app.state.settings
    login = _open_login(session, f.get("login_id", ""), ("google_ok", "code_ok"))
    if login is None or not login.email_hash:
        return _error_page("This sign-in expired. Go back to your app and connect again.")
    if not _browser_ok(request, settings, login):
        return _error_page(WRONG_SIGNIN, 403)
    nickname = "".join(ch for ch in (f.get("nickname") or "") if ch >= " ").strip()[:40]
    if not nickname:
        return _nickname_form(login, "", "Pick a nickname.")
    return _finish(session, settings, login, nickname)


def _client_auth(request: Request, f: dict[str, str], session: Session) -> PilotOAuthClient | None:
    client_id, secret = f.get("client_id"), f.get("client_secret")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            raw = base64.b64decode(auth[6:]).decode()
            from urllib.parse import unquote
            client_id, secret = (unquote(x) for x in raw.split(":", 1))
        except (ValueError, UnicodeDecodeError):
            return None
    client_id = client_id or ""
    client = session.get(PilotOAuthClient, cimd_id(client_id) if _is_cimd_url(client_id) else client_id)
    if client is None:
        return None
    if client.secret_hash and not hmac.compare_digest(sha256_hex(secret or ""), client.secret_hash):
        return None
    return client


def _pkce_ok(verifier: str, challenge: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier or ""):
        return False
    digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return hmac.compare_digest(digest, challenge)


@router.post("/oauth/token")
async def token(request: Request, session: Session = Depends(get_session)):
    f = await _form(request)
    settings = request.app.state.settings
    _limiter(request, "token", 120, 60).check("tok:" + client_ip(request))
    client = _client_auth(request, f, session)
    if client is None:
        return _oauth_error("invalid_client", "unknown client or wrong secret", 401)
    resource = f.get("resource")
    if not _resource_ok(settings, resource):
        return _oauth_error("invalid_target", "unknown resource")
    grant = f.get("grant_type")
    if grant == "authorization_code":
        login = session.scalar(select(PilotOAuthLogin).where(
            PilotOAuthLogin.code_hash == sha256_hex(f.get("code") or "")))
        if login is None or login.client_id != client.id:
            return _oauth_error("invalid_grant", "unknown code")
        if login.status == "used":  # a code used twice: someone copied it; end that sign-in
            _revoke_family(session, login.id)
            session.commit()
            return _oauth_error("invalid_grant", "code already used")
        if login.status != "authorized" or _aware(login.expires_at) <= now():
            return _oauth_error("invalid_grant", "code expired")
        if f.get("redirect_uri") and f.get("redirect_uri") != login.redirect_uri:
            return _oauth_error("invalid_grant", "redirect_uri does not match")
        if not _pkce_ok(f.get("code_verifier", ""), login.code_challenge):
            return _oauth_error("invalid_grant", "PKCE verification failed")
        login.status = "used"
        out = _issue(session, settings, login.member_id, client.id, login.id)
        return JSONResponse(out, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    if grant == "refresh_token":
        row = session.scalar(select(PilotOAuthToken).where(
            PilotOAuthToken.token_hash == sha256_hex(f.get("refresh_token") or ""),
            PilotOAuthToken.kind == "refresh"))
        if row is None or row.client_id != client.id:
            return _oauth_error("invalid_grant", "unknown refresh token")
        if row.revoked_at is not None:  # an old refresh token came back: treat the sign-in as stolen
            _revoke_family(session, row.family)
            session.commit()
            return _oauth_error("invalid_grant", "refresh token was already used or revoked")
        member = session.get(PilotMember, row.member_id)
        if _aware(row.expires_at) <= now() or member is None or member.status != "active":
            return _oauth_error("invalid_grant", "refresh token expired")
        session.execute(update(PilotOAuthToken).where(PilotOAuthToken.family == row.family,
                                                      PilotOAuthToken.revoked_at.is_(None))
                        .values(revoked_at=now()))  # rotation: the old pair stops working
        out = _issue(session, settings, row.member_id, client.id, row.family)
        return JSONResponse(out, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
    return _oauth_error("unsupported_grant_type", "authorization_code or refresh_token")


@router.post("/oauth/revoke")
async def revoke(request: Request, session: Session = Depends(get_session)):
    """RFC 7009: revoking either token ends that whole sign-in. Unknown tokens are answered 200 too."""
    f = await _form(request)
    client = _client_auth(request, f, session)
    if client is None:
        return _oauth_error("invalid_client", "unknown client or wrong secret", 401)
    row = session.scalar(select(PilotOAuthToken).where(PilotOAuthToken.token_hash == sha256_hex(f.get("token") or "")))
    if row is not None and row.client_id == client.id:
        _revoke_family(session, row.family)
    return JSONResponse({}, headers={"Cache-Control": "no-store"})
