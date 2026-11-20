"""Fixes from the 2026-11-19 full review: sign-in bound to the browser that started it, sign-out-everywhere also
voids fresh authorization codes, wrong-code cap per email, prohibited-word check on normalized text, IPv6 site-local
refused by the registry fetcher, bounded rate limiter."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import ipaddress
import re
import secrets

from fastapi.testclient import TestClient

from onaa_registry import models, oauth, prohibited
from onaa_registry.main import create_app
from onaa_registry.netsafety import _ip_is_public
from onaa_registry.security import RateLimiter

DOMAIN = "agents.example.test"
AT = chr(64)


def _app(settings, fetcher, txt, runner, **extra):
    s = dataclasses.replace(settings, pilot_enabled=True, hosting_domain=DOMAIN, hosting_scheme="http",
                            hosted_agent_secret="test-only-hosted-agent-secret-0123456789", pilot_open_signup=True,
                            oauth_secret="test-only-oauth-secret-0123456789abcdef", mail_backend="dev-log",
                            google_client_id="gid.apps.googleusercontent.com", google_client_secret="gsecret",
                            **extra)
    return TestClient(create_app(s, fetcher, txt, runner))


def _start(c, redirect="https://evil.example/cb"):
    reg = c.post("/oauth/register", json={"client_name": "Claude", "token_endpoint_auth_method": "none",
                                          "redirect_uris": [redirect]}).json()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    page = c.get("/oauth/authorize", params={
        "response_type": "code", "client_id": reg["client_id"], "redirect_uri": redirect,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "st"})
    assert page.status_code == 200, page.text
    return page, re.search(r"login_id=([A-Za-z0-9_-]+)'", page.text).group(1)


def test_a_sign_in_link_opened_in_another_browser_is_refused(settings, fetcher, txt, runner):
    with _app(settings, fetcher, txt, runner) as c:
        page, login_id = _start(c)
        # the page says where the code will be sent, so a stranger's app is easier to spot
        assert "evil.example" in page.text and oauth.LOGIN_COOKIE in page.headers.get("set-cookie", "")
        c.cookies.clear()  # the victim's browser never opened /oauth/authorize
        go = c.get("/oauth/google/start", params={"login_id": login_id}, follow_redirects=False)
        assert go.status_code == 403 and "another browser" in go.text
        r = c.post("/oauth/authorize/email", data={"login_id": login_id, "email": "ann" + AT + "example.org",
                                                    "nickname": "ann"})
        assert r.status_code == 403
        cb = c.get("/oauth/google/callback", params={"state": login_id + ".x", "code": "g"})
        assert "expired" in cb.text  # unknown nonce: refused before the browser check either way


def test_the_same_browser_still_signs_in(settings, fetcher, txt, runner):
    with _app(settings, fetcher, txt, runner) as c:
        _, login_id = _start(c)
        go = c.get("/oauth/google/start", params={"login_id": login_id}, follow_redirects=False)
        assert go.status_code == 302 and go.headers["location"].startswith(oauth.GOOGLE_AUTH)


def test_sign_out_everywhere_voids_codes_not_yet_exchanged(settings, fetcher, txt, runner):
    with _app(settings, fetcher, txt, runner) as c, c.app.state.sessionmaker() as s:
        m = models.PilotMember(nickname="ann", contact="", token_hash="t" * 64, email_hash="e" * 64)
        s.add(m)
        s.flush()
        s.add(models.PilotOAuthLogin(id="ol_test", client_id="c", redirect_uri="https://x.example/cb",
                                     code_challenge="c" * 43, scope=oauth.SCOPE, member_id=m.id,
                                     code_hash="h" * 64, status="authorized",
                                     expires_at=models.utcnow() + oauth.CODE_TTL))
        s.flush()
        oauth.sign_out_everywhere(s, m)
        s.commit()
        assert s.get(models.PilotOAuthLogin, "ol_test").status == "used"


def test_wrong_codes_are_capped_per_email_across_sign_ins(settings, fetcher, txt, runner):
    with _app(settings, fetcher, txt, runner) as c:
        email = "bob" + AT + "example.org"
        for _ in range(oauth.MAX_WRONG_CODES_PER_DAY // oauth.MAX_OTP_ATTEMPTS):
            _, login_id = _start(c)
            assert "6-digit" in c.post("/oauth/authorize/email", data={"login_id": login_id, "email": email,
                                                                       "nickname": "bob"}).text
            for _ in range(oauth.MAX_OTP_ATTEMPTS):
                c.post("/oauth/authorize/code", data={"login_id": login_id, "code": "000000x"})
        c.app.state.oauth_send_email_limiter = None  # a fresh 10-minute window for sending
        _, login_id = _start(c)
        c.post("/oauth/authorize/email", data={"login_id": login_id, "email": email, "nickname": "bob"})
        r = c.post("/oauth/authorize/code", data={"login_id": login_id, "code": "123456"})
        assert "today" in r.text


def test_prohibited_check_reads_text_as_it_is_stored():
    for text in ("Coc\x07aine 1g", "Co​caine", "ｃｏｃａｉｎｅ", "hand­gun"):
        assert prohibited.check(text), repr(text)
    for text in ("airsoft pistol", "paintball pistol", "shotgun microphone", "ammo can storage box",
                 "drug test kit", "water gun"):
        assert prohibited.check(text) is None, text


def test_registry_fetcher_refuses_ipv6_site_local_and_embedded_private():
    for a in ("fec0::1", "64:ff9b:1::a00:1", "2002:0a00:0001::1", "::ffff:10.0.0.1"):
        assert not _ip_is_public(ipaddress.ip_address(a)), a
    for a in ("8.8.8.8", "2001:4860:4860::8888"):
        assert _ip_is_public(ipaddress.ip_address(a)), a


def test_rate_limiter_remaining_and_hard_cap(monkeypatch):
    from onaa_registry import security

    lim = RateLimiter(2, window_seconds=60)
    assert lim.remaining("k") == 2
    lim.check("k")
    assert lim.remaining("k") == 1 and lim.remaining("never") == 2 and "never" not in lim._hits
    monkeypatch.setattr(security, "MAX_KEYS", 50)
    big = RateLimiter(5, window_seconds=3600)
    for i in range(10_100):
        big.check(f"ip{i}")
    # the sweep past 10,000 keys found nobody idle, so the hard cap dropped the oldest-seen keys
    assert len(big._hits) < 200 and "ip0" not in big._hits and "ip10099" in big._hits
