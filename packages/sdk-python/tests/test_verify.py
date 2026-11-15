"""CERT-010: `onaa verify` against the real Registry app in-process (TEST-ONLY staging keys, no network)."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

registry = pytest.importorskip("onaa_registry.main")
pytest.importorskip("onaa_protocol")
from fastapi.testclient import TestClient  # noqa: E402
from onaa_protocol import jose, transparency, trust  # noqa: E402
from onaa_protocol.envelope import utcnow  # noqa: E402
from onaa_registry.config import Settings  # noqa: E402
from onaa_registry.netsafety import FetchResult  # noqa: E402

from onaa import OnaaClient, cli  # noqa: E402
from onaa.verify import verify_offline, verify_subject  # noqa: E402

CARD = "https://seller.example.com/.well-known/agent-card.json"
ADMIN = {"Authorization": "Bearer adm"}


def material(label="sdk"):
    now = utcnow()
    root = jose.Signer(jose.derive_test_only_key(label + "-root"), "test-root-1")
    signers = {p: jose.Signer(jose.derive_test_only_key(f"{label}-{p}"), f"test-{p}-1")
               for p in ("attestation", "status", "log")}
    typ = {"attestation": jose.TYP_ATTESTATION, "status": jose.TYP_ATTESTATION_STATUS,
           "log": transparency.TYP_CHECKPOINT}
    nb = now - timedelta(days=1)
    keys = [trust.manifest_key(s.public_jwk(), typ[p], not_before=nb) for p, s in signers.items()]
    manifest = trust.sign_manifest(trust.build_manifest(
        "onaa-registry-staging", keys, issued_at=now - timedelta(hours=1), next_update=now + timedelta(days=30)), root)
    private = {p: json.dumps(jose.private_jwk(s.private_key, s.kid)) for p, s in signers.items()}
    return root.public_jwk(), manifest, private


ROOT, MANIFEST, KEYS = material()


class FakeFetcher:
    def __init__(self):
        self.routes = {CARD: (200, json.dumps({"name": "Acme Parts Seller", "skills": [{"id": "rfq"}]}))}

    def fetch(self, url, *, allow_redirects=True):
        status, body = self.routes.get(url, (404, "missing"))
        return FetchResult(url, status, body.encode(), "text/plain", 1)


def runner(req):
    return {"suite_version": "0.5.0", "results": [],
            "summary": {"verdict": "pass", "must": {"total": 1, "passed": 1}, "should": {"total": 0, "passed": 0}}}


@pytest.fixture
def certified():
    fetcher = FakeFetcher()
    settings = Settings(database_url="sqlite://", admin_token="adm", write_rate_limit_per_minute=0,
                        operator_write_limit_per_minute=0, auto_create_schema=True,
                        require_verification_entitlement=False, precheck_min_interval_seconds=0,
                        attestation_signing_jwk=KEYS["attestation"], status_signing_jwk=KEYS["status"],
                        log_signing_jwk=KEYS["log"], issuer_manifest=json.dumps(MANIFEST))
    with TestClient(registry.create_app(settings, fetcher, lambda n: [], runner)) as http:
        reg = OnaaClient("http://testserver", http_client=http)
        reg.create_operator("Acme Parts", "organization", accept_terms_version="draft-0.2", country="US")
        agent = reg.register_agent(display_name="Acme Parts Seller", roles=["seller_agent"], agent_card_url=CARD)
        chl = reg.start_verification("agents", agent["id"])
        fetcher.routes[chl["challenge_url"]] = (200, chl["token"])
        reg.complete_verification("agents", agent["id"], chl["challenge_id"])
        assert reg.precheck(agent["id"])["verdict"] == "pass"
        app_ = reg.apply_certification(agent["id"], "protocol_certified")
        r = http.post(f"/v1/admin/certifications/{app_['id']}/decision", headers=ADMIN,
                      json={"decision": "approve", "reviewer": "founder", "reason": "pilot review"})
        assert r.status_code == 200, r.text
        yield OnaaClient("http://testserver", http_client=http), agent["id"], http


def test_verify_subject_passes_with_pinned_root(certified):
    reg, aid, _ = certified
    report = verify_subject(reg, aid, ROOT, allow_test_only=True, level="protocol_certified")
    assert report.verified, report
    a = report.attestations[0]
    assert a.valid and a.status == "active" and a.test_only is True and a.log_index == 0
    assert report.checkpoint["tree_size"] == 1


def test_verify_fails_closed(certified):
    reg, aid, http = certified
    # TEST-ONLY material is refused unless explicitly allowed.
    assert verify_subject(reg, aid, ROOT).error == "attestation_test_only"
    # A different root key (e.g. a registry that swapped its manifest) is refused.
    other_root, _, _ = material("evil")
    assert not verify_subject(reg, aid, other_root, allow_test_only=True).verified
    # Wrong level, unknown subject.
    assert not verify_subject(reg, aid, ROOT, allow_test_only=True, level="commerce_certified").verified
    assert verify_subject(reg, "agt_missing", ROOT, allow_test_only=True).error == "no_attestation"
    # Suspension: status record says suspended -> invalid.
    cert_id = reg.attestations(aid)[0]["id"]
    http.post(f"/v1/admin/certifications/issued/{cert_id}/status", headers=ADMIN,
              json={"status": "suspended", "reason": "review", "reviewer": "founder"})
    report = verify_subject(reg, aid, ROOT, allow_test_only=True)
    assert not report.verified and report.attestations[0].error == "attestation_suspended"


def test_log_consistency_state_and_offline_mode(certified, tmp_path):
    reg, aid, http = certified
    first = verify_subject(reg, aid, ROOT, allow_test_only=True)
    cert_id = reg.attestations(aid)[0]["id"]
    http.post(f"/v1/admin/certifications/issued/{cert_id}/status", headers=ADMIN,
              json={"status": "suspended", "reason": "review", "reviewer": "founder"})
    http.post(f"/v1/admin/certifications/issued/{cert_id}/status", headers=ADMIN,
              json={"status": "active", "reason": "cleared", "reviewer": "founder"})
    second = verify_subject(reg, aid, ROOT, allow_test_only=True, previous_checkpoint=first.checkpoint)
    assert second.verified and second.checkpoint["tree_size"] == 3
    # A forged earlier checkpoint (history rewritten) fails the consistency proof.
    forged = dict(first.checkpoint, root_hash=transparency.b64(b"\x00" * 32))
    assert verify_subject(reg, aid, ROOT, allow_test_only=True, previous_checkpoint=forged).error == "log_inconsistent"

    att, rec = reg.attestation(cert_id), reg.attestation_status(cert_id)
    for name, obj in (("a", att), ("s", rec), ("m", MANIFEST), ("r", ROOT)):
        (tmp_path / f"{name}.json").write_text(json.dumps(obj))
    assert verify_offline(att, rec, MANIFEST, ROOT, allow_test_only=True, subject_id=aid).valid
    args = ["verify", "--offline", "--allow-test-only", "--root-jwk", str(tmp_path / "r.json"),
            "--attestation", str(tmp_path / "a.json"), "--status", str(tmp_path / "s.json"),
            "--manifest", str(tmp_path / "m.json")]
    assert cli.main(args) == 0
    assert cli.main([a for a in args if a != "--allow-test-only"]) == 1
    tampered = dict(att, level="security_reviewed")
    (tmp_path / "a.json").write_text(json.dumps(tampered))
    assert cli.main(args) == 1
    assert cli.main(["verify", "agt_x"]) == 2  # no pinned root
