"""``onaa`` command line. Subcommand ``verify`` checks a counterparty's attestations before you trade.

    onaa verify agt_123 --registry https://api.onaa.net --root-jwk root.json [--level protocol_certified]
    onaa verify --offline --attestation a.json --status s.json --manifest m.json --root-jwk root.json

The root key is the trust anchor: obtain it from the ONAA repository/docs out of band and pin it. Staging
attestations are TEST-ONLY and verify only with ``--allow-test-only``. Output is JSON; exit code 0 = verified,
1 = not verified (fail closed), 2 = usage error. ``--state FILE`` remembers the last log checkpoint and makes
the next run prove the log only grew (consistency proof).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

DEFAULT_REGISTRY = os.environ.get("ONAA_REGISTRY_URL", "https://api.onaa.net")


def _load_json(value: str) -> Any:
    p = Path(value)
    text = p.read_text(encoding="utf-8") if p.exists() else value
    return json.loads(text)


def _verify(args: argparse.Namespace) -> int:
    from . import verify as v
    from .client import OnaaClient

    root_src = args.root_jwk or os.environ.get("ONAA_ROOT_JWK")
    if not root_src:
        print("error: pin the issuer root key with --root-jwk FILE|JSON or ONAA_ROOT_JWK", file=sys.stderr)
        return 2
    root = _load_json(root_src)
    if args.offline:
        if not (args.attestation and args.status and args.manifest):
            print("error: --offline needs --attestation, --status and --manifest", file=sys.stderr)
            return 2
        check = v.verify_offline(_load_json(args.attestation), _load_json(args.status), _load_json(args.manifest),
                                 root, allow_test_only=args.allow_test_only, subject_id=args.subject)
        ok = check.valid and (not args.level or check.level == args.level)
        print(json.dumps({"verified": ok, "attestation": check.__dict__}, indent=2))
        return 0 if ok else 1
    if not args.subject:
        print("error: give a registry listing id (agt_... / svc_...)", file=sys.stderr)
        return 2
    previous = None
    if args.state and Path(args.state).exists():
        previous = json.loads(Path(args.state).read_text(encoding="utf-8")).get("checkpoint")
    with OnaaClient(args.registry) as client:
        report = v.verify_subject(client, args.subject, root, allow_test_only=args.allow_test_only, level=args.level,
                                  check_transparency=not args.skip_log, previous_checkpoint=previous)
    if args.state and report.checkpoint:
        Path(args.state).write_text(json.dumps({"checkpoint": report.checkpoint}), encoding="utf-8")
    print(json.dumps(report.as_dict(), indent=2))
    return 0 if report.verified else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="onaa", description="ONAA command line tools")
    sub = ap.add_subparsers(dest="command", required=True)
    vp = sub.add_parser("verify", help="verify a listing's signed attestations, status and transparency log")
    vp.add_argument("subject", nargs="?", help="registry listing id (agt_... or svc_...)")
    vp.add_argument("--registry", default=DEFAULT_REGISTRY, help="registry base URL (default: %(default)s)")
    vp.add_argument("--root-jwk", help="pinned issuer root public JWK (file path or JSON)")
    vp.add_argument("--level", help="require this level, e.g. protocol_certified")
    vp.add_argument("--allow-test-only", action="store_true", help="accept TEST-ONLY (staging) attestations")
    vp.add_argument("--skip-log", action="store_true", help="skip the transparency log checks (not recommended)")
    vp.add_argument("--state", help="file that remembers the last verified log checkpoint")
    vp.add_argument("--offline", action="store_true", help="verify saved files without network access")
    vp.add_argument("--attestation", help="offline: attestation JSON file")
    vp.add_argument("--status", help="offline: status record JSON file")
    vp.add_argument("--manifest", help="offline: issuer manifest JSON file")
    args = ap.parse_args(argv)
    try:
        return _verify(args)
    except ImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
