"""Run the steward standalone against a registry: `onaa-steward serve` or `onaa-steward sweep`."""

from __future__ import annotations

import argparse
import json
import logging

from .runtime import Scheduler, StewardConfig, build


def main() -> None:
    ap = argparse.ArgumentParser(prog="onaa-steward")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="serve the A2A agent and run the periodic sweep")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8100)
    sw = sub.add_parser("sweep", help="run one sweep and print the summary")
    sw.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cfg = StewardConfig()
    steward, app = build(cfg)
    if args.cmd == "sweep":
        print(json.dumps(steward.sweep(args.limit)))
        return
    import uvicorn

    sched = Scheduler(steward, cfg)
    sched.start()
    try:
        uvicorn.run(app, host=args.host, port=args.port)
    finally:
        sched.stop()


if __name__ == "__main__":
    main()
