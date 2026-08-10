#!/usr/bin/env python3
"""Derive the evidence cleanup contract from a benchmark's raw JSON report
(R2-F07).

The evidence wrapper must not hardcode cleanup=clean: each bench declares
the cleanup metrics it promises (--contracts), and every promised metric
must be present AND satisfy its contract. A missing or violated metric
writes cleanup.state=failed so the evidence gate refuses the envelope. A
bench that promises no cleanup metrics (e.g. pure VM benches) reports
clean with an explicit "no cleanup contract applicable" detail.

Contracts:
  - cleanup_owner_queue_depth       == 0   (mailbox drained)
  - cleanup_future_pending_backlog  == 0   (no in-flight futures)
  - cleanup_deferred_target_releases == 0  (deferred refs drained)
  - owner_claim_delta               == owner_release_delta (claims balanced)

Usage: python3 tools/docs/derive-cleanup.py RAW_JSON_PATH
       [--contracts a,b,c] [--metrics-key KEY]
Output: single JSON object {"state": "...", "detail": "..."}
"""

import argparse
import json
import sys

PAIR_CONTRACTS = {"owner_claim_delta": "owner_release_delta"}
ZERO_CONTRACTS = {
    "cleanup_owner_queue_depth",
    "cleanup_future_pending_backlog",
    "cleanup_deferred_target_releases",
}


def derive(payload: dict, contracts: list[str]) -> dict:
    if not contracts:
        return {"state": "clean", "detail": "no cleanup contract applicable"}
    checks = {}
    for key in contracts:
        if key not in payload:
            checks[key] = "missing"
            continue
        if key in PAIR_CONTRACTS:
            partner = PAIR_CONTRACTS[key]
            if partner not in payload:
                checks[key] = f"missing partner {partner}"
                continue
            checks[f"{key}=={partner}"] = payload[key] == payload[partner]
        else:
            checks[key] = payload[key] == 0
    ok = all(v is True for v in checks.values())
    return {
        "state": "clean" if ok else "failed",
        "detail": json.dumps(checks, sort_keys=True),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_path")
    parser.add_argument("--contracts", default="",
                        help="comma-separated cleanup metrics this bench promises")
    parser.add_argument("--metrics-key", default="",
                        help="JSON key holding the metric map (e.g. 'metrics')")
    args = parser.parse_args()

    with open(args.raw_path, encoding="utf-8") as f:
        payload = json.load(f)
    if args.metrics_key:
        payload = payload.get(args.metrics_key, {})
    contracts = [c.strip() for c in args.contracts.split(",") if c.strip()]
    json.dump(derive(payload, contracts), sys.stdout)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
