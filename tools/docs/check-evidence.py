#!/usr/bin/env python3
"""Validate FluffOS evidence reports against the evidence manifest schema.

Checks that every benchmark/smoke/capacity report in the given list (or under
the reports directory) carries the required metadata fields, that the commit
SHA matches the current checkout, that timestamps are sane, and that the
cleanup state is recorded.

Exit codes:
  0: all checked reports pass
  1: at least one report is missing required fields or fails a check

Usage:
  tools/docs/check-evidence.py [--report PATH ...] [--reports-dir DIR] [--schema PATH]
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA_FIELD = "schema"
REQUIRED_SCHEMA = "fluffos.evidence.manifest.v1"
REQUIRED_FIELDS = [
    "schema",
    "run_id",
    "commit_sha",
    "build_config_hash",
    "compiler",
    "platform",
    "workload_version",
    "started_at",
    "ended_at",
    "command",
    "cleanup",
]


def current_commit(repo: str) -> str:
    out = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() if out.returncode == 0 else ""


def check_report(path: str, expected_commit: str, schema_path: str) -> list[str]:
    errors: list[str] = []
    try:
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [f"{path}: cannot read/parse JSON: {e}"]

    if report.get(SCHEMA_FIELD) != REQUIRED_SCHEMA:
        errors.append(
            f"{path}: schema field is {report.get(SCHEMA_FIELD)!r}, expected {REQUIRED_SCHEMA!r}"
        )

    missing = [f for f in REQUIRED_FIELDS if f not in report]
    if missing:
        errors.append(f"{path}: missing required fields: {', '.join(missing)}")

    if expected_commit and report.get("commit_sha") != expected_commit:
        errors.append(
            f"{path}: commit_sha {report.get('commit_sha')!r} != current checkout {expected_commit!r}"
        )

    for ts_field in ("started_at", "ended_at"):
        if ts_field in report:
            try:
                datetime.fromisoformat(report[ts_field].replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{path}: {ts_field} is not ISO-8601: {report[ts_field]!r}")

    cleanup = report.get("cleanup")
    if isinstance(cleanup, dict) and cleanup.get("state") not in (
        "clean",
        "partial",
        "failed",
        "unknown",
    ):
        errors.append(f"{path}: cleanup.state must be clean/partial/failed/unknown")

    compiler = report.get("compiler")
    if isinstance(compiler, dict) and ("name" not in compiler or "version" not in compiler):
        errors.append(f"{path}: compiler must include name and version")

    platform = report.get("platform")
    if isinstance(platform, dict) and ("os" not in platform or "arch" not in platform):
        errors.append(f"{path}: platform must include os and arch")

    if errors:
        return errors

    # A report may be historical (evidence_kind=historical) but a report that
    # claims current readiness must not be mislabeled.
    kind = report.get("evidence_kind")
    if kind not in ("historical", "current", "external-required", "unknown"):
        # Not strictly an error (schema allows additionalProperties), but warn
        # loudly: classification is required for gate decisions.
        errors.append(
            f"{path}: evidence_kind should be one of historical/current/external-required/unknown"
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="append", default=[], help="report JSON path (repeatable)")
    parser.add_argument("--reports-dir", default="", help="scan all *.json under this dir")
    parser.add_argument("--schema", default="", help="path to manifest.schema.json (optional)")
    parser.add_argument("--repo", default=".", help="repo root for current commit SHA")
    parser.add_argument("--skip-commit-check", action="store_true", help="do not compare commit_sha")
    args = parser.parse_args()

    paths = list(args.report)
    if args.reports_dir:
        for root, _dirs, files in os.walk(args.reports_dir):
            for f in sorted(files):
                if f.endswith(".json"):
                    paths.append(os.path.join(root, f))

    if not paths:
        print("no reports to check", file=sys.stderr)
        return 0

    expected_commit = "" if args.skip_commit_check else current_commit(args.repo)

    all_errors: list[str] = []
    for p in sorted(set(paths)):
        all_errors.extend(check_report(p, expected_commit, args.schema))

    if all_errors:
        for e in all_errors:
            print(f"FAIL: {e}")
        print(f"check-evidence: {len(all_errors)} error(s) across {len(paths)} report(s)")
        return 1

    print(f"check-evidence: OK ({len(paths)} report(s) validated against {REQUIRED_SCHEMA})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
