#!/usr/bin/env python3
"""Validate FluffOS evidence envelopes against the evidence manifest schema
(R2-F07).

Two layers:

1. VALIDATOR (--mode validator): format only - schema, required fields,
   types, ISO-8601 parseability. Answers "is this a legal envelope?".
2. GATE (--mode gate, default): the validator PLUS release-gate policy:
   - evidence_kind must be "current" (historical/external-required reports
     cannot gate the current HEAD);
   - cleanup.state must be "clean";
   - ended_at >= started_at, both must carry a UTC timezone, and the
     timestamps must not be in the future beyond a small skew;
   - source_sha/tested_sha must match the values passed from the workflow
     context (--expected-tested-sha / --expected-source-sha); every report
     must carry the same tested_sha as the checkout when --repo is given;
   - run_id must be unique across the report set;
   - when an envelope binds a raw report digest (raw_report + raw_sha256),
     the raw file (same directory) must exist and its SHA-256 must match.

JSON Schema validation runs with jsonschema.FormatChecker so format
annotations (date-time) are actually enforced.

Exit codes: 0 all reports pass; 1 empty gate, schema/format failure, or a
gate policy failure; 2 usage error.

Usage:
  tools/docs/check-evidence.py --reports-dir DIR --schema PATH --repo .
      [--expected-tested-sha SHA] [--expected-source-sha SHA] [--mode gate]
"""

import argparse
import hashlib
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
# Allow a small clock skew between the runner and the gate host.
MAX_FUTURE_SKEW_SECONDS = 300

UTC_FORMATS = ("+00:00", "Z")


def current_commit(repo: str) -> str:
    out = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() if out.returncode == 0 else ""


def validate_json_schema(report: dict, schema_path: str, path: str) -> list[str]:
    """Validate a report against the JSON Schema with FormatChecker."""
    errors: list[str] = []
    if not schema_path:
        return errors
    try:
        import jsonschema  # type: ignore
    except ImportError:
        errors.append(
            f"{path}: JSON Schema validation requested but 'jsonschema' is not installed"
        )
        return errors
    try:
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        errors.append(f"{path}: cannot read schema {schema_path}: {e}")
        return errors
    try:
        jsonschema.validate(report, schema, format_checker=jsonschema.FormatChecker())
    except jsonschema.ValidationError as e:
        errors.append(f"{path}: schema validation failed: {e.message}")
    except jsonschema.SchemaError as e:
        errors.append(f"{path}: schema file is invalid: {e}")
    return errors


def parse_utc_timestamp(path: str, field: str, value: object) -> list[str]:
    """Returns (errors, datetime or None). Timestamps must be ISO-8601 with
    an explicit UTC timezone; naive timestamps are rejected."""
    errors: list[str] = []
    if not isinstance(value, str):
        errors.append(f"{path}: {field} must be a string, got {type(value).__name__}")
        return errors
    text = value
    if not text.endswith(UTC_FORMATS) and not (
        "+00:00" in text or "-00:00" in text
    ):
        errors.append(f"{path}: {field} must carry an explicit UTC timezone: {text!r}")
        return errors
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{path}: {field} is not ISO-8601: {text!r}")
        return errors
    if parsed.tzinfo is None:
        errors.append(f"{path}: {field} is missing a timezone: {text!r}")
        return errors
    if parsed.utcoffset() != timezone.utc.utcoffset(None):
        errors.append(f"{path}: {field} must be UTC: {text!r}")
        return errors
    return errors


def check_raw_digest(path: str, report: dict) -> list[str]:
    """When the envelope binds a raw report (raw_report + raw_sha256), the
    raw file must exist next to the envelope and its SHA-256 must match."""
    errors: list[str] = []
    raw_name = report.get("raw_report")
    raw_digest = report.get("raw_sha256")
    if not raw_name and not raw_digest:
        return errors
    if not raw_name or not raw_digest:
        errors.append(f"{path}: raw_report and raw_sha256 must be set together")
        return errors
    if not isinstance(raw_digest, str) or len(raw_digest) != 64:
        errors.append(f"{path}: raw_sha256 must be a 64-hex SHA-256")
        return errors
    raw_path = os.path.join(os.path.dirname(path), raw_name)
    if not os.path.isfile(raw_path):
        errors.append(f"{path}: bound raw report missing: {raw_path}")
        return errors
    try:
        with open(raw_path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
    except OSError as e:
        errors.append(f"{path}: cannot read raw report {raw_path}: {e}")
        return errors
    if digest != raw_digest:
        errors.append(f"{path}: raw report digest mismatch (recorded {raw_digest}, actual {digest})")
    return errors


def check_report(path: str, schema_path: str, mode: str, expected_tested_sha: str,
                 expected_source_sha: str) -> list[str]:
    errors: list[str] = []
    try:
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [f"{path}: cannot read/parse JSON: {e}"]

    # --- validator layer ---
    if report.get(SCHEMA_FIELD) != REQUIRED_SCHEMA:
        errors.append(
            f"{path}: schema field is {report.get(SCHEMA_FIELD)!r}, expected {REQUIRED_SCHEMA!r}"
        )
    missing = [f for f in REQUIRED_FIELDS if f not in report]
    if missing:
        errors.append(f"{path}: missing required fields: {', '.join(missing)}")

    compiler = report.get("compiler")
    if isinstance(compiler, dict) and ("name" not in compiler or "version" not in compiler):
        errors.append(f"{path}: compiler must include name and version")
    platform = report.get("platform")
    if isinstance(platform, dict) and ("os" not in platform or "arch" not in platform):
        errors.append(f"{path}: platform must include os and arch")

    started_errors = parse_utc_timestamp(path, "started_at", report.get("started_at"))
    ended_errors = parse_utc_timestamp(path, "ended_at", report.get("ended_at"))
    errors.extend(started_errors)
    errors.extend(ended_errors)

    # Time order: ended_at >= started_at, no future beyond skew.
    if not started_errors and not ended_errors:
        started = datetime.fromisoformat(report["started_at"].replace("Z", "+00:00"))
        ended = datetime.fromisoformat(report["ended_at"].replace("Z", "+00:00"))
        if ended < started:
            errors.append(
                f"{path}: ended_at {report['ended_at']!r} is before started_at {report['started_at']!r}"
            )
        now = datetime.now(timezone.utc)
        for field, value in (("started_at", started), ("ended_at", ended)):
            if value > now:
                skew = (value - now).total_seconds()
                if skew > MAX_FUTURE_SKEW_SECONDS:
                    errors.append(
                        f"{path}: {field} is in the future by {skew:.0f}s (> {MAX_FUTURE_SKEW_SECONDS}s)"
                    )

    errors.extend(validate_json_schema(report, schema_path, path))
    errors.extend(check_raw_digest(path, report))

    kind = report.get("evidence_kind")
    if kind not in ("historical", "current", "external-required", "unknown", None):
        errors.append(
            f"{path}: evidence_kind should be one of historical/current/external-required/unknown"
        )

    # --- gate layer ---
    if mode != "gate":
        return errors

    if kind != "current":
        errors.append(
            f"{path}: gate requires evidence_kind=current, got {kind!r} "
            "(historical/external-required evidence cannot gate the current HEAD)"
        )

    cleanup = report.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("state") != "clean":
        errors.append(
            f"{path}: gate requires cleanup.state=clean, got "
            f"{cleanup.get('state') if isinstance(cleanup, dict) else cleanup!r}"
        )

    commit_sha = report.get("commit_sha")
    if expected_tested_sha and commit_sha != expected_tested_sha:
        errors.append(
            f"{path}: commit_sha {commit_sha!r} != expected tested SHA {expected_tested_sha!r}"
        )
    tested_sha = report.get("tested_sha")
    if expected_tested_sha and tested_sha != expected_tested_sha:
        errors.append(
            f"{path}: tested_sha {tested_sha!r} != expected tested SHA {expected_tested_sha!r}"
        )
    source_sha = report.get("source_sha")
    if expected_source_sha and source_sha != expected_source_sha:
        errors.append(
            f"{path}: source_sha {source_sha!r} != expected source SHA {expected_source_sha!r}"
        )

    run_id = report.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        errors.append(f"{path}: run_id must be a non-empty string")
    if isinstance(commit_sha, str) and len(commit_sha) != 40:
        errors.append(f"{path}: commit_sha must be a full 40-hex SHA, got {commit_sha!r}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="append", default=[], help="report JSON path (repeatable)")
    parser.add_argument("--reports-dir", default="", help="scan all *.json under this dir")
    parser.add_argument("--schema", default="", help="path to manifest.schema.json (required for gates)")
    parser.add_argument("--repo", default=".", help="repo root for current commit SHA")
    parser.add_argument("--mode", choices=["validator", "gate"], default="gate",
                        help="validator: format only; gate: validator + release policy (default)")
    parser.add_argument("--expected-tested-sha", default="",
                        help="tested SHA the gate must match (workflow context, e.g. GITHUB_SHA)")
    parser.add_argument("--expected-source-sha", default="",
                        help="source SHA for pull_request runs (GITHUB_BASE_SHA or PR head SHA)")
    parser.add_argument("--skip-commit-check", action="store_true",
                        help="do not compare commit_sha to the checkout (forbidden for CI gates)")
    args = parser.parse_args()

    if args.skip_commit_check and os.environ.get("CI"):
        print("FAIL: --skip-commit-check is forbidden in CI: every report must match the PR HEAD",
              file=sys.stderr)
        return 1

    paths = list(args.report)
    if args.reports_dir:
        # Envelope directory scan: every JSON is an envelope EXCEPT files
        # that an envelope binds as raw_report (those are verified via the
        # SHA-256 binding inside check_raw_digest, not as envelopes).
        raw_names = set()
        for root, _dirs, files in os.walk(args.reports_dir):
            for f in sorted(files):
                if not f.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(root, f), encoding="utf-8") as fp:
                        data = json.load(fp)
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(data.get("raw_report"), str):
                    raw_names.add(data["raw_report"])
        for root, _dirs, files in os.walk(args.reports_dir):
            for f in sorted(files):
                if f.endswith(".json") and f not in raw_names:
                    paths.append(os.path.join(root, f))

    if not paths:
        print("FAIL: no reports to check (empty evidence gate)", file=sys.stderr)
        return 1

    expected_tested_sha = args.expected_tested_sha
    if not expected_tested_sha and not args.skip_commit_check:
        expected_tested_sha = current_commit(args.repo)

    all_errors: list[str] = []
    seen_run_ids: dict[str, str] = {}
    for p in sorted(set(paths)):
        all_errors.extend(check_report(p, args.schema, args.mode, expected_tested_sha,
                                       args.expected_source_sha))
        # run_id uniqueness is a set-level gate property.
        try:
            with open(p, encoding="utf-8") as f:
                run_id = json.load(f).get("run_id")
        except (OSError, json.JSONDecodeError):
            run_id = None
        if isinstance(run_id, str) and run_id:
            if run_id in seen_run_ids:
                all_errors.append(
                    f"duplicate run_id {run_id!r} across {seen_run_ids[run_id]} and {p}"
                )
            seen_run_ids[run_id] = p

    if all_errors:
        for e in all_errors:
            print(f"FAIL: {e}")
        print(f"check-evidence: {len(all_errors)} error(s) across {len(paths)} report(s)")
        return 1

    print(f"check-evidence: OK ({len(paths)} report(s), mode={args.mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
