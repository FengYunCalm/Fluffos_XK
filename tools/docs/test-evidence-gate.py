#!/usr/bin/env python3
"""Negative tests for the evidence gate (R2-F07).

Every negative fixture below must be rejected by check-evidence.py in gate
mode. This is the repository test that keeps the gate honest: a checker
that accepts any of these would silently certify unusable evidence.

Run: python3 tools/docs/test-evidence-gate.py
Exit: 0 all negatives rejected; 1 a negative was accepted or the harness
      itself is broken.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check-evidence.py")
SCHEMA = os.path.abspath(os.path.join(HERE, "..", "..", "docs", "evidence", "manifest.schema.json"))

FUTURE = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
PAST = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

FAILURES = []


def make_envelope(overrides=None):
    env = {
        "schema": "fluffos.evidence.manifest.v1",
        "run_id": str(uuid.uuid4()),
        "commit_sha": "a" * 40,
        "tested_sha": "a" * 40,
        "source_sha": "a" * 40,
        "build_config_hash": "b" * 64,
        "compiler": {"name": "gcc", "version": "13.3.0"},
        "platform": {"os": "Linux", "arch": "x86_64", "cpu_cores": 32},
        "workload_version": "owner-scheduler-capacity-v1",
        "started_at": PAST,
        "ended_at": NOW,
        "command": "owner_runtime_bench --json out.json",
        "cleanup": {"state": "clean", "detail": "derived from bench metrics"},
        "evidence_kind": "current",
        "bench": {"cleanup_owner_queue_depth": 0, "cleanup_future_pending_backlog": 0,
                  "cleanup_deferred_target_releases": 0},
    }
    env.update(overrides or {})
    return env


def write_envelope(dirpath, name, overrides=None, raw=None):
    env = make_envelope(overrides)
    if raw is not None:
        env["raw_report"] = raw[0]
        env["raw_sha256"] = raw[1]
    with open(os.path.join(dirpath, name), "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)


def run_gate(dirpath, extra=None):
    cmd = [sys.executable, CHECKER, "--reports-dir", dirpath, "--schema", SCHEMA,
           "--expected-tested-sha", "a" * 40, "--expected-source-sha", "a" * 40]
    if extra:
        cmd.extend(extra)
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode


def expect_rejected(dirpath, what, extra=None):
    rc = run_gate(dirpath, extra)
    if rc == 0:
        FAILURES.append(f"{what}: gate ACCEPTED a negative fixture (exit 0)")


def expect_accepted(dirpath, what, extra=None):
    rc = run_gate(dirpath, extra)
    if rc != 0:
        FAILURES.append(f"{what}: gate rejected a valid envelope (exit {rc})")


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        # 0. Positive control: a fully valid envelope must pass.
        write_envelope(td, "e.json")
        expect_accepted(td, "positive control")
        os.remove(os.path.join(td, "e.json"))

        # 1. Empty report set.
        empty = os.path.join(td, "empty")
        os.makedirs(empty)
        expect_rejected(empty, "empty report set")

        # 2. Raw benchmark JSON mixed into the envelope directory.
        mixed = os.path.join(td, "mixed")
        os.makedirs(mixed)
        write_envelope(mixed, "owner.json")
        with open(os.path.join(mixed, "raw_bench.json"), "w", encoding="utf-8") as f:
            json.dump({"some": "raw payload"}, f)
        expect_rejected(mixed, "raw JSON mixed into envelope dir")

        # 3. cleanup.state failed / partial / unknown.
        for state in ("failed", "partial", "unknown"):
            d = os.path.join(td, "cleanup-" + state)
            os.makedirs(d)
            write_envelope(d, "e.json", {"cleanup": {"state": state, "detail": "x"}})
            expect_rejected(d, f"cleanup.state={state}")

        # 4. Reversed timestamps.
        d = os.path.join(td, "reversed-time")
        os.makedirs(d)
        write_envelope(d, "e.json", {"started_at": NOW, "ended_at": PAST})
        expect_rejected(d, "reversed timestamps")

        # 5. Naive (no timezone) timestamps.
        d = os.path.join(td, "naive-time")
        os.makedirs(d)
        write_envelope(d, "e.json", {"started_at": "2026-08-10T10:00:00",
                                     "ended_at": "2026-08-10T10:01:00"})
        expect_rejected(d, "naive timestamps")

        # 6. Future timestamps beyond skew.
        d = os.path.join(td, "future-time")
        os.makedirs(d)
        write_envelope(d, "e.json", {"started_at": FUTURE, "ended_at": FUTURE})
        expect_rejected(d, "future timestamps")

        # 7. Source/tested SHA mismatch.
        d = os.path.join(td, "sha-mismatch")
        os.makedirs(d)
        write_envelope(d, "e.json", {"tested_sha": "c" * 40, "commit_sha": "c" * 40,
                                     "source_sha": "c" * 40})
        expect_rejected(d, "tested/source SHA mismatch")

        # 8. Duplicate run_id across two envelopes.
        d = os.path.join(td, "dup-run-id")
        os.makedirs(d)
        write_envelope(d, "e1.json", {"run_id": "dup-run"})
        write_envelope(d, "e2.json", {"run_id": "dup-run"})
        expect_rejected(d, "duplicate run_id")

        # 9. Raw artifact digest modified.
        d = os.path.join(td, "digest-modified")
        os.makedirs(d)
        raw = b'{"cleanup_owner_queue_depth": 0}'
        import hashlib
        write_envelope(d, "e.json", raw=("raw.json", hashlib.sha256(raw).hexdigest()))
        with open(os.path.join(d, "raw.json"), "wb") as f:
            f.write(b'{"cleanup_owner_queue_depth": 1}')
        expect_rejected(d, "raw digest modified")

        # 10. Bench metrics report non-clean cleanup (queue/ref not drained):
        # the wrapper's derive-cleanup must write failed, and the gate must
        # refuse the resulting envelope.
        d = os.path.join(td, "undrained")
        os.makedirs(d)
        raw_path = os.path.join(d, "raw.json")
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump({"cleanup_owner_queue_depth": 3,
                       "cleanup_future_pending_backlog": 0,
                       "cleanup_deferred_target_releases": 0}, f)
        derive = subprocess.run(
            [sys.executable, os.path.join(HERE, "derive-cleanup.py"), raw_path,
             "--contracts", "cleanup_owner_queue_depth,cleanup_future_pending_backlog,cleanup_deferred_target_releases",
             "--metrics-key", "metrics"],
            capture_output=True, text=True)
        if derive.returncode != 0:
            FAILURES.append(f"undrained queue metrics: derive-cleanup failed to run")
        else:
            cleanup = json.loads(derive.stdout)
            if cleanup.get("state") != "failed":
                FAILURES.append(
                    f"undrained queue metrics: derive-cleanup wrote {cleanup.get('state')!r}, expected failed")
            write_envelope(d, "e.json", {"cleanup": cleanup,
                                         "bench": {"metrics": {"cleanup_owner_queue_depth": 3}}})
            expect_rejected(d, "undrained queue metrics envelope")

        # 11. evidence_kind=historical cannot gate.
        d = os.path.join(td, "historical")
        os.makedirs(d)
        write_envelope(d, "e.json", {"evidence_kind": "historical"})
        expect_rejected(d, "evidence_kind=historical in gate mode")

        # 12. Valid envelope in validator mode passes even with gate-level
        # violations (layering: validator answers format, gate answers policy).
        d = os.path.join(td, "validator-mode")
        os.makedirs(d)
        write_envelope(d, "e.json", {"cleanup": {"state": "failed", "detail": "x"},
                                     "evidence_kind": "historical"})
        expect_accepted(d, "validator-mode relaxation", extra=["--mode", "validator"])

    if FAILURES:
        for f in FAILURES:
            print(f"FAIL: {f}")
        print(f"test-evidence-gate: {len(FAILURES)} negative fixture(s) accepted")
        return 1
    print("test-evidence-gate: OK (all negative fixtures rejected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
