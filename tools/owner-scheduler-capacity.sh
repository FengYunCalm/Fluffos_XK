#!/usr/bin/env bash
# owner-scheduler-capacity.sh - T14: owner scheduler capacity matrix evidence.
#
# Runs the owner runtime bench (1/2/4 worker matrix built in), the LPC VM
# bench and the object store bench, then wraps each JSON report into the
# fluffos.evidence.manifest.v1 envelope (commit, compiler, platform, times,
# command, cleanup) so results are reproducible and gate-comparable.
#
# Usage: tools/owner-scheduler-capacity.sh [--build-dir build] [--report-dir build/reports/capacity]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build}"
JOBS="${JOBS:-${CMAKE_BUILD_PARALLEL_LEVEL:-8}}"
export REPORT_DIR="${REPORT_DIR:-$ROOT_DIR/build/reports/capacity}"

case "$BUILD_DIR" in
  /*) ;;
  *) BUILD_DIR="$ROOT_DIR/$BUILD_DIR" ;;
esac
mkdir -p "$REPORT_DIR"

COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD)"
# R2-F07: CI passes the PR head as SOURCE_SHA; local runs use the checkout.
SOURCE_SHA="${SOURCE_SHA:-$COMMIT_SHA}"
export SOURCE_SHA
COMPILER_NAME="$(c++ --version | head -1 | awk '{print $1}')"
COMPILER_VERSION="$(c++ --version | head -1)"
PLATFORM_OS="$(uname -s)"
PLATFORM_ARCH="$(uname -m)"
CPU_CORES="$(nproc)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Build config hash: full SHA-256 over the compiler identity, the CMake
# cache, the preset, and the key environment, so a changed cache/preset/
# flags/flags-commit invalidates the evidence.
BUILD_CONFIG_HASH="$( {
  c++ --version | head -1
  if [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
    grep -E '^(CMAKE_BUILD_TYPE|CMAKE_C_COMPILER|CMAKE_CXX_COMPILER|CMAKE_CXX_FLAGS|CMAKE_CXX_FLAGS_DEBUG|CMAKE_CXX_FLAGS_RELWITHDEBINFO|ENABLE_ASAN|ENABLE_UBSAN|ENABLE_TSAN|ENABLE_LTO|MARCH_NATIVE|PACKAGE_DB_SQLITE):' "$BUILD_DIR/CMakeCache.txt" || true
  fi
  if [ -f "$ROOT_DIR/CMakePresets.json" ]; then
    cat "$ROOT_DIR/CMakePresets.json"
  fi
} | sha256sum | cut -c1-64 )"
# Local runs get a UUID run id (CI passes run_id+run_attempt+matrix key).
LOCAL_RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"

cmake --build "$BUILD_DIR" --target owner_runtime_bench lpc_vm_bench object_store_bench -j "$JOBS" >/dev/null

wrap() {
  local raw="$1" name="$2" command="$3" run_id="$4" contracts="$5" metrics_key="$6"
  local ended_at raw_digest
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  raw_digest="$(sha256sum "$raw" | cut -c1-64)"
  # Unique run id per envelope (CI passes run_id+run_attempt+matrix key).
  if [ -z "$run_id" ] || [ "$run_id" = "auto" ]; then
    run_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  fi
  python3 - "$raw" "$name" "$command" "$COMMIT_SHA" "$BUILD_CONFIG_HASH" "$COMPILER_NAME" "$COMPILER_VERSION" \
    "$PLATFORM_OS" "$PLATFORM_ARCH" "$CPU_CORES" "$STARTED_AT" "$ended_at" "$run_id" "$raw_digest" \
    "$ROOT_DIR/tools/docs/derive-cleanup.py" "$contracts" "$metrics_key" <<'PY'
import json, sys, os, subprocess

raw, name, command = sys.argv[1:4]
(commit, build_hash, cc_name, cc_version, os_name, arch, cores, started, ended, run_id, raw_digest) = sys.argv[4:15]
derive_script = sys.argv[15]
contracts = sys.argv[16]
metrics_key = sys.argv[17]

with open(raw, encoding="utf-8") as f:
    payload = json.load(f)

# R2-F07: cleanup is DERIVED from the benchmark's own metrics (queue
# drained, claims balanced, deferred refs zero, futures settled); a run
# that leaves work behind writes failed and the gate refuses the envelope.
derive = subprocess.run(
    [sys.executable, derive_script, raw, "--contracts", contracts,
     "--metrics-key", metrics_key],
    capture_output=True, text=True, check=True)
cleanup = json.loads(derive.stdout)

envelope = {
    "schema": "fluffos.evidence.manifest.v1",
    "run_id": run_id,
    "commit_sha": commit,
    # R2-F07: explicit commit identity - tested_sha is the SHA actually
    # checked out for the run; source_sha is the PR head for CI runs.
    "tested_sha": commit,
    "source_sha": os.environ.get("SOURCE_SHA", commit),
    "build_config_hash": build_hash,
    "compiler": {"name": cc_name, "version": cc_version},
    "platform": {"os": os_name, "arch": arch, "cpu_cores": int(cores)},
    "workload_version": "owner-scheduler-capacity-v1",
    "started_at": started,
    "ended_at": ended,
    "command": command,
    "cleanup": cleanup,
    "evidence_kind": "current",
    "bench": payload,
    "raw_report": os.path.basename(raw),
    "raw_sha256": raw_digest,
}
out = os.path.join(os.environ["REPORT_DIR"], f"{name}.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(envelope, f, indent=2)
print(f"wrapped: {out} (cleanup={cleanup['state']})")
PY
}

BENCH_BIN="$BUILD_DIR/src/tests"
echo "== owner scheduler capacity matrix (workers 1/2/4) =="
"$BENCH_BIN/owner_runtime_bench" --json "$REPORT_DIR/owner_runtime_bench_raw.json"
wrap "$REPORT_DIR/owner_runtime_bench_raw.json" "owner_runtime_bench_capacity" \
  "owner_runtime_bench --json owner_runtime_bench_raw.json" "auto" \
  "cleanup_owner_queue_depth,cleanup_future_pending_backlog,cleanup_deferred_target_releases,owner_claim_delta" \
  "metrics"

echo "== lpc vm bench =="
"$BENCH_BIN/lpc_vm_bench" --json "$REPORT_DIR/lpc_vm_bench_raw.json" >/dev/null
if [ ! -f "$REPORT_DIR/lpc_vm_bench_raw.json" ]; then
  echo "FAIL: lpc_vm_bench produced no report" >&2
  exit 1
fi
wrap "$REPORT_DIR/lpc_vm_bench_raw.json" "lpc_vm_bench_capacity" "lpc_vm_bench --json lpc_vm_bench_raw.json" "auto" "" "metrics"

echo "== object store bench =="
"$BENCH_BIN/object_store_bench" --json "$REPORT_DIR/object_store_bench_raw.json" >/dev/null
if [ ! -f "$REPORT_DIR/object_store_bench_raw.json" ]; then
  echo "FAIL: object_store_bench produced no report" >&2
  exit 1
fi
wrap "$REPORT_DIR/object_store_bench_raw.json" "object_store_bench_capacity" "object_store_bench --json object_store_bench_raw.json" "auto" "" "metrics"

echo "== validate evidence =="
python3 "$ROOT_DIR/tools/docs/check-evidence.py" \
  --report "$REPORT_DIR/owner_runtime_bench_capacity.json" \
  --report "$REPORT_DIR/lpc_vm_bench_capacity.json" \
  --report "$REPORT_DIR/object_store_bench_capacity.json" \
  --schema "$ROOT_DIR/docs/evidence/manifest.schema.json" \
  --expected-tested-sha "$COMMIT_SHA" \
  --expected-source-sha "$SOURCE_SHA"

echo "reports in: $REPORT_DIR"
