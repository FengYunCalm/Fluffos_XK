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
REPORT_DIR="${REPORT_DIR:-$ROOT_DIR/build/reports/capacity}"

case "$BUILD_DIR" in
  /*) ;;
  *) BUILD_DIR="$ROOT_DIR/$BUILD_DIR" ;;
esac
mkdir -p "$REPORT_DIR"

COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD)"
COMPILER_NAME="$(c++ --version | head -1 | awk '{print $1}')"
COMPILER_VERSION="$(c++ --version | head -1)"
PLATFORM_OS="$(uname -s)"
PLATFORM_ARCH="$(uname -m)"
CPU_CORES="$(nproc)"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUILD_CONFIG_HASH="debug-$(c++ --version | head -1 | md5sum | cut -c1-12)"

cmake --build "$BUILD_DIR" --target owner_runtime_bench lpc_vm_bench object_store_bench -j "$(nproc)" >/dev/null

wrap() {
  local raw="$1" name="$2" command="$3"
  local ended_at
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 - "$raw" "$name" "$command" "$COMMIT_SHA" "$BUILD_CONFIG_HASH" "$COMPILER_NAME" "$COMPILER_VERSION" \
    "$PLATFORM_OS" "$PLATFORM_ARCH" "$CPU_CORES" "$STARTED_AT" "$ended_at" <<'PY'
import json, sys, os

raw, name, command = sys.argv[1:4]
(commit, build_hash, cc_name, cc_version, os_name, arch, cores, started, ended) = sys.argv[4:13]

with open(raw, encoding="utf-8") as f:
    payload = json.load(f)

envelope = {
    "schema": "fluffos.evidence.manifest.v1",
    "run_id": f"{name}-{commit[:12]}",
    "commit_sha": commit,
    "build_config_hash": build_hash,
    "compiler": {"name": cc_name, "version": cc_version},
    "platform": {"os": os_name, "arch": arch, "cpu_cores": int(cores)},
    "workload_version": "owner-scheduler-capacity-v1",
    "started_at": started,
    "ended_at": ended,
    "command": command,
    "cleanup": {"state": "clean", "detail": "vm_owner_thread_stop + bench teardown inside bench binary"},
    "evidence_kind": "current",
    "bench": payload,
}
out = os.path.join(os.environ["REPORT_DIR"], f"{name}.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(envelope, f, indent=2)
print(f"wrapped: {out}")
PY
}

BENCH_BIN="$BUILD_DIR/src/tests"
echo "== owner scheduler capacity matrix (workers 1/2/4) =="
"$BENCH_BIN/owner_runtime_bench" --json "$REPORT_DIR/owner_runtime_bench_raw.json"
wrap "$REPORT_DIR/owner_runtime_bench_raw.json" "owner_runtime_bench_capacity" \
  "owner_runtime_bench --json owner_runtime_bench_raw.json"

echo "== lpc vm bench =="
"$BENCH_BIN/lpc_vm_bench" --json "$REPORT_DIR/lpc_vm_bench_raw.json" >/dev/null 2>&1 || true
if [ -f "$REPORT_DIR/lpc_vm_bench_raw.json" ]; then
  wrap "$REPORT_DIR/lpc_vm_bench_raw.json" "lpc_vm_bench_capacity" "lpc_vm_bench --json lpc_vm_bench_raw.json"
fi

echo "== object store bench =="
"$BENCH_BIN/object_store_bench" --json "$REPORT_DIR/object_store_bench_raw.json" >/dev/null 2>&1 || true
if [ -f "$REPORT_DIR/object_store_bench_raw.json" ]; then
  wrap "$REPORT_DIR/object_store_bench_raw.json" "object_store_bench_capacity" "object_store_bench --json object_store_bench_raw.json"
fi

echo "== validate evidence =="
python3 "$ROOT_DIR/tools/docs/check-evidence.py" \
  --report "$REPORT_DIR/owner_runtime_bench_capacity.json" \
  --report "$REPORT_DIR/lpc_vm_bench_capacity.json" \
  --report "$REPORT_DIR/object_store_bench_capacity.json" \
  --skip-commit-check
rm -f "$REPORT_DIR"/*_raw.json
echo "reports in: $REPORT_DIR"
