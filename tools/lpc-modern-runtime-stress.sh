#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-build}"
PROFILE="${1:-${PROFILE:-smoke}}"
JOBS="${JOBS:-2}"

case "$BUILD_DIR" in
  /*) ;;
  *) BUILD_DIR="$ROOT_DIR/$BUILD_DIR" ;;
esac

case "$PROFILE" in
  smoke) REPEAT="${REPEAT:-1}" ;;
  storm) REPEAT="${REPEAT:-3}" ;;
  *) echo "usage: $0 [smoke|storm]" >&2; exit 2 ;;
esac

REPORT_DIR="${REPORT_DIR:-$BUILD_DIR/reports}"
mkdir -p "$REPORT_DIR"

bash "$ROOT_DIR/tools/owner-runtime-v4-stress.sh" "$PROFILE"

cmake --build "$BUILD_DIR" --target lpc_tests driver lpc_vm_bench object_store_bench -j "$JOBS"

TARGETED_FILTER="DriverTest.TestLpcModernProfilePragmasAndAuditRules"
TARGETED_FILTER+=":DriverTest.TestLpcVmProfileRecordsApplyCacheLookups"
TARGETED_FILTER+=":DriverTest.TestVmOwnerQueryObjectSnapshotOnlyForCrossOwnerTargets"
TARGETED_FILTER+=":DriverTest.TestVmObjectHandleReportsCapabilityMetadata"
TARGETED_FILTER+=":DriverTest.TestVmObjectHandleReportsBasicResolveFailures"
TARGETED_FILTER+=":DriverTest.TestGatewayCommandPayloadSnapshotsActiveInputToState"
TARGETED_FILTER+=":DriverTest.TestGatewayCommandPayloadSnapshotsActiveGetCharState"

for run in $(seq 1 "$REPEAT"); do
  "$BUILD_DIR/src/tests/lpc_tests" --gtest_filter="$TARGETED_FILTER"
done

LPC_VM_JSON="$REPORT_DIR/lpc_vm_bench_${PROFILE}.json"
OBJECT_STORE_JSON="$REPORT_DIR/object_store_bench_${PROFILE}.json"
"$BUILD_DIR/src/tests/lpc_vm_bench" --json "$LPC_VM_JSON"
"$BUILD_DIR/src/tests/object_store_bench" --json "$OBJECT_STORE_JSON"

python3 - "$LPC_VM_JSON" "$OBJECT_STORE_JSON" <<'PY'
import json
import sys

lpc_vm_path, object_store_path = sys.argv[1:3]
with open(lpc_vm_path, "r", encoding="utf-8") as handle:
    lpc_vm = json.load(handle)
with open(object_store_path, "r", encoding="utf-8") as handle:
    object_store = json.load(handle)

if lpc_vm.get("schema") != "lpc_vm_bench_v1":
    raise SystemExit(f"unexpected lpc_vm_bench schema: {lpc_vm.get('schema')}")
if object_store.get("schema") != "object_store_bench_v1":
    raise SystemExit(f"unexpected object_store_bench schema: {object_store.get('schema')}")

lpc_metrics = lpc_vm.get("metrics", {})
object_metrics = object_store.get("metrics", {})
if lpc_metrics.get("apply_dispatch_cache_hits", 0) <= 0:
    raise SystemExit("lpc vm benchmark did not record apply dispatch cache hits")
if object_metrics.get("object_resolve_global_fallback_count") != 0:
    raise SystemExit(
        "object store benchmark used global fallback on owner fast path: "
        f"{object_metrics.get('object_resolve_global_fallback_count')}"
    )
if object_metrics.get("owner_local_fast_path_count", 0) <= 0:
    raise SystemExit("object store benchmark did not record owner-local fast path resolves")
PY

echo "lpc-modern-runtime ${PROFILE} profile passed"
echo "lpc_vm_json=${LPC_VM_JSON}"
echo "object_store_json=${OBJECT_STORE_JSON}"
