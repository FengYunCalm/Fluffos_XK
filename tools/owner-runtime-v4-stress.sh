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
  storm) REPEAT="${REPEAT:-5}" ;;
  *) echo "usage: $0 [smoke|storm]" >&2; exit 2 ;;
esac

REPORT_DIR="${REPORT_DIR:-$BUILD_DIR/reports}"
mkdir -p "$REPORT_DIR"

TARGETED_FILTER="DriverTest.TestVmOwnerRuntimeReportsExecutorTaskContract"
TARGETED_FILTER+=":DriverTest.TestOwnerSchedulerBackpressureRejectsOverLimit"
TARGETED_FILTER+=":DriverTest.TestVmOwnerExecutorCallbackTaskBoundaryDispatchesAndDropsStaleTasks"
TARGETED_FILTER+=":DriverTest.TestVmOwnerHeartbeatDispatchesThroughOwnerExecutor"
TARGETED_FILTER+=":DriverTest.TestVmOwnerCalloutDispatchesThroughOwnerExecutor"
TARGETED_FILTER+=":DriverTest.TestVmOwnerAsyncDnsCallbacksDispatchThroughOwnerExecutor"
TARGETED_FILTER+=":DriverTest.TestVmOwnerSocketCallbacksDispatchThroughOwnerExecutor"
TARGETED_FILTER+=":DriverTest.TestGatewayCommandExecutesThroughOwnerExecutor"
TARGETED_FILTER+=":DriverTest.TestVmOwnerFuturePollTracksMessageCompletion"
TARGETED_FILTER+=":DriverTest.TestVmObjectHandleRejectsStaleOwnerEpoch"
TARGETED_FILTER+=":DriverTest.TestVmObjectStoreShardRemovesDestructedObject"
TARGETED_FILTER+=":DriverTest.TestVmOwnerRuntimePerformanceProbesRecordDiagnostics"

cmake --build "$BUILD_DIR" --target lpc_tests driver owner_runtime_bench -j "$JOBS"

for run in $(seq 1 "$REPEAT"); do
  "$BUILD_DIR/src/tests/lpc_tests" --gtest_filter="$TARGETED_FILTER"
done

JSON_REPORT="$REPORT_DIR/owner_runtime_bench_${PROFILE}.json"
"$BUILD_DIR/src/tests/owner_runtime_bench" --json "$JSON_REPORT"

python3 - "$JSON_REPORT" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    report = json.load(handle)

metrics = report.get("metrics", {})
required_zero = [
    "normal_path_main_fallback_count",
    "executor_context_cleanup_leaks",
    "executor_same_owner_claim_conflicts",
    "object_resolve_global_fallback_count",
]
missing = [name for name in required_zero if name not in metrics]
nonzero = [name for name in required_zero if metrics.get(name) != 0]

if missing or nonzero:
    raise SystemExit(
        "owner runtime benchmark regression: "
        f"missing={missing} nonzero={{{', '.join(f'{name}: {metrics.get(name)}' for name in nonzero)}}}"
    )
PY

(cd "$ROOT_DIR/testsuite" && "$BUILD_DIR/bin/driver" etc/config.test -ftest:single/tests/efuns/owner_executor_contract)

echo "owner-runtime-v4 ${PROFILE} profile passed"
echo "benchmark_json=${JSON_REPORT}"
