#!/usr/bin/env bash
# test-port-isolation.sh - port-0 isolation stress test (R2-F11).
#
# Verifies the driver's OS-assigned port contract under load:
#   1. 5 serial runs: every run binds four DISTINCT loopback ports and
#      exits cleanly with LPC assertions passing;
#   2. 20 concurrent runs: zero port conflicts (the OS cannot hand out the
#      same port twice while bound) and zero leftover processes, sandbox
#      directories, or lock files afterwards.
#
# Usage: tools/testsuite/test-port-isolation.sh --driver PATH [--quick]
#   --quick: 1 serial + 4 concurrent runs (for local iteration)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RUNNER="$HERE/run-isolated.sh"
DRIVER=""
QUICK=0

while [ $# -gt 0 ]; do
  case "$1" in
    --driver) DRIVER="$2"; shift 2 ;;
    --quick) QUICK=1; shift ;;
    *) echo "usage: $0 --driver PATH [--quick]" >&2; exit 2 ;;
  esac
done
[ -n "$DRIVER" ] && [ -x "$DRIVER" ] || {
  echo "error: --driver must point to an executable driver" >&2
  exit 2
}

SERIAL_RUNS=$([ "$QUICK" -eq 1 ] && echo 1 || echo 5)
CONCURRENT_RUNS=$([ "$QUICK" -eq 1 ] && echo 4 || echo 20)

FAIL=0
fail() {
  echo "FAIL: $1"
  FAIL=1
}

echo "== port isolation: $SERIAL_RUNS serial runs =="
for i in $(seq 1 "$SERIAL_RUNS"); do
  if ! bash "$RUNNER" --driver "$DRIVER" --mode audit >/tmp/portiso-serial-$i.log 2>&1; then
    fail "serial run $i failed (see /tmp/portiso-serial-$i.log)"
  fi
done

echo "== port isolation: $CONCURRENT_RUNS concurrent runs (ports-only) =="
PIDS=()
for i in $(seq 1 "$CONCURRENT_RUNS"); do
  # Ports-only mode: the LPC testsuite writes shared files under testsuite/
  # (single-instance design), so the concurrency stress targets the port-0
  # contract itself - unique OS-assigned loopback ports and zero leftovers.
  bash "$RUNNER" --driver "$DRIVER" --mode audit --ports-only >/tmp/portiso-conc-$i.log 2>&1 &
  PIDS+=("$!")
done
CONC_FAIL=0
for pid in "${PIDS[@]}"; do
  if ! wait "$pid"; then
    CONC_FAIL=1
  fi
done
if [ "$CONC_FAIL" -ne 0 ]; then
  fail "at least one concurrent run failed (logs /tmp/portiso-conc-*.log)"
fi

echo "== residual check =="
# Sandbox dirs and the mkdir fallback lockdir are transient; the flock
# lock FILE (.run-isolated.lock) is intentionally persistent (flock needs
# a stable inode), so it is not a leak.
LEFTOVERS="$(find "$ROOT/testsuite" -maxdepth 1 \( -name '.run-isolated-??????' -o -name '.run-isolated.lockdir' \) | wc -l)"
if [ "$LEFTOVERS" -ne 0 ]; then
  fail "leftover sandbox/lock entries: $LEFTOVERS"
fi
# No leftover driver processes from this test run (the ports-only phase
# starts real driver binaries; match the exact executable name so this
# script's own command line is not matched).
if pgrep -x driver >/dev/null 2>&1; then
  fail "leftover driver processes"
fi

if [ "$FAIL" -ne 0 ]; then
  echo "port-isolation: FAILED"
  exit 1
fi
echo "port-isolation: OK ($SERIAL_RUNS serial + $CONCURRENT_RUNS concurrent, zero conflicts, zero leftovers)"
