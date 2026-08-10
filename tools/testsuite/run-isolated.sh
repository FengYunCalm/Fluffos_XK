#!/usr/bin/env bash
# run-isolated.sh - Run the LPC testsuite in an isolated, repeatable sandbox.
#
# Each invocation:
#   - creates a private temp dir for the rendered config and driver log
#   - picks four free loopback ports (with a cross-process allocation lock,
#     same-batch dedup, and whole-round retry on bind failure)
#   - renders a temp config that binds to 127.0.0.1 by default
#   - runs the driver with a timeout and traps cleanup of the driver and temp dir
#   - classifies the run: LPC assertions, expected crashers, and real failures
#
# Exit code: 0 only if the driver exited 0 and LPC assertions succeeded.
#
# NOTE: the port selection is a best-effort mitigation while the driver does
# not yet support binding port 0 and reporting the OS-assigned port back.
# Parallel invocations are serialized through a lock file, and a bind failure
# anywhere retries the whole round. This is NOT strict isolation: the OS can
# still race between the probe socket close and the driver bind.
#
# Usage:
#   tools/testsuite/run-isolated.sh --driver <path-to-driver> [--bind-all] [--keep] [--timeout SECS]

set -euo pipefail

DRIVER=""
BIND_ALL=0
KEEP=0
TIMEOUT_SECS=300
MODE="audit"

usage() {
  echo "Usage: $0 --driver <driver> [--bind-all] [--keep] [--timeout SECS] [--mode off|audit|enforced]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --driver)
      DRIVER="$2"
      shift 2
      ;;
    --bind-all)
      BIND_ALL=1
      shift
      ;;
    --keep)
      KEEP=1
      shift
      ;;
    --timeout)
      TIMEOUT_SECS="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [ -z "$DRIVER" ]; then
  usage
fi
if [ ! -x "$DRIVER" ]; then
  echo "error: driver not executable: $DRIVER" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TESTSUITE_DIR="$REPO_ROOT/testsuite"
TEMPLATE="$TESTSUITE_DIR/etc/config.test"

# Resolve the driver to an absolute path so it survives the cd into testsuite.
case "$DRIVER" in
  /*) DRIVER_ABS="$DRIVER" ;;
  *) DRIVER_ABS="$(cd "$(dirname "$DRIVER")" && pwd)/$(basename "$DRIVER")" ;;
esac

if [ ! -f "$TEMPLATE" ]; then
  echo "error: testsuite template not found: $TEMPLATE" >&2
  exit 2
fi

# The driver resolves the log directory relative to the mudlib dir (it strips
# a leading '/'), so the sandbox must live inside the testsuite dir.
WORKDIR="$(mktemp -d "$TESTSUITE_DIR/.run-isolated-XXXXXX")"
CONFIG_FILE="$WORKDIR/config.test"
DRIVER_LOG="$WORKDIR/driver.log"
DRIVER_PID=""

cleanup() {
  if [ -n "$DRIVER_PID" ] && kill -0 "$DRIVER_PID" 2>/dev/null; then
    kill "$DRIVER_PID" 2>/dev/null
    wait "$DRIVER_PID" 2>/dev/null || true
  fi
  if [ "$KEEP" -eq 1 ]; then
    echo "workspace kept at: $WORKDIR" >&2
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT INT TERM

# Cross-process allocation lock: parallel invocations serialize port picking
# so the probe/close/rebind window cannot overlap two runners.
LOCK_FILE="$TESTSUITE_DIR/.run-isolated.lock"
LOCK_FD=""
acquire_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec {LOCK_FD}>"$LOCK_FILE"
    flock "$LOCK_FD"
  else
    # Fallback: mkdir-based lock with a bounded wait.
    local lock_dir="$TESTSUITE_DIR/.run-isolated.lockdir"
    local waited=0
    while ! mkdir "$lock_dir" 2>/dev/null; do
      waited=$((waited + 1))
      if [ "$waited" -gt 200 ]; then
        echo "error: could not acquire port lock" >&2
        exit 2
      fi
      sleep 0.05
    done
    LOCK_FD="mkdir"
  fi
}
release_lock() {
  if [ "$LOCK_FD" = "mkdir" ]; then
    rmdir "$TESTSUITE_DIR/.run-isolated.lockdir" 2>/dev/null || true
  else
    flock -u "$LOCK_FD" 2>/dev/null || true
    exec {LOCK_FD}>&- 2>/dev/null || true
  fi
}

# Pick four distinct loopback ports under the allocation lock.
pick_ports() {
  python3 - <<'EOF'
import socket
ports = []
while len(ports) < 4:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    if port not in ports:
        ports.append(port)
print(" ".join(str(p) for p in ports))
EOF
}

MUD_IP="127.0.0.1"
if [ "$BIND_ALL" -eq 1 ]; then
  MUD_IP="0.0.0.0"
fi

# Whole-round retry: if the driver reports a bind error, re-pick ports and
# re-render (the OS may have raced us after the probe sockets closed).
RC=1
ROUND=0
MAX_ROUNDS=5
while [ "$RC" -ne 0 ] && [ "$ROUND" -lt "$MAX_ROUNDS" ]; do
  ROUND=$((ROUND + 1))
  acquire_lock
  PORTS="$(pick_ports)"
  release_lock
  P1="$(echo "$PORTS" | cut -d' ' -f1)"
  P2="$(echo "$PORTS" | cut -d' ' -f2)"
  P3="$(echo "$PORTS" | cut -d' ' -f3)"
  P4="$(echo "$PORTS" | cut -d' ' -f4)"
  if [ -z "$P1" ] || [ -z "$P2" ] || [ -z "$P3" ] || [ -z "$P4" ]; then
    echo "error: failed to pick four ports" >&2
    exit 2
  fi
  if [ "$P1" = "$P2" ] || [ "$P1" = "$P3" ] || [ "$P1" = "$P4" ] ||
     [ "$P2" = "$P3" ] || [ "$P2" = "$P4" ] || [ "$P3" = "$P4" ]; then
    echo "error: duplicate ports picked: $PORTS" >&2
    exit 2
  fi

  # Render the temp config: loopback by default, dynamic ports, sandbox log dir.
  # The log dir must stay relative to the mudlib dir (driver strips leading '/').
  sed -e "s/^mud ip : .*/mud ip : ${MUD_IP}/" \
    -e "s/^port number : .*/port number : ${P1}/" \
    -e "s/^external_port_2: websocket .*/external_port_2: websocket ${P2}/" \
    -e "s/^external_port_3: websocket .*/external_port_3: websocket ${P3}/" \
    -e "s/^external_port_4: telnet .*/external_port_4: telnet ${P4}/" \
    -e "s|^log directory : .*|log directory : ${WORKDIR##*/}/log|" \
    -e "s/^multicore mode : .*/multicore mode : ${MODE}/" \
    "$TEMPLATE" >"$CONFIG_FILE"

  # Validate the rendered config: every fixed placeholder must be gone and
  # each dynamic value must be present exactly once.
  if grep -qE 'port number : (4000|4001|4002|4003)' "$CONFIG_FILE"; then
    echo "error: rendered config still contains a fixed port" >&2
    exit 2
  fi
  for key in "mud ip : ${MUD_IP}" "external_port_2: websocket ${P2}" \
             "external_port_3: websocket ${P3}" "external_port_4: telnet ${P4}" \
             "multicore mode : ${MODE}"; do
    if ! grep -qF "$key" "$CONFIG_FILE"; then
      echo "error: rendered config missing: $key" >&2
      exit 2
    fi
  done

  mkdir -p "$WORKDIR/log"

  echo "== run-isolated: round=${ROUND} ports ${P1}/${P2}/${P3}/${P4}, bind=${MUD_IP}, mode=${MODE} =="

  # Run the driver from the testsuite dir (config paths are mudlib-relative).
  # stdin is /dev/null: a backgrounded driver would otherwise get SIGTTIN
  # when it reads the terminal, turning a clean exit into 255.
  (
    cd "$TESTSUITE_DIR" || exit 1
    timeout "$TIMEOUT_SECS" "$DRIVER_ABS" "$CONFIG_FILE" -ftest </dev/null
  ) >"$DRIVER_LOG" 2>&1 &
  DRIVER_PID=$!

  if wait "$DRIVER_PID"; then
    RC=0
  else
    RC=$?
  fi
  DRIVER_PID=""

  # Classify the run.
  ASSERT_OK=""
  if grep -q "Checks succeeded\." "$DRIVER_LOG"; then
    ASSERT_OK="yes"
  fi
  BIND_FAIL=""
  if grep -q "bind error\|Address already in use\|init_user_conn" "$DRIVER_LOG"; then
    BIND_FAIL="yes"
  fi

  echo "== run-isolated: driver exit=$RC, lpc_assertions_ok=${ASSERT_OK:-no}, bind_error=${BIND_FAIL:-no} =="
  if [ "$KEEP" -eq 1 ]; then
    echo "driver log: $DRIVER_LOG"
  else
    # Show the tail of the log for diagnostics before cleanup.
    tail -n 20 "$DRIVER_LOG" | sed 's/^/  | /'
  fi

  if [ "$RC" -ne 0 ] && [ "$BIND_FAIL" = "yes" ] && [ "$ROUND" -lt "$MAX_ROUNDS" ]; then
    echo "== run-isolated: bind failure; retrying round with fresh ports ==" >&2
    RC=1
    continue
  fi
  break
done

# Acceptance: driver must exit 0 and LPC assertions must have succeeded.
if [ "$RC" -ne 0 ] || [ "${ASSERT_OK:-}" != "yes" ]; then
  echo "== run-isolated: FAIL ==" >&2
  exit 1
fi
echo "== run-isolated: PASS =="
exit 0
