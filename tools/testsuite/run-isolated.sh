#!/usr/bin/env bash
# run-isolated.sh - Run the LPC testsuite in an isolated, repeatable sandbox.
#
# Each invocation:
#   - creates a private temp dir for the rendered config and driver log
#   - picks four free loopback ports instead of the fixed 4000-4003 range
#   - renders a temp config that binds to 127.0.0.1 by default
#   - runs the driver with a timeout and traps cleanup of the driver and temp dir
#   - classifies the run: LPC assertions, expected crashers, and real failures
#
# Exit code: 0 only if the driver exited 0 and LPC assertions succeeded.
#
# Usage:
#   tools/testsuite/run-isolated.sh --driver <path-to-driver> [--bind-all] [--keep] [--timeout SECS]

set -u

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
    wait "$DRIVER_PID" 2>/dev/null
  fi
  if [ "$KEEP" -eq 1 ]; then
    echo "workspace kept at: $WORKDIR" >&2
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT INT TERM

# Pick four free loopback ports (open then close; races are unlikely in CI).
pick_port() {
  python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
EOF
}

P1="$(pick_port)"
P2="$(pick_port)"
P3="$(pick_port)"
P4="$(pick_port)"

MUD_IP="127.0.0.1"
if [ "$BIND_ALL" -eq 1 ]; then
  MUD_IP="0.0.0.0"
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

mkdir -p "$WORKDIR/log"

echo "== run-isolated: ports ${P1}/${P2}/${P3}/${P4}, bind=${MUD_IP}, mode=${MODE} =="

# Run the driver from the testsuite dir (config paths are mudlib-relative).
(
  cd "$TESTSUITE_DIR" || exit 1
  timeout "$TIMEOUT_SECS" "$DRIVER_ABS" "$CONFIG_FILE" -ftest
) >"$DRIVER_LOG" 2>&1 &
DRIVER_PID=$!

wait "$DRIVER_PID"
RC=$?
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

# Acceptance: driver must exit 0 and LPC assertions must have succeeded.
if [ "$RC" -ne 0 ] || [ "$ASSERT_OK" != "yes" ]; then
  echo "== run-isolated: FAIL ==" >&2
  exit 1
fi
echo "== run-isolated: PASS =="
exit 0
