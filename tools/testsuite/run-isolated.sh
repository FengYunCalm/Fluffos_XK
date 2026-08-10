#!/usr/bin/env bash
# run-isolated.sh - Run the LPC testsuite in an isolated, repeatable sandbox.
#
# Each invocation:
#   - creates a private temp dir for the rendered config and driver log
#   - renders a temp config that binds port 0 (OS-assigned ports) to
#     127.0.0.1 by default
#   - runs the driver with a timeout and traps cleanup of the driver and
#     temp dir
#   - classifies the run: LPC assertions, expected crashers, and real
#     failures
#
# Exit code: 0 only if the driver exited 0, LPC assertions succeeded, and
# (loopback mode) the four OS-assigned ports were distinct.
#
# R2-F11: the driver supports configuring port 0 and reports the actual
# OS-assigned port back after bind (getsockname); this runner therefore
# renders four zeros - there is no probe/close/rebind window anymore.
# Parallel invocations are still serialized through a lock file (guarding
# the sandbox lifecycle), and the fallback lock records owner PID/time,
# cleans up via trap, and recognizes stale locks.
#
# --ports-only skips the LPC testsuite phase and only verifies the port-0
# contract in a normal boot; used by the concurrency stress test (the LPC
# tests themselves write shared files under testsuite/ by single-instance
# design and would conflict under 20-way parallelism).
#
# Usage:
#   tools/testsuite/run-isolated.sh --driver <path-to-driver>
#       [--bind-all] [--keep] [--timeout SECS] [--mode off|audit|enforced]
#       [--ports-only]

set -euo pipefail

DRIVER=""
BIND_ALL=0
KEEP=0
TIMEOUT_SECS=300
MODE="audit"
PORTS_ONLY=0

usage() {
  echo "Usage: $0 --driver <driver> [--bind-all] [--keep] [--timeout SECS] [--mode off|audit|enforced] [--ports-only]" >&2
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
    --ports-only)
      # Skip the LPC testsuite phase and only verify the port-0 contract
      # (used by the concurrency stress test; the LPC tests write shared
      # files under testsuite/ and would conflict under 20-way parallelism -
      # port binding is fully exercised).
      PORTS_ONLY=1
      shift
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

# Cross-process allocation lock: parallel invocations serialize workspace
# and config rendering. With port 0 the OS assigns ports at bind time, so
# no probe/close/rebind window exists anymore; the lock now only guards the
# sandbox directory lifecycle.
LOCK_FILE="$TESTSUITE_DIR/.run-isolated.lock"
LOCK_FD=""
acquire_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec {LOCK_FD}>"$LOCK_FILE"
    flock "$LOCK_FD"
  else
    # Fallback: mkdir-based lock that records owner PID + timestamp and can
    # recognize stale locks (owner died).
    local lock_dir="$TESTSUITE_DIR/.run-isolated.lockdir"
    local waited=0
    while ! mkdir "$lock_dir" 2>/dev/null; do
      # Stale-lock detection: a lock older than 10 minutes whose owner PID
      # is no longer alive is removed and retried.
      if [ -f "$lock_dir/owner" ]; then
        local owner_pid owner_time now
        read -r owner_pid owner_time < "$lock_dir/owner"
        now="$(date +%s)"
        if [ -n "$owner_pid" ] && ! kill -0 "$owner_pid" 2>/dev/null && \
           [ -n "$owner_time" ] && [ $((now - owner_time)) -gt 600 ]; then
          rm -rf "$lock_dir"
          continue
        fi
      fi
      waited=$((waited + 1))
      if [ "$waited" -gt 200 ]; then
        echo "error: could not acquire port lock" >&2
        exit 2
      fi
      sleep 0.05
    done
    echo "$$ $(date +%s)" > "$lock_dir/owner"
    LOCK_FD="mkdir"
  fi
}
release_lock() {
  if [ "$LOCK_FD" = "mkdir" ]; then
    # Only the owner may remove the lock directory.
    if [ -f "$TESTSUITE_DIR/.run-isolated.lockdir/owner" ] && \
       [ "$(head -1 "$TESTSUITE_DIR/.run-isolated.lockdir/owner")" = "$$" ]; then
      rm -rf "$TESTSUITE_DIR/.run-isolated.lockdir"
    fi
  else
    flock -u "$LOCK_FD" 2>/dev/null || true
    # Close the lock fd explicitly; bash does not support {var}>&- for
    # closing, so use eval with the numeric fd.
    eval "exec ${LOCK_FD}>&-" 2>/dev/null || true
  fi
}

MUD_IP="127.0.0.1"
if [ "$BIND_ALL" -eq 1 ]; then
  MUD_IP="0.0.0.0"
fi

# Port 0 mode: the driver binds port 0 and the OS assigns real ports at
# bind time (R2-F11); the runner renders four zeros and later extracts the
# actual ports from the driver log to assert uniqueness and loopback.
render_config() {
  # Render the temp config: loopback by default, port 0 for every listener
  # (OS-assigned), sandbox log dir.
  # The log dir must stay relative to the mudlib dir (driver strips leading '/').
  sed -e "s/^mud ip : .*/mud ip : ${MUD_IP}/" \
    -e "s/^port number : .*/port number : 0/" \
    -e "s/^external_port_2: websocket .*/external_port_2: websocket 0/" \
    -e "s/^external_port_3: websocket .*/external_port_3: websocket 0/" \
    -e "s/^external_port_4: telnet .*/external_port_4: telnet 0/" \
    -e "s|^log directory : .*|log directory : ${WORKDIR##*/}/log|" \
    -e "s/^multicore mode : .*/multicore mode : ${MODE}/" \
    "$TEMPLATE" >"$CONFIG_FILE"

  # Validate the rendered config: every fixed placeholder must be gone and
  # every listener must be port 0 (OS-assigned).
  if grep -qE 'port number : (4000|4001|4002|4003)' "$CONFIG_FILE"; then
    echo "error: rendered config still contains a fixed port" >&2
    exit 2
  fi
  for key in "mud ip : ${MUD_IP}" "external_port_2: websocket 0" \
             "external_port_3: websocket 0" "external_port_4: telnet 0" \
             "multicore mode : ${MODE}"; do
    if ! grep -qF "$key" "$CONFIG_FILE"; then
      echo "error: rendered config missing: $key" >&2
      exit 2
    fi
  done
  mkdir -p "$WORKDIR/log"
}

# R2-F11 port verification: -ftest shuts down BEFORE the listeners bind, so
# the OS-assigned ports are verified in a normal boot: start the driver
# without -ftest, wait for all four bind-time 'port 0 assigned' log lines
# (stdbuf keeps the stdout line-buffered so the log is live), then SIGTERM
# for a graceful shutdown. Sets PORTS_OK and ACTUAL_PORTS.
verify_ports() {
  local port_log="$WORKDIR/port-verify.log"
  # exec makes the timeout process the background pid itself, so SIGTERM
  # reaches timeout (which forwards it to the driver) instead of an orphaned
  # subshell.
  ( cd "$TESTSUITE_DIR" && exec timeout 60 stdbuf -oL "$DRIVER_ABS" "$CONFIG_FILE" </dev/null ) >"$port_log" 2>&1 &
  local port_pid=$!
  local port_ready="no"
  for _ in $(seq 1 600); do
    local port_count
    port_count=$(grep -c "port 0 assigned actual port" "$port_log" 2>/dev/null || true)
    if [ "$port_count" -ge 4 ]; then
      port_ready="yes"
      break
    fi
    if ! kill -0 "$port_pid" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  kill -TERM "$port_pid" 2>/dev/null || true
  wait "$port_pid" 2>/dev/null || true

  PORTS_OK="no"
  ACTUAL_PORTS="$(grep -oE 'Accepting [A-Za-z]+(\(TLS\))? connections on 127\.0\.0\.1:[0-9]+' "$port_log" 2>/dev/null | grep -oE '[0-9]+$' | sort -n | uniq | tr '\n' ' ' || true)"
  local actual_count
  actual_count=$(echo "$ACTUAL_PORTS" | wc -w)
  if [ "$actual_count" -eq 4 ]; then
    PORTS_OK="yes"
  fi
  if [ "$BIND_ALL" -eq 1 ]; then
    # Explicit network tests only: loopback is not required.
    PORTS_OK="yes"
  fi
  echo "== run-isolated: port verification: ready=$port_ready ports_ok=$PORTS_OK actual_ports=${ACTUAL_PORTS:-none} =="
  if [ "$PORTS_OK" != "yes" ]; then
    echo "== run-isolated: FAIL (port verification: ready=$port_ready ports_ok=$PORTS_OK) ==" >&2
    tail -n 20 "$port_log" | sed 's/^/  | /' >&2
    exit 1
  fi
}

if [ "$PORTS_ONLY" -eq 1 ]; then
  acquire_lock
  render_config
  release_lock
  echo "== run-isolated: ports-only mode (no LPC testsuite) =="
  verify_ports
  echo "== run-isolated: PASS (ports-only; four distinct loopback ports: ${ACTUAL_PORTS}) =="
  exit 0
fi

RC=1
ROUND=0
MAX_ROUNDS=5
while [ "$RC" -ne 0 ] && [ "$ROUND" -lt "$MAX_ROUNDS" ]; do
  ROUND=$((ROUND + 1))
  acquire_lock
  render_config
  release_lock

  echo "== run-isolated: round=${ROUND} ports OS-assigned (port 0), bind=${MUD_IP}, mode=${MODE} =="

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

# Acceptance: driver must exit 0, LPC assertions must have succeeded.
if [ "$RC" -ne 0 ] || [ "${ASSERT_OK:-}" != "yes" ]; then
  echo "== run-isolated: FAIL (exit=$RC assertions=${ASSERT_OK:-no}) ==" >&2
  exit 1
fi

verify_ports
echo "== run-isolated: PASS (LPC assertions ok; four distinct loopback ports: ${ACTUAL_PORTS}) =="
exit 0
