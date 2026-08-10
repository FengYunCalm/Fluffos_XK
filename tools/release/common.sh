#!/usr/bin/env bash
# Shared helpers for the release pipeline (R2-F08).
#
# Every release decision lives in a script so the workflow only orchestrates
# permissions and DAG edges. All scripts are dry-run safe: they read inputs,
# verify, and exit nonzero on failure without ever writing to the registry,
# tags or releases.
set -euo pipefail

# Canonical required-check set for a releaseable SHA. This is the FULL gate
# list maintained by the release policy itself - never the (possibly
# smaller) branch-protection minimum. Each entry is a stable job display
# name from ci.yml / the other workflows. Missing, queued, cancelled,
# neutral, skipped or failed conclusions are all failures.
RELEASE_REQUIRED_CHECKS=(
  "Workflow Lint (actionlint + parse + repo tests)"
  "Docs Evidence & Links"
  "Evidence Gate (non-empty, schema + HEAD)"
  "Fuzz (libFuzzer gateway_fuzz, clang)"
  "Ubuntu GCC Debug"
  "Ubuntu GCC RelWithDebInfo"
  "Ubuntu Clang Debug"
  "Ubuntu Clang RelWithDebInfo"
  "Ubuntu Clang ASan Debug"
  "Ubuntu Clang ASan RelWithDebInfo"
  "Ubuntu Clang UBSan Debug"
  "Ubuntu Clang TSan Debug"
  "macOS Debug"
  "macOS RelWithDebInfo"
  "Windows Debug"
  "Windows RelWithDebInfo"
  "Analyze (cpp)"
  "Build Docker Image (no push)"
)

# Normalize a GitHub repository name to lowercase (registry references are
# lowercased by Docker; ${{ github.repository }} preserves display case).
normalize_image_name() {
  echo "${1,,}"
}

# Resolve the status of one named check on a commit. Prints
# "name<TAB>conclusion" or "name<TAB>missing". Uses the check-runs API
# (JSON, no space-splitting of context names).
check_conclusion() {
  local repo="$1" sha="$2" name="$3" data="$4"
  python3 -c '
import json, sys
name = sys.argv[1]
data = json.loads(sys.argv[2])
runs = [r for r in data.get("check_runs", []) if r.get("name") == name]
if not runs:
    print(name + "\tmissing")
    sys.exit(0)
print(name + "\t" + (runs[-1].get("conclusion") or "in_progress"))
' "$name" "$data"
}

# Verify every required check on a SHA is green. Reads check-runs JSON from
# stdin. Exit 1 on any missing/non-success conclusion.
verify_required_checks() {
  local repo="$1" sha="$2" data
  data="$(cat)"
  local failed=0
  for name in "${RELEASE_REQUIRED_CHECKS[@]}"; do
    local conclusion
    conclusion="$(check_conclusion "$repo" "$sha" "$name" "$data")"
    local verdict="${conclusion##*$'\t'}"
    echo "  $name: $verdict"
    if [ "$verdict" != "success" ]; then
      failed=1
    fi
  done
  if [ "$failed" -ne 0 ]; then
    echo "FAIL: required checks are not all green on $sha" >&2
    return 1
  fi
  echo "PASS: all $((${#RELEASE_REQUIRED_CHECKS[@]})) required checks green on $sha"
}

# Fail when the local shell is not allowed to mutate anything (dry-run).
assert_dry_run() {
  if [ "${RELEASE_DRY_RUN:-0}" = "1" ]; then
    echo "FAIL: dry_run mode: refusing $1" >&2
    return 1
  fi
  return 0
}
