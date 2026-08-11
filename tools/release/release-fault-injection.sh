#!/usr/bin/env bash
# release-fault-injection.sh - dry-run fault injection tests for the release
# pipeline (R2-F08). Every injected fault must be caught by the read-only
# verification scripts; the mutation jobs must never start.
#
# Run: bash tools/release/release-fault-injection.sh
# Exit: 0 all faults caught; 1 a fault slipped through.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
FAIL=0

note_failure() {
  echo "FAIL: $1"
  FAIL=1
}

# --- fixture helpers -------------------------------------------------------
make_fixture_dir() {
  mktemp -d
}

VALID_SHA="$(printf 'a%.0s' {1..40})"
OTHER_SHA="$(printf 'b%.0s' {1..40})"
VALID_DIGEST="$(printf 'sha256:%064d' 1)"

write_valid_fixture() {
  local dir="$1"
  local asset
  for asset in \
    "fluffos-v1.0-linux-x86_64-static.tar.gz" \
    "fluffos-v1.0-windows-x86_64.zip"; do
    printf 'binary-data-%s\n' "$asset" > "$dir/$asset"
    (cd "$dir" && sha256sum "$asset" > "${asset}.sha256")
  done
  cp "$ROOT/third_party/sbom.json" "$dir/sbom.json"
  cp "$ROOT/third_party/manifest.yaml" "$dir/manifest.yaml"
  printf '%s\n' "$VALID_DIGEST" > "$dir/digest.txt"
  printf 'target_sha: %s\n' "$VALID_SHA" > "$dir/provenance.txt"
  python3 - "$dir/trivy.json" "$VALID_DIGEST" <<'PY'
import json, sys
with open(sys.argv[1], "w", encoding="utf-8") as out:
    json.dump({"FluffOSImageDigest": sys.argv[2], "Results": []}, out)
    out.write("\n")
PY
}

verify_fixture() {
  local dir="$1"
  local expected_sha="${2:-$VALID_SHA}"
  bash "$HERE/verify-release-inputs.sh" \
    --assets-dir "$dir" \
    --sbom "$dir/sbom.json" \
    --manifest "$dir/manifest.yaml" \
    --expected-sha "$expected_sha" \
    --digest-file "$dir/digest.txt" \
    --trivy-report "$dir/trivy.json"
}

# 1. Required-check verification: a missing check and a failed check must
#    both be detected (never treated as success).
echo "== 1. required checks: missing + failed conclusions =="
DATA_MISSING='{"check_runs": []}'
DATA_FAILED=$(python3 -c '
import json
print(json.dumps({"check_runs": [
  {"name": "Ubuntu GCC Debug", "conclusion": "failure"},
  {"name": "Docs Evidence & Links", "conclusion": "success"},
]}))
')
source "$HERE/common.sh"
if verify_required_checks "org/repo" "$VALID_SHA" <<<"$DATA_MISSING" >/dev/null 2>&1; then
  note_failure "missing required check was treated as green"
fi
if verify_required_checks "org/repo" "$VALID_SHA" <<<"$DATA_FAILED" >/dev/null 2>&1; then
  note_failure "failed required check was treated as green"
fi
if ! verify_required_checks "org/repo" "$VALID_SHA" <<<"$DATA_FAILED" >/dev/null 2>&1; then
  :
fi

# A rerun may leave multiple check-runs with the same display name. Selection
# must use the newest run identity, not API array order or an older green run.
DATA_RERUN='{"check_runs":[
  {"id":12,"name":"Ubuntu GCC Debug","started_at":"2026-08-11T02:00:00Z","conclusion":"success"},
  {"id":11,"name":"Ubuntu GCC Debug","started_at":"2026-08-11T01:00:00Z","conclusion":"failure"}
]}'
RERUN_RESULT="$(check_conclusion "org/repo" "$VALID_SHA" "Ubuntu GCC Debug" "$DATA_RERUN")"
if [ "${RERUN_RESULT##*$'\t'}" != "success" ]; then
  note_failure "newest successful rerun was not selected"
fi
DATA_PENDING='{"check_runs":[
  {"id":21,"name":"Ubuntu GCC Debug","started_at":"2026-08-11T03:00:00Z","conclusion":null},
  {"id":20,"name":"Ubuntu GCC Debug","started_at":"2026-08-11T02:00:00Z","conclusion":"success"}
]}'
PENDING_RESULT="$(check_conclusion "org/repo" "$VALID_SHA" "Ubuntu GCC Debug" "$DATA_PENDING")"
if [ "${PENDING_RESULT##*$'\t'}" != "in_progress" ]; then
  note_failure "newest in-progress rerun was hidden by an older success"
fi
DATA_PAGINATED='[
  {"check_runs":[
    {"id":30,"name":"Ubuntu GCC Debug","started_at":"2026-08-11T01:00:00Z","conclusion":"failure"}
  ]},
  {"check_runs":[
    {"id":31,"name":"Ubuntu GCC Debug","started_at":"2026-08-11T04:00:00Z","conclusion":"success"}
  ]}
]'
PAGINATED_RESULT="$(check_conclusion "org/repo" "$VALID_SHA" "Ubuntu GCC Debug" "$DATA_PAGINATED")"
if [ "${PAGINATED_RESULT##*$'\t'}" != "success" ]; then
  note_failure "newest check from a later API page was not selected"
fi

# 2. Image name normalization: uppercase repo names must be lowercased.
echo "== 2. image name normalization =="
NORMALIZED="$(normalize_image_name "FengYunCalm/Fluffos_XK")"
if [ "$NORMALIZED" != "fengyuncalm/fluffos_xk" ]; then
  note_failure "normalize_image_name returned $NORMALIZED"
fi

# 3. The shared fixture must pass before any fault is injected. Otherwise a
#    later negative could be a false positive caused by an unrelated omission.
echo "== 3. valid release input baseline =="
D=$(make_fixture_dir)
write_valid_fixture "$D"
if ! verify_fixture "$D" >/dev/null 2>&1; then
  note_failure "valid release fixture failed verification"
fi
rm -rf "$D"

# 4. verify-release-inputs: modified checksum must fail.
echo "== 4. modified checksum =="
D=$(make_fixture_dir)
write_valid_fixture "$D"
echo "tampered" >> "$D/fluffos-v1.0-linux-x86_64-static.tar.gz"
if verify_fixture "$D" >/dev/null 2>&1; then
  note_failure "modified checksum passed verification"
fi
rm -rf "$D"

# 5. verify-release-inputs: digest <-> scan binding mismatch must fail.
echo "== 5. digest/scan binding mismatch =="
D=$(make_fixture_dir)
write_valid_fixture "$D"
python3 - "$D/trivy.json" <<'PY'
import json, sys
with open(sys.argv[1], "w", encoding="utf-8") as out:
    json.dump({"FluffOSImageDigest": "sha256:" + "0" * 64, "Results": []}, out)
    out.write("\n")
PY
if verify_fixture "$D" >/dev/null 2>&1; then
  note_failure "digest/scan mismatch passed verification"
fi
rm -rf "$D"

# 6. verify-release-inputs: a different target SHA in provenance must fail.
echo "== 6. provenance SHA mismatch =="
D=$(make_fixture_dir)
write_valid_fixture "$D"
printf 'target_sha: %s\n' "$OTHER_SHA" > "$D/provenance.txt"
if verify_fixture "$D" "$VALID_SHA" >/dev/null 2>&1; then
  note_failure "provenance SHA mismatch passed verification"
fi
rm -rf "$D"

# 7. verify-release-inputs: the exact release SBOM copy must match the full
#    manifest, including vendored components. Removing one component from the
#    copied asset must fail even when the repository SBOM remains valid.
echo "== 7. release SBOM copy missing vendored component =="
D=$(make_fixture_dir)
write_valid_fixture "$D"
python3 - "$D/sbom.json" <<'PY'
import json, sys
sbom = json.load(open(sys.argv[1], encoding="utf-8"))
sbom["components"] = [
    component for component in sbom.get("components", [])
    if component.get("name") != "libevent"
]
with open(sys.argv[1], "w", encoding="utf-8") as out:
    json.dump(sbom, out, indent=2)
    out.write("\n")
PY
if verify_fixture "$D" >/dev/null 2>&1; then
  note_failure "release SBOM copy missing a vendored component passed verification"
fi
rm -rf "$D"

# 8. The uploaded manifest must be the exact copy from the target checkout.
echo "== 8. release manifest copy mismatch =="
D=$(make_fixture_dir)
write_valid_fixture "$D"
printf '\n# injected drift\n' >> "$D/manifest.yaml"
if verify_fixture "$D" >/dev/null 2>&1; then
  note_failure "modified release manifest passed verification"
fi
rm -rf "$D"

# 9. dry-run guard: mutation helpers must refuse to run in dry_run mode.
echo "== 9. dry-run mutation guard =="
source "$HERE/common.sh"
if RELEASE_DRY_RUN=1 assert_dry_run "push tag" >/dev/null 2>&1; then
  note_failure "dry-run guard allowed a mutation"
fi
if RELEASE_DRY_RUN=0 assert_dry_run "push tag" >/dev/null 2>&1; then
  :
else
  note_failure "non-dry-run guard rejected a mutation"
fi

if [ "$FAIL" -ne 0 ]; then
  echo "release-fault-injection: FAILED"
  exit 1
fi
echo "release-fault-injection: OK (all injected faults caught)"
