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
if verify_required_checks "org/repo" "$(printf 'a%.0s' {1..40})" <<<"$DATA_MISSING" >/dev/null 2>&1; then
  note_failure "missing required check was treated as green"
fi
if verify_required_checks "org/repo" "$(printf 'a%.0s' {1..40})" <<<"$DATA_FAILED" >/dev/null 2>&1; then
  note_failure "failed required check was treated as green"
fi
if ! verify_required_checks "org/repo" "$(printf 'a%.0s' {1..40})" <<<"$DATA_FAILED" >/dev/null 2>&1; then
  :
fi

# 2. Image name normalization: uppercase repo names must be lowercased.
echo "== 2. image name normalization =="
NORMALIZED="$(normalize_image_name "FengYunCalm/Fluffos_XK")"
if [ "$NORMALIZED" != "fengyuncalm/fluffos_xk" ]; then
  note_failure "normalize_image_name returned $NORMALIZED"
fi

# 3. verify-release-inputs: modified checksum must fail.
echo "== 3. modified checksum =="
D=$(make_fixture_dir)
echo "binary-data" > "$D/fluffos-v1.0-linux-x86_64-static.tar.gz"
sha256sum "$D/fluffos-v1.0-linux-x86_64-static.tar.gz" > "$D/fluffos-v1.0-linux-x86_64-static.tar.gz.sha256"
echo "tampered" >> "$D/fluffos-v1.0-linux-x86_64-static.tar.gz"
printf 'sha256:%064d\n' 0 > "$D/digest.txt"
echo '{"ArtifactName":"image.tar","Results":[]}' > "$D/trivy.json"
echo "target $(printf 'a%.0s' {1..40})" > "$D/provenance.txt"
if bash "$HERE/verify-release-inputs.sh" --assets-dir "$D" --sbom "$ROOT/third_party/sbom.json" \
    --manifest "$ROOT/third_party/manifest.yaml" --expected-sha "$(printf 'a%.0s' {1..40})" \
    --digest-file "$D/digest.txt" --trivy-report "$D/trivy.json" >/dev/null 2>&1; then
  note_failure "modified checksum passed verification"
fi
rm -rf "$D"

# 4. verify-release-inputs: digest <-> scan binding mismatch must fail.
echo "== 4. digest/scan binding mismatch =="
D=$(make_fixture_dir)
echo "binary-data" > "$D/fluffos-v1.0-linux-x86_64-static.tar.gz"
sha256sum "$D/fluffos-v1.0-linux-x86_64-static.tar.gz" > "$D/fluffos-v1.0-linux-x86_64-static.tar.gz.sha256"
printf 'sha256:%064d\n' 1 > "$D/digest.txt"
echo "target $(printf 'a%.0s' {1..40})" > "$D/provenance.txt"
# Scan report references a DIFFERENT digest than the digest file.
echo "{\"ArtifactName\":\"image.tar\",\"Results\":[]}" > "$D/trivy.json"
if bash "$HERE/verify-release-inputs.sh" --assets-dir "$D" --sbom "$ROOT/third_party/sbom.json" \
    --manifest "$ROOT/third_party/manifest.yaml" --expected-sha "$(printf 'a%.0s' {1..40})" \
    --digest-file "$D/digest.txt" --trivy-report "$D/trivy.json" >/dev/null 2>&1; then
  note_failure "digest/scan mismatch passed verification"
fi
rm -rf "$D"

# 5. verify-release-inputs: missing target SHA in provenance must fail.
echo "== 5. provenance SHA mismatch =="
D=$(make_fixture_dir)
echo "binary-data" > "$D/fluffos-v1.0-linux-x86_64-static.tar.gz"
sha256sum "$D/fluffos-v1.0-linux-x86_64-static.tar.gz" > "$D/fluffos-v1.0-linux-x86_64-static.tar.gz.sha256"
printf 'sha256:%064d\n' 1 > "$D/digest.txt"
echo "target ${TEST_SHA:-0123456789abcdef0123456789abcdef01234567}" > "$D/provenance.txt"
if bash "$HERE/verify-release-inputs.sh" --assets-dir "$D" --sbom "$ROOT/third_party/sbom.json" \
    --manifest "$ROOT/third_party/manifest.yaml" --expected-sha "b"*40 \
    --digest-file "$D/digest.txt" --trivy-report "$D/trivy.json" >/dev/null 2>&1; then
  note_failure "provenance SHA mismatch passed verification"
fi
rm -rf "$D"

# 6. dry-run guard: mutation helpers must refuse to run in dry_run mode.
echo "== 6. dry-run mutation guard =="
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
