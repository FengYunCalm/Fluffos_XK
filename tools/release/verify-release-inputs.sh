#!/usr/bin/env bash
# verify-release-inputs.sh - read-only release asset verification (R2-F08).
#
# Verifies, WITHOUT any write permission:
#   1. every binary asset has a matching checksum file and the checksums
#      verify;
#   2. the CycloneDX SBOM parses and validates against the official schema;
#   3. the SBOM's components match the third-party manifest;
#   4. the recorded target SHA appears in the provenance summary;
#   5. the OCI digest file matches the digest recorded for the scan.
#
# Usage:
#   verify-release-inputs.sh --assets-dir DIR --sbom PATH --manifest PATH \
#       --expected-sha SHA --digest-file PATH --trivy-report PATH
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

ASSETS_DIR=""
SBOM=""
MANIFEST=""
EXPECTED_SHA=""
DIGEST_FILE=""
TRIVY_REPORT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --assets-dir) ASSETS_DIR="$2"; shift 2 ;;
    --sbom) SBOM="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --expected-sha) EXPECTED_SHA="$2"; shift 2 ;;
    --digest-file) DIGEST_FILE="$2"; shift 2 ;;
    --trivy-report) TRIVY_REPORT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$ASSETS_DIR" ] && [ -n "$SBOM" ] && [ -n "$MANIFEST" ] && [ -n "$EXPECTED_SHA" ] \
  && [ -n "$DIGEST_FILE" ] && [ -n "$TRIVY_REPORT" ] || {
  echo "usage: $0 --assets-dir DIR --sbom PATH --manifest PATH --expected-sha SHA --digest-file PATH --trivy-report PATH" >&2
  exit 2
}

fail=0

echo "== 1. asset checksums =="
found_asset=0
found_linux=0
found_windows=0
for bin in "$ASSETS_DIR"/fluffos-*.tar.gz "$ASSETS_DIR"/fluffos-*.zip; do
  [ -f "$bin" ] || continue
  found_asset=1
  case "$bin" in
    *-linux-x86_64-static.tar.gz) found_linux=1 ;;
    *-windows-x86_64.zip) found_windows=1 ;;
  esac
  sha="${bin}.sha256"
  if [ ! -f "$sha" ]; then
    echo "FAIL: no checksum for $(basename "$bin")" >&2
    fail=1
    continue
  fi
  if [ "$(wc -l < "$sha")" -ne 1 ]; then
    echo "FAIL: checksum file must contain exactly one record: $(basename "$sha")" >&2
    fail=1
    continue
  fi
  checksum_target="$(awk 'NR == 1 { print $2 }' "$sha")"
  checksum_target="${checksum_target#\*}"
  if [ "$checksum_target" != "$(basename "$bin")" ]; then
    echo "FAIL: checksum target must be the local asset basename: $(basename "$sha")" >&2
    fail=1
    continue
  fi
  (cd "$ASSETS_DIR" && sha256sum -c "$(basename "$sha")") || fail=1
done
[ "$found_asset" -eq 1 ] || { echo "FAIL: no release binary assets found in $ASSETS_DIR" >&2; fail=1; }
[ "$found_linux" -eq 1 ] || { echo "FAIL: Linux release asset is missing" >&2; fail=1; }
[ "$found_windows" -eq 1 ] || { echo "FAIL: Windows release asset is missing" >&2; fail=1; }

echo "== 2. SBOM CycloneDX schema =="
EXPECTED_SBOM="$(mktemp)"
trap 'rm -f "$EXPECTED_SBOM"' EXIT
if ! cmp -s "$MANIFEST" "$ROOT_DIR/third_party/manifest.yaml"; then
  echo "FAIL: release manifest copy differs from the target checkout" >&2
  fail=1
fi
python3 "$ROOT_DIR/tools/sbom-generate.py" --manifest "$MANIFEST" --out "$EXPECTED_SBOM" --validate || fail=1

echo "== 3. exact release SBOM <-> manifest consistency =="
python3 - "$SBOM" "$EXPECTED_SBOM" <<'PY' || fail=1
import json, sys

try:
    actual = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as error:
    print(f"FAIL: release SBOM unreadable: {error}")
    sys.exit(1)

expected = json.load(open(sys.argv[2], encoding="utf-8"))
if actual != expected:
    def identities(sbom):
        return {
            (component.get("type"), component.get("name"), component.get("version"))
            for component in sbom.get("components", [])
        }

    actual_ids = identities(actual)
    expected_ids = identities(expected)
    missing = sorted(expected_ids - actual_ids)
    unexpected = sorted(actual_ids - expected_ids)
    if missing:
        print(f"FAIL: release SBOM missing manifest components: {missing}")
    if unexpected:
        print(f"FAIL: release SBOM contains unexpected components: {unexpected}")
    if not missing and not unexpected:
        print("FAIL: release SBOM component metadata or document metadata differs from the manifest-generated SBOM")
    sys.exit(1)

print(f"PASS: release SBOM exactly matches {len(expected.get('components', []))} manifest-generated components")
PY

echo "== 4. provenance / target SHA binding =="
if [[ ! "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "FAIL: expected target SHA must be exactly 40 lowercase hex characters" >&2
  fail=1
fi
grep -Fqx "target_sha: $EXPECTED_SHA" "$ASSETS_DIR"/provenance.txt || {
  echo "FAIL: provenance.txt does not record target SHA $EXPECTED_SHA" >&2
  fail=1
}

echo "== 5. OCI digest <-> scan binding =="
[ -f "$DIGEST_FILE" ] || { echo "FAIL: digest file missing: $DIGEST_FILE" >&2; fail=1; }
recorded_digest="$(tr -d ' \n' < "$DIGEST_FILE")"
if [[ ! "$recorded_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "FAIL: digest file content is not an exact sha256 digest: $recorded_digest" >&2
  fail=1
fi
python3 - "$TRIVY_REPORT" "$recorded_digest" <<'PY' || fail=1
import json, sys
try:
    report = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print(f"FAIL: trivy report unreadable: {e}")
    sys.exit(1)
digest = sys.argv[2]
# The workflow records the independently inspected archive digest after Trivy
# writes its report. Require that exact, dedicated binding field; accepting a
# matching string anywhere in arbitrary report data would be ambiguous.
bound_digest = report.get("FluffOSImageDigest")
if bound_digest != digest:
    print(f"FAIL: trivy report digest binding {bound_digest!r} != {digest}")
    sys.exit(1)
print(f"PASS: trivy report bound to {digest[:20]}...")
PY

if [ "$fail" -ne 0 ]; then
  echo "FAIL: release inputs verification failed" >&2
  exit 1
fi
echo "PASS: release inputs verified (checksums, SBOM, provenance, digest binding)"
