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
for sha in "$ASSETS_DIR"/*.sha256; do
  [ -e "$sha" ] || continue
  found_asset=1
  (cd "$ASSETS_DIR" && sha256sum -c "$(basename "$sha")")
done
for bin in "$ASSETS_DIR"/fluffos-*; do
  [ -e "$bin" ] || continue
  case "$bin" in *.sha256) continue ;; esac
  grep -q "$(basename "$bin")" "$ASSETS_DIR"/*.sha256 || {
    echo "FAIL: no checksum for $(basename "$bin")" >&2
    fail=1
  }
done
[ "$found_asset" -eq 1 ] || { echo "FAIL: no checksum files found in $ASSETS_DIR" >&2; fail=1; }

echo "== 2. SBOM CycloneDX schema =="
python3 tools/sbom-generate.py --validate || fail=1

echo "== 3. manifest <-> SBOM consistency =="
python3 - "$SBOM" "$MANIFEST" <<'PY' || fail=1
import json, sys, yaml
sbom = json.load(open(sys.argv[1], encoding="utf-8"))
manifest = yaml.safe_load(open(sys.argv[2], encoding="utf-8"))
sbom_names = {c.get("name") for c in sbom.get("components", [])}
manifest_names = set()
for tc in manifest.get("toolchain", []):
    if tc.get("name") == "github-actions":
        for e in tc.get("entries", []):
            manifest_names.add(e["name"])
for dl in manifest.get("external_downloads", []):
    manifest_names.add(dl["name"])
missing = manifest_names - sbom_names
if missing:
    print(f"FAIL: manifest components missing from SBOM: {sorted(missing)}")
    sys.exit(1)
print(f"PASS: SBOM covers {len(manifest_names)} manifest components")
PY

echo "== 4. provenance / target SHA binding =="
grep -q "$EXPECTED_SHA" "$ASSETS_DIR"/provenance.txt || {
  echo "FAIL: provenance.txt does not record target SHA $EXPECTED_SHA" >&2
  fail=1
}

echo "== 5. OCI digest <-> scan binding =="
[ -f "$DIGEST_FILE" ] || { echo "FAIL: digest file missing: $DIGEST_FILE" >&2; fail=1; }
recorded_digest="$(cat "$DIGEST_FILE" | tr -d ' \n')"
case "$recorded_digest" in sha256:[0-9a-f]*) ;; *)
  echo "FAIL: digest file content is not sha256:hex: $recorded_digest" >&2; fail=1 ;;
esac
python3 - "$TRIVY_REPORT" "$recorded_digest" <<'PY' || fail=1
import json, sys
try:
    report = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print(f"FAIL: trivy report unreadable: {e}")
    sys.exit(1)
digest = sys.argv[2]
# The scan report must reference the exact digest it scanned.
found = json.dumps(report).find(digest) != -1
if not found:
    print(f"FAIL: trivy report does not reference scanned digest {digest}")
    sys.exit(1)
print(f"PASS: trivy report bound to {digest[:20]}...")
PY

if [ "$fail" -ne 0 ]; then
  echo "FAIL: release inputs verification failed" >&2
  exit 1
fi
echo "PASS: release inputs verified (checksums, SBOM, provenance, digest binding)"
