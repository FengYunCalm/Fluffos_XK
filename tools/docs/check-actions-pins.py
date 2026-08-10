#!/usr/bin/env python3
"""Verify every `uses:` reference in GitHub Actions workflows is declared in
third_party/manifest.yaml (T08 supply-chain gate).

Scans .github/workflows/*.yml for `uses: owner/repo@ref` lines and checks:

1. every action reference appears in the manifest's github-actions entries;
2. no manifest entry is stale (references an action no workflow uses).

Exit codes:
  0: all references declared and all entries used
  1: an undeclared reference or an unused entry was found

Usage: tools/docs/check-actions-pins.py [--manifest third_party/manifest.yaml]
"""

import argparse
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required: pip install pyyaml\n")
    sys.exit(2)

USES_RE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.M)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="third_party/manifest.yaml")
    parser.add_argument("--workflows-dir", default=".github/workflows")
    args = parser.parse_args()

    with open(args.manifest, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    declared = set()
    for tc in manifest.get("toolchain", []):
        if tc.get("name") != "github-actions":
            continue
        for entry in tc.get("entries", []):
            declared.add(entry)

    used = set()
    if os.path.isdir(args.workflows_dir):
        for fname in sorted(os.listdir(args.workflows_dir)):
            if not fname.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(args.workflows_dir, fname)
            with open(path, encoding="utf-8") as f:
                for match in USES_RE.finditer(f.read()):
                    used.add(match.group(1))

    errors = []
    for ref in sorted(used - declared):
        errors.append(f"undeclared action reference: {ref}")
    for entry in sorted(declared - used):
        errors.append(f"manifest entry not used by any workflow: {entry}")

    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        return 1
    print(f"check-actions-pins: OK ({len(declared)} declared, {len(used)} used)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
