#!/usr/bin/env python3
"""Generate a CycloneDX-ish SBOM from third_party/manifest.yaml.

The repository has no pinned SBOM tool, so this script emits a minimal
JSON SBOM (CycloneDX 1.4 component subset) from the single source of
truth manifest. CI can later swap in cyclonedx-bom; the manifest stays
the canonical inventory.

Usage: tools/sbom-generate.py [--out third_party/sbom.json]
"""

import argparse
import json
import sys
from datetime import date

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required: pip install pyyaml\n")
    sys.exit(2)

SCHEMA = "fluffos.third_party.manifest.v1"


def build_sbom(manifest):
    components = []
    for dep in manifest.get("vendored", []):
        components.append(
            {
                "type": "library",
                "name": dep["name"],
                "version": dep.get("version") or "unknown",
                "purl": None,
                "licenses": [{"license": {"name": dep.get("license")}}],
                "externalReferences": [
                    {"type": "vcs", "url": dep.get("upstream")}
                ],
                "supplier": {"name": dep.get("upstream")},
            }
        )
    for dl in manifest.get("external_downloads", []):
        components.append(
            {
                "type": "library",
                "name": dl["name"],
                "version": dl["version"],
                "purl": None,
                "licenses": [{"license": {"name": dl.get("license")}}],
                "externalReferences": [
                    {"type": "distribution", "url": dl.get("url")}
                ],
                "hashes": [{"alg": "SHA-256", "content": dl.get("sha256")}],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{date.today().isoformat()}-fluffos-sbom",
        "version": 1,
        "metadata": {
            "timestamp": date.today().isoformat() + "T00:00:00Z",
            "tools": [{"vendor": "FluffOS", "name": "sbom-generate.py"}],
        },
        "components": components,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="third_party/manifest.yaml")
    parser.add_argument("--out", default="third_party/sbom.json")
    args = parser.parse_args()

    with open(args.manifest, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    if manifest.get("schema") != SCHEMA:
        sys.stderr.write(f"unexpected manifest schema: {manifest.get('schema')}\n")
        sys.exit(1)

    sbom = build_sbom(manifest)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"SBOM written: {args.out} ({len(sbom['components'])} components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
