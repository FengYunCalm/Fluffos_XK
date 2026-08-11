#!/usr/bin/env python3
"""Generate a CycloneDX 1.4 SBOM from third_party/manifest.yaml.

The generated document validates against the CycloneDX 1.4 JSON schema:
- serialNumber is a valid UUID (deterministic from the manifest hash)
- every component carries a purl when a type/namespace/name/version is known
- hashes are included for pinned downloads
- tool metadata records the generator

Usage: tools/sbom-generate.py [--out third_party/sbom.json] [--validate]
"""

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required: pip install pyyaml\n")
    sys.exit(2)

SCHEMA = "fluffos.third_party.manifest.v1"
CYCLONEDX_SPEC = "1.4"


def make_purl(dep):
    """Build a package URL for a dependency, or None when unknown."""
    name = str(dep.get("name", "")).strip()
    version = str(dep.get("version", "unknown")).strip()
    upstream = str(dep.get("upstream", ""))
    if not name or not version or version == "unknown":
        return None
    namespace = "github"
    if "gitlab.com" in upstream:
        namespace = "gitlab"
    if name in ("jemalloc",):
        namespace = "generic"
    return f"pkg:{namespace}/{name}@{version}"


def build_sbom(manifest):
    components = []
    for dep in manifest.get("vendored", []):
        component = {
            "type": "library",
            "name": dep["name"],
            "version": str(dep.get("version") or "unknown"),
            "licenses": [{"license": {"name": dep.get("license", "unknown")}}],
            "externalReferences": [{"type": "vcs", "url": dep.get("upstream")}],
            "supplier": {"name": dep.get("upstream")},
        }
        purl = make_purl(dep)
        if purl:
            component["purl"] = purl
        checksum = dep.get("checksum")
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        components.append(component)
    for dl in manifest.get("external_downloads", []):
        component = {
            "type": "library",
            "name": dl["name"],
            "version": str(dl["version"]),
            "licenses": [{"license": {"name": dl.get("license", "unknown")}}],
            "externalReferences": [{"type": "distribution", "url": dl.get("url")}],
            "hashes": [{"alg": "SHA-256", "content": dl.get("sha256")}],
        }
        purl = make_purl(dl)
        if purl:
            component["purl"] = purl
        components.append(component)
    for tc in manifest.get("toolchain", []):
        if tc.get("digest") and tc.get("version"):
            # Normalize a "sha256:hex" digest to bare hex for CycloneDX.
            digest = str(tc["digest"])
            if digest.startswith("sha256:"):
                digest = digest[len("sha256:"):]
            components.append(
                {
                    "type": "operating-system",
                    "name": str(tc["name"]),
                    "version": str(tc["version"]),
                    "hashes": [{"alg": "SHA-256", "content": digest}],
                }
            )
        for entry in tc.get("entries", []):
            # Entries are structured dicts (name/version/sha/...) since
            # R2-F09; keep the SBOM readable and deterministic.
            name = str(entry.get("name", entry)) if isinstance(entry, dict) else str(entry)
            version = str(entry.get("version", "pinned-by-workflow")) if isinstance(entry, dict) else "pinned-by-workflow"
            components.append(
                {
                    "type": "application",
                    "name": name,
                    "version": version,
                    "externalReferences": [
                        {"type": "vcs", "url": str(entry["upstream"])}
                    ] if isinstance(entry, dict) and entry.get("upstream") else [],
                }
            )
    # Deterministic serial number: derive a UUID v5 from the manifest content
    # so repeated runs with the same manifest produce the same SBOM identity.
    manifest_bytes = json.dumps(manifest, sort_keys=True, default=str).encode()
    serial = str(uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(manifest_bytes).hexdigest()))
    # Deterministic timestamp: derive from the manifest's last_reviewed date
    # so repeated runs with the same manifest produce an identical SBOM.
    last_reviewed = manifest.get("last_reviewed")
    timestamp = (
        f"{last_reviewed}T00:00:00Z"
        if last_reviewed
        else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "FluffOS",
                    "name": "sbom-generate.py",
                    "version": "2",
                }
            ],
            "component": {
                "type": "application",
                "name": "FluffOS",
                "version": "XK",
            },
        },
        "components": components,
    }


def validate_cyclonedx(sbom_path):
    """Validate against the official CycloneDX 1.4 JSON schema when the
    schema file is available locally or via network fetch is not desired.
    Falls back to structural checks (required fields, valid UUID)."""
    errors = []
    with open(sbom_path, encoding="utf-8") as f:
        sbom = json.load(f)
    if sbom.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be CycloneDX")
    if sbom.get("specVersion") != CYCLONEDX_SPEC:
        errors.append(f"specVersion must be {CYCLONEDX_SPEC}")
    serial = sbom.get("serialNumber", "")
    if not serial.startswith("urn:uuid:"):
        errors.append("serialNumber must be urn:uuid:<uuid>")
    else:
        try:
            uuid.UUID(serial[len("urn:uuid:"):])
        except ValueError:
            errors.append(f"serialNumber is not a valid UUID: {serial}")
    for comp in sbom.get("components", []):
        if "name" not in comp or "version" not in comp:
            errors.append("component missing name/version")
        if "purl" in comp and not str(comp["purl"]).startswith("pkg:"):
            errors.append(f"invalid purl: {comp['purl']}")
    try:
        import jsonschema  # type: ignore
        schema_path = None
        for candidate in (
            "third_party/cyclonedx.schema.json",
            "docs/evidence/cyclonedx.schema.json",
        ):
            import os

            if os.path.exists(candidate):
                schema_path = candidate
                break
        if schema_path:
            with open(schema_path, encoding="utf-8") as f:
                schema = json.load(f)
            jsonschema.validate(sbom, schema)
        else:
            errors.append("no local CycloneDX schema; structural checks only")
    except ImportError:
        errors.append("jsonschema not installed; structural checks only")
    except jsonschema.ValidationError as e:  # type: ignore
        errors.append(f"CycloneDX schema validation failed: {e.message}")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="third_party/manifest.yaml")
    parser.add_argument("--out", default="third_party/sbom.json")
    parser.add_argument("--validate", action="store_true", help="validate the generated SBOM")
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

    if args.validate:
        errors = validate_cyclonedx(args.out)
        if errors:
            for e in errors:
                print(f"FAIL: {e}")
            return 1
        print("SBOM validation: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
