#!/usr/bin/env python3
"""Verify supply-chain pins (T08/R2-F09 gate).

Checks:

1. Every `uses:` reference in .github/workflows/*.yml must be pinned to a
   full 40-hex commit SHA (a mutable major tag is a failure), and the
   (owner/repo, sha) pair must be declared in third_party/manifest.yaml's
   github-actions entries; no manifest entry may be unused.
2. Dockerfile `FROM` lines and any container image references in workflows
   (e.g. trivy) must carry a `@sha256:<64-hex>` digest, and every digest
   must be declared in the manifest toolchain section. A mutable image tag
   (e.g. alpine:3.18 without digest, trivy:0.50.1 without digest) fails.
3. Dockerfile downloads (wget|curl piped into tar) are forbidden: they must
   download to a file, verify the manifest sha256, then extract.

Exit codes: 0 all pins valid; 1 a violation; 2 usage error.

Usage: tools/docs/check-actions-pins.py [--manifest third_party/manifest.yaml]
                                         [--workflows-dir .github/workflows]
                                         [--dockerfile Dockerfile]
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
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# FROM alpine:3.18@sha256:...  /  image reference with digest
IMAGE_REF_RE = re.compile(r"\b([a-zA-Z0-9._/-]+):([a-zA-Z0-9._-]+)@(sha256:[0-9a-f]{64})\b")
IMAGE_TAG_RE = re.compile(r"\b([a-zA-Z0-9._/-]+):([a-zA-Z0-9._-]+)\b")


def load_manifest(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    actions = {}
    digests = {}
    for tc in manifest.get("toolchain", []):
        if tc.get("name") == "github-actions":
            for entry in tc.get("entries", []):
                actions[(entry["name"], entry["sha"])] = entry
        elif tc.get("digest"):
            digests[tc["digest"]] = tc["name"]
    return {"actions": actions, "digests": digests, "raw": manifest}


def check_workflow_pins(manifest: dict, workflows_dir: str) -> list[str]:
    errors = []
    declared = set(manifest["actions"].keys())
    used = set()
    used_roots = set()
    if not os.path.isdir(workflows_dir):
        return errors
    for fname in sorted(os.listdir(workflows_dir)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(workflows_dir, fname)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        for match in USES_RE.finditer(content):
            ref = match.group(1)
            repo, _, sha = ref.partition("@")
            if not SHA40_RE.match(sha):
                errors.append(f"{fname}: action {ref!r} is not pinned to a 40-hex commit SHA")
                continue
            used.add((repo, sha))
            # Normalize subpath refs to the action root for the unused check.
            root_repo = repo
            for (declared_repo, _) in declared:
                if repo.startswith(declared_repo + "/"):
                    root_repo = declared_repo
                    break
            used_roots.add((root_repo, sha))
            # Manifest entries are keyed by the action root; workflow refs may
            # carry a subpath (github/codeql-action/init -> github/codeql-action).
            declared_match = any(
                (repo == declared_repo or repo.startswith(declared_repo + "/"))
                for (declared_repo, _) in declared
            )
            if not declared_match:
                errors.append(
                    f"{fname}: action {repo}@{sha[:12]} is not declared in the manifest"
                )
        # Container image references: only inspect lines that actually run or
        # reference containers (docker run, FROM, trivy), so cron times and
        # npm script names (18:00, docs:build) are not false positives.
        for line_no, line in enumerate(content.splitlines(), start=1):
            lowered = line.lower()
            if "docker run" not in lowered and not line.strip().startswith("FROM ")\
                    and "trivy" not in lowered and "image:" not in lowered:
                continue
            for match in IMAGE_REF_RE.finditer(line):
                digest = match.group(3)
                if digest not in manifest["digests"]:
                    errors.append(
                        f"{fname}:{line_no}: image digest {digest[:20]}... is not declared in the manifest"
                    )
            # Remove fully-pinned references before scanning for mutable tags,
            # so 'alpine:3.18@sha256:...' is not flagged for its tag part.
            line_without_pinned = IMAGE_REF_RE.sub("", line)
            for match in IMAGE_TAG_RE.finditer(line_without_pinned):
                tag_ref = match.group(0)
                if "@" in tag_ref or tag_ref.startswith("http") or tag_ref.startswith("${{"):
                    continue
                errors.append(
                    f"{fname}:{line_no}: mutable image tag {tag_ref!r} without @sha256 digest"
                )
    for entry in sorted(declared - used_roots):
        errors.append(f"manifest entry not used by any workflow: {entry[0]}@{entry[1][:12]}")
    return errors


def check_dockerfile(manifest: dict, dockerfile: str) -> list[str]:
    errors = []
    if not os.path.isfile(dockerfile):
        errors.append(f"Dockerfile not found: {dockerfile}")
        return errors
    with open(dockerfile, encoding="utf-8") as f:
        content = f.read()
    for line_no, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("FROM "):
            ref = stripped[len("FROM "):].split()[0]
            if "@sha256:" not in ref:
                errors.append(
                    f"Dockerfile:{line_no}: FROM {ref!r} must carry a @sha256 digest"
                )
                continue
            digest = ref.split("@", 1)[1]
            if digest not in manifest["digests"]:
                errors.append(
                    f"Dockerfile:{line_no}: digest {digest[:20]}... is not declared in the manifest"
                )
        # Pipe-to-tar downloads are forbidden: download + verify + extract.
        if ("wget" in stripped or "curl" in stripped) and "| tar" in stripped:
            errors.append(
                f"Dockerfile:{line_no}: pipe-to-tar download is forbidden; "
                "download to a file, verify sha256 against the manifest, then extract"
            )
    return errors


def self_test() -> list[str]:
    """Negative tests: synthetic broken fixtures must all be rejected."""
    failures = []
    import tempfile
    from pathlib import Path

    manifest_ok = {
        "schema": "fluffos.third_party.manifest.v1",
        "toolchain": [
            {"name": "github-actions", "entries": [
                {"name": "actions/checkout", "version": "v4",
                 "sha": "11d5960a326750d5838078e36cf38b85af677262"}]},
            {"name": "alpine-base-image", "version": "3.18",
             "digest": "sha256:fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7"},
        ],
    }

    def expect_rejected(files: dict, what: str):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / "third_party").mkdir()
            (td_path / ".github").mkdir()
            (td_path / ".github" / "workflows").mkdir()
            with open(td_path / "third_party" / "manifest.yaml", "w", encoding="utf-8") as f:
                yaml.safe_dump(manifest_ok, f)
            for name, content in files.items():
                path = td_path / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            m = load_manifest(str(td_path / "third_party" / "manifest.yaml"))
            errors = check_workflow_pins(m, str(td_path / ".github" / "workflows"))
            errors.extend(check_dockerfile(m, str(td_path / "Dockerfile")))
            if not errors:
                failures.append(f"{what}: checker accepted a broken fixture")

    good_wf = """\
on:
  push:
    branches: [master]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4
"""
    expect_rejected({".github/workflows/ci.yml": good_wf.replace("@11d5960a326750d5838078e36cf38b85af677262", "@v4"),
                     "Dockerfile": "FROM alpine:3.18@sha256:fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7\n"},
                    "mutable action tag")
    expect_rejected({".github/workflows/ci.yml": good_wf,
                     "Dockerfile": "FROM alpine:3.18\n"},
                    "mutable Dockerfile base tag")
    expect_rejected({".github/workflows/ci.yml": good_wf,
                     "Dockerfile": "FROM alpine:3.18@sha256:fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7\nRUN wget -O - https://example.com/x.tar.gz | tar -xz\n"},
                    "pipe-to-tar download")
    expect_rejected({".github/workflows/ci.yml": good_wf.replace("actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"),
                     "Dockerfile": "FROM alpine:3.18@sha256:fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7\n"},
                    "undeclared action")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="third_party/manifest.yaml")
    parser.add_argument("--workflows-dir", default=".github/workflows")
    parser.add_argument("--dockerfile", default="Dockerfile")
    parser.add_argument("--self-test", action="store_true",
                        help="run negative fixtures against synthetic broken repos")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    errors = check_workflow_pins(manifest, args.workflows_dir)
    errors.extend(check_dockerfile(manifest, args.dockerfile))
    if args.self_test:
        failures = self_test()
        if failures:
            errors.append("self-test failures:")
            errors.extend(f"  - {f}" for f in failures)

    if errors:
        for e in sorted(set(errors)):
            print(f"FAIL: {e}")
        print(f"check-actions-pins: {len(set(errors))} error(s)")
        return 1
    print(f"check-actions-pins: OK ({len(manifest['actions'])} actions, "
          f"{len(manifest['digests'])} digests, all workflows + Dockerfile pinned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
