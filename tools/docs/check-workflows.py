#!/usr/bin/env python3
"""Repository tests for GitHub Actions workflow hygiene (R2-F01/F03).

This script is the "workflow lint gate" companion to actionlint. It asserts
contracts that actionlint cannot express and that the CI workflow itself
cannot protect once it fails to parse:

1. every workflow YAML parses with PyYAML (catches YAML tag errors such as
   `if: !matrix.sanitizer`, which GitHub treats as an unknown tag and which
   aborts the workflow before any job is created);
2. every job display name is unique within its workflow, and every matrix
   entry carries a stable `check_name` that is actually used as the job name
   (branch-protection and release required-check lists can then reference
   exact, stable names instead of space-split fragments);
3. the expected sanitizer/build matrix set is complete: deleting a matrix
   entry (e.g. an ASan config) must fail this check so a silently shrunk
   matrix cannot be mistaken for a green gate;
4. the Docker PR gate smoke path matches the Dockerfile ENTRYPOINT (R2-F03):
   a renamed binary or entrypoint that the smoke does not exercise fails here.
5. capacity evidence uploads only `*_capacity.json` envelopes while raw JSON
   is retained in the separate raw artifact (R2-F07);
6. the release workflow mounts the exact image archive into Trivy, persists
   the scan report, verifies the copied release SBOM/manifest, and binds the
   scan report to the independently inspected digest (R2-F08).

Negative tests for all of the above are executed with --self-test: the
checker is fed synthetic broken fixtures and must reject every one of them.

Exit codes: 0 all good; 1 a contract is violated; 2 usage error.

Usage:
  python3 tools/docs/check-workflows.py [--self-test] [--workflows-dir DIR]
"""

import argparse
import os
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required: pip install pyyaml\n")
    sys.exit(2)

# The canonical matrix contract for the CI build-and-test workflow. Every
# entry must exist as a job name in ci.yml. Deleting or renaming any of
# these (for example to shrink the sanitizer matrix) fails the gate.
EXPECTED_CI_CHECK_NAMES = {
    "Ubuntu GCC Debug",
    "Ubuntu GCC RelWithDebInfo",
    "Ubuntu Clang Debug",
    "Ubuntu Clang RelWithDebInfo",
    "Ubuntu Clang ASan Debug",
    "Ubuntu Clang ASan RelWithDebInfo",
    "Ubuntu Clang UBSan Debug",
    "Ubuntu Clang TSan Debug",
    "macOS Debug",
    "macOS RelWithDebInfo",
    "Windows Debug",
    "Windows RelWithDebInfo",
}

# Workflows that are allowed to be skipped by a paths-ignore/on filter; the
# name-based checks still apply to every workflow.
CI_WORKFLOW = "ci.yml"
DOCKER_WORKFLOW = "docker-publish.yml"
RELEASE_WORKFLOW = "release.yml"


def load_workflows(workflows_dir: str) -> list[tuple[str, dict]]:
    """Parse every workflow YAML. Raises on parse errors."""
    loaded = []
    errors = []
    for fname in sorted(os.listdir(workflows_dir)):
        if not fname.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(workflows_dir, fname)
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            errors.append(f"{fname}: YAML parse error: {e}")
            continue
        if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
            errors.append(f"{fname}: missing top-level 'jobs' mapping")
            continue
        loaded.append((fname, data))
    if errors:
        raise RuntimeError("\n".join(errors))
    if not loaded:
        raise RuntimeError("no workflow files found")
    return loaded


def job_names_with_context(workflow: dict, require_check_name: bool) -> list[tuple[str, str]]:
    """Return (job_id, display_name) pairs, resolving matrix names.

    require_check_name: the CI workflow's matrix job names are consumed by
    branch-protection/release required-check lists, so every matrix entry
    must carry a stable `check_name` (the raw template rendered non-unique
    names such as "Ubuntu (clang+sanitizer, Debug)" for every sanitizer).
    Other workflows (e.g. the release build matrix) are checked for
    uniqueness of their rendered name only.
    """
    pairs = []
    for job_id, job in (workflow.get("jobs") or {}).items():
        name = job.get("name", job_id)
        strategy = job.get("strategy") or {}
        matrix = strategy.get("matrix") or {}
        entries = matrix.get("include") or []
        if entries and require_check_name:
            names = []
            for entry in entries:
                check_name = entry.get("check_name")
                if not check_name:
                    raise ValueError(
                        f"job {job_id}: matrix entry is missing stable 'check_name' "
                        f"(entry keys: {sorted(entry)})"
                    )
                names.append(str(check_name))
            for n in names:
                pairs.append((job_id, n))
        elif entries:
            # Static template: e.g. "Build ${{ matrix.platform }} Binary"
            # renders distinct names per platform; rely on that rendering.
            pairs.append((job_id, name))
        else:
            pairs.append((job_id, name))
    return pairs


def check_job_names_unique(workflows: list[tuple[str, dict]]) -> list[str]:
    errors = []
    for fname, workflow in workflows:
        seen = {}
        try:
            pairs = job_names_with_context(workflow, require_check_name=(fname == CI_WORKFLOW))
        except ValueError as e:
            errors.append(f"{fname}: {e}")
            continue
        for _job_id, name in pairs:
            if name in seen:
                errors.append(
                    f"{fname}: duplicate job display name {name!r} "
                    f"(jobs {seen[name]} and {_job_id})"
                )
            seen[name] = _job_id
    return errors


def check_ci_matrix_complete(workflows: list[tuple[str, dict]]) -> list[str]:
    errors = []
    actual = set()
    for fname, workflow in workflows:
        if fname != CI_WORKFLOW:
            continue
        try:
            pairs = job_names_with_context(workflow, require_check_name=True)
        except ValueError as e:
            errors.append(f"{fname}: {e}")
            return errors
        actual.update(name for _job_id, name in pairs)
    missing = EXPECTED_CI_CHECK_NAMES - actual
    if missing:
        errors.append(
            f"{CI_WORKFLOW}: expected matrix check names missing from job names: "
            + ", ".join(sorted(missing))
        )
    return errors


def dockerfile_entrypoint(workflows_dir: str) -> str:
    """Parse the Dockerfile ENTRYPOINT (exec form only).

    The Dockerfile lives at the repository root, two levels above the
    workflows directory (.github/workflows).
    """
    dockerfile = os.path.join(
        os.path.dirname(os.path.dirname(workflows_dir)), "Dockerfile"
    )
    if not os.path.isfile(dockerfile):
        raise RuntimeError(
            f"Dockerfile not found at {dockerfile} (expected repo root)"
        )
    with open(dockerfile, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("ENTRYPOINT"):
                # ENTRYPOINT ["/fluffos/bin/driver"]
                inner = stripped[len("ENTRYPOINT"):].strip()
                if not (inner.startswith("[") and inner.endswith("]")):
                    raise RuntimeError(
                        f"Dockerfile ENTRYPOINT must be exec form, got: {stripped}"
                    )
                parts = [p.strip().strip('"') for p in inner[1:-1].split(",")]
                return parts[0] if parts else ""
    raise RuntimeError("Dockerfile has no ENTRYPOINT")


def check_docker_smoke_path(workflows: list[tuple[str, dict]],
                             workflows_dir: str) -> list[str]:
    errors = []
    entry = dockerfile_entrypoint(os.path.abspath(workflows_dir))
    for fname, workflow in workflows:
        if fname != DOCKER_WORKFLOW:
            continue
        smoke = (
            (workflow.get("jobs") or {})
            .get("build-and-scan", {})
            .get("steps", [])
        )
        found = False
        for step in smoke:
            run = step.get("run", "")
            if "driver" in run and "smoke" in step.get("name", "").lower():
                found = True
                if entry not in run:
                    errors.append(
                        f"{fname}: smoke step must exercise the Dockerfile "
                        f"ENTRYPOINT ({entry!r}); run snippet: {run[:120]!r}"
                    )
        if not found:
            errors.append(f"{fname}: no smoke step found that exercises the driver")
    return errors


def find_step(workflow: dict, job_id: str, step_name: str) -> dict | None:
    """Return a named step from a job, or None when the contract is absent."""
    steps = ((workflow.get("jobs") or {}).get(job_id, {}).get("steps") or [])
    for step in steps:
        if step.get("name") == step_name:
            return step
    return None


def check_capacity_artifact_split(workflows: list[tuple[str, dict]]) -> list[str]:
    errors = []
    ci = next((workflow for fname, workflow in workflows if fname == CI_WORKFLOW), None)
    if ci is None:
        return [f"{CI_WORKFLOW}: workflow is missing"]

    envelope = find_step(ci, "build-and-test", "Upload capacity evidence envelope")
    if envelope is None:
        errors.append(f"{CI_WORKFLOW}: capacity evidence envelope upload step is missing")
    else:
        path = str((envelope.get("with") or {}).get("path", "")).strip()
        if path != "build/reports/capacity/*_capacity.json":
            errors.append(
                f"{CI_WORKFLOW}: envelope artifact path must be exactly "
                f"'build/reports/capacity/*_capacity.json', got {path!r}"
            )

    raw = find_step(ci, "build-and-test", "Upload LPC Modern Runtime Benchmark Raw Reports")
    if raw is None:
        errors.append(f"{CI_WORKFLOW}: raw benchmark artifact upload step is missing")
    else:
        raw_path = str((raw.get("with") or {}).get("path", ""))
        if "build/reports/capacity/*_raw.json" not in raw_path:
            errors.append(
                f"{CI_WORKFLOW}: raw benchmark artifact must retain "
                "build/reports/capacity/*_raw.json"
            )
    return errors


def check_release_artifact_contract(workflows: list[tuple[str, dict]]) -> list[str]:
    errors = []
    release = next((workflow for fname, workflow in workflows if fname == RELEASE_WORKFLOW), None)
    if release is None:
        return [f"{RELEASE_WORKFLOW}: workflow is missing"]

    required_checks = find_step(
        release, "validate-target", "Verify required checks on target SHA"
    )
    if required_checks is None:
        errors.append(f"{RELEASE_WORKFLOW}: required-check verification step is missing")
    else:
        run = str(required_checks.get("run", ""))
        for label, fragment in {
            "paginated API traversal": "--paginate --slurp",
            "explicit page size": "check-runs?per_page=100",
        }.items():
            if fragment not in run:
                errors.append(
                    f"{RELEASE_WORKFLOW}: required-check verification lacks {label}: {fragment}"
                )

    scan = find_step(release, "build-docker", "Scan image archive (Trivy, blocking)")
    if scan is None:
        errors.append(f"{RELEASE_WORKFLOW}: blocking Trivy archive scan step is missing")
    else:
        run = str(scan.get("run", ""))
        required_fragments = {
            "read-only archive mount": "--volume /tmp/fluffos-image.tar:/input/fluffos-image.tar:ro",
            "host output mount": "--volume /tmp:/output",
            "container input path": "--input /input/fluffos-image.tar",
            "persisted report path": "--output /output/trivy.json",
            "explicit digest binding": 'report["FluffOSImageDigest"] = digest',
        }
        for label, fragment in required_fragments.items():
            if fragment not in run:
                errors.append(f"{RELEASE_WORKFLOW}: Trivy scan lacks {label}: {fragment}")

    binary_download = find_step(release, "verify-release-inputs", "Download binary artifacts")
    if binary_download is None or (binary_download.get("with") or {}).get("pattern") != "release-asset-*":
        errors.append(
            f"{RELEASE_WORKFLOW}: release verifier must download binary artifacts with pattern release-asset-*"
        )
    oci_download = find_step(release, "verify-release-inputs", "Download OCI verification artifact")
    if oci_download is None or (oci_download.get("with") or {}).get("name") != "oci-image":
        errors.append(
            f"{RELEASE_WORKFLOW}: release verifier must download the named oci-image verification artifact"
        )

    verify = find_step(
        release,
        "verify-release-inputs",
        "Verify checksums, SBOM, provenance and digest binding",
    )
    if verify is None:
        errors.append(f"{RELEASE_WORKFLOW}: read-only release verification step is missing")
    else:
        run = str(verify.get("run", ""))
        for expected in ("--sbom assets/sbom.json", "--manifest assets/manifest.yaml"):
            if expected not in run:
                errors.append(
                    f"{RELEASE_WORKFLOW}: release verification must consume the copied asset: {expected}"
                )
    return errors


def check_all(workflows_dir: str) -> list[str]:
    errors = []
    try:
        workflows = load_workflows(workflows_dir)
    except RuntimeError as e:
        return [str(e)]
    errors.extend(check_job_names_unique(workflows))
    errors.extend(check_ci_matrix_complete(workflows))
    errors.extend(check_docker_smoke_path(workflows, workflows_dir))
    errors.extend(check_capacity_artifact_split(workflows))
    errors.extend(check_release_artifact_contract(workflows))
    return errors


def self_test() -> list[str]:
    """Negative tests: every synthetic broken fixture must be rejected."""
    failures = []

    def expect_rejected(fixture_files: dict[str, str], what: str):
        with tempfile.TemporaryDirectory() as td:
            # Repository layout: .github/workflows/*.yml + repo-root Dockerfile.
            wf_dir = Path(td) / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (Path(td) / "Dockerfile").write_text(
                'FROM alpine:3.18\nENTRYPOINT ["/fluffos/bin/driver"]\n',
                encoding="utf-8",
            )
            for name, content in fixture_files.items():
                (wf_dir / name).write_text(content, encoding="utf-8")
            try:
                errors = check_all(str(wf_dir))
            except Exception as e:  # pragma: no cover - unexpected crash
                failures.append(f"{what}: checker crashed: {e}")
                return
            if not errors:
                failures.append(f"{what}: checker accepted a broken fixture")

    minimal_ci = """\
name: CI
on:
  push:
    branches: [master]
  pull_request:
    branches: [master]
jobs:
  build:
    name: ${{ matrix.check_name }}
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - platform: Ubuntu
            build: Debug
            check_name: Ubuntu GCC Debug
    steps:
      - run: echo ok
"""
    docker_ok = """\
name: Docker
on:
  pull_request:
    branches: [master]
jobs:
  build-and-scan:
    name: Build Docker Image (no push)
    runs-on: ubuntu-latest
    steps:
      - name: Verify image builds and runs (smoke)
        run: |
          IMAGE="example"
          docker run --rm "$IMAGE" /fluffos/bin/driver --version
"""
    docker_broken = docker_ok.replace("/fluffos/bin/driver --version",
                                     "/usr/local/bin/driver --version")

    # 1. YAML tag error (`if: !matrix.sanitizer`).
    bad_yaml = minimal_ci.replace(
        "    steps:\n      - run: echo ok",
        "    steps:\n      - name: Unit\n        if: !matrix.sanitizer\n        run: echo ok",
    )
    expect_rejected({"ci.yml": bad_yaml}, "yaml tag error (!matrix.sanitizer)")

    # 2. Non-unique job names (sanitizer template renders the same name).
    dup = minimal_ci.replace(
        "          - platform: Ubuntu\n            build: Debug\n            check_name: Ubuntu GCC Debug",
        "          - platform: Ubuntu\n            build: Debug\n            check_name: Same Name\n          - platform: Ubuntu\n            build: RelWithDebInfo\n            check_name: Same Name",
    )
    expect_rejected({"ci.yml": dup}, "duplicate job display names")

    # 3. Matrix entry missing check_name.
    no_check = minimal_ci.replace("            check_name: Ubuntu GCC Debug\n", "")
    expect_rejected({"ci.yml": no_check}, "matrix entry without check_name")

    # 4. A sanitizer matrix entry removed (the complete-matrix contract).
    shrunk = minimal_ci.replace("check_name: Ubuntu GCC Debug", "check_name: Ubuntu Clang ASan Debug")
    expect_rejected({"ci.yml": shrunk}, "shrunk matrix (missing GCC Debug)")

    # 5. Docker smoke path not matching the Dockerfile ENTRYPOINT.
    expect_rejected({"ci.yml": minimal_ci, "docker-publish.yml": docker_broken},
                    "docker smoke path != Dockerfile ENTRYPOINT")
    expect_rejected({"ci.yml": minimal_ci, "docker-publish.yml": docker_ok.replace("name: Docker", "name: Docker\n")},
                    "docker smoke missing ENTRYPOINT path")

    # 6. No jobs mapping at all.
    expect_rejected({"ci.yml": "name: CI\non: push\n"}, "workflow without jobs")

    # 7. Direct contract tests for artifact separation and release scan mounts.
    capacity_ok = {
        "jobs": {
            "build-and-test": {
                "steps": [
                    {
                        "name": "Upload capacity evidence envelope",
                        "with": {"path": "build/reports/capacity/*_capacity.json"},
                    },
                    {
                        "name": "Upload LPC Modern Runtime Benchmark Raw Reports",
                        "with": {"path": "build/reports/capacity/*_raw.json"},
                    },
                ]
            }
        }
    }
    if check_capacity_artifact_split([(CI_WORKFLOW, capacity_ok)]):
        failures.append("capacity artifact split: checker rejected the valid contract")
    capacity_bad = {
        "jobs": {
            "build-and-test": {
                "steps": [
                    {
                        "name": "Upload capacity evidence envelope",
                        "with": {"path": "build/reports/capacity/*.json"},
                    },
                    {
                        "name": "Upload LPC Modern Runtime Benchmark Raw Reports",
                        "with": {"path": "build/reports/*.json"},
                    },
                ]
            }
        }
    }
    if not check_capacity_artifact_split([(CI_WORKFLOW, capacity_bad)]):
        failures.append("capacity artifact split: checker accepted raw JSON in the envelope")

    release_scan = """\
docker run --rm \\
  --volume /tmp/fluffos-image.tar:/input/fluffos-image.tar:ro \\
  --volume /tmp:/output image \\
  image --input /input/fluffos-image.tar --output /output/trivy.json
report[\"FluffOSImageDigest\"] = digest
"""
    release_ok = {
        "jobs": {
            "validate-target": {
                "steps": [{
                    "name": "Verify required checks on target SHA",
                    "run": "gh api --paginate --slurp 'check-runs?per_page=100'",
                }]
            },
            "build-docker": {
                "steps": [{"name": "Scan image archive (Trivy, blocking)", "run": release_scan}]
            },
            "verify-release-inputs": {
                "steps": [
                    {"name": "Download binary artifacts", "with": {"pattern": "release-asset-*"}},
                    {"name": "Download OCI verification artifact", "with": {"name": "oci-image"}},
                    {
                        "name": "Verify checksums, SBOM, provenance and digest binding",
                        "run": "verify --sbom assets/sbom.json --manifest assets/manifest.yaml",
                    },
                ]
            },
        }
    }
    if check_release_artifact_contract([(RELEASE_WORKFLOW, release_ok)]):
        failures.append("release artifact contract: checker rejected the valid contract")
    release_bad = {
        "jobs": {
            **release_ok["jobs"],
            "build-docker": {
                "steps": [{
                    "name": "Scan image archive (Trivy, blocking)",
                    "run": release_scan.replace(
                        "--volume /tmp/fluffos-image.tar:/input/fluffos-image.tar:ro", ""
                    ),
                }]
            },
        }
    }
    if not check_release_artifact_contract([(RELEASE_WORKFLOW, release_bad)]):
        failures.append("release artifact contract: checker accepted an unmounted scan archive")

    release_unpaginated = {
        "jobs": {
            **release_ok["jobs"],
            "validate-target": {
                "steps": [{
                    "name": "Verify required checks on target SHA",
                    "run": "gh api check-runs",
                }]
            },
        }
    }
    if not check_release_artifact_contract([(RELEASE_WORKFLOW, release_unpaginated)]):
        failures.append("release artifact contract: checker accepted an unpaginated check-runs query")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflows-dir",
                        default=os.path.join(os.path.dirname(__file__), "..", "..", ".github", "workflows"))
    parser.add_argument("--self-test", action="store_true",
                        help="run the negative tests against synthetic broken fixtures")
    args = parser.parse_args()

    errors = check_all(os.path.abspath(args.workflows_dir))

    if args.self_test:
        failures = self_test()
        if failures:
            errors.append("self-test failures:")
            errors.extend(f"  - {f}" for f in failures)

    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        print(f"check-workflows: {len(errors)} error(s)")
        return 1

    print("check-workflows: OK (parse/names/matrix, Docker smoke, evidence split, "
          "release artifact binding)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
