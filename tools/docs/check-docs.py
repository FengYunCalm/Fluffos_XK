#!/usr/bin/env python3
"""Validate Markdown docs for stale links, paths, commit SHAs and report refs.

Checks performed:
  1. Explicit markdown links [text](path) and [text](path#anchor) whose target
     is a local file must exist (resolved against repo root or docs/).
  2. Inline code references that start with a known repo top-level dir
     (docs/, src/, tools/, testsuite/, .github/, third_party/, CMakeLists.txt)
     must exist.
  3. 40-hex commit SHA references must exist in git history.
  4. Report paths under docs/reports/ must exist.

Exit code 0 = all checks pass; 1 = violations found.

Usage:
  tools/docs/check-docs.py [--repo DIR] [--skip-git] [--dir docs]
"""

import argparse
import os
import re
import subprocess
import sys

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
INLINE_PATH_RE = re.compile(r"`([^`]+)`")
KNOWN_PREFIXES = (
    "docs/", "src/", "tools/", "testsuite/", ".github/", "third_party/",
    "cmake/", "compat/", "CMakeLists.txt", "Dockerfile", "SECURITY.md",
    "README", "CHANGELOG.md", "RELEASE.md", "Testing", "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md", "NOTICE", "LICENSE", "Credits", "Copyright",
    "ChangeLog", "qodana.yaml", "fix_permission.sh", "CMakePresets.json",
)
SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")
IGNORED_DIRS = (
    "docs/efun",   # generated API docs with .html cross-refs
    "docs/lpc",    # generated language reference with .html cross-refs
)

# Known-stale references in historical/archived docs (2026-06 era) that refer
# to deleted reports, moved files or SHAs not in this checkout. They are
# tracked here deliberately: T17 keeps current docs strict while historical
# evidence stays readable. New violations in current docs must NOT be added
# here; fix the reference instead.
KNOWN_STALE = {
    "docs/codebase-audit-and-execution-plan-2026-08-09.md": {
        "docs/reports/multicore-mudlib-audit-2026-06-25.md",
        ".github/workflows/release-gates.yml",
    },
    "docs/multicore-production-gate.md": {
        "docs/reports/multicore-mudlib-audit-2026-06-25.md",
    },
    "docs/releases/multicore-production-baseline-2026-06-27.md": {
        "5b5e433e0ad02c0432246f7a4369694669f1aef0",
        "87007f089a3d431a1dfd12af54e94fa6b62cc5c7",
        "5041b078e2e08ae2c58bdfd694ac43312bbd2603",
        "tools/public-beta-smoke-ubuntu.sh --cloud --skip-contracts",
        "tools/cloud-health-check-ubuntu.sh --ssh --smoke --json docs/reports/cloud-health-2026-06-27.json",
    },
    "docs/archive/multicore/multicore-actor-vm-plan-2026-06.md": {
        "src/vm/internal/object_store.h",
        "src/vm/internal/stralloc.cc",
        "f80968b0868059d97e02da4062c3a233f1225bd8",
    },
    "docs/archive/multicore/multicore-refactor-execution-plan-2026-06.md": {
        "docs/multicore-actor-vm-plan.md",
        "src/vm/internal/stralloc.cc",
    },
    "docs/driver/adding_efuns.md": {
        "src/packages/mypkg",
    },
}
IGNORED_FILES = set()


def git_has_sha(repo: str, sha: str) -> bool:
    out = subprocess.run(
        ["git", "-C", repo, "cat-file", "-e", sha + "^{commit}"],
        capture_output=True,
        check=False,
    )
    return out.returncode == 0


def resolve(repo: str, ref: str, base_dir: str = ""):
    """Return the first existing candidate path, or None.

    Relative links are resolved against base_dir (the directory of the
    referencing file) first, then against the repo root and docs/.
    """
    ref = ref.strip()
    if not ref or ref.startswith(("http://", "https://", "mailto:", "#", "!")):
        return True  # external/anchor/ignored
    ref = ref.split("#", 1)[0].split("?", 1)[0]
    if not ref:
        return True
    if ref.startswith("$") or ref.startswith("<") or ref.startswith("{%"):
        return True  # template/placeholder
    if ref.endswith("*") or "*" in ref:
        return True  # glob pattern, not a literal path
    if ref.endswith(".html"):
        return True  # generated docs-site page, built at publish time
    # Strip line/range suffixes ("file:12", "file.cc:52-60,75-100", "file.sh smoke").
    ref = re.sub(r":\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$", "", ref)
    ref = re.sub(r"^(tools/[A-Za-z0-9_./-]+) .*$", r"\1", ref)
    candidates = []
    if not ref.startswith("/"):
        if base_dir:
            candidates.append(os.path.normpath(os.path.join(base_dir, ref)))
    candidates += [
        os.path.normpath(os.path.join(repo, ref)),
        os.path.normpath(os.path.join(repo, "docs", ref)),
    ]
    for c in candidates:
        if os.path.exists(c):
            return True
    # Generated docs-site pages ship as .html next to the .md source.
    for c in candidates:
        if c.endswith(".md") and os.path.exists(c[:-3] + ".html"):
            return True
    return False


def check_file(path: str, repo: str, skip_git: bool) -> list[str]:
    errors: list[str] = []
    rel = os.path.relpath(path, repo)
    if rel in IGNORED_FILES or rel.startswith(IGNORED_DIRS):
        return errors
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return [f"{rel}: unreadable: {e}"]

    stale = KNOWN_STALE.get(rel, set())
    for lineno, line in enumerate(text.splitlines(), 1):
        base_dir = os.path.dirname(os.path.abspath(path))
        for m in LINK_RE.finditer(line):
            ref = m.group(1)
            if ref in stale:
                continue
            if not resolve(repo, ref, base_dir):
                errors.append(f"{rel}:{lineno}: missing link target: {ref!r}")
        for m in INLINE_PATH_RE.finditer(line):
            ref = m.group(1)
            if ref in stale:
                continue
            if ref.startswith(KNOWN_PREFIXES) and not resolve(repo, ref, base_dir):
                errors.append(f"{rel}:{lineno}: missing path reference: {ref!r}")
        if not skip_git:
            for sha in set(SHA_RE.findall(line)):
                if sha in stale:
                    continue
                if not git_has_sha(repo, sha):
                    errors.append(f"{rel}:{lineno}: unknown commit SHA: {sha}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repo root")
    parser.add_argument("--dir", default="docs", help="docs directory (relative to repo)")
    parser.add_argument("--skip-git", action="store_true", help="skip commit SHA checks")
    args = parser.parse_args()

    docs_dir = os.path.join(args.repo, args.dir)
    if not os.path.isdir(docs_dir):
        print(f"docs dir not found: {docs_dir}", file=sys.stderr)
        return 2

    all_errors: list[str] = []
    checked = 0
    for root, _dirs, files in os.walk(docs_dir):
        for fname in sorted(files):
            if fname.endswith(".md"):
                checked += 1
                all_errors.extend(check_file(os.path.join(root, fname), args.repo, args.skip_git))

    if all_errors:
        for e in all_errors[:100]:
            print(f"FAIL: {e}")
        print(f"check-docs: {len(all_errors)} issue(s) across {checked} markdown files")
        return 1
    print(f"check-docs: OK ({checked} markdown files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
