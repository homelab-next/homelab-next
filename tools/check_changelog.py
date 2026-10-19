#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: check-changelog
#   kind: check
#   purpose: Fail unless CHANGELOG.md keeps an Unreleased section and one for the current version.
#   owner: maintainers
#   trigger: [ci:ci/lint, make:changelog-check]
#   inputs: [CHANGELOG.md, homelabnext/_version.py]
#   outputs: the reason on stderr when it fails
#   exit:
#     "0": both sections present
#     "1": a section is missing or the version cannot be read
"""Fail unless CHANGELOG.md has a section for the version in homelabnext/_version.py."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def current_version(root: Path = ROOT) -> str:
    text = (root / "homelabnext" / "_version.py").read_text()
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        raise SystemExit("check_changelog: VERSION not found in homelabnext/_version.py")
    return m.group(1)


def has_section(changelog: str, version: str) -> bool:
    return re.search(rf"^## \[{re.escape(version)}\]", changelog, re.M) is not None


def main() -> int:
    version = current_version()
    changelog = (ROOT / "CHANGELOG.md").read_text()
    if "## [Unreleased]" not in changelog:
        print("check_changelog: CHANGELOG.md must keep an [Unreleased] section", file=sys.stderr)
        return 1
    if not has_section(changelog, version):
        print(f"check_changelog: no '## [{version}]' section in CHANGELOG.md", file=sys.stderr)
        return 1
    print(f"check_changelog: version {version} present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
