# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_changelog as cc


def test_repo_changelog_matches_version():
    root = Path(__file__).resolve().parents[2]
    assert cc.has_section((root / "CHANGELOG.md").read_text(), cc.current_version(root))


def test_missing_version_section_detected():
    assert not cc.has_section("## [Unreleased]\n\n## [0.0.1] - 2026-01-01\n", "0.1.0")
    assert cc.has_section("## [0.1.0] - 2026-01-01\n", "0.1.0")
