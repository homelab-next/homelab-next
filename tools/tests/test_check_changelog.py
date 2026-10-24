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


def _tree(tmp_path, version_py, changelog):
    (tmp_path / "homelabnext").mkdir(parents=True)
    if version_py is not None:
        (tmp_path / "homelabnext" / "_version.py").write_text(version_py)
    if changelog is not None:
        (tmp_path / "CHANGELOG.md").write_text(changelog)
    return tmp_path


GOOD = "## [Unreleased]\n\n## [0.1.0] - 2026-01-01\n"


def test_exit_codes(tmp_path, capsys):
    assert cc.main(_tree(tmp_path / "ok", 'VERSION = "0.1.0"\n', GOOD)) == 0
    assert cc.main(_tree(tmp_path / "a", 'VERSION = "0.2.0"\n', GOOD)) == 1  # a missing section
    assert cc.main(_tree(tmp_path / "b", 'VERSION = "0.1.0"\n', "## [0.1.0]\n")) == 1


def test_an_unreadable_version_or_changelog_is_exit_2_not_a_failed_check(tmp_path, capsys):
    """docs/interfaces.md: 2 is misconfiguration or bad input; 1 is a failed check."""
    assert cc.main(_tree(tmp_path / "a", "VERSION = 1\n", GOOD)) == 2
    assert cc.main(_tree(tmp_path / "b", None, GOOD)) == 2
    assert cc.main(_tree(tmp_path / "c", 'VERSION = "0.1.0"\n', None)) == 2
    assert "Traceback" not in capsys.readouterr().err
