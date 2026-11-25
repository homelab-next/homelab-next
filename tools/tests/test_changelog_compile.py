# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import changelog_compile as cc

BASE = "# Changelog\n\n## [Unreleased]\n\n### Added\n- old\n\n### Fixed\n- oldfix\n\n## [0.1.0] - 2026-01-01\n\n### Added\n- released\n"


def _root(tmp_path, frags, changelog=BASE):
    (tmp_path / "CHANGELOG.md").write_text(changelog)
    (tmp_path / "changelog.d").mkdir()
    for name, text in frags.items():
        (tmp_path / "changelog.d" / name).write_text(text)
    return tmp_path


def test_parse_defaults_and_group():
    assert cc.parse_fragment("a.md", "thing\n") == ("Added", "- thing")
    assert cc.parse_fragment("a.md", "---\ngroup: Fixed\n---\n- thing\n") == ("Fixed", "- thing")


@pytest.mark.parametrize(
    "text",
    ["", "---\ngroup: Nope\n---\nx\n", "---\nfoo: bar\n---\nx\n", "x\n## [1.0.0]\n"],
)
def test_parse_refuses_malformed(text):
    with pytest.raises(cc.FragmentError):
        cc.parse_fragment("a.md", text)


def test_fold_inserts_at_top_of_group_and_deletes(tmp_path, capsys):
    root = _root(
        tmp_path,
        {"b.md": "bee\n", "a.md": "ay\n", "c.md": "---\ngroup: Fixed\n---\nsea\n", ".gitkeep": ""},
    )
    assert cc.main([], root) == 0
    out = (root / "CHANGELOG.md").read_text()
    assert out.index("- ay\n- bee\n- old") > 0
    assert out.index("- sea\n- oldfix") > 0
    assert out.endswith("### Added\n- released\n")  # released sections untouched
    assert sorted(p.name for p in (root / "changelog.d").iterdir()) == [".gitkeep"]


def test_creates_missing_group(tmp_path):
    root = _root(tmp_path, {"a.md": "---\ngroup: Changed\n---\nchg\n"})
    assert cc.main([], root) == 0
    out = (root / "CHANGELOG.md").read_text()
    assert out.index("### Changed\n- chg\n") < out.index("### Added\n- old")


def test_malformed_changes_nothing(tmp_path):
    root = _root(tmp_path, {"a.md": "ok\n", "b.md": ""})
    assert cc.main([], root) == 1
    assert (root / "CHANGELOG.md").read_text() == BASE
    assert (root / "changelog.d" / "a.md").exists()


def test_no_unreleased_section_is_refused(tmp_path):
    root = _root(tmp_path, {"a.md": "ok\n"}, changelog="# Changelog\n")
    assert cc.main([], root) == 1
    assert (root / "changelog.d" / "a.md").exists()


def test_check_does_not_mutate_and_no_fragments_is_ok(tmp_path):
    root = _root(tmp_path, {"a.md": "ok\n"})
    assert cc.main(["--check"], root) == 0
    assert (root / "CHANGELOG.md").read_text() == BASE
    assert (root / "changelog.d" / "a.md").exists()


def test_no_fragments_is_ok(tmp_path):
    assert cc.main([], _root(tmp_path, {})) == 0
    assert (tmp_path / "CHANGELOG.md").read_text() == BASE
