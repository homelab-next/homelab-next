# SPDX-License-Identifier: Apache-2.0
"""Target files and capabilities.yml are validated against schemas/conform/: a misspelt key is
refused (ConformError, exit 2), never ignored, and every file the tree ships validates."""

from __future__ import annotations

from pathlib import Path

import pytest

from homelabnext.conform.cli import main
from homelabnext.conform.registry import ConformError, declared_capabilities
from homelabnext.conform.target import load_target

ROOT = Path(__file__).resolve().parents[2]
SHIPPED = sorted(
    [
        *(ROOT / "conformance" / "targets").glob("*.yml"),
        *(ROOT / "compose" / "lab-in-a-box" / "targets").glob("*.yml"),
    ]
)


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: f"{p.parent.parent.name}/{p.name}")
def test_every_shipped_target_file_validates(path):
    assert load_target(str(path)).bindings


@pytest.mark.parametrize(
    ("text", "word"),
    [
        # a misspelt config used to build the adapter with no arguments at all
        ("capabilities:\n  secrets:\n    adapter: a.b:c\n    confg: {mount: m}\n", "confg"),
        ("capabilites: {}\ncapabilities:\n  secrets: {builtin: fake}\n", "capabilites"),
        ("capabilities:\n  secrets:\n    adapter: a.b:c\n    feature: [x]\n", "feature"),
        ("capabilities:\n  secrets: {adapter: a.b:c, builtin: fake}\n", "oneOf"),
        ("capabilities:\n  Secrets: {builtin: fake}\n", "capabilities: does not match"),
    ],
)
def test_a_target_file_with_a_key_the_schema_does_not_name_is_refused(tmp_path, text, word):
    p = tmp_path / "t.yml"
    p.write_text(text, encoding="utf-8")
    with pytest.raises(ConformError, match="not a valid target file") as err:
        load_target(str(p))
    assert word in str(err.value)


def test_the_cli_reports_a_bad_target_file_as_misconfiguration(tmp_path, capsys):
    p = tmp_path / "t.yml"
    p.write_text("capabilities:\n  secrets:\n    adapter: a.b:c\n    confg: {}\n", encoding="utf-8")
    assert main(["run", "secrets", "--target", str(p)]) == 2
    assert "confg" in capsys.readouterr().err


def test_a_capabilities_file_with_another_key_is_refused(tmp_path):
    (tmp_path / "capabilities.yml").write_text(
        "capabilities: [secrets]\ncapabilties: [object-store]\n", encoding="utf-8"
    )
    with pytest.raises(ConformError, match="capabilties"):
        declared_capabilities(tmp_path)


def test_a_capability_name_outside_the_grammar_is_refused(tmp_path):
    (tmp_path / "capabilities.yml").write_text("capabilities: [Object_Store]\n", encoding="utf-8")
    with pytest.raises(ConformError, match="capabilities/0: does not match"):
        declared_capabilities(tmp_path)


def test_the_tree_s_capabilities_file_validates():
    assert "secrets" in declared_capabilities(ROOT)
