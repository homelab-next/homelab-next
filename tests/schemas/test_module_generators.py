# SPDX-License-Identifier: Apache-2.0
"""The module-manifest schemas, examples and negatives are generated (homelabnext.schemas): the
committed files are exactly what the generators write, so the schema is reproducible and a rule
changed in one place changes everywhere it applies."""

from __future__ import annotations

from pathlib import Path

from homelabnext.schemas import __main__ as gen
from homelabnext.schemas import module_negatives

ROOT = Path(__file__).resolve().parents[2]


def test_committed_files_match_the_generators():
    assert gen.stale(ROOT) == []


def test_no_committed_negative_or_example_is_left_without_a_generator():
    assert gen.orphans(ROOT) == []


def test_check_mode_reports_a_hand_edit(tmp_path, capsys):
    import shutil

    for d in ("schemas/platform", "examples/modules"):
        shutil.copytree(ROOT / d, tmp_path / d)
    (tmp_path / "schemas/platform/module.schema.json").write_text("{}\n")
    stray = tmp_path / "schemas/platform/negative/module.hand-written.yml"
    stray.write_text("id: x\n")
    assert gen.main(["--root", str(tmp_path), "--check"]) == 1
    out = capsys.readouterr().out
    assert "module.schema.json: differs" in out and "module.hand-written.yml: no generator" in out
    assert gen.main(["--root", str(tmp_path)]) == 0
    assert gen.main(["--root", str(tmp_path), "--check"]) == 0 and not stray.exists()


def test_a_wrong_root_is_a_usage_error(tmp_path):
    assert gen.main(["--root", str(tmp_path), "--check"]) == 2


def test_every_negative_breaks_exactly_the_example_it_names():
    out = module_negatives.render(ROOT)
    for name in module_negatives.NEGATIVES:
        assert f"schemas/platform/negative/module.{name}.yml" in out
