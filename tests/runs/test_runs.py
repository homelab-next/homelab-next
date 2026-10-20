# SPDX-License-Identifier: Apache-2.0
"""Per-run private output directories."""

import pytest

from homelabnext.runs import RUNS_ENV, RunIdError, run_dir, runs_base


def test_run_dir_is_created_under_the_base(tmp_path):
    d = run_dir("lint-20261020T093000Z", tmp_path, env={})
    assert d == tmp_path / "runs" / "lint-20261020T093000Z" and d.is_dir()
    assert d.stat().st_mode & 0o777 == 0o700
    assert run_dir("lint-20261020T093000Z", tmp_path, env={}) == d  # the same run, again


@pytest.mark.parametrize(
    "bad", ["../escape", "..", "a/b", "/abs", "", ".hidden", "a\\b", "x" * 129, "a..b", None]
)
def test_run_dir_refuses_traversal_and_odd_ids(tmp_path, bad):
    with pytest.raises(RunIdError):
        run_dir(bad, tmp_path, env={})
    assert not (tmp_path / "escape").exists() and not (tmp_path / "runs").exists()


def test_run_dir_refuses_a_symlinked_run(tmp_path):
    (tmp_path / "runs").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "runs" / "r1").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(RunIdError, match="symlink"):
        run_dir("r1", tmp_path, env={})


def test_the_base_is_configurable(tmp_path):
    base = tmp_path / "scratch"
    assert runs_base(tmp_path, {RUNS_ENV: str(base)}) == base
    assert run_dir("r2", tmp_path, env={RUNS_ENV: str(base)}) == base / "r2"
