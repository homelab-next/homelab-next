# SPDX-License-Identifier: Apache-2.0
"""A built wheel imports without the source tree, ships its package data and the plugin entry point.

Schemas live in the source checkout (``schemas/``), not in the wheel: libraries that need them
resolve the checkout or ``HNX_SCHEMAS_DIR`` (see README, "Installing").  This test pins what the
wheel *does* promise: the core CLI runs on a bare interpreter, templates and example specs are
packaged, and the invariants plugin is registered.
"""

import importlib.util
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def wheel_dir(tmp_path_factory):
    if importlib.util.find_spec("setuptools") is None:
        pytest.skip("setuptools is not installed (build without network needs it)")
    work = tmp_path_factory.mktemp("wheelsrc")
    for name in ("pyproject.toml", "README.md"):
        shutil.copy(ROOT / name, work / name)
    shutil.copytree(
        ROOT / "homelabnext", work / "homelabnext", ignore=shutil.ignore_patterns("__pycache__")
    )
    out = tmp_path_factory.mktemp("wheelout")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "-q",
            "-w",
            str(out),
            str(work),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return out


def _unpack(wheel_dir, tmp_path):
    wheels = list(wheel_dir.glob("homelabnext-*.whl"))
    assert len(wheels) == 1
    target = tmp_path / "site"
    with zipfile.ZipFile(wheels[0]) as z:
        z.extractall(target)
        return target, set(z.namelist())


def test_wheel_ships_package_data_and_entry_point(wheel_dir, tmp_path):
    target, names = _unpack(wheel_dir, tmp_path)
    assert "homelabnext/decide/examples/decision_spec.yml" in names
    assert "homelabnext/golden/examples/classifier_smoke.yml" in names
    assert "homelabnext/generators/templates/caddy_site.tmpl" in names
    eps = (target / next(n for n in names if n.endswith("entry_points.txt"))).read_text()
    assert "[homelabnext.invariants.checks]" in eps
    assert "hnx = homelabnext.cli:main" in eps
    assert not any(n.startswith(("tests/", "schemas/")) for n in names)


def test_installed_copy_runs_hnx_help_without_the_source_tree(wheel_dir, tmp_path):
    target, _ = _unpack(wheel_dir, tmp_path)
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]);"
        "import homelabnext.cli as c; sys.exit(c.main(['--help']))"
    )
    run = subprocess.run(
        [sys.executable, "-I", "-c", code, str(target)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert run.returncode == 0, run.stderr
    assert "usage: hnx" in run.stdout
