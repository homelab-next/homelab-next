# SPDX-License-Identifier: Apache-2.0
"""A built wheel is self-contained: it carries the data and runs with no source tree.

``setup.py`` copies the tracked files of ``schemas/``, ``profiles/`` and ``examples/`` into ``homelabnext/_data`` at
build time.  This test builds the wheel, installs it into a throwaway venv that cannot see the
checkout, and runs the data-dependent commands against example files shipped inside the wheel.
"""

import filecmp
import importlib.util
import json
import os
import subprocess
import venv
import zipfile
from pathlib import Path

import pytest
from pkgbuild import build, export_tree, git

ROOT = Path(__file__).resolve().parents[2]
DATA_TREES = ("schemas", "profiles", "examples")

pytestmark = pytest.mark.slow


def _tree_files(base: Path) -> set[str]:
    return {
        p.relative_to(base).as_posix()
        for p in base.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    }


@pytest.fixture(scope="module")
def wheel_dir(tmp_path_factory):
    work = export_tree(tmp_path_factory.mktemp("wheelsrc"))
    out = tmp_path_factory.mktemp("wheelout")
    build("wheel", work, out)
    return out


def _wheel(wheel_dir):
    wheels = list(wheel_dir.glob("homelabnext-*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def test_wheel_ships_package_data_and_entry_point(wheel_dir, tmp_path):
    with zipfile.ZipFile(_wheel(wheel_dir)) as z:
        names = set(z.namelist())
        eps_name = next(n for n in names if n.endswith("entry_points.txt"))
        eps = z.read(eps_name).decode()
    assert "homelabnext/decide/examples/decision_spec.yml" in names
    assert "homelabnext/golden/examples/classifier_smoke.yml" in names
    assert "homelabnext/agent/terms.md" in names  # the terms every session pack carries
    assert "homelabnext/generators/templates/caddy_site.tmpl" in names
    assert "homelabnext/_data/schemas/platform/site.schema.json" in names
    assert "homelabnext/_data/schemas/ocsf/authentication.v1.json" in names
    assert "homelabnext/_data/profiles/README.md" in names
    assert "homelabnext/_data/examples/minimal/site.yml" in names
    assert "homelabnext/_data/schemas/platform/swap_record.schema.json" in names
    assert "homelabnext/_data/schemas/events/swap.step.schema.json" in names
    assert "homelabnext/swap/events.py" in names and "homelabnext/conform/cli.py" in names
    assert "[homelabnext.invariants.checks]" in eps
    assert (
        "x09_customizations = homelabnext.customization.plugins.x09_customizations:register" in eps
    )
    assert "x10_conformance = homelabnext.conform.plugins.x10_conformance:register" in eps
    assert "hnx = homelabnext.cli:main" in eps
    assert not any(n.startswith(("tests/", "schemas/", "compose/", "conformance/")) for n in names)


def test_packaged_data_equals_the_source_of_truth(wheel_dir, tmp_path):
    """No divergence: every packaged file is byte-identical to its top-level original."""
    with zipfile.ZipFile(_wheel(wheel_dir)) as z:
        z.extractall(tmp_path)
    tracked = git(ROOT, "ls-files", "-z").decode().split("\0")
    for tree in DATA_TREES:
        packaged = tmp_path / "homelabnext" / "_data" / tree
        source = {n[len(tree) + 1 :] for n in tracked if n.startswith(tree + "/")}
        assert _tree_files(packaged) == source, tree
        _match, mismatch, errors = filecmp.cmpfiles(
            ROOT / tree, packaged, sorted(source), shallow=False
        )
        assert not mismatch and not errors, (tree, mismatch, errors)


@pytest.fixture(scope="module")
def installed(wheel_dir, tmp_path_factory):
    """A venv holding only the wheel (plus the test interpreter's third-party libraries)."""
    for mod in ("yaml", "jsonschema", "referencing"):
        if importlib.util.find_spec(mod) is None:
            pytest.skip(f"{mod} is not installed; the installed-wheel CLI needs the core extra")
    env_dir = tmp_path_factory.mktemp("venv")
    venv.EnvBuilder(with_pip=True, system_site_packages=False, clear=True).create(env_dir)
    py = env_dir / ("Scripts" if os.name == "nt" else "bin") / "python"
    subprocess.run(
        [str(py), "-m", "pip", "install", "--no-deps", "--no-index", "-q", str(_wheel(wheel_dir))],
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    # expose the third-party libraries by path only: a .pth *path line* does not run the
    # editable-install hooks that would put this checkout on sys.path
    libs = set()
    for mod in ("yaml", "jsonschema", "referencing", "rpds", "attr", "jsonschema_specifications"):
        spec = importlib.util.find_spec(mod)
        if spec and spec.submodule_search_locations:
            libs.add(str(Path(next(iter(spec.submodule_search_locations))).parent))
        elif spec and spec.origin:
            libs.add(str(Path(spec.origin).parent))
    site = next((env_dir / "lib").glob("python*/site-packages"), None) or (
        env_dir / "Lib" / "site-packages"
    )
    (site / "zz_testlibs.pth").write_text("\n".join(sorted(libs)) + "\n", encoding="utf-8")
    return py, site


def _run(py, args, cwd):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HNX_", "PYTHON"))}
    return subprocess.run(
        [str(py), "-I", "-m", "homelabnext.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _data(py, tmp_path):
    code = "import homelabnext.paths as p; print(p.data_root()); print(p.__file__)"
    run = subprocess.run(
        [str(py), "-I", "-c", code], cwd=tmp_path, capture_output=True, text=True, timeout=60
    )
    assert run.returncode == 0, run.stderr
    root, where = run.stdout.split("\n")[:2]
    return Path(root), Path(where)


def test_installed_wheel_never_sees_the_source_tree(installed, tmp_path):
    py, site = installed
    root, where = _data(py, tmp_path)
    assert site in where.parents, where
    assert root == site / "homelabnext" / "_data"
    assert ROOT not in root.parents


def test_installed_help_runs_without_the_source_tree(installed, tmp_path):
    py, _ = installed
    run = _run(py, ["--help"], tmp_path)
    assert run.returncode == 0, run.stderr
    assert "usage: hnx" in run.stdout


def test_installed_cli_validates_shipped_examples(installed, tmp_path):
    py, _ = installed
    ex, _where = _data(py, tmp_path)
    ex = ex / "examples" / "minimal"
    site = _run(py, ["site", "validate", str(ex / "site.yml")], tmp_path)
    assert site.returncode == 0, site.stderr + site.stdout
    assert site.stdout.strip().endswith("ok"), site.stdout
    guests = _run(
        py, ["guests", "validate", str(ex / "guests"), "--site", str(ex / "site.yml")], tmp_path
    )
    assert guests.returncode == 0, guests.stderr + guests.stdout
    assert guests.stdout.startswith("ok: 2 guests")
    custom = _run(py, ["custom", "list"], tmp_path)
    assert custom.returncode == 0, custom.stderr + custom.stdout
    assert "custom:vlan-aware-bridge-verifier" in custom.stdout
    reg = _run(py, ["registry", "validate", str(ex / "services.yml")], tmp_path)
    assert reg.returncode == 0, reg.stderr + reg.stdout
    assert reg.stdout.startswith("ok: ")


def test_installed_custom_check_and_ocsf_schemas(installed, tmp_path):
    py, _ = installed
    check = _run(py, ["custom", "check"], tmp_path)
    assert check.returncode == 0, check.stderr + check.stdout
    code = (
        "from homelabnext.lake.tables import load_schemas; "
        "from homelabnext.records import notes; "
        "assert (notes.schema_dir() / 'records' / 'note.schema.json').is_file(); "
        "print(len(load_schemas()))"
    )
    run = subprocess.run(
        [str(py), "-I", "-c", code], cwd=tmp_path, capture_output=True, text=True, timeout=60
    )
    assert run.returncode == 0, run.stderr
    assert int(run.stdout) >= 5


def test_installed_wheel_runs_conform_list_and_swap_plan_on_a_minimal_example(installed, tmp_path):
    """Wave-3 coherence: the swap and conformance CLIs work from the wheel, without a checkout."""
    py, _ = installed
    listing = _run(py, ["conform", "list"], tmp_path)
    assert listing.returncode == 0, listing.stderr + listing.stdout
    for cap in ("lake-query", "object-store", "detections"):
        assert cap in listing.stdout
    assert len([ln for ln in listing.stdout.splitlines() if ln.strip()]) == 15
    # the suites are a source-tree asset: from a wheel the listing says so instead of failing
    assert "no suite" in listing.stdout
    as_json = _run(py, ["conform", "list", "--json"], tmp_path)
    assert as_json.returncode == 0, as_json.stderr
    assert len(json.loads(as_json.stdout)["capabilities"]) == 15

    plan = _run(py, ["swap", "plan"], tmp_path)
    assert plan.returncode == 0, plan.stderr + plan.stdout
    for step in ("declare", "shadow-start", "cutover", "decommission-check", "close"):
        assert step in plan.stdout

    ex, _where = _data(py, tmp_path)
    registry = ex / "examples" / "minimal" / "services.yml"
    flip = _run(
        py,
        ["swap", "plan", "--registry", str(registry), "--service", "dns", "--to-host", "lake-core",
         "--to-port", "5353"],
        tmp_path,
    )  # fmt: skip
    assert flip.returncode == 0, flip.stderr + flip.stdout
    assert "services.dns.host: dns-core -> lake-core" in flip.stdout
    assert "rollback (inverse):" in flip.stdout
