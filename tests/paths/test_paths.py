# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.paths``: lookup order, injected roots, caching, error text, no stray locators."""

import re
import sys
from pathlib import Path

import pytest

from homelabnext import paths

ROOT = Path(__file__).resolve().parents[2]


def _tree(base: Path, *kinds: str) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    for k in kinds:
        (base / k).mkdir(parents=True, exist_ok=True)
    return base


def test_source_tree_is_the_last_resort(tmp_path):
    src = _tree(tmp_path / "src", "schemas")
    got = paths.resource_dir("schemas", env={}, package_root=tmp_path / "nopkg", source_root=src)
    assert got == src / "schemas"


def test_package_data_beats_source_tree(tmp_path):
    pkg = _tree(tmp_path / "pkg", "schemas")
    src = _tree(tmp_path / "src", "schemas")
    assert (
        paths.resource_dir("schemas", env={}, package_root=pkg, source_root=src) == pkg / "schemas"
    )


def test_env_override_beats_everything(tmp_path):
    pkg = _tree(tmp_path / "pkg", "schemas")
    src = _tree(tmp_path / "src", "schemas")
    mine = _tree(tmp_path / "mine")
    got = paths.resource_dir(
        "schemas", env={"HNX_SCHEMAS_DIR": str(mine)}, package_root=pkg, source_root=src
    )
    assert got == mine


def test_legacy_schema_dir_spelling_still_works(tmp_path):
    mine = _tree(tmp_path / "mine")
    env = {"HNX_SCHEMA_DIR": str(mine)}
    assert paths.resource_dir("schemas", env=env, package_root=tmp_path / "x") == mine


def test_data_dir_env_supplies_every_kind(tmp_path):
    data = _tree(tmp_path / "d", "schemas", "profiles", "examples")
    env = {"HNX_DATA_DIR": str(data)}
    for kind in paths.KINDS:
        got = paths.resource_dir(kind, env=env, package_root=tmp_path / "x", source_root=tmp_path)
        assert got == data / kind


def test_a_set_but_missing_override_falls_through_and_is_reported(tmp_path):
    src = _tree(tmp_path / "src", "schemas")
    env = {"HNX_SCHEMAS_DIR": str(tmp_path / "typo")}
    assert paths.resource_dir("schemas", env=env, package_root=tmp_path / "p", source_root=src) == (
        src / "schemas"
    )


def test_error_lists_every_place_tried(tmp_path):
    env = {"HNX_SCHEMAS_DIR": str(tmp_path / "typo")}
    with pytest.raises(paths.ResourceNotFound) as ei:
        paths.resource_dir(
            "profiles", env={}, package_root=tmp_path / "pkg", source_root=tmp_path / "src"
        )
    msg = str(ei.value)
    assert "HNX_PROFILES_DIR" in msg
    assert "HNX_DATA_DIR" in msg
    assert "package data" in msg and str(tmp_path / "pkg" / "profiles") in msg
    assert "source tree" in msg and str(tmp_path / "src" / "profiles") in msg
    assert len(ei.value.tried) == 4
    assert isinstance(ei.value, FileNotFoundError)
    with pytest.raises(paths.ResourceNotFound) as ej:
        paths.resource_dir("schemas", env=env, package_root=tmp_path / "p", source_root=tmp_path)
    assert str(tmp_path / "typo") in str(ej.value)


def test_resource_file_names_the_missing_file(tmp_path):
    src = _tree(tmp_path / "src", "schemas")
    with pytest.raises(paths.ResourceNotFound, match=r"platform/site\.schema\.json"):
        paths.schema_file(
            "platform", "site.schema.json", env={}, package_root=tmp_path / "p", source_root=src
        )
    f = src / "schemas" / "platform" / "site.schema.json"
    f.parent.mkdir()
    f.write_text("{}")
    got = paths.schema_file(
        "platform", "site.schema.json", env={}, package_root=tmp_path / "p", source_root=src
    )
    assert got == f


def test_unknown_kind_is_a_value_error():
    with pytest.raises(ValueError, match="unknown data kind"):
        paths.resource_dir("nope")


def test_ocsf_dir_accepts_root_or_ocsf_itself(tmp_path):
    root = _tree(tmp_path / "s", "ocsf")
    assert paths.ocsf_dir(env={"HNX_SCHEMAS_DIR": str(root)}) == root / "ocsf"
    flat = _tree(tmp_path / "flat")
    assert paths.ocsf_dir(env={"HNX_SCHEMAS_DIR": str(flat)}) == flat


def test_data_root_is_the_parent_of_schemas(tmp_path):
    src = _tree(tmp_path / "src", "schemas")
    assert paths.data_root(env={}, package_root=tmp_path / "p", source_root=src) == src


def test_lookups_are_cached_until_cleared(monkeypatch, tmp_path):
    a = _tree(tmp_path / "a")
    b = _tree(tmp_path / "b")
    paths.clear_cache()
    try:
        monkeypatch.setenv("HNX_EXAMPLES_DIR", str(a))
        assert paths.examples_dir() == a
        monkeypatch.setenv("HNX_EXAMPLES_DIR", str(b))
        assert paths.examples_dir() == a  # cached
        paths.clear_cache()
        assert paths.examples_dir() == b
    finally:
        paths.clear_cache()


def test_injecting_a_root_bypasses_the_cache(tmp_path):
    paths.clear_cache()
    first = paths.schemas_dir()
    other = _tree(tmp_path / "o", "schemas")
    assert (
        paths.schemas_dir(env={}, package_root=tmp_path / "p", source_root=other)
        == other / "schemas"
    )
    assert paths.schemas_dir() == first


def test_this_checkout_resolves_every_kind():
    for kind in paths.KINDS:
        assert paths.resource_dir(kind).is_dir()
    assert paths.schema_file("platform", "site.schema.json").is_file()
    assert (paths.ocsf_dir() / "authentication.v1.json").is_file()
    assert paths.example_file("minimal", "site.yml").is_file()


def test_source_tree_holds_no_packaged_copy():
    """The build copies the data into the wheel only; a stale copy here would shadow the truth."""
    assert not (ROOT / "homelabnext" / "_data").exists()


LOCATOR = re.compile(r"parents\[\d\]\s*/\s*\"(schemas|profiles|examples)\"|HNX_SCHEMA(S)?_DIR\"")


def test_no_module_locates_data_on_its_own():
    offenders = []
    for py in sorted((ROOT / "homelabnext").rglob("*.py")):
        if py.name == "paths.py":
            continue
        for n, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            if LOCATOR.search(line) or re.search(r"REPO_ROOT\s*/\s*\"(schemas|profiles)\"", line):
                offenders.append(f"{py.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not offenders, "use homelabnext.paths instead:\n" + "\n".join(offenders)


# ---- the source root is verified before anything is read or executed from it
@pytest.fixture
def not_a_checkout(tmp_path, monkeypatch):
    """Pretend the package was imported from site-packages (no homelabnext pyproject above it)."""
    site = tmp_path / "site-packages"
    (site / "tools").mkdir(parents=True)
    (site / "tools" / "schema_check.py").write_text("raise SystemExit('planted code ran')\n")
    (site / "tools" / "role_lint.py").write_text("raise SystemExit('planted code ran')\n")
    (site / "tools" / "no_raw_endpoints.py").write_text("raise SystemExit('planted code ran')\n")
    (site / "schemas").mkdir()
    monkeypatch.setattr(paths, "_SOURCE_ROOT", site)
    paths.clear_cache()
    yield site
    paths.clear_cache()


def test_this_checkout_is_verified():
    assert paths.checkout_root() == ROOT
    assert paths.checkout_tool("schema_check.py", feature="t") == ROOT / "tools" / "schema_check.py"


def test_site_packages_is_not_a_checkout(not_a_checkout, tmp_path):
    assert paths.checkout_root() is None
    with pytest.raises(paths.NotACheckout, match="needs a homelabnext source checkout"):
        paths.checkout_tool("schema_check.py", feature="hnx schema-check")
    (not_a_checkout / "pyproject.toml").write_text('[project]\nname = "someone-else"\n')
    paths.clear_cache()
    assert paths.checkout_root() is None
    labels = [
        label for label, p in paths.candidates("schemas", env={}, package_root=tmp_path / "x")
    ]
    assert any("is not a homelabnext checkout" in label for label in labels)
    with pytest.raises(paths.ResourceNotFound):
        paths.resource_dir("schemas", env={}, package_root=tmp_path / "x")


def test_tool_runners_refuse_outside_a_checkout(not_a_checkout, capsys):
    import importlib

    from homelabnext import cli
    from homelabnext.scaffold import core

    assert cli.main(["schema-check"]) == 2
    assert "needs a homelabnext source checkout" in capsys.readouterr().err
    with pytest.raises(core.ScaffoldError, match="source checkout"):
        core._role_lint()
    lint = importlib.import_module("homelabnext.customization.lint")
    assert lint._tools_path() is None  # falls back to the built-in matcher


def test_conformance_suites_are_not_imported_outside_a_checkout(not_a_checkout, monkeypatch):
    from homelabnext.conform import registry

    planted = not_a_checkout / "conformance" / "suites"
    planted.mkdir(parents=True)
    (not_a_checkout / "conformance" / "__init__.py").write_text("")
    (planted / "__init__.py").write_text("")
    (planted / "idp.py").write_text("raise SystemExit('planted code ran')\n")
    monkeypatch.syspath_prepend(str(not_a_checkout))
    for name in [m for m in sys.modules if m == "conformance" or m.startswith("conformance.")]:
        monkeypatch.delitem(sys.modules, name)
    with pytest.raises(registry.ConformError, match="needs a source checkout"):
        registry.load_module("idp")
