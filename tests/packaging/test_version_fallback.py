# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.__version__`` on a checkout that is not installed is the checkout's own version.

It used to fall back to ``0.0.0+local``, which no changelog section names, so anything that looks
the running version up in CHANGELOG.md (``hnx deploy-changed --to``, the events tests) failed on an
uninstalled tree and passed only where the wheel happened to be installed."""

import importlib
from importlib import metadata

import homelabnext
from homelabnext import _version


def _reload_without_metadata(monkeypatch):
    def missing(name):
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(metadata, "version", missing)
    try:
        return importlib.reload(homelabnext).__version__
    finally:
        monkeypatch.undo()
        importlib.reload(homelabnext)


def test_an_uninstalled_checkout_reports_the_single_source_version(monkeypatch):
    assert _reload_without_metadata(monkeypatch) == _version.VERSION


def test_the_fallback_version_has_a_changelog_section(monkeypatch):
    from pathlib import Path

    changelog = (Path(__file__).resolve().parents[2] / "CHANGELOG.md").read_text()
    assert f"## [{_reload_without_metadata(monkeypatch)}]" in changelog


def test_a_partial_copy_without_the_version_module_still_imports(tmp_path):
    """config_leak_scan copies only ``__init__.py`` and ``shapes.py`` of the package to the host it
    scans: the package must import there, with no ``_version`` beside it and no metadata."""
    import subprocess
    import sys
    from pathlib import Path

    pkg = tmp_path / "homelabnext"
    pkg.mkdir()
    src = Path(homelabnext.__file__).parent
    for name in ("__init__.py", "shapes.py"):
        (pkg / name).write_bytes((src / name).read_bytes())
    # the copy first on the path, and no package metadata (as on the scanned host, where an
    # installed homelabnext would not be the copy either)
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); from importlib import metadata\n"
        "def missing(name): raise metadata.PackageNotFoundError(name)\n"
        "metadata.version = missing\n"
        "import homelabnext, homelabnext.shapes\n"
        "assert homelabnext.__file__.startswith(sys.argv[1]), homelabnext.__file__\n"
        "print(homelabnext.__version__)\n"
    )
    r = subprocess.run(
        [sys.executable, "-I", "-c", code, str(tmp_path)],
        cwd=tmp_path, capture_output=True, text=True, timeout=60,
    )  # fmt: skip
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "0.0.0+local"
