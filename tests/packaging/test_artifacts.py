# SPDX-License-Identifier: Apache-2.0
"""What a wheel and an sdist may contain, and what they must never contain.

Regression for the packaging leak: the build used to copy the data trees with ``copytree``, so an
untracked ``.env`` (or any scratch file) and the target of a symbolic link were shipped.  The build
now packages only git-tracked files (or, from an sdist, its manifest) and refuses symbolic links.
Every artefact is checked against an allowlist of paths and leak-scanned after unpacking.
"""

import re
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from pkgbuild import ROOT, BuildFailed, build, export_tree, git

sys.path.insert(0, str(ROOT / "tools"))
import leak_scan

pytestmark = pytest.mark.slow

WHEEL_ALLOW = re.compile(
    r"^(?:homelabnext/(?!.*/\.)[\w/.-]+\.(?:py|tmpl|yml)"
    r"|homelabnext/agent/terms\.md"  # the terms every agent session pack carries
    r"|homelabnext/status/maps/static/maps\.(?:js|css)"  # the interactive maps' script and style
    r"|homelabnext/_data/(?:schemas|profiles|examples)/(?!.*/\.)[\w/.-]+\.(?:json|ya?ml|md|txt|j2)"
    # the example broker manifest pins these handlers by digest; without them it does not validate
    r"|homelabnext/_data/examples/broker/handlers/[\w-]+\.sh"
    # the Code Mode goldens generated from that manifest (hnx codemode gen, ADR-0031)
    r"|homelabnext/_data/examples/codemode/[\w-]+/(?:stubs\.pyi|types\.d\.ts)"
    # the capability contracts runtime code imports; never the suites, fakes or targets
    r"|conformance/protocols/\w+\.py"
    r"|homelabnext-[\w.]+\.dist-info/(?:METADATA|RECORD|WHEEL|entry_points\.txt|top_level\.txt"
    r"|licenses/(?:LICENSE|NOTICE)))$"
)
SDIST_TOP_ALLOW = {
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "MANIFEST.in",
    "NOTICE",
    "PKG-INFO",
    "README.md",
    "SECURITY.md",
    "conformance",
    "conftest.py",
    "examples",
    "homelabnext",
    "homelabnext.egg-info",
    "profiles",
    "pyproject.toml",
    "schemas",
    "setup.cfg",
    "setup.py",
    "tests",
    "tools",
}
PLANTED = "LAB_DB_PASS" + "WORD=Zq81kXw" + "Lm2pV9a\n"
# a stand-in for the Go module (orchestrator/): source, an example config and a Python helper
ORCHESTRATOR = {
    "orchestrator/go.mod": "module example.com/fixture\n\ngo 1.21\n",
    "orchestrator/internal/queue/queue.go": "package queue\n",
    "orchestrator/examples/controller.yaml": "listen: example.internal\n",
    "orchestrator/contrib/hnx_adapter/adapter.py": "X = 1\n",
}


@pytest.fixture(scope="module")
def artefacts(tmp_path_factory):
    """sdist and wheel built from a clean tracked copy that also holds untracked bait files."""
    work = export_tree(tmp_path_factory.mktemp("src"))
    for bait in ("examples/.env", "schemas/local.env", "homelabnext/scratch_notes.py"):
        (work / bait).write_text(PLANTED)  # untracked: must not ship
    for rel, text in ORCHESTRATOR.items():  # tracked, as the Go module will be: must not ship
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(text)
    git(work, "add", "orchestrator")
    out = tmp_path_factory.mktemp("dist")
    sdist = build("sdist", work, out)
    wheel = build("wheel", work, out)
    return work, sdist, wheel


def test_wheel_contents_match_the_allowlist(artefacts):
    _work, _sdist, wheel = artefacts
    names = zipfile.ZipFile(wheel).namelist()
    stray = [n for n in names if not WHEEL_ALLOW.match(n)]
    assert stray == []
    assert not any(n.endswith((".env", "scratch_notes.py")) for n in names)


def test_sdist_contents_match_the_allowlist(artefacts):
    _work, sdist, _wheel = artefacts
    with tarfile.open(sdist) as t:
        members = t.getmembers()
    rel = [m.name.split("/", 1)[1] for m in members if "/" in m.name]
    tops = {r.split("/", 1)[0] for r in rel}
    assert tops <= SDIST_TOP_ALLOW, sorted(tops - SDIST_TOP_ALLOW)
    for must in ("tests", "conformance", "tools", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md"):
        assert must in tops
    assert not any(Path(r).name.startswith(".") for r in rel)  # no dotfiles at any depth
    assert not any(".env" in Path(r).name for r in rel)
    assert not any(m.issym() or m.islnk() for m in members)
    assert not any(r.endswith("scratch_notes.py") for r in rel)


def test_the_go_module_is_in_neither_artefact(artefacts):
    """orchestrator/ is a Go module with its own CI job; MANIFEST.in prunes it from the sdist and
    the wheel's package list never reaches it (docs: the migration plan, section 3.3)."""
    work, sdist, wheel = artefacts
    assert (work / "orchestrator" / "go.mod").is_file()  # the stand-in was really there
    with tarfile.open(sdist) as t:
        sdist_names = [m.name.split("/", 1)[1] for m in t.getmembers() if "/" in m.name]
    wheel_names = zipfile.ZipFile(wheel).namelist()
    for names in (sdist_names, wheel_names):
        assert [n for n in names if "orchestrator" in Path(n).parts] == []
        assert not any(n.endswith((".go", "go.mod", "hnx_adapter/adapter.py")) for n in names)


def test_unpacked_artefacts_are_leak_clean(artefacts, tmp_path):
    _work, sdist, wheel = artefacts
    with tarfile.open(sdist) as t:
        t.extractall(tmp_path / "sdist", filter="data")
    zipfile.ZipFile(wheel).extractall(tmp_path / "wheel")
    for record in (tmp_path / "wheel").glob("*.dist-info/RECORD"):
        record.unlink()  # file hashes by construction (high entropy, nothing to leak)
    skipped: list = []
    hits = leak_scan.scan_paths([str(tmp_path)], skipped=skipped)
    assert hits == [] and skipped == []


def test_wheel_from_the_sdist_needs_no_git_and_matches(artefacts, tmp_path):
    _work, sdist, wheel = artefacts
    with tarfile.open(sdist) as t:
        t.extractall(tmp_path, filter="data")
    src = next(tmp_path.glob("homelabnext-*"))
    assert not (src / ".git").exists()
    again = build("wheel", src, tmp_path / "out")
    assert sorted(zipfile.ZipFile(again).namelist()) == sorted(zipfile.ZipFile(wheel).namelist())


def test_tracked_symlink_is_refused(tmp_path):
    work = export_tree(tmp_path / "src")
    outside = tmp_path / "outside.json"
    outside.write_text('{"not": "part of the tree"}\n')
    (work / "schemas" / "linked.json").symlink_to(outside)
    git(work, "add", "schemas/linked.json")
    with pytest.raises(BuildFailed, match="symbolic link"):
        build("wheel", work, tmp_path / "out")


def test_build_without_git_or_manifest_is_refused(tmp_path):
    work = export_tree(tmp_path / "src")
    import shutil

    shutil.rmtree(work / ".git")
    with pytest.raises(BuildFailed, match="no reviewed list"):
        build("wheel", work, tmp_path / "out")
