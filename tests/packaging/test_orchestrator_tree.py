# SPDX-License-Identifier: Apache-2.0
"""The repository is ready for Go modules (orchestrator/ first) before any Go code lands: build
outputs are ignored, the module is owned and dependency-updated, and MANIFEST.in prunes it."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import go_modules


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
@pytest.mark.parametrize(
    ("path", "ignored"),
    [
        ("orchestrator/internal/api/api.test", True),  # go test -c, in any module
        ("labkit/probe/probe.test", True),
        ("orchestrator/internal/queue/cpu.prof", True),
        ("orchestrator/coverage.out", True),
        ("build/bin/controller", True),  # where binaries are built
        ("orchestrator/cmd/controller/main.go", False),
        ("orchestrator/internal/api/api_test.go", False),
        ("orchestrator/go.sum", False),
        ("orchestrator/skips.yml", False),
        ("orchestrator/internal/api/testdata/request.json", False),
    ],
)
def test_go_build_outputs_are_ignored_and_sources_are_not(path, ignored):
    r = subprocess.run(
        ["git", "check-ignore", "--no-index", "-q", path], cwd=ROOT, capture_output=True
    )
    assert r.returncode in (0, 1), r.stderr
    assert (r.returncode == 0) is ignored


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_a_directory_named_for_the_test_tld_is_not_ignored_like_a_test_binary(tmp_path):
    # verify3.md: *.test also matched directories, so fixtures under a reserved-TLD name such as
    # examples/zones/ca.test/ were silently left out of git (check-ignore needs them on disk to
    # tell a directory from a file)
    (tmp_path / ".gitignore").write_text((ROOT / ".gitignore").read_text())
    files = [
        "examples/zones/ca.test/zone.txt",
        "orchestrator/internal/api/testdata/host.test/request.json",
        "orchestrator/internal/api/api.test",  # go test -c: still ignored
    ]
    for rel in files:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    r = subprocess.run(
        ["git", "check-ignore", *files], cwd=tmp_path, capture_output=True, text=True
    )
    assert r.stdout.splitlines() == ["orchestrator/internal/api/api.test"], r.stderr


def test_the_root_gitignore_names_no_components_binaries():
    """A component's binary names belong to the component (its own .gitignore or /build/)."""
    lines = [x for x in (ROOT / ".gitignore").read_text().splitlines() if not x.startswith("#")]
    assert not [x for x in lines if "orchestrator" in x]


def test_codeowners_own_the_go_module():
    lines = (ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
    assert any(line.split()[:1] == ["/orchestrator/"] and len(line.split()) > 1 for line in lines)


def _gomod_directories() -> list[str]:
    updates = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())["updates"]
    return [d for u in updates if u["package-ecosystem"] == "gomod" for d in u["directories"]]


def test_dependabot_updates_go_modules_like_the_other_ecosystems():
    updates = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())["updates"]
    (go,) = [u for u in updates if u["package-ecosystem"] == "gomod"]
    pip = next(u for u in updates if u["package-ecosystem"] == "pip")
    for key in ("schedule", "cooldown", "commit-message"):
        assert go[key] == pip[key], key


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_every_discovered_go_module_has_a_dependabot_entry():
    """Dependabot cannot glob for modules: its gomod directories are listed by hand, and every
    module tools/go_modules.py discovers (and its linters' module) must be among them."""
    files, _links = go_modules.tracked(ROOT)
    wanted = go_modules.dependabot_directories(go_modules.modules(files))
    assert sorted(set(wanted) - set(_gomod_directories())) == []


def test_the_dependabot_check_names_each_module_and_its_linters():
    mods = go_modules.modules(
        ["orchestrator/go.mod", "orchestrator/tools/go.mod", "lab/go.mod", "go.mod"]
    )
    assert go_modules.dependabot_directories(mods) == [
        "/",
        "/lab",
        "/orchestrator",
        "/orchestrator/tools",
    ]


def test_manifest_prunes_the_go_module():
    lines = [line.strip() for line in (ROOT / "MANIFEST.in").read_text().splitlines()]
    assert "prune orchestrator" in lines
    assert not any(
        line.startswith(("graft orchestrator", "recursive-include orchestrator")) for line in lines
    )
