# SPDX-License-Identifier: Apache-2.0
"""The repository is ready for the Go module at orchestrator/ before any Go code lands: build
outputs are ignored, the module is owned and dependency-updated, and MANIFEST.in prunes it."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
@pytest.mark.parametrize(
    ("path", "ignored"),
    [
        ("orchestrator/controller", True),  # `go build ./cmd/controller` in the module root
        ("orchestrator/vaultmcp", True),
        ("orchestrator/internal/api/api.test", True),  # go test -c
        ("orchestrator/internal/queue/cpu.prof", True),
        ("orchestrator/coverage.out", True),
        ("orchestrator/bin/controller", True),
        ("orchestrator/cmd/controller/main.go", False),
        ("orchestrator/internal/api/api_test.go", False),
        ("orchestrator/go.sum", False),
        ("orchestrator/skips.yml", False),
        ("orchestrator/internal/api/testdata/request.json", False),
        ("homelabnext/controller", False),  # the names are scoped to orchestrator/
    ],
)
def test_go_build_outputs_are_ignored_and_sources_are_not(path, ignored):
    r = subprocess.run(
        ["git", "check-ignore", "--no-index", "-q", path], cwd=ROOT, capture_output=True
    )
    assert r.returncode in (0, 1), r.stderr
    assert (r.returncode == 0) is ignored


def test_codeowners_own_the_go_module():
    lines = (ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
    assert any(line.split()[:1] == ["/orchestrator/"] and len(line.split()) > 1 for line in lines)


def test_dependabot_updates_the_go_module_like_the_other_ecosystems():
    updates = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())["updates"]
    (go,) = [u for u in updates if u["package-ecosystem"] == "gomod"]
    pip = next(u for u in updates if u["package-ecosystem"] == "pip")
    assert go["directories"] == ["/orchestrator", "/orchestrator/tools"]
    for key in ("schedule", "cooldown", "commit-message"):
        assert go[key] == pip[key], key


def test_manifest_prunes_the_go_module():
    lines = [line.strip() for line in (ROOT / "MANIFEST.in").read_text().splitlines()]
    assert "prune orchestrator" in lines
    assert not any(
        line.startswith(("graft orchestrator", "recursive-include orchestrator")) for line in lines
    )
