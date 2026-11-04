# SPDX-License-Identifier: Apache-2.0
""".github/dependabot.yml watches every manifest it can parse, at directories that exist, with one
cooldown: a directory that does not exist is dead config that updates nothing (the gomod block
for an ``orchestrator/`` that never landed was one), and a manifest no entry names is never
updated at all."""

from __future__ import annotations

import subprocess
from pathlib import Path, PurePosixPath

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
UPDATES = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())["updates"]

# what dependabot reads in a listed directory, per ecosystem (its own file fetchers)
MANIFESTS = {
    "github-actions": ("*.yml", "*.yaml"),
    "pip": ("*.txt", "*.in"),
    "pre-commit": (".pre-commit-config.yaml",),
    "docker-compose": ("docker-compose.yml", "compose.yml", "docker-compose.yaml", "compose.yaml"),
    "docker": ("Dockerfile",),
}


def _dirs(ecosystem: str) -> list[str]:
    return [d for u in UPDATES if u["package-ecosystem"] == ecosystem for d in u["directories"]]


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [p for p in out.split("\0") if p]


def test_every_entry_has_a_known_ecosystem_and_the_same_cadence_and_cooldown():
    pip = next(u for u in UPDATES if u["package-ecosystem"] == "pip")
    assert pip["cooldown"] == {"default-days": 14}  # = `make constraints` --exclude-newer 14 days
    for u in UPDATES:
        assert u["package-ecosystem"] in MANIFESTS or u["package-ecosystem"] == "gomod", u
        for key in ("schedule", "cooldown"):
            assert u[key] == pip[key], (u["package-ecosystem"], key)
        assert u["commit-message"]["prefix"] in ("ci", "deps"), u["package-ecosystem"]


@pytest.mark.parametrize(
    "ecosystem", sorted(e for e in {u["package-ecosystem"] for u in UPDATES} if e != "gomod")
)
def test_every_listed_directory_exists_and_holds_what_the_ecosystem_reads(ecosystem):
    for d in _dirs(ecosystem):
        path = ROOT / d.lstrip("/")
        if ecosystem == "github-actions" and d == "/":
            path = ROOT / ".github" / "workflows"
        assert path.is_dir(), f"{ecosystem}: {d} does not exist"
        found = [f for pat in MANIFESTS[ecosystem] for f in path.glob(pat) if f.is_file()]
        assert found, f"{ecosystem}: {d} holds none of {MANIFESTS[ecosystem]}"


@pytest.mark.requires_tool("git")
def test_every_manifest_in_the_tree_is_watched():
    files = _tracked()
    want: dict[str, set[str]] = {e: set() for e in ("github-actions", "docker-compose", "docker")}
    for f in files:
        p = PurePosixPath(f)
        parent = "/" + str(p.parent) if str(p.parent) != "." else "/"
        if p.name == "Dockerfile":
            want["docker"].add(parent)
        elif p.name in MANIFESTS["docker-compose"] and not f.startswith("tests/"):
            want["docker-compose"].add(parent)
        elif p.parent.name == "workflows" and p.parent.parent.name == ".github":
            want["github-actions"].add("/" if f.startswith(".github/") else parent)
        elif p.name in ("action.yml", "action.yaml") and f.startswith(".github/actions/"):
            want["github-actions"].add(parent)
    for ecosystem, dirs in want.items():
        assert sorted(dirs - set(_dirs(ecosystem))) == [], ecosystem
    assert (ROOT / ".pre-commit-config.yaml").is_file() and "/" in _dirs("pre-commit")
