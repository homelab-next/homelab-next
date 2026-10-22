# SPDX-License-Identifier: Apache-2.0
"""The pin controls what runs (ADR-0024): each launcher's argv is read the way the launcher reads
it, and its launch position must be the pinned spec.  Every command line below is fictional; each
"refused" one ran something other than the pin while the pinned spec still appeared in its
arguments, or used a launcher no pin controls."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from homelabnext.mcp import importer, launch, servers

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "examples" / "mcp"
GH, NOTES, DOCKER = (
    yaml.safe_load((CATALOG / f"{sid}.yml").read_text()) for sid in ("github", "notes", "docker")
)
D = DOCKER["origin"]["digest"]
IMG = f"registry.example/mcp/docker@{D}"
GIT = {"kind": "git", "repo": "https://code.example/org/srv", "commit": "a" * 40}
FIRST = {"kind": "first-party", "path": "homelabnext/"}


def _problems(base: dict, command: str, args: list[str], origin: dict | None = None) -> list[str]:
    rec = copy.deepcopy(base)
    rec["transport"].update(command=command, args=args)
    if origin is not None:
        rec["origin"] = origin
    return servers.launch_problems(rec, "x")


ACCEPTED = [
    (GH, "npx", ["-y", "@example/mcp-github@3.2.0"], None),
    (GH, "bunx", ["@example/mcp-github@3.2.0", "--read-only"], None),
    (GH, "npx", ["--package=@example/mcp-github@3.2.0", "-y", "mcp-github"], None),
    (GH, "/usr/local/bin/npx", ["-y", "@example/mcp-github@v3.2.0"], None),  # v is no difference
    (NOTES, "uvx", ["--from", "example-notes-mcp==1.2.0", "notes-mcp"], None),
    (NOTES, "uvx", ["--python", "3.12", "example-notes-mcp==1.2.0"], None),
    (NOTES, "uvx", ["--from", "Example_Notes.MCP==1.2.0", "notes-mcp"], None),  # PEP 503
    (NOTES, "uv", ["tool", "run", "--from", "example-notes-mcp==1.2.0", "notes-mcp"], None),
    (NOTES, "pipx", ["run", "--spec", "example-notes-mcp==1.2.0", "notes-mcp"], None),
    (NOTES, "uvx", ["--from", "example-notes-mcp==1.2.0", "notes-mcp"],
     {**NOTES["origin"], "version": "v1.2.0"}),  # V10
    (DOCKER, "docker", ["run", "-i", "--rm", IMG], None),
    (DOCKER, "podman", ["run", "-it", "-eLOG_LEVEL=debug", "-v", "/srv/x:/x", IMG, "--flag"], None),
    (NOTES, "uvx", ["--from", f"git+{GIT['repo']}@{'a' * 40}", "srv"], GIT),
    (GH, "npx", ["-y", f"git+{GIT['repo']}#{'a' * 40}"], GIT),
    (GH, "hnx", ["mcp", "serve"], FIRST),
    (GH, "./bin/serve", [], FIRST),
]  # fmt: skip

REFUSED = [
    # npm: another package first, --package/-p naming another, a launcher no pin controls
    (GH, "npx", ["-y", "evil-pkg@latest", "@example/mcp-github@3.2.0"], None, "does not launch the pinned"),
    (GH, "npx", ["--package=evil@1.0.0", "-y", "@example/mcp-github@3.2.0"], None, "does not launch the pinned"),
    (GH, "npx", ["-p", "evil@1.0.0", "@example/mcp-github@3.2.0"], None, "does not launch the pinned"),
    (GH, "npx", ["-c", "evil", "@example/mcp-github@3.2.0"], None, "runs a shell line"),
    (GH, "npx", ["--registry", "https://npm.example", "@example/mcp-github@3.2.0"], None, "another registry"),
    (GH, "npx", ["--fancy", "@example/mcp-github@3.2.0"], None, "unknown flag"),
    (GH, "npm", ["exec", "-y", "@example/mcp-github@3.2.0"], None, "not npm"),
    (GH, "pnpm", ["dlx", "@example/mcp-github@3.2.0"], None, "not pnpm"),
    (GH, "/usr/bin/env", ["npx", "-y", "@example/mcp-github@3.2.0"], None, "not env"),
    (GH, "sh", ["-c", "npx -y @example/mcp-github@3.2.0"], None, "not sh"),
    (GH, "node", ["/opt/x/index.js", "@example/mcp-github@3.2.0"], None, "not node"),
    # pypi: extra packages, another --from, another index, a range, uv run, python -m
    (NOTES, "uvx", ["--with", "evil", "--from", "example-notes-mcp==1.2.0", "notes-mcp"], None, "adds packages"),
    (NOTES, "uvx", ["--from", "evil==9", "example-notes-mcp==1.2.0"], None, "does not launch the pinned"),
    (NOTES, "uvx", ["--index-url", "https://pypi.example/simple", "--from", "example-notes-mcp==1.2.0", "n"], None, "another index"),
    (NOTES, "uvx", ["--extra-index-url", "https://pypi.example/simple", "example-notes-mcp==1.2.0"], None, "another index"),
    (NOTES, "pipx", ["run", "--spec", "example-notes-mcp", "notes-mcp", "example-notes-mcp==1.2.0"], None, "does not launch the pinned"),
    (NOTES, "pipx", ["run", "--pip-args=--index-url=x", "example-notes-mcp==1.2.0"], None, "pip another index"),
    (NOTES, "uv", ["run", "--with", "example-notes-mcp==1.2.0", "notes-mcp"], None, "only `uv tool run`"),
    (NOTES, "python3", ["-m", "notes_mcp", "example-notes-mcp==1.2.0"], None, "not python3"),
    # images: another image first, a replaced entrypoint, a tag, a runner no pin controls
    (DOCKER, "docker", ["run", "-i", "--rm", "evil:latest", IMG], None, "does not run the pinned"),
    (DOCKER, "docker", ["run", "-i", "--entrypoint", "sh", IMG, "-c", "x"], None, "entrypoint"),
    (DOCKER, "podman", ["run", "-i", "registry.example/mcp/docker:latest"], None, "does not run the pinned"),
    (DOCKER, "nerdctl", ["run", "-i", IMG], None, "not nerdctl"),
    (DOCKER, "docker", ["-H", "tcp://x", "run", IMG], None, "only `docker run`"),
    (GH, "docker", ["run", "-i", "evil:latest"], None, "not docker"),
    # origin kind and launcher must agree; a git origin runs its commit, not a branch
    (GH, "npx", ["-y", "evil@latest"], FIRST, "not npx"),
    (NOTES, "uvx", ["--from", f"git+{GIT['repo']}@main", "srv"], GIT, "does not launch the pinned"),
    (NOTES, "uvx", ["--from", f"git+https://code.example/other/x@{'a' * 40}", "srv"], GIT, "does not launch the pinned"),
    (GH, "npx", ["-y", "@example/mcp-github@3.2.0"],
     {"kind": "package", "ecosystem": "cargo", "package": "x", "version": "1.0.0", "sha256": "b" * 64}, "run it from an image"),
]  # fmt: skip


@pytest.mark.parametrize(("base", "command", "args", "origin"), ACCEPTED)
def test_the_pinned_launch_is_accepted(base, command, args, origin):
    assert _problems(base, command, args, origin) == []


@pytest.mark.parametrize(
    ("base", "command", "args", "origin", "phrase"),
    REFUSED,
    ids=[f"{r[1]} {' '.join(r[2])[:40]}" for r in REFUSED],
)
def test_a_launch_the_pin_does_not_control_is_refused(base, command, args, origin, phrase):
    problems = _problems(base, command, args, origin)
    assert any(phrase in p for p in problems), problems


def test_the_launch_position_skips_launcher_flags_and_their_values():
    got = launch.parse("docker", ["run", "-i", "-e", "K=v", "--name", "x", IMG, "--srv-flag"])
    assert (got.spec, got.spec_index, got.server_args) == (IMG, 6, 7)
    got = launch.parse("uvx", ["--from", "a==1.0.0", "cmd", "--x"])
    assert (got.spec, got.server_args) == ("a==1.0.0", 3)
    assert launch.parse("hnx", ["mcp"]).ecosystem == "first-party"
    assert launch.parse("/opt/x/sh", []).ecosystem is None  # a shell is never "a path"


def test_the_importer_reads_the_origin_from_the_same_launch_position():
    assert (
        importer.guess_origin("npx", ["-y", "evil@1.0.0", "@example/mcp-github@3.2.0"])["package"]
        == "evil"
    )
    assert importer.guess_origin("docker", ["run", "-i", "--name", "n", IMG])["digest"] == D
    assert (
        importer.guess_origin("pipx", ["run", "--spec", "pkg==1.0.0", "app"])["version"] == "1.0.0"
    )
