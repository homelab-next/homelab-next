# SPDX-License-Identifier: Apache-2.0
"""Helpers for the packaging tests: a git-tracked copy of the checkout and PEP 517 builds.

Builds run the PEP 517 hooks of ``setuptools.build_meta`` in a subprocess (no network, no build
isolation), against a throwaway copy holding exactly the tracked files, so the real checkout is
never written to and an untracked file in it cannot leak into what the tests inspect.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.org",
}


def git(cwd: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        env={**os.environ, **GIT_ENV},
    ).stdout


def export_tree(dst: Path) -> Path:
    """Copy the checkout's tracked files into ``dst`` and track them there too."""
    if importlib.util.find_spec("setuptools") is None:
        pytest.skip("setuptools is not installed (build without network needs it)")
    if not (ROOT / ".git").exists() or shutil.which("git") is None:
        pytest.skip("needs a git checkout and git")
    names = [n for n in git(ROOT, "ls-files", "-z").decode().split("\0") if n]
    for n in names:
        src = ROOT / n
        if not src.exists():
            continue  # deleted in the working tree
        (dst / n).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst / n, follow_symlinks=False)
    git(dst, "init", "-q")
    git(dst, "add", "-A")
    return dst


def build(kind: str, src: Path, out: Path) -> Path:
    """Run the ``build_sdist``/``build_wheel`` hook in ``src``; return the artefact path."""
    out.mkdir(parents=True, exist_ok=True)
    code = f"import sys; from setuptools import build_meta as b; print(b.build_{kind}(sys.argv[1]))"
    run = subprocess.run(
        [sys.executable, "-c", code, str(out)],
        cwd=src,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if run.returncode != 0:
        raise BuildFailed(run.stdout + run.stderr)
    return out / run.stdout.strip().splitlines()[-1]


class BuildFailed(Exception):
    pass
