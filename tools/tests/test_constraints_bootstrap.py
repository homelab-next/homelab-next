# SPDX-License-Identifier: Apache-2.0
"""constraints/bootstrap.txt is the pip block of constraints/ci.txt, and constraints/build.txt its
setuptools block (the wheel's pinned build backend, docs/broker.md "Deploying with Ansible"), as
`make constraints` cuts them.

Dependabot edits either file in place (hashes included) and never runs `make constraints`, so a
pip bump in one file alone would leave CI installing one pip under one name and another under the
other; this ties the two together offline."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def pip_block(ci: str, package: str = "pip") -> str:
    """What the Makefile's awk prints: from the ``<package>==`` line through its last continued
    line."""
    out: list[str] = []
    for line in ci.splitlines():
        if not out and not line.startswith(f"{package}=="):
            continue
        out.append(line)
        if not line.endswith("\\"):
            break
    return "".join(f"{line}\n" for line in out)


def test_the_pip_block_is_cut_like_the_makefile_cuts_it():
    ci = "a==1 \\\n    --hash=sha256:aa\npip==2 \\\n    --hash=sha256:bb \\\n    --hash=sha256:cc\n    # via x\nz==3\n"
    assert pip_block(ci) == "pip==2 \\\n    --hash=sha256:bb \\\n    --hash=sha256:cc\n"
    assert pip_block("a==1\n") == ""


def test_bootstrap_is_the_pip_block_of_the_ci_constraints():
    ci = (ROOT / "constraints" / "ci.txt").read_text()
    bootstrap = (ROOT / "constraints" / "bootstrap.txt").read_text()
    block = pip_block(ci)
    assert block, "constraints/ci.txt pins no pip"
    assert bootstrap == block, "run `make constraints` (or copy ci.txt's pip block) and commit"


def test_the_makefile_still_cuts_bootstrap_from_ci():
    make = (ROOT / "Makefile").read_text()
    assert (
        "awk '/^pip==/{p=1} p{print} p&&!/\\\\$$/{exit}' constraints/ci.txt > constraints/bootstrap.txt"
        in make
    )


def test_build_is_the_setuptools_block_of_the_ci_constraints():
    ci = (ROOT / "constraints" / "ci.txt").read_text()
    build = (ROOT / "constraints" / "build.txt").read_text()
    block = pip_block(ci, "setuptools")
    assert block, "constraints/ci.txt pins no setuptools"
    assert build == block, "run `make constraints` (or copy ci.txt's setuptools block) and commit"


def test_the_makefile_still_cuts_build_from_ci():
    make = (ROOT / "Makefile").read_text()
    assert (
        "awk '/^setuptools==/{p=1} p{print} p&&!/\\\\$$/{exit}' constraints/ci.txt > constraints/build.txt"
        in make
    )
