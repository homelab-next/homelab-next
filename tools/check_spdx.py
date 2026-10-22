#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: check-spdx
#   kind: check
#   purpose: Fail when a tracked source or config file has no SPDX-License-Identifier in its first five lines.
#   owner: maintainers
#   trigger: [ci:ci/lint, make:spdx, pre-commit:spdx-header]
#   invariant: [Q-09]
#   inputs: the tracked tree (git ls-files), or the files named on the command line
#   outputs: one line per file without the header
#   exit:
#     "0": every file carries the header
#     "1": some file does not
"""Fail if a source or config file lacks an SPDX-License-Identifier header in its first 5 lines.

Checked: ``*.py``, ``*.sh``, ``*.yml``, ``*.yaml``, ``*.toml``.  With no arguments the file list is
``git ls-files`` (falling back to a directory walk outside a work tree).  Two escape hatches,
both reviewed in this file rather than spread through the tree:

* ``GENERATED``: expected outputs compared byte for byte (``golden/`` directories, the rendered
  MCP client configurations); a header there would have to be emitted by the generator.
* ``VENDORED``: third-party files kept verbatim.  They must still carry *an* SPDX identifier
  (their own licence), just not necessarily Apache-2.0.  Add ``"glob": "reason"`` entries.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from pathlib import Path

HEADER = "SPDX-License-Identifier: Apache-2.0"
ANY_HEADER = re.compile(r"SPDX-License-Identifier:\s*\S")
SUFFIXES = {".py", ".sh", ".yml", ".yaml", ".toml"}
SKIP_DIRS = {".git", ".venv", "venv", "build", "dist", "__pycache__", "node_modules"}
GENERATED = (
    "*/golden/*",
    # client configurations rendered from the MCP catalog (hnx mcp catalog render, compared byte
    # for byte by its --check): the formats are other programs', so the render adds no licence line
    "examples/mcp/clients/hermes/*",
    "examples/mcp/clients/llm-orchestrator/mcp_catalog.yaml",
)
VENDORED: dict[str, str] = {
    # "path/glob/*.sh": "upstream project X, kept verbatim",
}


def _matches(path: Path, globs) -> bool:
    posix = path.as_posix()
    return any(fnmatch.fnmatch(posix, g) or fnmatch.fnmatch("./" + posix, g) for g in globs)


def missing_header(path: Path) -> bool:
    if path.stat().st_size == 0:
        return False  # empty __init__.py is allowed
    if _matches(path, GENERATED):
        return False
    head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:5]
    if _matches(path, VENDORED):
        return not any(ANY_HEADER.search(line) for line in head)
    return not any(HEADER in line for line in head)


def _tracked() -> list[Path] | None:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=False)
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return [Path(n) for n in out.stdout.decode().split("\0") if n]


def collect(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args]
    files = _tracked()
    if files is None:
        files = [p for p in Path(".").rglob("*") if not SKIP_DIRS & set(p.parts)]
    return [p for p in files if p.suffix in SUFFIXES and p.is_file() and not p.is_symlink()]


def main(argv: list[str] | None = None) -> int:
    bad = [p for p in collect(sys.argv[1:] if argv is None else argv) if missing_header(p)]
    for p in bad:
        print(f"{p}: missing '{HEADER}'")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
