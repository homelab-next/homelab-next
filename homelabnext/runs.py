# SPDX-License-Identifier: Apache-2.0
"""Per-run private output directories: ``runs/<run_id>/``.

A script, tool or agent run that writes scratch output (intermediate files, a report before it is
published, a capture) writes it into a directory of its own, so two runs never write the same
path and nothing is left in the source tree or a shared temp directory for the next run to
mistake for its own.  ``tools/run_output_lint.py`` holds the repository's scripts to this.

The base is ``<root>/runs`` (gitignored), or ``$HNX_RUNS_DIR`` when set; ``root`` defaults to the
working directory.  A run id is one path segment of ``[A-Za-z0-9._-]`` starting with a letter or
digit (a timestamp, a UUID, ``<script>-<stamp>``), so it can never name a directory outside the
base.  The directory is created ``0700``: run output may hold what the run read.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path

__all__ = ["RUNS_ENV", "RunIdError", "run_dir", "runs_base", "validate_run_id"]

RUNS_ENV = "HNX_RUNS_DIR"
DEFAULT_BASE = "runs"
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class RunIdError(ValueError):
    """A run id that is not one safe path segment."""


def validate_run_id(run_id) -> str:
    """``run_id`` unchanged when it is one safe segment, else :class:`RunIdError`."""
    if not isinstance(run_id, str) or not _RUN_ID.match(run_id) or ".." in run_id:
        raise RunIdError(
            f"run id {run_id!r} must be one path segment of [A-Za-z0-9._-] starting with a "
            "letter or digit, without '..'"
        )
    return run_id


def runs_base(root=None, env: Mapping[str, str] | None = None) -> Path:
    """Where run directories live: ``$HNX_RUNS_DIR``, else ``<root>/runs``."""
    env = os.environ if env is None else env
    if env.get(RUNS_ENV):
        return Path(env[RUNS_ENV])
    return Path(root if root is not None else ".") / DEFAULT_BASE


def run_dir(run_id: str, root=None, *, env: Mapping[str, str] | None = None) -> Path:
    """``<base>/<run_id>/``, created (``0700``) if missing; refuses an id that would leave the
    base, and a run directory that is a symlink."""
    validate_run_id(run_id)
    base = runs_base(root, env)
    base.mkdir(parents=True, exist_ok=True)
    d = base / run_id
    if d.is_symlink():
        raise RunIdError(f"{d} is a symlink; a run directory is a real directory")
    d.mkdir(mode=0o700, exist_ok=True)
    if d.resolve().parent != base.resolve():
        raise RunIdError(f"{d} resolves outside {base}")
    return d
