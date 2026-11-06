# SPDX-License-Identifier: Apache-2.0
"""The one writer of an ``inbox/`` note: what a filed note's front matter gets stamped with, and
how its bytes reach disk.

Two callers file notes into an inbox: the agent library (:class:`homelabnext.records.Records`,
inside the agent's process) and the broker's ``records-inbox`` lanes
(:mod:`homelabnext.broker.lanes`, the agent's only path when it runs under the broker).  Each
keeps its own checks (the broker's are its refusal reasons, the library's its exceptions); both
stamp a note with :func:`stamp` and write it with :func:`write_inbox`, so the note format and the
atomicity rule cannot drift apart.  ``tools/shared_helpers_lint.py`` (rule ``records``) refuses a
file write into an inbox anywhere else.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import MutableMapping
from typing import Any

from homelabnext._tempfile import write_temp

from .notes import DECIDED_LANES

__all__ = ["decided_clash", "stamp", "write_inbox"]


def stamp(fm: MutableMapping[str, Any], *, agent: str | None, created: str) -> None:
    """Stamp a note about to be filed: ``requesting_agent`` is ``agent`` (a caller checks first
    that the note named no one else; None leaves the note's own, an unbound library writer's),
    ``created`` defaults to ``created``, and a proposal starts ``status: proposed``."""
    if agent is not None:
        fm["requesting_agent"] = agent
    fm.setdefault("created", created)
    if fm.get("type") == "proposal":
        fm.setdefault("status", "proposed")


def decided_clash(records_fd: int, name: str) -> str | None:
    """``decided/<lane>/<name>`` when a decided lane of the records directory ``records_fd``
    already holds ``name`` (no symlink followed), else None.  A note filed under such a name
    would collide when the decider moves it, and an audit link to the decided note would then
    name the other one, so neither writer files it."""
    for lane in DECIDED_LANES:
        try:
            os.stat(f"{lane}/{name}", dir_fd=records_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        return f"{lane}/{name}"
    return None


def write_inbox(dir_fd: int, name: str, data: bytes, *, mode: int = 0o600) -> None:
    """Create ``name`` holding ``data`` in the inbox directory ``dir_fd``, atomically and
    exclusively: the bytes are written and fsynced under a temporary name, the final name is taken
    with a hard link (never following a symlink, :class:`FileExistsError` when the name exists, so
    a note is never overwritten), the temporary name is removed and the directory fsynced.  A
    reader never sees a partial note.  ``mode`` is the new file's (less the umask)."""
    tmp = write_temp(name, data, dir_fd=dir_fd, mode=mode)
    try:
        os.link(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp, dir_fd=dir_fd)
    os.fsync(dir_fd)
