# SPDX-License-Identifier: Apache-2.0
"""Operator-side movers: approve, deny, complete.

This module is the decision maker's tool.  It is **not** imported by ``homelabnext.records`` or
by the agent API, and a test pins that: an agent process that imports the agent API cannot reach
these functions without importing this module by name, which is exactly the review signal wanted.
Notes are never edited; each move leaves a ``<name>.decision.json`` audit sidecar beside it.

Keeping this module out of the agent's imports is a review signal, not an access control: any
code in the agent's process could import it.  What actually stops an agent from deciding is
filesystem ownership: run the decider as a different OS user that owns ``decided/``, and give the
agent's user write access to ``inbox/`` only.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .agent import LaneViolation
from .notes import (
    AGENT_LANE,
    DECIDED_LANES,
    Note,
    NoteError,
    check_filename,
    read_note,
    validate_note,
)

APPROVED, DENIED, COMPLETED = DECIDED_LANES


def init_tree(root: str | os.PathLike) -> None:
    """Create the lane directories (the operator owns the tree layout)."""
    for lane in (AGENT_LANE, *DECIDED_LANES):
        (Path(root) / lane).mkdir(parents=True, exist_ok=True)


class Decider:
    def __init__(
        self,
        root: str | os.PathLike,
        *,
        decided_by: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        if not decided_by:
            raise ValueError("decided_by is required (the audit sidecar names the decider)")
        self.root = Path(root)
        self.decided_by = decided_by
        self.clock = clock

    # ---------------------------------------------------------------- public movers
    def approve(self, name: str) -> Path:
        note = self._load(AGENT_LANE, name)
        if note.type == "completion-request":
            raise NoteError("a completion-request is closed with complete(), not approve()")
        return self._move(note, APPROVED, "approved", None)

    def deny(self, name: str, reason: str | None = None) -> Path:
        note = self._load(AGENT_LANE, name)
        return self._move(note, DENIED, "denied", reason)

    def complete(self, name: str, reason: str | None = None) -> list[Path]:
        """Close a completion-request: move every ``related:`` item approved -> completed.

        All-or-nothing preflight: if any related item is missing the call changes nothing.
        The request itself is filed under ``decided/completed/`` as well.
        """
        req = self._load(AGENT_LANE, name)
        if req.type != "completion-request":
            raise NoteError(f"{name} is type {req.type!r}, not a completion-request")
        related = list(req.frontmatter.get("related", []))
        missing = [r for r in related if not (self.root / r).is_file()]
        if missing:
            raise NoteError(f"related: not in the approved lane: {', '.join(missing)}")
        moved = []
        for rel in related:
            note = self._load(APPROVED, Path(rel).name, validate_filename=False)
            moved.append(self._move(note, COMPLETED, "completed", reason, via=name))
        moved.append(self._move(req, COMPLETED, "completed", reason))
        return moved

    def fulfil(self, name: str, reason: str | None = None) -> Path:
        """Approve an inbox note and close it at once, for a request the decision maker carried
        out itself (the register decider applying a ``register-transition``).  Both moves leave
        their audit sidecar, exactly as :meth:`approve` then :meth:`complete` would.

        Idempotent across a crash between the two moves: a note already in the approved lane
        (and no longer in the inbox) is only completed."""
        if (self.root / AGENT_LANE / name).is_file() or not (self.root / APPROVED / name).is_file():
            self.approve(name)
        note = self._load(APPROVED, name, validate_filename=False)
        return self._move(note, COMPLETED, "completed", reason)

    # ---------------------------------------------------------------- internals
    def _load(self, lane: str, name: str, *, validate_filename: bool = True) -> Note:
        if "/" in name or "\\" in name or not name.endswith(".md"):
            raise LaneViolation(f"not a bare note filename: {name!r}")
        path = self.root / lane / name
        if not path.is_file():
            raise FileNotFoundError(f"{lane}/{name} does not exist")
        note = read_note(path, lane)
        validate_note(note.frontmatter)
        if validate_filename:
            problems = check_filename(name, note.frontmatter)
            if problems:
                raise NoteError("; ".join(problems))
        return note

    def _move(
        self, note: Note, dest_lane: str, decision: str, reason: str | None, via: str | None = None
    ) -> Path:
        src = self.root / note.lane / note.name
        dest_dir = self.root / dest_lane
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / note.name
        if dest.exists():
            raise FileExistsError(f"{dest_lane}/{note.name} already exists")
        side: dict[str, Any] = {
            "decision": decision,
            "decided_by": self.decided_by,
            "decided_at": self.clock().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "from_lane": note.lane,
        }
        if reason:
            side["reason"] = reason
        if via:
            side["via"] = via
        sidecar = dest_dir / f"{note.name}.decision.json"
        tmp = dest_dir / f".{note.name}.{os.getpid()}.decision.tmp"
        tmp.write_text(json.dumps(side, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, sidecar)
        os.rename(src, dest)  # atomic within one filesystem
        return dest
