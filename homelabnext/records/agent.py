# SPDX-License-Identifier: Apache-2.0
"""Agent-side records API: the ONE write path, plus a reader.

Agents write only into ``inbox/``.  Every note is validated against the schema and the filename
convention before a byte is written, and a note is created exclusively (never overwrites).  There is
deliberately no way here to touch ``decided/``: the approve/deny/complete movers live in
``homelabnext.records.decider`` which this module never imports.

What this module enforces and what it cannot.  It is a library running inside the agent's own
process, so it is a guard against mistakes, not a security boundary: code in that process can
write files without it.  The real enforcement is **filesystem ownership**: ``decided/`` must be
owned by the decision maker and not writable by the agent's OS user, and ``inbox/`` writable by
it.  Likewise ``requesting_agent`` is only as trustworthy as the identity binding: construct
:class:`Records` with ``agent=`` (one instance per agent, ideally one inbox or OS user per agent)
and every note is stamped with that identity and a note naming anyone else is refused.  An
unbound instance takes ``requesting_agent`` from the caller, which any caller can set to any name.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .notes import (
    AGENT_LANE,
    ALL_LANES,
    DECIDED_LANES,
    Note,
    NoteError,
    agent_slug,
    build_filename,
    read_note,
    render_note,
    slugify,
    validate_note,
)


class LaneViolation(PermissionError):
    """An attempt to write outside the proposing lane."""


class RecordsReader:
    """Read-only view of every lane (agents may read what was decided about their notes)."""

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)

    def _lane_dir(self, lane: str) -> Path:
        if lane not in ALL_LANES:
            raise ValueError(f"unknown lane {lane!r}; expected one of {ALL_LANES}")
        return self.root / lane

    def list(self, lane: str) -> list[str]:
        d = self._lane_dir(lane)
        return sorted(p.name for p in d.glob("*.md")) if d.is_dir() else []

    def read(self, lane: str, name: str) -> Note:
        if "/" in name or "\\" in name or not name.endswith(".md"):
            raise ValueError(f"not a note filename: {name!r}")
        note = read_note(self._lane_dir(lane) / name, lane)
        validate_note(note.frontmatter)
        return note

    def iter_notes(self, lane: str, *, type: str | None = None) -> Iterator[Note]:
        for name in self.list(lane):
            note = self.read(lane, name)
            if type is None or note.type == type:
                yield note


class Records:
    """The agent write path.  ``agent`` binds the requesting identity (see the module doc)."""

    def __init__(
        self,
        root: str | os.PathLike,
        clock: Callable[[], datetime],
        *,
        agent: str | None = None,
    ):
        self.root = Path(root)
        self.clock = clock
        self.reader = RecordsReader(self.root)
        self.agent = self._profile(agent) if agent is not None else None

    @staticmethod
    def _profile(agent: str) -> str:
        who = agent if agent.startswith("profile:") else f"profile:{agent}"
        agent_slug(who)
        return who

    def _bind(self, fm: dict[str, Any]) -> None:
        """Stamp the bound identity; refuse a note that names another agent."""
        if self.agent is None:
            return
        claimed = fm.get("requesting_agent")
        if claimed is not None and claimed != self.agent:
            raise LaneViolation(
                f"requesting_agent {claimed!r} is not this writer's identity {self.agent!r}"
            )
        fm["requesting_agent"] = self.agent

    # ---------------------------------------------------------------- public writes
    def propose(self, note: Mapping[str, Any], *, body: str = "", slug: str | None = None) -> Path:
        return self._submit(dict(note), body, slug, expect="proposal")

    def submit(self, note: Mapping[str, Any], *, body: str = "", slug: str | None = None) -> Path:
        """Write a finding, escalation or task (any type except completion-request)."""
        fm = dict(note)
        if fm.get("type") == "completion-request":
            raise NoteError("type: use completion_request() for completion requests")
        return self._submit(fm, body, slug, expect=None)

    def completion_request(
        self,
        related: Sequence[str],
        body: str,
        *,
        agent: str | None = None,
        title: str | None = None,
        outcome: str = "implemented",
        slug: str | None = None,
    ) -> Path:
        if agent is None and self.agent is None:
            raise NoteError("agent: required when the writer is not bound to an identity")
        who = self._profile(agent) if agent is not None else self.agent
        self._bind({"requesting_agent": who})
        rel = [self._normalise_related(r) for r in related]
        for r in rel:
            if not (self.root / r).is_file():
                raise NoteError(f"related: {r} does not exist in the approved lane")
        fm: dict[str, Any] = {
            "type": "completion-request",
            "title": title or (f"Done: {Path(rel[0]).stem}" if rel else "Done"),
            "related": rel,
            "outcome": outcome,
            "requesting_agent": who,
        }
        return self._submit(fm, body, slug, expect="completion-request")

    # ---------------------------------------------------------------- internals
    @staticmethod
    def _normalise_related(item: str) -> str:
        item = str(item)
        return item if "/" in item else f"decided/approved/{item}"

    def _now(self) -> str:
        return self.clock().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _submit(
        self, fm: dict[str, Any], body: str, slug: str | None, *, expect: str | None
    ) -> Path:
        if expect is not None:
            fm.setdefault("type", expect)
            if fm["type"] != expect:
                raise NoteError(f"type: expected {expect!r}, got {fm['type']!r}")
        self._bind(fm)
        fm.setdefault("created", self._now())
        if fm["type"] == "proposal":
            fm.setdefault("status", "proposed")
        validate_note(fm)
        if not isinstance(body, str):
            raise NoteError("body must be a string")
        name = build_filename(fm, slug or slugify(str(fm["title"])))
        return self._write_note(AGENT_LANE, name, render_note(fm, body))

    def _write_note(self, lane: str, name: str, text: str) -> Path:
        """The single place bytes reach disk.  Refuses anything that is not ``inbox/<file>.md``."""
        if lane != AGENT_LANE:
            raise LaneViolation(f"agents may write only to {AGENT_LANE}/, not {lane!r}")
        if os.sep in name or "/" in name or name in ("", ".", "..") or not name.endswith(".md"):
            raise LaneViolation(f"filename {name!r} would leave the lane")
        lane_dir = self.root / AGENT_LANE
        lane_dir.mkdir(parents=True, exist_ok=True)
        real_root = self.root.resolve()
        if lane_dir.resolve().parent != real_root or lane_dir.is_symlink():
            raise LaneViolation("inbox/ resolves outside the records root")
        final = lane_dir / name
        # a name already decided would collide when the decider moves this note, and an audit
        # link to decided/<lane>/<name> would then name the other note
        for decided in DECIDED_LANES:
            if (self.root / decided / name).exists():
                raise FileExistsError(
                    f"{decided}/{name} already exists; choose another slug for this note"
                )
        tmp = lane_dir / f".{name}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(tmp, final)  # exclusive create: fails if the name exists
            except FileExistsError:
                raise FileExistsError(
                    f"{AGENT_LANE}/{name} already exists; refusing to overwrite"
                ) from None
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
        return final
