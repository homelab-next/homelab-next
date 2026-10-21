# SPDX-License-Identifier: Apache-2.0
"""``hnx broker import-proposals DIR``: move a vault-style proposal queue onto the broker.

The pattern this replaces (ADR-0017's context) kept proposals as Markdown files with YAML
front-matter in an agent-writable directory; a person approved them in a dashboard that moved
the file.  This reads such a directory and files each proposal as a ``proposal.file`` lane record
**through the broker**, so it is validated, named and audited like any agent's proposal.

Mapping (generic; field names vary between labs, so each target has a few accepted spellings):

=================  ==============================================  ============================
records note       taken from                                      if absent or unusable
=================  ==============================================  ============================
``title``          ``title`` / ``summary`` / ``subject``, else      the file is not imported
                   the body's first ``# heading``
``risk``           ``risk`` / ``risk_level`` / ``severity``         ``--default-risk``, else not
                   (low, medium, high; med/moderate -> medium,      imported
                   critical -> high)
``rollback``       ``rollback`` / ``rollback_plan`` / ``backout``   ``--default-rollback``, else
                                                                    not imported
``created``        ``created`` / ``date`` (a date alone is          the filename's leading date,
                   midnight UTC)                                    else the file's mtime
``affects``,       the same keys, when every entry is valid         dropped and reported
``related``
``provenance``     ``inputs``: ``imported-from:<file>`` and, when   -
                   the file names one, ``requested-by:<agent>``;
                   ``source``: the importing caller
slug               the original requester (sanitised), then the     from the title
                   filename after its date and that requester's
                   name
body               the Markdown after the front-matter              empty
=================  ==============================================  ============================

The filed name is ``<date>-<importer>-<slug>.md`` (the lane binds ``requesting_agent`` to the
importing caller), so the original requester is kept in the slug: two agents' proposals with the
same date and title land in two files.  Two source files that still map to one name are a
``conflict`` -- the second is not filed and the command exits nonzero -- rather than an
``exists`` that would hide a different proposal behind the first.

``requesting_agent`` is **never** carried over: the broker binds it to the caller doing the
import, so an import cannot file a note as someone else (the original requester survives as
provenance).  ``status`` is dropped (the request's state is the broker's, not the note's).
A ``type`` other than ``proposal`` is skipped -- a ``completion-request`` is a records-lifecycle
transition, not a new proposal.  Every other key is reported as unmapped and left behind.

Dry run (the default) maps and validates every file against the records schema and reports;
``--apply`` files them.  The filename is derived from ``created`` and the slug, so a second
``--apply`` answers ``lane-exists`` for what is already filed and adds nothing.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 1 << 20
DRY_RUN_SOURCE = "profile:importer"
_TITLE_KEYS = ("title", "summary", "subject")
_RISK_KEYS = ("risk", "risk_level", "severity")
_ROLLBACK_KEYS = ("rollback", "rollback_plan", "backout")
_CREATED_KEYS = ("created", "date")
_AGENT_KEYS = ("requesting_agent", "requesting-agent", "agent", "author", "requested_by")
_LIST_KEYS = ("affects", "related")
_DROPPED = ("status", "type")
_RISKS = {
    "low": "low",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "high",
}
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
_NAME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})-(.+)\.md$")
_HEADING_RE = re.compile(r"^#\s+(.+?)\s*#*\s*$", re.M)


@dataclass
class Mapped:
    """One source file: the ``proposal.file`` params, or why it cannot be filed."""

    source: str
    params: dict[str, Any] | None = None
    problem: str | None = None
    unmapped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    outcome: str = "mapped"  # mapped | skipped | unmappable | conflict | filed | exists | refused
    result: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out = {
            "source": self.source,
            "outcome": self.outcome,
            "unmapped": self.unmapped,
            "notes": self.notes,
        }
        if self.problem:
            out["problem"] = self.problem
        if self.result:
            out["result"] = self.result
        if self.params is not None:
            out["note"] = self.params["note"]
            out["slug"] = self.params.get("slug")
        return out


def _first(fm: Mapping[str, Any], keys: Iterable[str]) -> tuple[str | None, Any]:
    for k in keys:
        if fm.get(k) not in (None, "", []):
            return k, fm[k]
    return None, None


def _created(value: Any, name: str, mtime: float) -> tuple[str, str]:
    """(timestamp, where it came from)."""
    text = str(value).strip() if value is not None else ""
    if _TS_RE.match(text):
        return text, "front-matter"
    if _DATE_RE.match(text):
        return f"{text}T00:00:00Z", "front-matter date"
    m = _NAME_RE.match(name)
    if m:
        return f"{m.group(1)}T00:00:00Z", "filename date"
    stamp = datetime.fromtimestamp(mtime, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return stamp, "file mtime"


def _slug(name: str, agent: str | None, title: str) -> str | None:
    from homelabnext.records.notes import NoteError, slugify

    rest = _NAME_RE.match(name)
    text = rest.group(2) if rest else ""
    prefix = ""
    if agent:
        try:
            prefix = slugify(agent.partition(":")[2] or agent)
        except NoteError:
            prefix = ""
    if prefix and text.startswith(prefix + "-"):
        text = text[len(prefix) + 1 :]
    for candidate in (text, title):
        if not candidate:
            continue
        try:
            base = slugify(candidate)
        except NoteError:
            continue
        return slugify(f"{prefix}-{base}") if prefix else base
    return None


def map_proposal(
    name: str,
    text: str,
    *,
    mtime: float = 0.0,
    default_risk: str | None = None,
    default_rollback: str | None = None,
    source: str = DRY_RUN_SOURCE,
) -> Mapped:
    """Map one proposal file's text to ``proposal.file`` params (see the module doc)."""
    from homelabnext.records.notes import NoteError, parse_note, validate_note

    out = Mapped(source=name)
    try:
        fm, body = parse_note(text)
    except NoteError as exc:
        out.outcome, out.problem = "unmappable", str(exc)
        return out
    kind = str(fm.get("type") or "proposal")
    if kind != "proposal":
        out.outcome = "skipped"
        out.problem = f"type {kind} is not a proposal" + (
            " (close it with a records-lifecycle transition)"
            if kind == "completion-request"
            else ""
        )
        return out
    used: set[str] = set()
    tkey, title = _first(fm, _TITLE_KEYS)
    if tkey:
        used.add(tkey)
    else:
        m = _HEADING_RE.search(body)
        title = m.group(1) if m else None
        if title:
            out.notes.append("title from the first heading")
    rkey, risk = _first(fm, _RISK_KEYS)
    if rkey:
        used.add(rkey)
    risk = _RISKS.get(str(risk).strip().lower()) if risk is not None else None
    if risk is None and default_risk:
        risk = default_risk
        out.notes.append(f"risk defaulted to {default_risk}")
    bkey, rollback = _first(fm, _ROLLBACK_KEYS)
    if bkey:
        used.add(bkey)
    if not rollback and default_rollback:
        rollback = default_rollback
        out.notes.append("rollback defaulted")
    ckey, created_raw = _first(fm, _CREATED_KEYS)
    if ckey:
        used.add(ckey)
    created, origin = _created(created_raw, name, mtime)
    if origin != "front-matter":
        out.notes.append(f"created from the {origin}")
    akey, agent = _first(fm, _AGENT_KEYS)
    if akey:
        used.add(akey)
    missing = [f for f, v in (("title", title), ("risk", risk), ("rollback", rollback)) if not v]
    if missing:
        out.outcome = "unmappable"
        out.problem = "no usable " + ", ".join(missing)
    note: dict[str, Any] = {
        "type": "proposal",
        "title": str(title or "")[:200],
        "risk": risk,
        "rollback": str(rollback or ""),
        "created": created,
    }
    inputs = [f"imported-from:{name}"]
    if agent:
        inputs.append(f"requested-by:{agent}")
        out.notes.append("original requester kept as provenance, not as requesting_agent")
    note["provenance"] = {"source": source, "inputs": inputs}
    for key in _LIST_KEYS:
        if key in fm:
            used.add(key)
            value = fm[key]
            trial = {**note, key: value, "requesting_agent": source}
            try:
                validate_note(trial)
                note[key] = value
            except NoteError as exc:
                out.unmapped.append(f"{key} (invalid: {exc})")
    used.update(k for k in _DROPPED if k in fm)
    if "status" in fm:
        out.notes.append("status dropped: the broker keeps the state")
    out.unmapped.extend(sorted(str(k) for k in fm if k not in used))
    if out.outcome == "unmappable":
        return out
    slug = _slug(name, str(agent) if agent else None, note["title"])
    try:
        validate_note({**note, "requesting_agent": source})
        if slug is None:
            raise NoteError("cannot derive a slug")
    except NoteError as exc:
        out.outcome, out.problem = "unmappable", str(exc)
        return out
    out.params = {"note": note, "body": body, "slug": slug}
    return out


def read_dir(
    directory: str | Path,
    **kw: Any,
) -> list[Mapped]:
    """Map every ``*.md`` regular file directly in ``directory`` (sorted; symlinks skipped)."""
    root = Path(directory)
    if not root.is_dir():
        raise ValueError(f"{root} is not a directory")
    out = []
    for p in sorted(root.glob("*.md")):
        if p.is_symlink() or not p.is_file():
            out.append(Mapped(p.name, outcome="skipped", problem="not a regular file"))
            continue
        st = p.stat()
        if st.st_size > MAX_FILE_BYTES:
            out.append(Mapped(p.name, outcome="unmappable", problem="file too large"))
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            out.append(Mapped(p.name, outcome="unmappable", problem=f"unreadable: {exc}"))
            continue
        out.append(map_proposal(p.name, text, mtime=st.st_mtime, **kw))
    return mark_conflicts(out)


def mark_conflicts(rows: list[Mapped]) -> list[Mapped]:
    """Mark every mapped row whose filed name (date and slug) an earlier row already takes as a
    ``conflict``: it would otherwise be answered ``exists`` and silently not filed."""
    first: dict[tuple[str, str], str] = {}
    for row in rows:
        if row.params is None or row.outcome != "mapped":
            continue
        key = (str(row.params["note"]["created"])[:10], str(row.params["slug"]))
        if key in first:
            row.outcome = "conflict"
            row.problem = f"maps to the same file name as {first[key]}; rename one and re-run"
        else:
            first[key] = row.source
    return rows


def apply(rows: list[Mapped], call: Callable[[dict[str, Any]], Any], source: str) -> list[Mapped]:
    """File every mapped row with ``call(params)`` (the broker's ``proposal.file``), setting
    ``provenance.source`` to ``source`` (the importing caller).  A ``conflict`` is not filed."""
    for row in mark_conflicts(rows):
        if row.params is None or row.outcome != "mapped":
            continue
        row.params["note"]["provenance"]["source"] = source
        try:
            result = call(row.params)
        except Exception as exc:
            reason = str(getattr(exc, "reason", "") or type(exc).__name__)
            row.outcome = "exists" if reason == "lane-exists" else "refused"
            row.result = reason
            continue
        row.outcome = "filed"
        row.result = str((result or {}).get("path", "")) if isinstance(result, Mapping) else ""
    return rows
