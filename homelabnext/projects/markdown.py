# SPDX-License-Identifier: Apache-2.0
"""The reference backend: one Markdown file per project or work item.

::

    <root>/<uid>.md                       front-matter (the item's fields) + the description
    <root>/.changes/<stamp>-<uid>-v<n>.json   the change journal: one file per change

A file is replaced atomically (temp file and rename, :func:`homelabnext.state.atomic_write_text`)
and only while its stored ``version`` is still the one the writer read, under a host lock
(:func:`homelabnext.state.file_lock`); a new item and every journal entry are created
exclusively (a hard link that fails when the name exists), so nothing is ever overwritten by a
second writer.  Journal names are unique per ``(uid, version)``, so two clones that each record a
change merge in git without a conflict; the stamp is monotonic within one working copy, which is
what makes a cursor (the last journal name read) complete there.  After a ``git pull`` the cursor
of a consumer may predate entries that arrived with the pull: read from ``None`` (a snapshot) to
resynchronise.

The file layout (keys in this order, ``null`` fields left out)::

    ---
    uid: 0192f1e0-...         kind: project | step | task
    title: ...                status: ...      version: 3
    project: <uid>            order: 2         parent: <uid>
    external_key: ...         assignee: profile:responder        due: 2026-11-30
    result: ...               closed_on: 2026-10-21
    links: [{relation: supports, target: <uid>}]
    created: ...              updated: ...
    ---

    The description, as Markdown.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import pathlib
from collections.abc import Iterator
from typing import Any

import yaml

from homelabnext._yaml import UniqueKeyStrDateLoader
from homelabnext.state import atomic_write_text

from .model import Change, Conflict, InvalidField

try:  # POSIX; elsewhere the store still works, without a cross-process lock
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]
from homelabnext.identity import is_uid

__all__ = ["FIELD_ORDER", "MarkdownBackend", "parse_item", "render_item"]

FIELD_ORDER = (
    "uid", "kind", "title", "status", "version", "project", "order", "parent", "external_key",
    "assignee", "due", "result", "closed_on", "links", "created", "updated",
)  # fmt: skip
CHANGES = ".changes"


class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def render_item(doc: dict[str, Any]) -> str:
    front = {k: doc[k] for k in FIELD_ORDER if doc.get(k) not in (None, [], ())}
    body = yaml.dump(front, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=100)
    desc = str(doc.get("description") or "").strip()
    return f"---\n{body}---\n" + (f"\n{desc}\n" if desc else "")


def parse_item(text: str, name: str) -> dict[str, Any]:
    """The item document of one file; ``ValueError`` naming the file when it is not one."""
    if not text.startswith("---\n"):
        raise ValueError(f"{name}: no front-matter")
    head, sep, rest = text[4:].partition("\n---\n")
    if not sep:
        raise ValueError(f"{name}: the front-matter is not closed")
    try:
        doc = yaml.load(head, Loader=UniqueKeyStrDateLoader)
    except yaml.YAMLError as exc:
        raise ValueError(f"{name}: not YAML ({exc})".replace("\n", " ")) from None
    if not isinstance(doc, dict):
        raise ValueError(f"{name}: the front-matter is not a mapping")
    unknown = sorted(set(doc) - set(FIELD_ORDER))
    if unknown:
        raise ValueError(f"{name}: unknown field(s) {', '.join(map(str, unknown))}")
    for k in ("uid", "kind", "title", "status", "version"):
        if k not in doc:
            raise ValueError(f"{name}: {k} is required")
    if not isinstance(doc["version"], int) or doc["version"] < 1:
        raise ValueError(f"{name}: version must be a positive integer")
    body = rest.strip()
    links = doc.get("links") or []
    if not isinstance(links, list) or not all(
        isinstance(x, dict) and set(x) == {"relation", "target"} for x in links
    ):
        raise ValueError(f"{name}: links is a list of {{relation, target}}")
    return {**{k: doc.get(k) for k in FIELD_ORDER}, "links": links, "description": body}


class MarkdownBackend:
    """Items as ``<root>/<uid>.md``; see the module docstring."""

    def __init__(self, root: str | pathlib.Path, *, create: bool = True) -> None:
        self.root = pathlib.Path(root)
        if create:
            self.root.mkdir(parents=True, exist_ok=True)
        elif not self.root.is_dir():
            raise FileNotFoundError(f"no projects directory {self.root}")
        self.problems: list[str] = []

    @property
    def journal(self) -> pathlib.Path:
        return self.root / CHANGES

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        """An exclusive ``flock`` on the directory itself: no lock file appears in the tree."""
        fd = os.open(self.root, os.O_RDONLY)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # closing the descriptor releases the lock

    def files(self) -> list[pathlib.Path]:
        return sorted(p for p in self.root.glob("*.md") if p.is_file())

    def load(self) -> dict[str, dict[str, Any]]:
        """Every item; files that are not items are listed in :attr:`problems`."""
        out: dict[str, dict[str, Any]] = {}
        self.problems = []
        for p in self.files():
            if p.name == "README.md":
                continue
            try:
                doc = parse_item(p.read_text(encoding="utf-8"), p.name)
            except (OSError, ValueError) as exc:
                self.problems.append(str(exc))
                continue
            if not is_uid(doc["uid"]) or p.stem != doc["uid"]:
                self.problems.append(f"{p.name}: the file is named <uid>.md for its uid")
                continue
            out[doc["uid"]] = doc
        return out

    def _path(self, uid: str) -> pathlib.Path:
        if not is_uid(uid):
            raise InvalidField(f"not a uid: {uid!r}")
        return self.root / f"{uid}.md"

    def write(self, docs, changes):
        for doc, expected in docs:
            p = self._path(doc["uid"])
            if expected is None:
                if p.exists():
                    raise Conflict(f"{doc['uid']}: already exists")
                continue
            try:
                cur = parse_item(p.read_text(encoding="utf-8"), p.name)
            except FileNotFoundError:
                raise Conflict(f"{doc['uid']}: removed by another writer") from None
            if cur["version"] != expected:
                raise Conflict(f"{doc['uid']}: changed by another writer")
        for doc, expected in docs:
            atomic_write_text(self._path(doc["uid"]), render_item(doc), exclusive=expected is None)
        self.journal.mkdir(exist_ok=True)
        last = self._entries()[-1:] or [""]
        for ch in changes:
            name = self._entry_name(ch, last[0])
            atomic_write_text(
                self.journal / name, json.dumps(_change_doc(ch), sort_keys=True) + "\n",
                exclusive=True,
            )  # fmt: skip
            last = [name]
        return {d["uid"]: d for d, _ in docs}

    def _entries(self) -> list[str]:
        if not self.journal.is_dir():
            return []
        return sorted(p.name for p in self.journal.glob("*.json"))

    @staticmethod
    def _entry_name(ch: Change, last: str) -> str:
        """``<stamp>-<uid>-v<version>.json``; the stamp strictly grows within one copy."""
        fmt = "%Y%m%dT%H%M%S.%fZ"
        stamp = dt.datetime.strptime(ch.at, "%Y-%m-%dT%H:%M:%S.%fZ")
        if last:
            prev = dt.datetime.strptime(last.split("-", 1)[0], fmt)
            stamp = max(stamp, prev + dt.timedelta(microseconds=1))
        return f"{stamp.strftime(fmt)}-{ch.uid}-v{ch.version:06d}.json"

    def changes(self, cursor):
        names = self._entries()
        if cursor is None:
            return [], names[-1] if names else ""
        if cursor and not cursor.endswith(".json"):
            raise InvalidField(f"not a cursor of this store: {cursor!r}")
        out = []
        for n in names:
            if n <= cursor:
                continue
            with contextlib.suppress(OSError, ValueError, KeyError, TypeError):
                out.append(Change(**json.loads((self.journal / n).read_text(encoding="utf-8"))))
        return out, names[-1] if names else cursor


def _change_doc(ch: Change) -> dict[str, Any]:
    return {k: getattr(ch, k) for k in Change.__dataclass_fields__}
