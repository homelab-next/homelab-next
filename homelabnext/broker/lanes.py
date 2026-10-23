# SPDX-License-Identifier: Apache-2.0
"""Write lanes: the broker's built-in handlers for an agent's limited writes.

A lane is a directory an action may write one file into, declared in the manifest (``lanes``)
and bound to an action with ``lane: <name>`` (its ``handler`` is the reserved ``builtin/lane``).
Two kinds:

* ``files`` - params ``{name, content}``.  The file lands in ``<data_root>/<root>/<actor>/<name>``
  (``per_actor``, the default: the actor's own profile slug) or ``<data_root>/<root>/<name>``.
  ``format: text`` takes a string; ``format: json`` takes an object or list, validated against
  ``content_schema`` (``<dir>/<name>`` of a packaged schema) when one is set.
* ``records-inbox`` - params ``{note, body?, slug?}``: a records note (``schemas/records/note``)
  filed into ``<data_root>/<root>/inbox/`` under the records filename convention, its
  ``requesting_agent`` bound to the actor, its ``created`` set by the broker (a note that names
  its own ``created`` is refused), its ``type`` one of the lane's ``note_types`` (``proposal`` by
  default).  The file is ``<date>-<agent>-<slug>-<tag>.md``: ``tag`` (:data:`TAG_CHARS` hex) is a
  keyed hash of the actor, the date and the slug under the broker-held key, so the name stays
  ``<YYYY-MM-DD>-<agent>-<slug>.md`` to every records reader while no agent can produce another
  agent's name -- not even one whose profile slug is a prefix of the other's (``triage`` and
  ``triage-lead``): its own tag is computed over its own actor.  The same actor filing the same
  slug the same day gets the same name (``lane-exists``), so a retry never files twice.

Enforced on every write, each refusal with a machine reason (:class:`LaneError`):

* ``lane-name-invalid`` - the name is not one plain path segment (no ``/``, ``\\``, NUL, no
  leading ``.``, not ``..``, not absolute) or does not match ``filename_pattern``;
* ``lane-actor-invalid`` - a per-actor lane and an actor that is not ``profile:<slug>``;
* ``lane-path-escape`` - a directory on the way is a symlink or not a directory.  Directories are
  opened one component at a time with ``O_NOFOLLOW`` relative to the previous one, so there is no
  window between a check and the write in which a swapped-in symlink could redirect it;
* ``lane-symlink`` - the target name is a symlink;
* ``lane-exists`` - the target exists and the lane does not say ``overwrite: true`` (exclusive
  create by default: a hard link that fails when the name exists);
* ``lane-too-large`` - the encoded content exceeds ``max_bytes``;
* ``lane-quota-exceeded`` - the write would leave the target directory (the actor's own for a
  ``per_actor`` lane, the lane's shared one otherwise) holding more than ``max_files`` files or
  more than ``max_total_bytes`` bytes (manifest 1.5; defaults :data:`DEFAULT_MAX_FILES` and
  :data:`DEFAULT_MAX_TOTAL_BYTES`).  ``max_files: null`` (1.6) sets no file cap: an append-only
  lane (``findings``: one note per run, never deleted) is bounded by its byte cap and its write
  rate instead, since a file cap there is a retention limit in disguise.  A replaced file (``overwrite``) is counted once.  The count
  and the write happen under an exclusive ``flock`` on the directory, so concurrent writers --
  threads or processes -- cannot overshoot it together;
* ``lane-quota-exceeded`` also when, in a shared lane (``per_actor: false``), the write would
  leave *this actor's* files in it over ``max_files_per_actor`` or ``max_bytes_per_actor``
  (manifest 1.6; defaults an eighth of the lane's quotas, :data:`DEFAULT_SHARE_DIVISOR`), so one
  agent cannot fill the one directory every agent files into.  A records-inbox name carries its
  agent and the tag proves it (:func:`name_tag`); a shared ``files`` lane keeps who wrote each
  name in an owner index in the broker's lane ledger (``ledger``, the state directory's
  ``lanes-ledger/`` under the service), never in the lane directory itself;
* ``lane-rate-exceeded`` - the actor has written ``max_writes_per_hour`` files into the lane
  directory in the last hour (manifest 1.6; default :data:`DEFAULT_SHARED_WRITES_PER_HOUR` on a
  shared lane, none on a per-actor one), so an admitted write is bounded in time as well as in
  space.  The times are kept in the lane ledger, read and written under the lane directory's
  ``flock``;
* ``lane-content-invalid`` - wrong params shape, content not matching the format or schema, a note
  failing the records schema or a note type the lane does not take;
* ``lane-identity-mismatch`` - a note naming another ``requesting_agent`` than the actor;
* ``lane-created-set`` - a note naming its own ``created`` (the broker's clock dates every note,
  so no agent can file one back- or forward-dated, or claim a future day's name);
* ``lane-content-invalid`` also for a note whose front matter holds a template marker
  (:data:`TEMPLATE_MARKERS`): its title becomes the ``homelabnext.proposal.created`` summary, and
  an event consumer that renders templates (StackStorm renders Jinja, Orquesta YAQL) would run it.

Content is validated and sized *before* any byte is written, and the write itself is atomic: a
temp file in the target directory, fsynced, then linked (or, for an ``overwrite`` lane, renamed)
into place.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import validation
from .state import write_temp

__all__ = [
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_TOTAL_BYTES",
    "DEFAULT_NAME_PATTERN",
    "DEFAULT_SHARED_WRITES_PER_HOUR",
    "DEFAULT_SHARE_DIVISOR",
    "LANE_HANDLER",
    "MAX_CALLER_SLUG",
    "TAG_CHARS",
    "Lane",
    "LaneError",
    "check_params",
    "fill",
    "name_tag",
    "template_marker",
    "usage",
    "write",
]

#: the ``handler`` value of every lane action
LANE_HANDLER = "builtin/lane"
DEFAULT_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
#: a lane directory's quotas when the manifest sets none (``max_files``, ``max_total_bytes``)
DEFAULT_MAX_FILES = 4096
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
#: a shared lane's per-actor share when the manifest sets none: this fraction of the lane's quota
DEFAULT_SHARE_DIVISOR = 8
#: files one actor may write into a shared lane per hour when the manifest sets no rate
DEFAULT_SHARED_WRITES_PER_HOUR = 120
RATE_WINDOW_S = 3600.0
#: the fraction of a lane directory's quota at which validate and serve warn
USAGE_WARN = 0.8
#: where a write's bookkeeping lives when the caller names no ledger directory
DEFAULT_LEDGER = ".hnx-lane-ledger"
_PROFILE_RE = re.compile(r"^profile:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)$")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
#: hex characters of a records-inbox file name's tag
TAG_CHARS = 8
#: the longest slug a caller may give: the records convention's 60, less the tag and its hyphen
MAX_CALLER_SLUG = 60 - TAG_CHARS - 1
#: Jinja and YAQL delimiters: never in a note's front matter, which events carry (``docs/stackstorm.md``)
TEMPLATE_MARKERS = ("{{", "{%", "<%", "%>")


def template_marker(value: Any) -> str | None:
    """The first template marker in any string of ``value`` (keys included), else ``None``."""
    if isinstance(value, str):
        return next((m for m in TEMPLATE_MARKERS if m in value), None)
    if isinstance(value, Mapping):
        items = [x for kv in value.items() for x in kv]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return None
    return next((m for m in map(template_marker, items) if m is not None), None)


class LaneError(Exception):
    """A refused lane write.  ``outcome`` is the audit outcome: ``denied`` for an attempt to
    leave or clobber the lane, ``invalid`` for content that does not fit it."""

    def __init__(self, reason: str, message: str, outcome: str = "denied") -> None:
        super().__init__(message)
        self.reason = reason
        self.outcome = outcome


@dataclass(frozen=True)
class Lane:
    name: str
    kind: str  # files | records-inbox
    root: str
    max_bytes: int
    per_actor: bool = True
    filename_pattern: str = DEFAULT_NAME_PATTERN
    format: str = "text"  # text | json
    content_schema: str | None = None
    overwrite: bool = False
    note_types: tuple[str, ...] = ("proposal",)
    max_files: int | None = DEFAULT_MAX_FILES  # None: no file cap
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_files_per_actor: int | None = None
    max_bytes_per_actor: int | None = None
    max_writes_per_hour: int | None = None

    @classmethod
    def from_doc(cls, doc: Mapping[str, Any]) -> Lane:
        shared = not bool(doc.get("per_actor", doc["kind"] == "files"))
        files = doc.get("max_files", DEFAULT_MAX_FILES)
        max_files = None if files is None else int(files)
        max_total = int(doc.get("max_total_bytes", DEFAULT_MAX_TOTAL_BYTES))

        def share(key: str, whole: int | None, least: int = 1) -> int | None:
            if key in doc:
                return int(doc[key])
            if whole is None or not shared:
                return None
            return max(least, whole // DEFAULT_SHARE_DIVISOR)

        rate = doc.get("max_writes_per_hour", DEFAULT_SHARED_WRITES_PER_HOUR if shared else None)
        return cls(
            name=doc["name"],
            kind=doc["kind"],
            root=doc["root"],
            max_bytes=int(doc["max_bytes"]),
            per_actor=bool(doc.get("per_actor", doc["kind"] == "files")),
            filename_pattern=doc.get("filename_pattern", DEFAULT_NAME_PATTERN),
            format=doc.get("format", "text"),
            content_schema=doc.get("content_schema"),
            overwrite=bool(doc.get("overwrite", False)),
            note_types=tuple(doc.get("note_types", ("proposal",))),
            max_files=max_files,
            max_total_bytes=max_total,
            max_files_per_actor=share("max_files_per_actor", max_files),
            max_bytes_per_actor=share("max_bytes_per_actor", max_total, int(doc["max_bytes"])),
            max_writes_per_hour=None if rate is None else int(rate),
        )

    def problems(self) -> list[str]:
        """Configuration problems the schema cannot express (``hnx broker validate``)."""
        out = []
        try:
            re.compile(self.filename_pattern)
        except re.error as exc:
            out.append(f"lane {self.name}: filename_pattern does not compile: {exc}")
        if any(p in ("", ".", "..") for p in self.root.split("/")):
            out.append(f"lane {self.name}: root {self.root!r} has an empty, . or .. component")
        if self.content_schema is not None:
            if self.kind != "files" or self.format != "json":
                out.append(f"lane {self.name}: content_schema needs kind files and format json")
            elif not validation.schema_exists(self.content_schema):
                out.append(f"lane {self.name}: content_schema {self.content_schema!r} not found")
        if self.kind == "records-inbox" and self.per_actor:
            out.append(f"lane {self.name}: a records-inbox lane is shared (per_actor: false)")
        if self.max_total_bytes < self.max_bytes:
            out.append(f"lane {self.name}: max_total_bytes is smaller than one file (max_bytes)")
        if self.per_actor and (self.max_files_per_actor or self.max_bytes_per_actor):
            out.append(
                f"lane {self.name}: a per-actor share is for a shared lane (per_actor: false)"
            )
        if self.max_bytes_per_actor is not None and self.max_bytes_per_actor < self.max_bytes:
            out.append(
                f"lane {self.name}: max_bytes_per_actor is smaller than one file (max_bytes)"
            )
        if self.max_files is not None and (self.max_files_per_actor or 0) > self.max_files:
            out.append(f"lane {self.name}: max_files_per_actor is larger than max_files")
        if (self.max_bytes_per_actor or 0) > self.max_total_bytes:
            out.append(f"lane {self.name}: max_bytes_per_actor is larger than max_total_bytes")
        return out


# ---------------------------------------------------------------- admission (no filesystem)
def _actor_slug(actor: str) -> str:
    m = _PROFILE_RE.match(actor) if isinstance(actor, str) else None
    if not m:
        raise LaneError("lane-actor-invalid", f"actor {actor!r} is not a profile:<slug> id")
    return m.group(1)


def _check_name(lane: Lane, name: Any) -> str:
    bad = (
        not isinstance(name, str)
        or not name
        or len(name) > 255
        or any(c in name for c in ("/", "\\", "\x00"))
        or name.startswith(".")
        or os.path.isabs(name)
    )
    if bad or not re.fullmatch(lane.filename_pattern, name):
        raise LaneError("lane-name-invalid", f"lane {lane.name}: {name!r} is not an allowed name")
    return name


def _encode_files(lane: Lane, params: Mapping[str, Any]) -> tuple[str, bytes]:
    if set(params) != {"name", "content"}:
        raise LaneError(
            "lane-content-invalid",
            f"lane {lane.name}: params are exactly name and content",
            "invalid",
        )
    name = _check_name(lane, params["name"])
    content = params["content"]
    if lane.format == "text":
        if not isinstance(content, str):
            raise LaneError("lane-content-invalid", "content must be a string", "invalid")
        data = content.encode("utf-8")
    else:
        if not isinstance(content, dict | list):
            raise LaneError(
                "lane-content-invalid", "content must be a JSON object or list", "invalid"
            )
        if len(json.dumps(content, ensure_ascii=False).encode("utf-8")) > lane.max_bytes:
            raise LaneError("lane-too-large", f"content exceeds {lane.max_bytes} bytes", "invalid")
        if lane.content_schema:
            problems = validation.named_errors(lane.content_schema, content)
            if problems:
                raise LaneError("lane-content-invalid", f"content: {problems[0]}", "invalid")
        data = (json.dumps(content, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    if len(data) > lane.max_bytes:
        raise LaneError("lane-too-large", f"content exceeds {lane.max_bytes} bytes", "invalid")
    return name, data


def name_tag(key: bytes, actor: str, date: str, slug: str) -> str:
    """The keyed tag that ends a records-inbox file name (see the module doc)."""
    msg = json.dumps(["records-inbox-name", actor, date, slug]).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:TAG_CHARS]


def _encode_note(
    lane: Lane, actor: str, params: Mapping[str, Any], now: str, key: bytes
) -> tuple[str, bytes]:
    from homelabnext.records.notes import (
        MAX_SLUG,
        NoteError,
        build_filename,
        render_note,
        slugify,
        validate_note,
    )

    if not set(params) <= {"note", "body", "slug"} or not isinstance(params.get("note"), dict):
        raise LaneError("lane-content-invalid", "params are note, body and slug", "invalid")
    body = params.get("body", "")
    if not isinstance(body, str):
        raise LaneError("lane-content-invalid", "body must be a string", "invalid")
    _actor_slug(actor)
    fm = dict(params["note"])
    claimed = fm.get("requesting_agent")
    if claimed is not None and claimed != actor:
        raise LaneError(
            "lane-identity-mismatch", f"requesting_agent {claimed!r} is not the actor {actor!r}"
        )
    if "created" in fm:
        raise LaneError(
            "lane-created-set", "created is set by the broker; leave it out of the note", "invalid"
        )
    fm["requesting_agent"] = actor
    fm.setdefault("type", lane.note_types[0])
    if fm["type"] not in lane.note_types:
        raise LaneError(
            "lane-content-invalid",
            f"lane {lane.name} takes notes of {list(lane.note_types)}",
            "invalid",
        )
    marker = template_marker(fm)
    if marker is not None:
        raise LaneError(
            "lane-content-invalid",
            f"note front matter holds the template marker {marker!r}",
            "invalid",
        )
    fm["created"] = now
    if fm["type"] == "proposal":
        fm.setdefault("status", "proposed")
    room = min(MAX_CALLER_SLUG, MAX_SLUG - TAG_CHARS - 1)  # the tag and its hyphen end it
    try:
        validate_note(fm)
        slug = params.get("slug") or slugify(str(fm["title"]), max_len=room)
        if not isinstance(slug, str):
            raise NoteError("slug must be a string")
        if len(slug) > room:
            raise NoteError(f"slug is at most {room} characters (the broker adds a tag)")
        build_filename(fm, slug)  # the caller's slug, checked on its own
        name = build_filename(fm, f"{slug}-{name_tag(key, actor, now[:10], slug)}")
    except NoteError as exc:
        raise LaneError("lane-content-invalid", f"note: {exc}", "invalid") from None
    data = render_note(fm, body).encode("utf-8")
    if len(data) > lane.max_bytes:
        raise LaneError("lane-too-large", f"note exceeds {lane.max_bytes} bytes", "invalid")
    return _check_name(lane, name), data


def _target(lane: Lane, actor: str, params: Mapping[str, Any], now: str, key: bytes):
    """(directory components under data_root, file name, bytes), or :class:`LaneError`."""
    if not isinstance(params, Mapping):
        raise LaneError("lane-content-invalid", "params must be an object", "invalid")
    parts = lane.root.split("/")
    if lane.kind == "records-inbox":
        name, data = _encode_note(lane, actor, params, now, key)
        return [*parts, "inbox"], name, data
    name, data = _encode_files(lane, params)
    if lane.per_actor:
        parts = [*parts, _actor_slug(actor)]
    return parts, name, data


def check_params(
    lane: Lane, actor: str, params: Mapping[str, Any], now: str, *, key: bytes = b""
) -> None:
    """Every check that needs no filesystem: shape, name, identity, size, schema.  ``now`` is
    the broker's time (a records note's ``created``); ``key`` the broker-held key of a
    records-inbox name's tag."""
    _target(lane, actor, params, now, key)


# ---------------------------------------------------------------- the write
def _open_dir(parent_fd: int, name: str) -> int:
    with contextlib.suppress(FileExistsError):
        os.mkdir(name, 0o750, dir_fd=parent_fd)
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise LaneError(
                "lane-path-escape", f"{name!r} is a symlink or not a directory"
            ) from None
        raise


def write(
    lane: Lane,
    data_root: str | os.PathLike[str],
    actor: str,
    params: Mapping[str, Any],
    now: str,
    *,
    key: bytes = b"",
    at: float | None = None,
    ledger: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate, then write one file into ``lane``; returns ``{path, bytes, digest}`` (``path``
    relative to ``data_root``).  Raises :class:`LaneError` with the refusal reason.  ``now`` and
    ``key`` as for :func:`check_params`; ``at`` (epoch seconds, default now) is when the write
    happens, what the lane's write rate counts; ``ledger`` the directory of the lane bookkeeping
    (owner index, write times; default ``<data_root>/.hnx-lane-ledger``)."""
    parts, name, data = _target(lane, actor, params, now, key)
    at = time.time() if at is None else float(at)
    root = Path(data_root)
    root.mkdir(parents=True, exist_ok=True)
    fds = [os.open(root, os.O_RDONLY | os.O_DIRECTORY)]
    try:
        for part in parts:
            fds.append(_open_dir(fds[-1], part))
        fd = fds[-1]
        book = _Ledger(Path(ledger) if ledger is not None else root / DEFAULT_LEDGER, lane, parts)
        fcntl.flock(fd, fcntl.LOCK_EX)  # the quota check and the write, as one; close unlocks
        usage = _usage(fd)
        _check_quota(lane, usage, name, len(data))
        _check_target(fd, name, lane.overwrite)
        owners = None
        if not lane.per_actor and (lane.max_files_per_actor or lane.max_bytes_per_actor):
            owners = _check_share(lane, book, usage, actor, key, name, len(data))
        writes = _check_rate(lane, book, actor, at) if lane.max_writes_per_hour else None
        # the bookkeeping goes first: a write it cannot record is not made (lane-io-error)
        if owners is not None:
            owners[name] = actor
            book.save("owners", owners)
        if writes is not None:
            book.save("writes", writes)
        _write_in(fd, name, data, lane.overwrite)
    finally:
        for fd in fds:
            os.close(fd)
    return {
        "path": "/".join([*parts, name]),
        "bytes": len(data),
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
    }


def _usage(dir_fd: int) -> dict[str, int]:
    """name -> size of every regular file in the directory ``dir_fd`` (a write's temporary
    ``.name.tmp`` excluded: it is either linked into place or removed)."""
    out: dict[str, int] = {}
    with os.scandir(dir_fd) as entries:
        for entry in entries:
            if entry.name.startswith("."):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISREG(st.st_mode):
                out[entry.name] = st.st_size
    return out


def _fraction(lane: Lane, files: int, total: int) -> float:
    used = total / lane.max_total_bytes
    if lane.max_files is not None:
        used = max(used, files / lane.max_files)
    return used


def _share_fraction(lane: Lane, files: int, total: int) -> float:
    used = 0.0
    if lane.max_files_per_actor:
        used = files / lane.max_files_per_actor
    if lane.max_bytes_per_actor:
        used = max(used, total / lane.max_bytes_per_actor)
    return used


def _held(d: Path) -> dict[str, int] | None:
    try:
        fd = os.open(d, _DIR_FLAGS)
    except OSError:
        return None  # not there yet (or not a real directory: a write would refuse it)
    try:
        return _usage(fd)
    finally:
        os.close(fd)


def _shared_by_actor(
    lane: Lane,
    held: Mapping[str, int],
    parts: list[str],
    *,
    actors: tuple[str, ...] = (),
    key: bytes | None = None,
    ledger: str | os.PathLike[str] | None = None,
) -> dict[str, dict[str, int]]:
    """actor -> {name: size} of a shared lane directory's files: a records-inbox's by name (its
    tag verified when ``key`` is given, else the longest of ``actors`` whose slug the name
    carries), a ``files`` lane's by the owner index in ``ledger`` (none without it)."""
    out: dict[str, dict[str, int]] = {}
    if lane.kind == "records-inbox":
        if key is not None:
            for actor in actors:
                with contextlib.suppress(LaneError):
                    mine = _inbox_owned(held, actor, key)
                    if mine:
                        out[actor] = mine
            return out
        slugs = sorted(
            ((m.group(1), a) for a in actors if (m := _PROFILE_RE.match(a))),
            key=lambda sa: -len(sa[0]),
        )
        for name, size in held.items():
            who = next((a for slug, a in slugs if name[11:].startswith(f"{slug}-")), None)
            if who is not None:
                out.setdefault(who, {})[name] = size
        return out
    if ledger is None:
        return out
    for name, actor in _Ledger(Path(ledger), lane, parts).load("owners").items():
        if name in held and isinstance(actor, str):
            out.setdefault(actor, {})[name] = held[name]
    return out


def usage(
    lane: Lane,
    data_root: str | os.PathLike[str],
    *,
    actors: tuple[str, ...] = (),
    key: bytes | None = None,
    ledger: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """What each of the lane's directories holds against its quota (``hnx broker validate
    --data-root``, ``hnx broker serve``): one row per directory -- each actor's for a per-actor
    lane, the shared one otherwise -- with ``files``, ``bytes``, the quotas, ``used`` (the larger
    fraction of the two quotas) and ``warn`` (``used`` at :data:`USAGE_WARN` or more).  A shared
    lane's row also has ``actors``: each actor's files, bytes and ``used`` of its share (see
    :func:`_shared_by_actor` for how files are attributed), and warns when any share does."""
    base = Path(data_root, *lane.root.split("/"))
    if lane.kind == "records-inbox":
        dirs = [base / "inbox"]
    elif lane.per_actor:
        try:
            dirs = sorted(
                Path(e.path)
                for e in os.scandir(base)
                if e.is_dir(follow_symlinks=False) and not e.name.startswith(".")
            )
        except (FileNotFoundError, NotADirectoryError):
            dirs = []
    else:
        dirs = [base]
    rows = []
    for d in dirs:
        held = _held(d)
        if held is None:
            continue
        files, total = len(held), sum(held.values())
        used = _fraction(lane, files, total)
        row: dict[str, Any] = {
            "lane": lane.name,
            "dir": d.relative_to(data_root).as_posix(),
            "files": files,
            "bytes": total,
            "max_files": lane.max_files,
            "max_total_bytes": lane.max_total_bytes,
            "used": round(used, 4),
            "warn": used >= USAGE_WARN,
        }
        if not lane.per_actor and (lane.max_files_per_actor or lane.max_bytes_per_actor):
            parts = d.relative_to(data_root).parts
            by = _shared_by_actor(lane, held, list(parts), actors=actors, key=key, ledger=ledger)
            row["max_files_per_actor"] = lane.max_files_per_actor
            row["max_bytes_per_actor"] = lane.max_bytes_per_actor
            row["actors"] = {}
            for actor, mine in sorted(by.items()):
                share = _share_fraction(lane, len(mine), sum(mine.values()))
                row["actors"][actor] = {
                    "files": len(mine),
                    "bytes": sum(mine.values()),
                    "used": round(share, 4),
                    "warn": share >= USAGE_WARN,
                }
                row["warn"] = row["warn"] or share >= USAGE_WARN
        rows.append(row)
    return rows


def fill(
    lane: Lane,
    data_root: str | os.PathLike[str],
    actor: str,
    *,
    key: bytes = b"",
    ledger: str | os.PathLike[str] | None = None,
) -> float:
    """How full the directory ``actor`` writes into is: the largest fraction of any quota that
    applies to it (the lane's, and in a shared lane the actor's share).  What tells a lane that
    refused an actor from one it has room in again (the broker's "cleared" notice)."""
    parts = lane.root.split("/")
    if lane.kind == "records-inbox":
        parts = [*parts, "inbox"]
    elif lane.per_actor:
        parts = [*parts, _actor_slug(actor)]
    held = _held(Path(data_root, *parts)) or {}
    used = _fraction(lane, len(held), sum(held.values()))
    if not lane.per_actor and (lane.max_files_per_actor or lane.max_bytes_per_actor):
        if ledger is None:
            ledger = Path(data_root) / DEFAULT_LEDGER
        by = _shared_by_actor(lane, held, parts, actors=(actor,), key=key, ledger=ledger)
        mine = by.get(actor, {})
        used = max(used, _share_fraction(lane, len(mine), sum(mine.values())))
    return used


def _check_quota(lane: Lane, usage: Mapping[str, int], name: str, size: int) -> None:
    usage = dict(usage)
    if lane.overwrite:
        usage.pop(name, None)  # a replacement: the old file goes
    if lane.max_files is not None and len(usage) + 1 > lane.max_files:
        raise LaneError(
            "lane-quota-exceeded", f"lane {lane.name} holds its quota of {lane.max_files} files"
        )
    if sum(usage.values()) + size > lane.max_total_bytes:
        raise LaneError(
            "lane-quota-exceeded",
            f"lane {lane.name} would exceed its quota of {lane.max_total_bytes} bytes",
        )


class _Ledger:
    """A lane directory's bookkeeping (``owners``: name -> actor; ``writes``: actor -> the times
    of its writes in the last hour), one JSON file each in the ledger directory, keyed by the
    lane and the directory.  Read and written only under that directory's ``flock``."""

    def __init__(self, root: Path, lane: Lane, parts: list[str]) -> None:
        self.root = root
        where = hashlib.sha256("/".join(parts).encode("utf-8")).hexdigest()[:16]
        self.stem = f"{lane.name}.{where}"

    def load(self, what: str) -> dict[str, Any]:
        try:
            doc = json.loads((self.root / f"{self.stem}.{what}.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except ValueError:
            return {}  # an unreadable ledger starts again empty, never blocks the lane
        return doc if isinstance(doc, dict) else {}

    def save(self, what: str, doc: Mapping[str, Any]) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        name = f"{self.stem}.{what}.json"
        dir_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            data = (json.dumps(doc, sort_keys=True) + "\n").encode("utf-8")
            tmp = write_temp(name, data, dir_fd=dir_fd)
            try:
                os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp, dir_fd=dir_fd)
        finally:
            os.close(dir_fd)


def _inbox_owned(usage: Mapping[str, int], actor: str, key: bytes) -> dict[str, int]:
    """The files of a records-inbox directory ``actor`` filed: its name's agent segment is the
    actor's and its tag is the one only the broker computes for that actor (so ``triage`` never
    counts a file of ``triage-lead``'s, nor the other way round)."""
    agent = _actor_slug(actor)
    out = {}
    for name, size in usage.items():
        prefix = f"{name[:10]}-{agent}-"
        if not (name.startswith(prefix) and name.endswith(".md")):
            continue
        slug, _, tag = name[len(prefix) : -3].rpartition("-")
        if slug and name_tag(key, actor, name[:10], slug) == tag:  # any name, any bytes
            out[name] = size
    return out


def _check_share(lane, book, usage, actor, key, name, size) -> dict[str, str] | None:
    """Refuse a write that would put ``actor``'s files in a shared lane over its share; returns
    the owner index to update (a ``files`` lane) or None (a records-inbox: names say it)."""
    owners = None
    if lane.kind == "records-inbox":
        mine = _inbox_owned(usage, actor, key)
    else:  # the index, pruned of names no longer there
        owners = {n: a for n, a in book.load("owners").items() if n in usage}
        mine = {n: usage[n] for n, a in owners.items() if a == actor}
    if lane.overwrite:
        mine.pop(name, None)
    if lane.max_files_per_actor is not None and len(mine) + 1 > lane.max_files_per_actor:
        raise LaneError(
            "lane-quota-exceeded",
            f"lane {lane.name}: {actor} holds its share of {lane.max_files_per_actor} files",
        )
    if (
        lane.max_bytes_per_actor is not None
        and sum(mine.values()) + size > lane.max_bytes_per_actor
    ):
        raise LaneError(
            "lane-quota-exceeded",
            f"lane {lane.name}: {actor} would exceed its share of {lane.max_bytes_per_actor} bytes",
        )
    return owners


def _check_rate(lane: Lane, book: _Ledger, actor: str, at: float) -> dict[str, list[float]]:
    """Refuse a write past the actor's ``max_writes_per_hour``; returns the ledger with this
    write added (every actor's writes of the last hour, older ones dropped)."""
    ledger = {}
    for who, times in book.load("writes").items():
        if isinstance(times, list):
            kept = [t for t in times if isinstance(t, int | float) and at - t < RATE_WINDOW_S]
            if kept:
                ledger[who] = kept
    mine = ledger.setdefault(actor, [])
    if len(mine) >= lane.max_writes_per_hour:
        raise LaneError(
            "lane-rate-exceeded",
            f"lane {lane.name}: {actor} has written {lane.max_writes_per_hour} files this hour",
        )
    mine.append(at)
    return ledger


def _check_target(dir_fd: int, name: str, overwrite: bool) -> None:
    try:
        st = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise LaneError("lane-symlink", f"{name!r} is a symlink")
    if not overwrite:
        raise LaneError("lane-exists", f"{name!r} exists and the lane does not overwrite")
    if not stat.S_ISREG(st.st_mode):
        raise LaneError("lane-path-escape", f"{name!r} is not a regular file")


def _write_in(dir_fd: int, name: str, data: bytes, overwrite: bool) -> None:
    _check_target(dir_fd, name, overwrite)
    tmp = write_temp(name, data, dir_fd=dir_fd)
    try:
        if overwrite:
            os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        else:
            try:
                os.link(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
            except FileExistsError:
                raise LaneError("lane-exists", f"{name!r} was created concurrently") from None
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp, dir_fd=dir_fd)
    os.fsync(dir_fd)
