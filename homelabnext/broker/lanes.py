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
  ``requesting_agent`` bound to the actor, its ``type`` one of the lane's ``note_types``
  (``proposal`` by default).

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
* ``lane-content-invalid`` - wrong params shape, content not matching the format or schema, a note
  failing the records schema or a note type the lane does not take;
* ``lane-identity-mismatch`` - a note naming another ``requesting_agent`` than the actor.

Content is validated and sized *before* any byte is written, and the write itself is atomic: a
temp file in the target directory, fsynced, then linked (or, for an ``overwrite`` lane, renamed)
into place.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import validation
from .state import write_temp

__all__ = ["DEFAULT_NAME_PATTERN", "LANE_HANDLER", "Lane", "LaneError", "check_params", "write"]

#: the ``handler`` value of every lane action
LANE_HANDLER = "builtin/lane"
DEFAULT_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_PROFILE_RE = re.compile(r"^profile:([a-z][a-z0-9]*(?:-[a-z0-9]+)*)$")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


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

    @classmethod
    def from_doc(cls, doc: Mapping[str, Any]) -> Lane:
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


def _encode_note(lane: Lane, actor: str, params: Mapping[str, Any], now: str) -> tuple[str, bytes]:
    from homelabnext.records.notes import (
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
    fm["requesting_agent"] = actor
    fm.setdefault("type", lane.note_types[0])
    if fm["type"] not in lane.note_types:
        raise LaneError(
            "lane-content-invalid",
            f"lane {lane.name} takes notes of {list(lane.note_types)}",
            "invalid",
        )
    fm.setdefault("created", now)
    if fm["type"] == "proposal":
        fm.setdefault("status", "proposed")
    try:
        validate_note(fm)
        slug = params.get("slug") or slugify(str(fm["title"]))
        if not isinstance(slug, str):
            raise NoteError("slug must be a string")
        name = build_filename(fm, slug)
    except NoteError as exc:
        raise LaneError("lane-content-invalid", f"note: {exc}", "invalid") from None
    data = render_note(fm, body).encode("utf-8")
    if len(data) > lane.max_bytes:
        raise LaneError("lane-too-large", f"note exceeds {lane.max_bytes} bytes", "invalid")
    return _check_name(lane, name), data


def _target(lane: Lane, actor: str, params: Mapping[str, Any], now: str):
    """(directory components under data_root, file name, bytes), or :class:`LaneError`."""
    if not isinstance(params, Mapping):
        raise LaneError("lane-content-invalid", "params must be an object", "invalid")
    parts = lane.root.split("/")
    if lane.kind == "records-inbox":
        name, data = _encode_note(lane, actor, params, now)
        return [*parts, "inbox"], name, data
    name, data = _encode_files(lane, params)
    if lane.per_actor:
        parts = [*parts, _actor_slug(actor)]
    return parts, name, data


def check_params(lane: Lane, actor: str, params: Mapping[str, Any], now: str) -> None:
    """Every check that needs no filesystem: shape, name, identity, size, schema."""
    _target(lane, actor, params, now)


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
    lane: Lane, data_root: str | os.PathLike[str], actor: str, params: Mapping[str, Any], now: str
) -> dict[str, Any]:
    """Validate, then write one file into ``lane``; returns ``{path, bytes, digest}`` (``path``
    relative to ``data_root``).  Raises :class:`LaneError` with the refusal reason."""
    parts, name, data = _target(lane, actor, params, now)
    root = Path(data_root)
    root.mkdir(parents=True, exist_ok=True)
    fds = [os.open(root, os.O_RDONLY | os.O_DIRECTORY)]
    try:
        for part in parts:
            fds.append(_open_dir(fds[-1], part))
        _write_in(fds[-1], name, data, lane.overwrite)
    finally:
        for fd in fds:
            os.close(fd)
    return {
        "path": "/".join([*parts, name]),
        "bytes": len(data),
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
    }


def _write_in(dir_fd: int, name: str, data: bytes, overwrite: bool) -> None:
    try:
        st = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        st = None
    if st is not None:
        if stat.S_ISLNK(st.st_mode):
            raise LaneError("lane-symlink", f"{name!r} is a symlink")
        if not overwrite:
            raise LaneError("lane-exists", f"{name!r} exists and the lane does not overwrite")
        if not stat.S_ISREG(st.st_mode):
            raise LaneError("lane-path-escape", f"{name!r} is not a regular file")
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
