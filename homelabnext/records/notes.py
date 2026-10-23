# SPDX-License-Identifier: Apache-2.0
"""Note parsing, rendering and validation (shared by the agent and the operator side).

Validation is the JSON Schema ``schemas/records/note.schema.json`` plus the filename rule
``<YYYY-MM-DD>-<agent>-<slug>.md`` (date equals ``created``, agent equals the ``requesting_agent``
slug), which JSON Schema cannot express.  The schema directory is found next to the package in a
package data, or the source checkout (``homelabnext.paths``; override ``HNX_SCHEMAS_DIR``).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from homelabnext import paths

AGENT_LANE = "inbox"
DECIDED_LANES = ("decided/approved", "decided/denied", "decided/completed")
ALL_LANES = (AGENT_LANE, *DECIDED_LANES)

_SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_FILENAME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})-([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\.md$")
_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---[ \t]*(?:\n|\Z)", re.S)
MAX_SLUG = 60


class NoteError(ValueError):
    """A note is malformed or violates the contract."""


@dataclass(frozen=True)
class Note:
    lane: str
    name: str
    frontmatter: dict[str, Any]
    body: str

    @property
    def type(self) -> str:
        return str(self.frontmatter.get("type", ""))


def _yaml():
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without the extra
        raise ModuleNotFoundError(
            "homelabnext.records needs PyYAML (pip install 'homelabnext[core]')", name="yaml"
        ) from exc
    return yaml


@lru_cache(maxsize=1)
def _str_loader():
    """Keeps timestamps as strings (JSON Schema has no timestamp type) and refuses a duplicate
    key: PyYAML would keep the last value, the decider would act on it, and a person reading the
    note would see the first."""
    _yaml()
    from homelabnext._yaml import UniqueKeyStrDateLoader

    return UniqueKeyStrDateLoader


def slugify(text: str, *, max_len: int = MAX_SLUG) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    s = re.sub(r"^[0-9-]+", "", s)  # a slug starts with a letter
    s = s[:max_len].rstrip("-")
    if not s:
        raise NoteError(f"cannot derive a slug from {text!r}")
    return s


def agent_slug(requesting_agent: str) -> str:
    kind, _, slug = str(requesting_agent).partition(":")
    if kind != "profile" or not _SLUG_RE.match(slug or ""):
        raise NoteError(f"requesting_agent: {requesting_agent!r} is not a 'profile:<slug>' id")
    return slug


def build_filename(frontmatter: dict[str, Any], slug: str) -> str:
    if not _SLUG_RE.match(slug) or len(slug) > MAX_SLUG:
        raise NoteError(f"slug {slug!r} is not a lowercase hyphenated slug (max {MAX_SLUG})")
    date = str(frontmatter.get("created", ""))[:10]
    return f"{date}-{agent_slug(frontmatter.get('requesting_agent', ''))}-{slug}.md"


def check_filename(name: str, frontmatter: dict[str, Any]) -> list[str]:
    m = _FILENAME_RE.match(name)
    if not m:
        return [f"filename {name!r} is not <YYYY-MM-DD>-<agent>-<slug>.md"]
    date, rest = m.groups()
    problems = []
    if str(frontmatter.get("created", ""))[:10] != date:
        problems.append(f"filename date {date} != created {str(frontmatter.get('created'))[:10]!r}")
    try:
        agent = agent_slug(frontmatter.get("requesting_agent", ""))
    except NoteError as exc:
        return [*problems, str(exc)]
    if not rest.startswith(agent + "-"):
        problems.append(f"filename must be '{date}-{agent}-<slug>.md'")
    return problems


# ---------------------------------------------------------------- schema
def schema_dir() -> Path:
    return paths.schemas_dir()


@lru_cache(maxsize=4)
def _validator(sdir: str):
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise ModuleNotFoundError(
            "homelabnext.records needs jsonschema (pip install 'homelabnext[core]')", name=exc.name
        ) from exc
    root = Path(sdir)
    note_path = root / "records" / "note.schema.json"
    if not note_path.is_file():
        raise FileNotFoundError(
            f"{note_path} not found; set HNX_SCHEMAS_DIR to a schemas directory "
            "(installed wheels and source checkouts need no setting)"
        )
    reg = Registry()
    for p in sorted(root.glob("*/*.json")):
        if p.parent.name.startswith("_"):
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        if "$id" in doc:
            reg = reg.with_resource(
                doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
            )
    schema = json.loads(note_path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=reg)


def _non_string_key(value: Any) -> Any:
    """The first mapping key anywhere in ``value`` that is not a string, else None."""
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                return k
            found = _non_string_key(v)
            if found is not None:
                return found
    elif isinstance(value, list):
        for v in value:
            found = _non_string_key(v)
            if found is not None:
                return found
    return None


def validate_note(note: dict[str, Any] | Any) -> None:
    """Raise :class:`NoteError` (a ``ValueError``) naming the first offending field."""
    if not isinstance(note, dict):
        raise NoteError("note frontmatter must be a mapping")
    bad = _non_string_key(note)
    if bad is not None:
        raise NoteError(
            f"frontmatter key {bad!r} is not a string: YAML 1.1 reads an unquoted on, off, yes,"
            " no, y or n as a boolean (register-transition takes retired_on, not on)"
        )
    validator = _validator(str(schema_dir()))
    errors = sorted(validator.iter_errors(note), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        e = errors[0]
        field = "/".join(str(p) for p in e.absolute_path) or "$"
        extra = f" (+{len(errors) - 1} more)" if len(errors) > 1 else ""
        raise NoteError(f"{field}: {e.message}{extra}")


# ---------------------------------------------------------------- text <-> note
def parse_note(text: str) -> tuple[dict[str, Any], str]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        raise NoteError("no YAML frontmatter")
    try:
        fm = _yaml().load(m.group(1), Loader=_str_loader())
    except Exception as exc:
        why = getattr(exc, "problem", None)
        detail = f" ({why})" if isinstance(why, str) and why.startswith("duplicate key") else ""
        raise NoteError(f"frontmatter is not valid YAML: {type(exc).__name__}{detail}") from exc
    if not isinstance(fm, dict):
        raise NoteError("frontmatter must be a mapping")
    return fm, text[m.end() :]


def render_note(frontmatter: dict[str, Any], body: str) -> str:
    dumped = _yaml().safe_dump(
        frontmatter, sort_keys=False, default_flow_style=False, allow_unicode=True
    )
    body = body if body.endswith("\n") or not body else body + "\n"
    return f"---\n{dumped}---\n\n{body}"


def read_note(path: Path, lane: str) -> Note:
    fm, body = parse_note(path.read_text(encoding="utf-8"))
    return Note(lane=lane, name=path.name, frontmatter=fm, body=body.lstrip("\n"))
