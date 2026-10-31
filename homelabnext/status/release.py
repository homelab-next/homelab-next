# SPDX-License-Identifier: Apache-2.0
"""Release transforms: the only way the hub's ``red`` data reaches a looser reader (ADR-0033
decisions 7 and 8; ``docs/status.md``, "TLP ceilings and release transforms").

The registry is :data:`REGISTRY` (``release_transforms.yml`` beside this module, governance: a
change to it needs a human approve through CODEOWNERS).  Each :class:`Transform` names what it
serves (:data:`EXPORTS` and :data:`VIEWS`), its input and output label, the fields it keeps and
the fields it withdraws with the reason.  :meth:`Transform.apply` is an allow-list: a field it
does not keep is dropped, and a kept path keeps only a scalar (a list of scalars only through an
explicit ``x[]`` path), so a mapping is kept only through the fields listed under it.

:meth:`Releases.release` then does two things the allow-list alone cannot (decision 7: released
output still passes the egress content checks):

* **every kept value is checked** against its declared kind (:data:`KINDS`): a closed pattern or
  a closed set, and for every string no hostname-like dotted name, no IP address, no path and no
  TLP marker (:func:`content_problem`).  A value that fails is replaced by :data:`PLACEHOLDER`
  (a string kind) or ``None`` (a number or a flag), never passed and never fatal;
* **the output is re-checked** by separate code (:func:`leaf_paths` flattens the output's key
  paths and compares them with the keep list, :meth:`Transform.unlisted`): a transform that
  passes an unlisted field raises :class:`ReleaseError`.

A name no transform serves raises too (fail closed: an unserved public field is withdrawn, never
passed).  Paths: ``a.b`` is field ``b`` of mapping ``a``, ``a[]`` each item of list ``a``, ``*``
every key of a mapping whose keys are data (the view ids under ``views``).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from functools import cache, cached_property
from pathlib import Path
from typing import Any

import yaml

from homelabnext import tlp
from homelabnext._yaml import UniqueKeyLoader
from homelabnext.status.agents.model import SESSION_STATES
from homelabnext.status.model import STATES

__all__ = [
    "EVENTS_PUBLIC",
    "EXPORTS",
    "KINDS",
    "PLACEHOLDER",
    "REGISTRY",
    "REQUIRED",
    "SESSIONS_PUBLIC",
    "STATUS_PUBLIC",
    "VIEWS",
    "ReleaseError",
    "Releases",
    "Transform",
    "check_value",
    "content_problem",
    "leaf_paths",
    "load",
    "registry",
    "registry_problems",
]

#: the registry the hub serves with (package data, CODEOWNERS)
REGISTRY = Path(__file__).with_name("release_transforms.yml")
#: the public exports the hub serves: each needs exactly one transform
EXPORTS = ("status.json", "activity.csv", "activity.jsonl")
#: the views whose data a transform shapes: the sections of ``status.json`` and the agent pages
VIEWS = ("exceptions", "grid", "sources", "agents", "activity", "agent-analytics")
_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$(?!\n)")
_SEGMENT = re.compile(r"^(?:[a-z_][a-z0-9_]*|\*)(?:\[\])?$(?!\n)")
#: the transforms the hub's code applies, and what each must serve (a registry without one of
#: them is refused, so renaming a transform cannot switch its release off silently)
STATUS_PUBLIC = "status-public"
SESSIONS_PUBLIC = "agent-sessions-public"
EVENTS_PUBLIC = "agent-events-public"
REQUIRED = {
    STATUS_PUBLIC: ("status.json", "exceptions", "grid", "sources"),
    SESSIONS_PUBLIC: ("agents", "agent-analytics"),
    EVENTS_PUBLIC: ("agents", "activity", "agent-analytics", "activity.csv", "activity.jsonl"),
}
_KEYS = frozenset({"id", "what", "serves", "input", "output", "keep", "withdraw"})
_WILD, _ITEMS, _LEAF = "*", "[]", True
_SCALARS = (str, int, float, bool, type(None))

#: what a kept value that fails its check is replaced by (a string kind; a number or flag: None)
PLACEHOLDER = "withheld"
#: the closed sets a kept string may come from (agent activity: its schema's enums, held equal by
#: tests/status/test_status_tlp.py)
SETS = {
    "state": STATES,
    "session-state": SESSION_STATES,
    "menu-kind": ("panel", "page", "external"),
    "activity-kind": (
        "session_start", "session_end", "prompt", "tool_start", "tool_end", "approval_request",
        "approval_response", "notification", "stop", "subagent_stop", "error", "heartbeat",
        "usage",
    ),
    "outcome": ("success", "error", "denied", "pending", "approved", "info"),
    "surface": ("local", "cloud"),
}  # fmt: skip
_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_:-]{0,79}$(?!\n)")
_TITLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ,'()+-]{0,79}$(?!\n)")
_TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$(?!\n)")
#: the value kinds a kept path declares (``const:<value>`` and ``enum:<set>`` take an argument)
KINDS = {
    "slug": "an id or a name: a letter or digit, then letters, digits, _ : -; at most 80, no dot",
    "title": "a menu or page title: letters, digits, spaces and , ' ( ) + -; at most 80",
    "time": "an RFC 3339 UTC timestamp (Z)",
    "count": "a number (or null)",
    "bool": "true or false (or null)",
    "const": "exactly the value after the colon",
    "enum": "one of the closed set named after the colon (" + ", ".join(SETS) + ")",
}
# a dotted name with a letter in its first two labels (db1.lab.example, svc.local), an IP
# address, a path, and a TLP marker.  TODO(ADR-0033): use homelabnext.tlp_egress.markers once
# PR #169 lands, so the hub and the publishing gate read markers one way
_DOTTED = re.compile(r"[A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*\.[A-Za-z][A-Za-z0-9-]*")
_IP_TOKEN = re.compile(r"[0-9A-Fa-f:.%]{3,}")
_PATHISH = re.compile(r"[/\\]|^~")
_MARKER = re.compile(r"(?i)tlp\s*[:_ -]?\s*(?:clear|white|green|amber(?:\s*\+\s*strict)?|red)\b")


def content_problem(text: str) -> str | None:
    """Why ``text`` may not leave in a released field, or None: a hostname-like dotted name, an
    IP address, a path or a TLP marker (the egress content checks, decision 13)."""
    if _MARKER.search(text):
        return "a TLP marker"
    if _DOTTED.search(text):
        return "a dotted name"
    for token in _IP_TOKEN.findall(text):
        try:
            ipaddress.ip_address(token.split("%", 1)[0].strip(".:"))
        except ValueError:
            continue
        return "an IP address"
    if _PATHISH.search(text):
        return "a path"
    return None


def _kind_problem(kind: str) -> str | None:
    name, _, arg = kind.partition(":")
    if name not in KINDS:
        return f"unknown value kind {kind!r} (one of {', '.join(KINDS)})"
    if name == "enum" and arg not in SETS:
        return f"unknown set {arg!r} (one of {', '.join(SETS)})"
    if name == "const" and not arg:
        return "const needs its value"
    if name not in ("enum", "const") and arg:
        return f"{name} takes no argument"
    return None


def check_value(kind: str, value: Any) -> bool:
    """Whether a kept ``value`` passes its declared ``kind`` and, for a string, the content
    checks (``const`` is the registry's own literal and is compared exactly)."""
    name, _, arg = kind.partition(":")
    if name == "count":
        return value is None or (isinstance(value, int | float) and not isinstance(value, bool))
    if name == "bool":
        return value is None or isinstance(value, bool)
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    if name == "const":
        return value == arg
    if name == "enum":
        return value in SETS[arg]
    pattern = {"slug": _SLUG, "title": _TITLE, "time": _TIME}[name]
    return bool(pattern.match(value)) and content_problem(value) is None


def leaf_paths(value: Any, at: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    """Every leaf of ``value`` as ``(path, value)``, a list item's step ``[]``; an empty mapping or
    list is a leaf of its own.  Written apart from :func:`_apply`, so the output re-check does
    not trust the code it checks."""
    if isinstance(value, Mapping) and value:
        for k, v in value.items():
            yield from leaf_paths(v, (*at, str(k)))
    elif isinstance(value, list) and value:
        for v in value:
            yield from leaf_paths(v, (*at, _ITEMS))
    else:
        yield at, value


def _matches(path: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    return len(path) == len(pattern) and all(
        p == q or (q == _WILD and p != _ITEMS) for p, q in zip(path, pattern, strict=True)
    )


class ReleaseError(ValueError):
    """A release that cannot be made safely: an unserved name, or output an allow-list misses."""


def _steps(path: str) -> list[str]:
    """``a.b[].*`` -> ``["a", "b", "[]", "*"]``; ``ValueError`` for anything else."""
    if not isinstance(path, str) or not path:
        raise ValueError(f"not a field path: {path!r}")
    out = []
    for seg in path.split("."):
        if not _SEGMENT.match(seg):
            raise ValueError(f"not a field path: {path!r}")
        if seg.endswith("[]"):
            out += [seg[:-2], _ITEMS]
        else:
            out.append(seg)
    return out


def _tree(paths: Iterable[str]) -> dict[str, Any]:
    """The paths as a tree; a path that is a prefix of another, or repeated, is refused."""
    root: dict[str, Any] = {}
    for path in paths:
        node, steps = root, _steps(path)
        for i, step in enumerate(steps):
            last = i == len(steps) - 1
            child = node.get(step)
            if child is _LEAF or (last and child is not None):
                raise ValueError(f"{path!r} overlaps another listed path")
            if last:
                node[step] = _LEAF
            else:
                node = node.setdefault(step, {})
    return root


def _scalar(value: Any) -> bool:
    """A kept leaf holds a scalar only; a list of scalars is kept through an ``x[]`` path."""
    return isinstance(value, _SCALARS)


_DROP = object()


def _child(node: Mapping[str, Any], key: Any) -> Any:
    if not isinstance(key, str) or key in (_WILD, _ITEMS):
        return node.get(_WILD)
    return node[key] if key in node else node.get(_WILD)


def _apply(node: Any, value: Any) -> Any:
    if node is _LEAF:
        return value if _scalar(value) else _DROP
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            child = _child(node, k)
            if child is not None and (r := _apply(child, v)) is not _DROP:
                out[k] = r
        return out
    if isinstance(value, list) and _ITEMS in node:
        return [r for v in value if (r := _apply(node[_ITEMS], v)) is not _DROP]
    return _DROP


def _covered(node: Any, value: Any, at: str, withdrawn: Any) -> list[str]:
    """Fields under ``value`` neither kept (``node``) nor withdrawn (``withdrawn``)."""
    if withdrawn is _LEAF:
        return []
    if node is _LEAF:
        return [] if _scalar(value) else [at or "$"]
    node, withdrawn = node or {}, withdrawn or {}
    if isinstance(value, Mapping):
        out = []
        for k, v in value.items():
            keep, gone = _child(node, k), _child(withdrawn, k)
            where = f"{at}.{k}" if at else str(k)
            out += [where] if keep is None and gone is None else _covered(keep, v, where, gone)
        return out
    if isinstance(value, list) and (_ITEMS in node or _ITEMS in withdrawn):
        keep, gone = node.get(_ITEMS), withdrawn.get(_ITEMS)
        return [p for i, v in enumerate(value) for p in _covered(keep, v, f"{at}[{i}]", gone)]
    return [at or "$"]


@dataclass(frozen=True)
class Transform:
    """One release transform (a registry entry)."""

    id: str
    what: str
    serves: tuple[str, ...]
    input: tlp.Label
    output: tlp.Label
    #: path -> value kind (:data:`KINDS`)
    keep: Mapping[str, str]
    withdraw: Mapping[str, str]

    @cached_property
    def _keep(self) -> dict[str, Any]:
        return _tree(self.keep)

    @cached_property
    def _withdrawn(self) -> dict[str, Any]:
        return _tree(self.withdraw)

    @cached_property
    def _patterns(self) -> tuple[tuple[tuple[str, ...], str], ...]:
        return tuple((tuple(_steps(p)), kind) for p, kind in self.keep.items())

    def kind_of(self, path: tuple[str, ...]) -> str | None:
        """The declared kind of the leaf at ``path`` (an explicit key beats ``*``), or None."""
        hits = [(pat.count(_WILD), kind) for pat, kind in self._patterns if _matches(path, pat)]
        return min(hits)[1] if hits else None

    def keeps(self, field: str) -> bool:
        """Whether the top-level ``field`` is kept (a column of an export, a fact on a page)."""
        return field in self._keep

    def apply(self, data: Any) -> Any:
        """``data`` with only the kept fields (a copy; ``data`` is not changed)."""
        out = _apply(self._keep, data)
        return {} if out is _DROP else out

    def unlisted(self, data: Any) -> list[str]:
        """The leaves of ``data`` this transform does not keep, by separate code
        (:func:`leaf_paths`): a leaf whose path no kept path matches, or a kept path holding
        anything but a scalar.  An empty mapping or list passes only on the way to a kept path."""
        out = []
        for path, value in leaf_paths(data):
            if isinstance(value, Mapping | list):  # empty: a step towards a kept leaf, or not
                ok = any(_matches(path, pat[: len(path)]) for pat, _ in self._patterns
                         if len(pat) > len(path))  # fmt: skip
            else:
                ok = self.kind_of(path) is not None and isinstance(value, _SCALARS)
            if not ok:
                out.append(".".join(path).replace(".[]", "[]") or "$")
        return out

    def checked(self, data: Any, at: tuple[str, ...] = ()) -> Any:
        """``data`` (an applied output) with every leaf that fails its kind replaced:
        :data:`PLACEHOLDER` for a string kind, ``None`` for a number or a flag."""
        if isinstance(data, Mapping):
            return {k: self.checked(v, (*at, str(k))) for k, v in data.items()}
        if isinstance(data, list):
            return [self.checked(v, (*at, _ITEMS)) for v in data]
        kind = self.kind_of(at)
        if kind is None or check_value(kind, data):
            return data  # an unkept leaf is the re-check's to refuse
        return None if kind.partition(":")[0] in ("count", "bool") else PLACEHOLDER

    def unclassified(self, data: Any) -> list[str]:
        """The fields of ``data`` neither kept nor withdrawn: a field added to the source after
        the migration, which nobody has judged yet (the public-view test)."""
        return _covered(self._keep, data, "", self._withdrawn)


def _transform(i: int, raw: Any, problems: list[str]) -> Transform | None:
    where = f"transforms[{i}]"
    if not isinstance(raw, Mapping):
        problems.append(f"{where}: not a mapping")
        return None
    start = len(problems)
    for k in sorted(set(raw) - _KEYS, key=str):
        problems.append(f"{where}: unknown key {k!r}")
    for k in sorted(_KEYS - set(raw)):
        problems.append(f"{where}: missing {k!r}")
    if len(problems) > start:
        return None
    tid = raw["id"]
    if not (isinstance(tid, str) and _ID.match(tid)):
        problems.append(f"{where}: id {tid!r} is not a slug")
        return None
    where = f"transform {tid}"
    if not (isinstance(raw["what"], str) and raw["what"].strip()):
        problems.append(f"{where}: what is a sentence")
    serves = raw["serves"]
    if not (isinstance(serves, list) and serves and len(set(map(str, serves))) == len(serves)):
        problems.append(f"{where}: serves is a non-empty list of distinct names")
        serves = []
    for name in serves:
        if name not in EXPORTS + VIEWS:
            problems.append(
                f"{where}: serves {name!r}, not an export ({', '.join(EXPORTS)}) or a view "
                f"({', '.join(VIEWS)})"
            )
    labels = {}
    for k in ("input", "output"):
        try:
            labels[k] = tlp.parse(raw[k])
        except ValueError as exc:
            problems.append(f"{where}: {k}: {exc}")
    if len(labels) == 2 and labels["output"] > labels["input"]:
        problems.append(f"{where}: output {labels['output']} is stricter than its input")
    keep = raw["keep"]
    if not (isinstance(keep, Mapping) and keep):
        problems.append(f"{where}: keep is a non-empty mapping of field path to value kind")
        keep = {}
    for path, kind in keep.items():
        why = _kind_problem(kind) if isinstance(kind, str) else "a value kind is a string"
        if why:
            problems.append(f"{where}: keep {path!r}: {why}")
    withdraw: dict[str, str] = {}
    entries = raw["withdraw"] if isinstance(raw["withdraw"], list) else None
    if entries is None:
        problems.append(f"{where}: withdraw is a list of {{field, why}}")
        entries = []
    for e in entries:
        if not (
            isinstance(e, Mapping)
            and set(e) == {"field", "why"}
            and isinstance(e["why"], str)
            and e["why"].strip()
        ):
            problems.append(f"{where}: withdraw entry {e!r} is not {{field, why}} with a reason")
            continue
        if e["field"] in withdraw:
            problems.append(f"{where}: withdraws {e['field']!r} twice")
        withdraw[str(e["field"])] = e["why"]
    trees = True
    for name, paths in (("keep", keep), ("withdraw", list(withdraw))):
        try:
            _tree(paths)
        except ValueError as exc:
            problems.append(f"{where}: {name}: {exc}")
            trees = False
    if trees:
        try:
            _tree([*map(str, keep), *withdraw])
        except ValueError as exc:
            problems.append(f"{where}: keep and withdraw overlap: {exc}")
    if len(problems) > start:
        return None
    return Transform(
        id=tid,
        what=raw["what"],
        serves=tuple(serves),
        input=labels["input"],
        output=labels["output"],
        keep=dict(keep),
        withdraw=withdraw,
    )


class Releases:
    """The transforms of one registry, by what they serve."""

    def __init__(self, transforms: Iterable[Transform]):
        self.transforms = tuple(transforms)
        self.by_id = {t.id: t for t in self.transforms}

    def serving(self, name: str) -> tuple[Transform, ...]:
        """The transforms that serve ``name`` (an export or a view)."""
        return tuple(t for t in self.transforms if name in t.serves)

    def transform(self, tid: str, serves: str) -> Transform:
        """Transform ``tid``, which must serve ``serves``; :class:`ReleaseError` otherwise."""
        t = self.by_id.get(tid)
        if t is None or serves not in t.serves:
            raise ReleaseError(f"no release transform {tid!r} serves {serves!r}: withdrawn")
        return t

    def release(self, tid: str, serves: str, data: Any) -> Any:
        """``data`` through transform ``tid`` for ``serves``: applied, every kept value checked
        against its kind and the content checks (a failing one replaced, never passed), then the
        output re-checked against the transform's own list by separate code (fail closed: an
        unlisted field raises)."""
        t = self.transform(tid, serves)
        out = t.checked(t.apply(data))
        leaked = t.unlisted(out)
        if leaked:
            raise ReleaseError(
                f"release transform {t.id} passed unlisted fields: {', '.join(leaked[:5])}"
            )
        return out


def registry_problems(doc: Any) -> tuple[list[str], list[Transform]]:
    """The problems of a registry document, and its valid transforms."""
    if not isinstance(doc, Mapping):
        return ["the registry is not a mapping"], []
    top = {"release_transforms_version", "transforms"}
    problems = [f"unknown key {k!r}" for k in sorted(set(doc) - top, key=str)]
    if doc.get("release_transforms_version") != 1:
        problems.append("release_transforms_version is 1")
    raw = doc.get("transforms")
    if not isinstance(raw, list) or not raw:
        return [*problems, "transforms is a non-empty list"], []
    out = [t for i, r in enumerate(raw) if (t := _transform(i, r, problems)) is not None]
    ids = [t.id for t in out]
    problems += [
        f"transform {i}: id used twice" for i in sorted({i for i in ids if ids.count(i) > 1})
    ]
    for name in EXPORTS:
        serving = [t.id for t in out if name in t.serves]
        if len(serving) > 1:
            problems.append(
                f"export {name} is served by {len(serving)} transforms ({', '.join(serving)})"
            )
    by_id = {t.id: t for t in out}
    for tid, names in REQUIRED.items():
        missing = [n for n in names if tid not in by_id or n not in by_id[tid].serves]
        if missing:
            problems.append(
                f"the hub applies transform {tid} to {', '.join(missing)}: not declared"
            )
    return problems, out


def load(path: str | Path) -> Releases:
    """The registry at ``path``; ``ReleaseError`` listing every problem (fail closed)."""
    try:
        doc = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise ReleaseError(f"cannot read release transforms {path}: {exc}") from None
    problems, transforms = registry_problems(doc)
    if problems:
        raise ReleaseError(
            f"invalid release transforms {path}" + "".join(f"\n  - {p}" for p in problems)
        )
    return Releases(transforms)


@cache
def registry() -> Releases:
    """The hub's registry (:data:`REGISTRY`), read once."""
    return load(REGISTRY)
