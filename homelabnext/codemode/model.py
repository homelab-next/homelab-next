# SPDX-License-Identifier: Apache-2.0
"""What one profile's program may call: the model every Code Mode output is rendered from.

A profile sees exactly the actions the broker would admit for it, and nothing else.  Which those
are is asked of :func:`homelabnext.broker.decide` itself, one shadow-mode probe per action a
grant names (as :meth:`homelabnext.broker.service.BrokerService.actions_for` does), so the
namespaces cannot disagree with what a call gets: an action no grant of the profile names, one
above the grant's ``max_tier`` or one without a handler is never in the model, and an action
whose verdict is ``needs-approval`` is marked ``needs_approval``.  ``codemode.*`` actions are
never in it either: a program cannot start a program (the capability token's claims refuse them).

Each action becomes one :class:`Method`: its prefix (``dns`` of ``dns.lookup``) is the namespace,
the rest (``lookup``; ``a.b-c.d`` gives ``b_c_d``) the method, and its parameters are a JSON
Schema object:

* an **exec** action's ``params_schema`` from its handler document (the schema the broker
  validates the request against), with the handler's ``description`` as its summary;
* a **lane** action's parameters as the lane handler checks them
  (:mod:`homelabnext.broker.lanes`): ``{name, content}`` for a files lane (``content`` a string,
  or a JSON object or list for a ``json`` lane), ``{note, body?, slug?}`` for a records inbox.
  Its result is the lane write's ``{path, bytes, digest}``.

An exec handler may declare a ``result_schema`` (handler document 1.2): the schema of the
handler's ``output`` once decoded as JSON, rendered with the same type mapping as parameters and
held to the same text checks.  Without one its result is untyped: the runner hands a program the
handler's ``output``.

Names: a segment that cannot be an identifier in both stub languages, or would shadow a Python
builtin the stub's annotations use (a keyword, ``delete``, ``class``, ``list``, ``str``), gets a
trailing ``_``.  Refused (:class:`CodemodeError`) rather than renamed, since a renamed parameter
would not be the one the broker checks: two actions that land on one method; a parameter name that
is not an identifier, is a keyword, is ``self``, or is ``params`` while the spec admits more
parameters (``**params``); a ``required`` name the spec does not declare; a property key that is
not a string.  Every name the outputs carry is matched whole (a schema pattern's ``$`` also matches
before a trailing newline), and every text a stub comment carries is one line with no control,
format (bidi, zero-width) or separator character and nothing that would end the comment.
"""

from __future__ import annotations

import keyword
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from homelabnext.agent.digest import digest_of
from homelabnext.broker import MemoryApprovalStore, decide
from homelabnext.broker import lanes as _lanes
from homelabnext.generators.safe import UnsafeValueError, checked

__all__ = [
    "EXCLUDED_PREFIXES",
    "LANE_RESULT",
    "SLUG_RE",
    "CodemodeError",
    "Method",
    "ProfileModel",
    "build_models",
    "doc_line",
    "identifier",
]

#: what a lane write returns (:func:`homelabnext.broker.lanes.write`)
LANE_RESULT: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "bytes": {"type": "integer"},
        "digest": {"type": "string"},
    },
    "required": ["bytes", "digest", "path"],
    "additionalProperties": False,
}
#: action prefixes a program never sees (a program cannot start a program)
EXCLUDED_PREFIXES = frozenset({"codemode"})
#: a profile slug (the directory of its files), matched whole
SLUG_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_ACTION_RE = re.compile(r"[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
#: the probe's fixed decision time: no approval is probed, so it only fills ``decided_at``
_PROBE_NOW = "1970-01-01T00:00:00Z"
#: TypeScript's reserved and strict-mode words, which a namespace or function may not be named
_TS_WORDS = (
    "arguments await break case catch class const continue debugger default delete do else enum "
    "eval export extends false finally for function if implements import in instanceof interface "
    "let new null package private protected public return static super switch this throw true try "
    "typeof var void while with yield"
)
TS_RESERVED = frozenset(_TS_WORDS.split())
#: the builtins a stub's annotations use: a namespace or method of that name would shadow it in
#: the stub (``list: _List`` at module level, a method ``str`` in a class body)
PY_SHADOWED = frozenset({"bool", "dict", "float", "int", "list", "str"})
#: Unicode categories refused in comment text: format (bidi, zero-width, BOM), line and
#: paragraph separators, surrogates
_BAD_CATEGORIES = frozenset({"Cf", "Zl", "Zp", "Cs"})


class CodemodeError(ValueError):
    """The manifest cannot be rendered as namespaces; ``problems`` lists every reason."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems = list(problems)
        super().__init__("codemode: cannot generate:\n  - " + "\n  - ".join(self.problems))


@dataclass(frozen=True)
class Method:
    action: str  # the broker action, e.g. service.restart
    namespace: str  # service
    method: str  # restart
    tier: str
    needs_approval: bool
    kind: str  # exec | lane
    summary: str
    params: Mapping[str, Any]  # a JSON Schema object
    result: Mapping[str, Any] | None = None  # None: the action declares no result schema


@dataclass(frozen=True)
class ProfileModel:
    profile: str  # profile:triage
    source: str  # the manifest's manifest_id
    methods: tuple[Method, ...] = field(default_factory=tuple)

    @property
    def slug(self) -> str:
        """The profile's directory name: its id without ``profile:``."""
        return self.profile.split(":", 1)[1]

    @property
    def namespaces(self) -> dict[str, list[Method]]:
        out: dict[str, list[Method]] = {}
        for m in self.methods:
            out.setdefault(m.namespace, []).append(m)
        return out

    @property
    def digest(self) -> str:
        """``sha256:`` of the model: every output names it, so the three files of a profile can be
        seen to come from the same model."""
        return digest_of(
            {
                "profile": self.profile,
                "source": self.source,
                "methods": [asdict(m) for m in self.methods],
            }
        )


def identifier(name: str) -> str:
    """``name`` (a slug segment) as an identifier both stub languages accept, shadowing nothing."""
    out = name.replace("-", "_")
    if keyword.iskeyword(out) or out in TS_RESERVED or out in PY_SHADOWED:
        out += "_"
    return out


def _split(action: str) -> tuple[str, str]:
    head, *rest = action.split(".")
    return identifier(head), "_".join(identifier(p) for p in rest)


def _lane_params(lane: _lanes.Lane) -> dict[str, Any]:
    if lane.kind == "records-inbox":
        return {
            "type": "object",
            "properties": {
                "note": {
                    "type": "object",
                    "description": "records note frontmatter: title, risk, rollback, ...; type one "
                    f"of {', '.join(lane.note_types)}; requesting_agent is bound to the caller",
                },
                "body": {"type": "string", "description": "the note's Markdown body"},
                "slug": {"type": "string", "description": "the file name's slug"},
            },
            "required": ["note"],
            "additionalProperties": False,
        }
    content: dict[str, Any] = (
        {"type": "string"} if lane.format == "text" else {"type": ["object", "array"]}
    )
    content["description"] = f"{lane.format}, at most {lane.max_bytes} bytes" + (
        "" if lane.overwrite else "; an existing file is never replaced"
    )
    return {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "pattern": lane.filename_pattern,
                "description": "the file name",
            },
            "content": content,
        },
        "required": ["content", "name"],
        "additionalProperties": False,
    }


def _lane_summary(lane: _lanes.Lane) -> str:
    if lane.kind == "records-inbox":
        kinds = " or ".join(lane.note_types)
        return f"File a {kinds} note into the records inbox (lane {lane.name})."
    whose = "your own" if lane.per_actor else "the shared"
    return f"Write a {lane.format} file into {whose} {lane.name} lane."


def _granted(manifest: Mapping[str, Any], profile: str) -> list[tuple[str, bool]]:
    """(action, needs approval) for each action ``decide`` admits for ``profile``, sorted."""
    view = dict(manifest, mode="shadow")
    store = MemoryApprovalStore()
    names = sorted({a for g in manifest["grants"] if g["profile"] == profile for a in g["actions"]})
    out = []
    for name in names:
        if name.split(".", 1)[0] in EXCLUDED_PREFIXES:
            continue
        probe = {"request_id": "req-probe", "action": name, "actor": profile, "params": {}}
        verdict = decide(view, probe, None, now=_PROBE_NOW, store=store)["verdict"]
        if verdict in ("allow", "needs-approval"):
            out.append((name, verdict == "needs-approval"))
    return out


def doc_line(where: str, text: str) -> tuple[str, list[str]]:
    """``text`` as one line of a stub comment or docstring, or a problem.  A backslash is fine
    (the Python docstrings are raw); ``*/`` and ``\"\"\"`` would end the comment."""
    try:
        line = checked(text, where)
    except UnsafeValueError:
        return "", [f"{where}: holds a control character; it must be one line"]
    odd = next((c for c in line if unicodedata.category(c) in _BAD_CATEGORIES), None)
    if odd is not None:
        return "", [f"{where}: holds U+{ord(odd):04X} ({unicodedata.category(odd)})"]
    bad = [s for s in ("*/", '"""') if s in line]
    if bad:
        return "", [f"{where}: holds {bad[0]!r}, which would end a stub comment"]
    return line, []


def _text_problems(where: str, value: Any) -> list[str]:
    """:func:`doc_line` over every string key and value anywhere in ``value``: the index carries
    the whole schema (a nested ``title``, a ``default``, an ``enum`` value, a key), and any of it
    may reach a stub comment or a reader of ``codemode_describe``."""
    if isinstance(value, str):
        return doc_line(where, value)[1]
    out = []
    if isinstance(value, Mapping):
        for k, v in value.items():
            bad = doc_line(f"{where}: a key", k)[1] if isinstance(k, str) else []
            out += bad
            here = f"{where}.{k}" if isinstance(k, str) and not bad else f"{where}.<key>"
            out += _text_problems(here, v)
    elif isinstance(value, list | tuple):
        for i, v in enumerate(value):
            out += _text_problems(f"{where}[{i}]", v)
    return out


def _schema_problems(where: str, schema: Any, *, texts: bool = True) -> list[str]:
    """Shape problems of a (nested) schema the renderers would trip on or render wrongly, and
    (``texts``, at the root) a refused character in any string it holds."""
    if not isinstance(schema, Mapping):
        return []
    out = _text_problems(where, schema) if texts else []
    props = schema.get("properties", {})
    if not isinstance(props, Mapping):
        return [f"{where}: properties is not an object"]
    keys = [k for k in props if isinstance(k, str)]
    out += [f"{where}: a property key is not a string" for k in props if not isinstance(k, str)]
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(isinstance(r, str) for r in required):
        out.append(f"{where}: required is not a list of names")
    else:
        out += [
            f"{where}: required names {r!r}, which it does not declare"
            for r in required
            if r not in keys
        ]
    for k in keys:
        out += _schema_problems(f"{where}.{k}", props[k], texts=False)
    for key in ("items", "additionalProperties"):
        out += _schema_problems(f"{where}[{key}]", schema.get(key), texts=False)
    for key in ("oneOf", "anyOf"):
        for i, alt in enumerate(schema.get(key) or []):
            out += _schema_problems(f"{where}[{key}][{i}]", alt, texts=False)
    return out


def _param_problems(action: str, schema: Mapping[str, Any]) -> list[str]:
    problems = _schema_problems(f"{action}: params", schema)
    if problems:
        return problems
    props = schema.get("properties", {})
    open_ = schema.get("additionalProperties", True) is not False
    for name in props:
        if not _IDENT.fullmatch(name) or keyword.iskeyword(name):
            problems.append(
                f"{action}: parameter {name!r} is not an identifier (the stubs take it by name)"
            )
        elif name == "self" or (name == "params" and open_):
            problems.append(f"{action}: parameter {name!r} clashes with the stub's own {name}")
    return problems


def _name_problems(manifest: Mapping[str, Any], profile: str, names: Sequence[str]) -> list[str]:
    """Every name the outputs carry, matched whole: a schema pattern's ``$`` lets a trailing
    newline through, and these names reach paths and stub source."""
    out = []
    if not isinstance(manifest.get("manifest_id"), str) or not SLUG_RE.fullmatch(
        manifest["manifest_id"]
    ):
        out.append("manifest_id: not a slug")
    slug = profile.split(":", 1)[1] if profile.startswith("profile:") else ""
    if not SLUG_RE.fullmatch(slug):
        out.append(f"grants: profile {profile!r} is not profile:<slug>")
    out += [
        f"grants of {profile}: {n!r} is not an action name"
        for n in names
        if not _ACTION_RE.fullmatch(n)
    ]
    return out


def build_models(
    manifest: Mapping[str, Any], handler_docs: Sequence[Mapping[str, Any]]
) -> list[ProfileModel]:
    """One :class:`ProfileModel` per profile the manifest grants actions to, sorted by profile.

    ``manifest`` and ``handler_docs`` are what :func:`homelabnext.broker.service.load_manifest`
    returns (validated).  Raises :class:`CodemodeError` listing every problem."""
    docs = {d["action"]: d for d in handler_docs}
    lanes = {ld["name"]: _lanes.Lane.from_doc(ld) for ld in manifest.get("lanes", [])}
    entries = {a["action"]: a for a in manifest["actions"]}
    problems: list[str] = []
    models = []
    for profile in sorted({g["profile"] for g in manifest["grants"]}):
        granted = _granted(manifest, profile)
        bad_names = _name_problems(manifest, profile, [n for n, _ in granted])
        if bad_names:
            problems += bad_names
            continue
        methods: list[Method] = []
        seen: dict[tuple[str, str], str] = {}
        for name, needs in granted:
            entry = entries[name]
            ns, meth = _split(name)
            if (ns, meth) in seen:
                problems.append(f"{name} and {seen[ns, meth]} are both {ns}.{meth}")
                continue
            seen[ns, meth] = name
            if entry.get("lane"):
                lane = lanes[entry["lane"]]
                kind, params, result = "lane", _lane_params(lane), LANE_RESULT
                text = _lane_summary(lane)
            else:
                doc = docs.get(name)
                if doc is None:
                    problems.append(f"{name}: no handler document declares its params_schema")
                    continue
                kind, params, result = "exec", doc["params_schema"], doc.get("result_schema")
                text = doc["description"]
            summary, bad = doc_line(f"{name}: description", text)
            bad += _param_problems(name, params)
            if kind == "exec" and result is not None:
                bad += _text_problems(f"{name}: result", result)
                if _schema_problems(f"{name}: result", result, texts=False):
                    result = None  # not renderable faithfully: the method's result is untyped
            problems += bad
            if not bad:
                methods.append(
                    Method(name, ns, meth, entry["tier"], needs, kind, summary, params, result)
                )
        models.append(ProfileModel(profile, manifest["manifest_id"], tuple(methods)))
    if problems:
        raise CodemodeError(problems)
    return models
