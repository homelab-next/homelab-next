# SPDX-License-Identifier: Apache-2.0
"""What one profile's program may call: the model every Code Mode output is rendered from.

A profile sees exactly the actions the broker would admit for it, and nothing else.  Which those
are is asked of :func:`homelabnext.broker.decide` itself, one shadow-mode probe per action a
grant names (as :meth:`homelabnext.broker.service.BrokerService.actions_for` does), so the
namespaces cannot disagree with what a call gets: an action no grant of the profile names, one
above the grant's ``max_tier`` or one without a handler is never in the model, and an action
whose verdict is ``needs-approval`` is marked ``needs_approval``.

Each action becomes one :class:`Method`: its prefix (``dns`` of ``dns.lookup``) is the namespace,
the rest (``lookup``; ``a.b-c.d`` gives ``b_c_d``) the method, and its parameters are a JSON
Schema object:

* an **exec** action's ``params_schema`` from its handler document (the schema the broker
  validates the request against), with the handler's ``description`` as its summary;
* a **lane** action's parameters as the lane handler checks them
  (:mod:`homelabnext.broker.lanes`): ``{name, content}`` for a files lane (``content`` a string,
  or a JSON object or list for a ``json`` lane), ``{note, body?, slug?}`` for a records inbox.
  Its result is the lane write's ``{path, bytes, digest}``.

An exec handler declares no result schema yet, so its result is untyped.  A name that cannot be
an identifier in both stub languages (a keyword, ``delete``, ``class``) gets a trailing ``_``; two
actions that land on the same method, or a parameter name that is not an identifier, are refused
(:class:`CodemodeError`) rather than renamed, since a renamed parameter would not be the one the
broker checks.
"""

from __future__ import annotations

import keyword
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from homelabnext.agent.digest import digest_of
from homelabnext.broker import MemoryApprovalStore, decide
from homelabnext.broker import lanes as _lanes
from homelabnext.generators.safe import UnsafeValueError, checked

__all__ = [
    "LANE_RESULT",
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
#: the probe's fixed decision time: no approval is probed, so it only fills ``decided_at``
_PROBE_NOW = "1970-01-01T00:00:00Z"
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
#: TypeScript's reserved and strict-mode words, which a namespace or function may not be named
_TS_WORDS = (
    "arguments await break case catch class const continue debugger default delete do else enum "
    "eval export extends false finally for function if implements import in instanceof interface "
    "let new null package private protected public return static super switch this throw true try "
    "typeof var void while with yield"
)
TS_RESERVED = frozenset(_TS_WORDS.split())


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
    """``name`` (a slug segment) as an identifier both stub languages accept."""
    out = name.replace("-", "_")
    if keyword.iskeyword(out) or out in TS_RESERVED:
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
        probe = {"request_id": "req-probe", "action": name, "actor": profile, "params": {}}
        verdict = decide(view, probe, None, now=_PROBE_NOW, store=store)["verdict"]
        if verdict in ("allow", "needs-approval"):
            out.append((name, verdict == "needs-approval"))
    return out


def _param_problems(action: str, schema: Mapping[str, Any]) -> list[str]:
    props = schema.get("properties", {})
    if not isinstance(props, Mapping):
        return [f"{action}: params_schema properties is not an object"]
    return [
        f"{action}: parameter {name!r} is not an identifier (the stubs take it by name)"
        for name in props
        if not _IDENT.match(str(name)) or keyword.iskeyword(str(name))
    ]


def doc_line(action: str, text: str) -> tuple[str, list[str]]:
    """``text`` as one line of a comment or docstring, or a problem."""
    try:
        line = checked(text, f"{action}: description")
    except UnsafeValueError as exc:
        return "", [str(exc)]
    bad = [s for s in ("*/", '"""', "\\") if s in line]
    if bad:
        return "", [f"{action}: description holds {bad[0]!r}, which would end a stub comment"]
    return line, []


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
        methods: list[Method] = []
        seen: dict[tuple[str, str], str] = {}
        for name, needs in _granted(manifest, profile):
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
                kind, params, result = "exec", doc["params_schema"], None
                text = doc["description"]
            summary, bad = doc_line(name, text)
            bad += _param_problems(name, params)
            problems += bad
            if not bad:
                methods.append(
                    Method(name, ns, meth, entry["tier"], needs, kind, summary, params, result)
                )
        models.append(ProfileModel(profile, manifest["manifest_id"], tuple(methods)))
    if problems:
        raise CodemodeError(problems)
    return models
