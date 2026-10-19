# SPDX-License-Identifier: Apache-2.0
"""Reader -> actor handoff (checklist G-04): actors act only on validated structured input.

G-03 splits work that both reads untrusted content and acts into a **reader** that reports and an
**actor** that acts.  This module is the seam between them.  A handoff (``schemas/agent/handoff``)
declares the reader, the actor, the schema the reader's structured ``output`` must satisfy and
the broker actions the actor may take, each with its parameters bound to literals or to
``$output.<path>`` references.  Three rules make it hold:

1. **Structured input only.**  :func:`accept` takes the reader's ``report_result`` as a mapping;
   raw text (``str``/``bytes``) is refused without being parsed.  The report must validate
   (:func:`~homelabnext.agent.report.validate_report` against the pack it ran on), come from the
   declared reader, not be deferred, and carry an ``output`` that validates against the
   handoff's ``output_schema``.  Only then does the actor get an :class:`Accepted`, and an
   :class:`Accepted` cannot be built any other way.
2. **Free text never becomes a parameter.**  The actor does not choose parameters: a request's
   params are computed from the declaration, and a reference may name only a *constrained*
   field of the output - an ``enum``/``const``, a number or boolean, or a string with a checked
   ``format`` (:data:`CHECKED_FORMATS`) or a closed ``pattern`` (:func:`is_closed_pattern`), and
   arrays/closed objects made only of those.  The report's ``summary``, ``unknowns``, cites and memory updates, and any
   unconstrained string of the output, are free text: a model can be talked into writing
   anything there.  This is the same rule as the workflows validator's ``risky-params`` (a risky
   action takes no parameter from a prompt step's free text), applied to every action because
   everything an actor receives here came from a reader of untrusted content.
3. **Actions pass the allowlist.**  :func:`act` refuses an action the handoff does not declare,
   and sends every declared one through :func:`homelabnext.broker.decide`, so the broker
   manifest's grants, tiers and bound approvals still apply (default deny).

:func:`declaration_problems` checks a handoff offline: schema; the reader cannot act and the
actor does not read untrusted content (G-03); the output schema is a closed object; every
reference names a constrained field; every action is in the broker manifest and granted to the
actor at its tier.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .digest import digest_of
from .errors import AgentError
from .readers import is_reader, profile_problems
from .report import validate_report
from .schemas import schema_errors

OUTPUT_REF = "$output."
_TIER_RANK = {"read": 0, "write": 1, "execute": 2, "privileged": 3}
_SEAL = object()  # only accept() can build an Accepted
# formats the stock jsonschema FormatChecker always checks, with no optional package, and that
# admit no free text ("email" only checks for an "@"; "hostname" needs an optional package)
CHECKED_FORMATS = frozenset({"date", "ipv4", "ipv6", "uuid"})
# match-anything pieces: an unescaped "." (an even run of backslashes before it), a negated
# class, or a negated shorthand
_OPEN = re.compile(r"(?<!\\)(?:\\\\)*(?:\.|\[\^|\\[SWD])")


class HandoffError(AgentError):
    """The handoff declaration is malformed or unsafe."""


class HandoffRefused(AgentError):
    """The actor refused the reader's output or an action (``problems`` says why)."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("handoff refused: " + "; ".join(self.problems))


# ---------------------------------------------------------------- free text vs constrained
def _top_level_alternation(pattern: str) -> bool:
    depth, i, in_class = 0, 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            return True
        i += 1
    return False


def is_closed_pattern(pattern: str) -> bool:
    """A pattern that cannot match free text: anchored at both ends with no top-level ``|``
    (``^a$|.*`` is unanchored), and no ``.``, negated class or ``\\S``/``\\W``/``\\D``."""
    return (
        pattern.startswith("^")
        and pattern.endswith("$")
        and not pattern.endswith("\\$")
        and not _top_level_alternation(pattern)
        and not _OPEN.search(pattern)
    )


def is_constrained(schema: Any) -> bool:
    """True when every value ``schema`` admits is constrained enough to be an action parameter.

    Unknown or unsupported keywords (``$ref``, ``anyOf``, a missing ``type``) count as free text:
    what cannot be shown to be constrained is not.
    """
    if not isinstance(schema, Mapping):
        return False
    if "enum" in schema or "const" in schema:
        return True
    kind = schema.get("type")
    if kind in ("integer", "number", "boolean"):
        return True
    if kind == "string":
        if schema.get("format") in CHECKED_FORMATS:
            return True
        pattern = schema.get("pattern")
        return isinstance(pattern, str) and is_closed_pattern(pattern)
    if kind == "array":
        return is_constrained(schema.get("items"))
    if kind == "object":
        props = schema.get("properties")
        return (
            schema.get("additionalProperties") is False
            and isinstance(props, Mapping)
            and all(is_constrained(p) for p in props.values())
        )
    return False


def _subschema(schema: Any, path: list[str]) -> Any:
    """The schema of ``path`` inside an object schema (None if the path does not exist)."""
    for part in path:
        if not isinstance(schema, Mapping):
            return None
        if schema.get("type") == "array" and part.isdigit():
            schema = schema.get("items")
        else:
            props = schema.get("properties")
            schema = props.get(part) if isinstance(props, Mapping) else None
    return schema


def _is_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("$") and not value.startswith("$$")


def _refs(value: Any) -> list[str]:
    if _is_ref(value):
        return [value]
    if isinstance(value, Mapping):
        return [r for v in value.values() for r in _refs(v)]
    if isinstance(value, list):
        return [r for v in value for r in _refs(v)]
    return []


def _path(ref: str) -> list[str] | None:
    if not ref.startswith(OUTPUT_REF) or len(ref) == len(OUTPUT_REF):
        return None
    return ref[len(OUTPUT_REF) :].split(".")


# ---------------------------------------------------------------- the declaration
@dataclass(frozen=True)
class Handoff:
    """A validated handoff declaration (build it with :meth:`from_mapping`)."""

    id: str
    reader: str
    actor: str
    output_schema: Mapping[str, Any]
    actions: tuple[Mapping[str, Any], ...]
    digest: str

    @classmethod
    def from_mapping(cls, doc: Mapping[str, Any]) -> Handoff:
        errs = schema_errors("agent", "handoff", doc)
        if errs:
            raise HandoffError("handoff is not a valid agent/handoff document: " + "; ".join(errs))
        problems = _shape_problems(doc)
        if problems:
            raise HandoffError("; ".join(problems))
        doc = copy.deepcopy(dict(doc))
        return cls(
            id=doc["handoff"],
            reader=doc["reader"],
            actor=doc["actor"],
            output_schema=doc["output_schema"],
            actions=tuple(doc["actions"]),
            digest=digest_of(doc),
        )

    def action(self, name: str) -> Mapping[str, Any] | None:
        return next((a for a in self.actions if a["action"] == name), None)


def _shape_problems(doc: Mapping[str, Any]) -> list[str]:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError

    out: list[str] = []
    schema = doc["output_schema"]
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        out.append(f"output_schema is not a valid JSON Schema: {exc.message}")
        return out
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        out.append(
            "output_schema must be a closed object (type: object, additionalProperties: false)"
        )
    if doc["reader"] == doc["actor"]:
        out.append("reader and actor are the same profile; a handoff joins two")
    seen: set[str] = set()
    for act in doc["actions"]:
        name = act["action"]
        if name in seen:
            out.append(f"action {name!r} is declared twice")
        seen.add(name)
        for ref in _refs(act["params"]):
            path = _path(ref)
            if path is None:
                out.append(
                    f"{name}: {ref!r} is not an $output.<path> reference; an action parameter "
                    "comes from the validated output or is a literal (summary, unknowns and "
                    "cites are free text)"
                )
                continue
            sub = _subschema(schema, path)
            if sub is None:
                out.append(f"{name}: {ref!r} names no field of output_schema")
            elif not is_constrained(sub):
                out.append(
                    f"{name}: {ref!r} is a free-text field; constrain it (enum, a checked "
                    "format, a closed pattern) or do not pass it to an action"
                )
    return out


def declaration_problems(
    doc: Mapping[str, Any],
    *,
    reader_profile: Mapping[str, Any],
    actor_profile: Mapping[str, Any],
    broker_manifest: Mapping[str, Any],
) -> list[str]:
    """Every problem with a handoff declaration against the profiles and broker it joins."""
    try:
        handoff = Handoff.from_mapping(doc)
    except HandoffError as exc:
        return [str(exc)]
    out: list[str] = []
    if reader_profile.get("id") != handoff.reader:
        out.append(f"reader profile is {reader_profile.get('id')!r}, not {handoff.reader!r}")
    if actor_profile.get("id") != handoff.actor:
        out.append(f"actor profile is {actor_profile.get('id')!r}, not {handoff.actor!r}")
    out += profile_problems(reader_profile)  # a reader cannot act (G-03)
    if is_reader(actor_profile):
        out.append(
            f"actor {handoff.actor} reads untrusted content (reads_untrusted is not false); "
            "an actor receives only the reader's validated output"
        )
    for act in handoff.actions:
        out += _grant_problems(broker_manifest, handoff.actor, act["action"])
    return out


def _grant_problems(manifest: Mapping[str, Any], actor: str, action: str) -> list[str]:
    entry = next((a for a in manifest.get("actions", []) if a["action"] == action), None)
    if entry is None:
        return [f"{action}: not in broker manifest {manifest.get('manifest_id')!r}"]
    grant = next(
        (g for g in manifest.get("grants", []) if g["profile"] == actor and action in g["actions"]),
        None,
    )
    if grant is None:
        return [f"{action}: {actor} holds no broker grant for it"]
    if _TIER_RANK[entry["tier"]] > _TIER_RANK[grant["max_tier"]]:
        return [f"{action}: tier {entry['tier']} is above {actor}'s max_tier {grant['max_tier']}"]
    return []


# ---------------------------------------------------------------- accept, then act
@dataclass(frozen=True)
class Accepted:
    """A reader's output the actor has accepted.  Only :func:`accept` builds one."""

    handoff: Handoff
    output: Mapping[str, Any]
    report_digest: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise HandoffRefused(["an Accepted output is only built by accept()"])


def accept(
    handoff: Handoff,
    message: Any,
    *,
    pack: Mapping[str, Any],
    pack_hash: str,
    manifest: Mapping[str, Any] | None = None,
) -> Accepted:
    """The reader's ``report_result`` as an :class:`Accepted`, or :class:`HandoffRefused`."""
    if isinstance(message, (str, bytes, bytearray)):
        raise HandoffRefused(
            ["raw text is not a report: the actor accepts only a structured report_result"]
        )
    if not isinstance(message, Mapping):
        raise HandoffRefused([f"expected a report_result object, got {type(message).__name__}"])
    problems = validate_report(message, pack, pack_hash, manifest)
    if problems:
        raise HandoffRefused([f"report: {p}" for p in problems])
    if message["profile"] != handoff.reader:
        problems.append(f"report is from {message['profile']}, not the reader {handoff.reader}")
    if message["status"] == "deferred":
        problems.append("report is deferred: there is nothing to act on")
    if "output" not in message:
        problems.append("report carries no structured output")
    else:
        problems += _output_problems(handoff.output_schema, message["output"])
        if not problems:
            problems += _control_chars(handoff, message["output"])
    if problems:
        raise HandoffRefused(problems)
    return Accepted(handoff, copy.deepcopy(message["output"]), digest_of(message), _SEAL)


def _output_problems(schema: Mapping[str, Any], output: Any) -> list[str]:
    from jsonschema import Draft202012Validator, FormatChecker

    v = Draft202012Validator(schema, format_checker=FormatChecker())
    return [
        f"output/{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}"
        for e in sorted(v.iter_errors(output), key=lambda e: list(map(str, e.absolute_path)))
    ]


def _control_chars(handoff: Handoff, output: Mapping[str, Any]) -> list[str]:
    """A ``$`` anchor also matches before a final newline, so a bound string is re-checked."""
    out = []
    for act in handoff.actions:
        for ref in _refs(act["params"]):
            for text in _strings(_resolve(ref, output)):
                if any(ord(c) < 32 or ord(c) == 127 for c in text):
                    out.append(f"output field {ref[1:]} holds a control character")
    return sorted(set(out))


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _resolve(value: Any, output: Mapping[str, Any]) -> Any:
    if _is_ref(value):
        cur: Any = output
        for part in _path(value) or []:
            if isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
                cur = cur[int(part)]
            elif isinstance(cur, Mapping):
                cur = cur.get(part)
            else:
                cur = None
        return copy.deepcopy(cur)
    if isinstance(value, str) and value.startswith("$$"):
        return value[1:]
    if isinstance(value, Mapping):
        return {k: _resolve(v, output) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, output) for v in value]
    return value


def build_request(accepted: Accepted, action: str, *, request_id: str) -> dict[str, Any]:
    """The broker request for one declared ``action``; its params come only from the output."""
    if not isinstance(accepted, Accepted):
        raise HandoffRefused(["the actor acts only on an Accepted output"])
    decl = accepted.handoff.action(action)
    if decl is None:
        raise HandoffRefused(
            [f"action {action!r} is not declared by handoff {accepted.handoff.id!r}"]
        )
    request: dict[str, Any] = {
        "request_id": request_id,
        "action": action,
        "actor": accepted.handoff.actor,
        "params": _resolve(decl["params"], accepted.output),
    }
    if "target" in decl:
        request["target"] = decl["target"]
    return request


def act(
    accepted: Accepted,
    action: str,
    broker_manifest: Mapping[str, Any],
    *,
    request_id: str,
    approval: Mapping[str, Any] | None = None,
    now: str,
    store: Any = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """``(request, decision)``: build the declared request and let the broker decide it.

    The caller runs the handler only for an enforced ``allow``; everything else is the broker's
    deny or hold, exactly as for any other request.
    """
    from homelabnext import broker  # broker imports agent.digest: import it late

    request = build_request(accepted, action, request_id=request_id)
    return request, broker.decide(broker_manifest, request, approval, now=now, store=store)
