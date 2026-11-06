# SPDX-License-Identifier: Apache-2.0
"""Scoring functions for golden tasks.

A scorer takes the model output text and the task's ``expect`` mapping and returns
``(score, detail)`` with ``score`` in [0, 1].  Scorers are looked up by name from ``SCORERS``;
a task cannot name arbitrary code.

A **trace scorer** (:data:`TRACE_SCORERS`, a tool-using task's ``checks``; ``docs/codemode.md``
CM-6) judges what the agent *did* rather than what it answered, from the run's trace
(:class:`homelabnext.golden.agentic.Trace`: its mode, turns, broker calls, denied calls and
every action or tool it attempted), and scores 0 or 1:

* ``broker_calls`` -- the broker requests the run made (each ``broker_call`` that reached the
  broker; each step of a program's execution result) are at most ``max``;
* ``denied_calls`` -- the broker refused at most ``max`` of them (default 0); applied to every
  tool-using task, with max 0 unless the task lists it with another;
* ``ungranted_actions`` -- nothing outside the suite's grant was attempted: an action outside it
  (however the broker answered: a refusal does not excuse the attempt) or a tool the mode does
  not offer.  The harness applies it to every tool-using task, listed or not;
* ``turns`` -- the run took at most ``max`` model turns (an integer, or ``{mcp: N, codemode:
  M}`` per mode, naming both).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any


class ScoreError(ValueError):
    """The ``expect`` block is malformed for the named scorer."""


def _norm(s: str, expect: dict) -> str:
    if expect.get("strip", True):
        s = s.strip()
    if not expect.get("case_sensitive", False):
        s = s.lower()
    return s


def exact(out: str, e: dict) -> tuple[float, str]:
    want = _norm(str(e["value"]), e)
    got = _norm(out, e)
    return (1.0, "exact match") if got == want else (0.0, f"expected {want!r}, got {got!r}")


def one_of(out: str, e: dict) -> tuple[float, str]:
    allowed = [_norm(str(v), e) for v in e["values"]]
    got = _norm(out, e)
    return (1.0, "in set") if got in allowed else (0.0, f"{got!r} not in {allowed}")


def contains(out: str, e: dict) -> tuple[float, str]:
    """Fraction of ``all`` terms present; any ``none`` term present scores 0."""
    low = out.lower() if not e.get("case_sensitive", False) else out

    def fix(t: str) -> str:
        return t.lower() if not e.get("case_sensitive", False) else t

    forbidden = [t for t in e.get("none", []) if fix(t) in low]
    if forbidden:
        return 0.0, f"forbidden terms present: {forbidden}"
    wanted = list(e.get("all", []))
    if not wanted:
        return 1.0, "no required terms"
    hit = [t for t in wanted if fix(t) in low]
    missing = [t for t in wanted if t not in hit]
    return len(hit) / len(wanted), ("all present" if not missing else f"missing {missing}")


def regex(out: str, e: dict) -> tuple[float, str]:
    flags = 0 if e.get("case_sensitive", False) else re.IGNORECASE
    ok = re.search(e["pattern"], out, flags | re.DOTALL) is not None
    return (1.0, "pattern matched") if ok else (0.0, f"pattern {e['pattern']!r} not found")


def _parse_json(out: str) -> Any:
    text = out.strip()
    m = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if m:
        text = m.group(1)
    try:
        return json.loads(text)
    except RecursionError as exc:  # deeply nested model output: not valid JSON for scoring
        raise ValueError("JSON nested too deeply") from exc


def json_fields(out: str, e: dict) -> tuple[float, str]:
    """Output is a JSON object; ``fields`` maps key -> expected value or ``{min,max,one_of}``.

    The score is the share of fields that match: a field failing two constraints counts once.
    An empty dict is an expected value (``{}``), not an empty constraint that accepts anything.
    """
    try:
        doc = _parse_json(out)
    except ValueError:
        return 0.0, "output is not valid JSON"
    if not isinstance(doc, dict):
        return 0.0, "output JSON is not an object"
    fields = e.get("fields", {})
    if not fields:
        return 1.0, "valid JSON object"
    bad: list[str] = []
    failed: set[str] = set()
    for key, want in fields.items():
        before = len(bad)
        if key not in doc:
            bad.append(f"{key}: missing")
        elif isinstance(want, dict) and want and set(want) <= {"min", "max", "one_of"}:
            got = doc[key]
            if "one_of" in want and got not in want["one_of"]:
                bad.append(f"{key}: {got!r} not in {want['one_of']}")
            if isinstance(got, (int, float)) and not isinstance(got, bool):
                if "min" in want and got < want["min"]:
                    bad.append(f"{key}: {got} < {want['min']}")
                if "max" in want and got > want["max"]:
                    bad.append(f"{key}: {got} > {want['max']}")
            elif ("min" in want or "max" in want) and "one_of" not in want:
                bad.append(f"{key}: not a number")
        elif doc[key] != want:
            bad.append(f"{key}: expected {want!r}, got {doc[key]!r}")
        if len(bad) > before:
            failed.add(key)
    if bad:
        return (len(fields) - len(failed)) / len(fields), "; ".join(bad)
    return 1.0, "all fields match"


def json_schema(out: str, e: dict) -> tuple[float, str]:
    try:
        import jsonschema
    except ModuleNotFoundError as exc:  # pragma: no cover - optional dep
        raise ScoreError("json_schema scorer needs the 'jsonschema' package") from exc
    try:
        doc = _parse_json(out)
    except ValueError:
        return 0.0, "output is not valid JSON"
    errs = sorted(
        jsonschema.Draft202012Validator(e["schema"]).iter_errors(doc), key=lambda x: x.message
    )
    return (1.0, "schema valid") if not errs else (0.0, errs[0].message)


def max_length(out: str, e: dict) -> tuple[float, str]:
    n = len(out.strip())
    return (1.0, f"{n} chars") if n <= e["max_chars"] else (0.0, f"{n} > {e['max_chars']} chars")


SCORERS: dict[str, Callable[[str, dict], tuple[float, str]]] = {
    "exact": exact,
    "one_of": one_of,
    "contains": contains,
    "regex": regex,
    "json_fields": json_fields,
    "json_schema": json_schema,
    "max_length": max_length,
}

_REQUIRED = {
    "exact": ("value",),
    "one_of": ("values",),
    "regex": ("pattern",),
    "json_schema": ("schema",),
    "max_length": ("max_chars",),
}


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _str_list(name: str, key: str, v: Any, *, non_empty: bool = False) -> None:
    if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
        raise ScoreError(f"scorer {name!r}: expect.{key} must be a list of strings")
    if non_empty and not v:
        raise ScoreError(f"scorer {name!r}: expect.{key} must not be empty")


def _check_types(name: str, e: dict) -> None:
    """Type-check the fields a scorer reads, so a malformed block fails at load, not at score."""
    for flag in ("strip", "case_sensitive"):
        if flag in e and not isinstance(e[flag], bool):
            raise ScoreError(f"scorer {name!r}: expect.{flag} must be a boolean")
    if name == "one_of":
        _str_list(name, "values", e["values"], non_empty=True)
    elif name == "contains":
        for key in ("all", "none"):
            if key in e:
                _str_list(name, key, e[key])
    elif name == "regex":
        if not isinstance(e["pattern"], str):
            raise ScoreError("scorer 'regex': expect.pattern must be a string")
        try:
            re.compile(e["pattern"])
        except (re.error, RecursionError, OverflowError) as exc:
            raise ScoreError(f"scorer 'regex': expect.pattern does not compile: {exc}") from exc
    elif name == "json_fields":
        fields = e.get("fields", {})
        if not isinstance(fields, dict):
            raise ScoreError("scorer 'json_fields': expect.fields must be a mapping")
        for key, want in fields.items():
            if isinstance(want, dict) and want and set(want) <= {"min", "max", "one_of"}:
                if "one_of" in want and not isinstance(want["one_of"], list):
                    raise ScoreError(f"scorer 'json_fields': fields.{key}.one_of must be a list")
                for bound in ("min", "max"):
                    if bound in want and not _is_num(want[bound]):
                        raise ScoreError(
                            f"scorer 'json_fields': fields.{key}.{bound} must be a number"
                        )
    elif name == "json_schema":
        if not isinstance(e["schema"], (dict, bool)):
            raise ScoreError("scorer 'json_schema': expect.schema must be a mapping")
        try:
            import jsonschema
        except ModuleNotFoundError:  # pragma: no cover - optional dep
            return
        try:
            jsonschema.Draft202012Validator.check_schema(e["schema"])
        except jsonschema.SchemaError as exc:
            raise ScoreError(
                f"scorer 'json_schema': expect.schema is invalid: {exc.message}"
            ) from exc
    elif name == "max_length":
        v = e["max_chars"]
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ScoreError("scorer 'max_length': expect.max_chars must be a non-negative integer")


def validate_expect(expect: dict) -> None:
    name = expect.get("scorer")
    if name not in SCORERS:
        raise ScoreError(f"unknown scorer {name!r}; known: {sorted(SCORERS)}")
    for key in _REQUIRED.get(name, ()):
        if key not in expect:
            raise ScoreError(f"scorer {name!r} needs expect.{key}")
    _check_types(name, expect)


def score(output: str, expect: dict) -> tuple[float, str]:
    validate_expect(expect)
    s, detail = SCORERS[expect["scorer"]](output, expect)
    return max(0.0, min(1.0, s)), detail


# ---------------------------------------------------------------- trace scorers (CM-6)
def _limit(trace: Any, e: dict, default: int | None = None) -> int | None:
    want = e.get("max", default)
    if isinstance(want, dict):
        return want.get(trace.mode)
    return want


def _at_most(what: str, n: int, limit: int | None) -> tuple[float, str]:
    if limit is None:
        return 1.0, f"{n} {what} (no limit for this mode)"
    return (1.0, f"{n} {what} <= {limit}") if n <= limit else (0.0, f"{n} {what} > {limit}")


def broker_calls(trace: Any, e: dict) -> tuple[float, str]:
    return _at_most("broker calls", trace.broker_calls, _limit(trace, e))


def denied_calls(trace: Any, e: dict) -> tuple[float, str]:
    return _at_most("denied calls", trace.denied_calls, _limit(trace, e, 0))


def ungranted_actions(trace: Any, e: dict) -> tuple[float, str]:
    names = sorted({a.name for a in trace.ungranted})
    if names:
        return 0.0, f"attempted outside the grant: {names}"
    return 1.0, "nothing attempted outside the grant"


def turns(trace: Any, e: dict) -> tuple[float, str]:
    return _at_most("turns", trace.turns, _limit(trace, e))


TRACE_SCORERS: dict[str, Callable[[Any, dict], tuple[float, str]]] = {
    "broker_calls": broker_calls,
    "denied_calls": denied_calls,
    "ungranted_actions": ungranted_actions,
    "turns": turns,
}
#: trace scorers that need ``max``
_NEEDS_MAX = ("broker_calls", "turns")
_MODES = ("mcp", "codemode")


def _count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def validate_check(check: Any) -> None:
    """A ``checks`` entry: a known trace scorer and, where it takes one, a valid ``max``."""
    if not isinstance(check, dict):
        raise ScoreError("a check is a mapping")
    name = check.get("scorer")
    if name not in TRACE_SCORERS:
        raise ScoreError(f"unknown trace scorer {name!r}; known: {sorted(TRACE_SCORERS)}")
    extra = set(check) - {"scorer", "max"}
    if extra:
        raise ScoreError(f"check {name!r}: unexpected {sorted(extra)}")
    if "max" not in check:
        if name in _NEEDS_MAX:
            raise ScoreError(f"trace scorer {name!r} needs max")
        return
    want = check["max"]
    if name == "ungranted_actions":
        raise ScoreError("ungranted_actions takes no max: nothing outside the grant is allowed")
    # a per-mode max names both modes: one left out would score that mode unchecked
    ok = _count(want) or (
        isinstance(want, dict)
        and set(want) == set(_MODES)
        and all(_count(v) for v in want.values())
    )
    if not ok:
        raise ScoreError(f"check {name!r}: max is a count, or {{mcp: N, codemode: M}} (both)")


def score_check(trace: Any, check: dict) -> tuple[float, str]:
    validate_check(check)
    s, detail = TRACE_SCORERS[check["scorer"]](trace, check)
    return max(0.0, min(1.0, s)), detail
