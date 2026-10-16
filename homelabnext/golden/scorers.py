# SPDX-License-Identifier: Apache-2.0
"""Scoring functions for golden tasks.

A scorer takes the model output text and the task's ``expect`` mapping and returns
``(score, detail)`` with ``score`` in [0, 1].  Scorers are looked up by name from ``SCORERS``;
a task cannot name arbitrary code.
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
    return json.loads(text)


def json_fields(out: str, e: dict) -> tuple[float, str]:
    """Output is a JSON object; ``fields`` maps key -> expected value or ``{min,max,one_of}``."""
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
    for key, want in fields.items():
        if key not in doc:
            bad.append(f"{key}: missing")
            continue
        got = doc[key]
        if isinstance(want, dict) and set(want) <= {"min", "max", "one_of"}:
            if "one_of" in want and got not in want["one_of"]:
                bad.append(f"{key}: {got!r} not in {want['one_of']}")
            if isinstance(got, (int, float)) and not isinstance(got, bool):
                if "min" in want and got < want["min"]:
                    bad.append(f"{key}: {got} < {want['min']}")
                if "max" in want and got > want["max"]:
                    bad.append(f"{key}: {got} > {want['max']}")
            elif ("min" in want or "max" in want) and "one_of" not in want:
                bad.append(f"{key}: not a number")
        elif got != want:
            bad.append(f"{key}: expected {want!r}, got {got!r}")
    if bad:
        return (len(fields) - len(bad)) / len(fields) if len(bad) < len(fields) else 0.0, "; ".join(
            bad
        )
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


def validate_expect(expect: dict) -> None:
    name = expect.get("scorer")
    if name not in SCORERS:
        raise ScoreError(f"unknown scorer {name!r}; known: {sorted(SCORERS)}")
    for key in _REQUIRED.get(name, ()):
        if key not in expect:
            raise ScoreError(f"scorer {name!r} needs expect.{key}")


def score(output: str, expect: dict) -> tuple[float, str]:
    validate_expect(expect)
    s, detail = SCORERS[expect["scorer"]](output, expect)
    return max(0.0, min(1.0, s)), detail
