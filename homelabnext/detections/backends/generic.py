# SPDX-License-Identifier: Apache-2.0
"""Generic backend: a deterministic, engine-neutral boolean query text."""

from __future__ import annotations

import json

from ..adapters import Artifact, Target, register
from ..sigma import Matcher, Rule

_OP = {
    "equals": "=",
    "contains": "~contains",
    "startswith": "~startswith",
    "endswith": "~endswith",
    "re": "~re",
}


def _q(v) -> str:
    return json.dumps(v) if not isinstance(v, str) else json.dumps(v, ensure_ascii=False)


def _matcher(m: Matcher, tgt: Target) -> str:
    if m.field is None:
        return "ANY(" + " OR ".join(f"{_OP[m.op]} {_q(v)}" for v in m.values) + ")"
    f = tgt.field_mapping.get(m.field, m.field)
    if m.op == "null":
        return f"{f} IS NULL"
    joiner = " AND " if m.match_all else " OR "
    parts = [f"{f} {_OP[m.op]} {_q(v)}" for v in m.values]
    return parts[0] if len(parts) == 1 else "(" + joiner.join(parts) + ")"


def _sel(rule: Rule, name: str, tgt: Target) -> str:
    alts = [
        "(" + " AND ".join(_matcher(m, tgt) for m in alt) + ")" for alt in rule.selections[name]
    ]
    return alts[0] if len(alts) == 1 else "(" + " OR ".join(alts) + ")"


def _ast(rule: Rule, ast: tuple, tgt: Target) -> str:
    k = ast[0]
    if k == "sel":
        return _sel(rule, ast[1], tgt)
    if k == "not":
        return "NOT " + _ast(rule, ast[1], tgt)
    j = " AND " if k == "and" else " OR "
    return "(" + j.join(_ast(rule, a, tgt) for a in ast[1]) + ")"


class GenericBackend:
    name = "generic"

    def compile(self, rule: Rule, target: Target) -> Artifact:
        body = _ast(rule, rule.condition, target)
        head = [
            f"-- {rule.det_id}",
            f"-- title: {rule.title}",
            f"-- level: {rule.level}",
            f"-- tags: {', '.join(sorted(rule.tags))}",
        ]
        return Artifact(rule.det_id, self.name, "text/plain", "\n".join(head) + f"\nWHERE {body}\n")


register(GenericBackend())
