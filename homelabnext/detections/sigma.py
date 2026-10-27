# SPDX-License-Identifier: Apache-2.0
"""A small, dependency-light Sigma-subset: loader, condition parser, evaluator.

Supported
  * detection: named selections (map, list of maps = OR, list of keywords)
  * field modifiers: contains, startswith, endswith, re, all  (default: equals,
    case-insensitive, with * and ? wildcards); ``field: null`` matches absence
  * condition: and / or / not / parentheses, ``1 of sel*``, ``all of sel*``,
    ``any of them``, ``all of them``
Not supported (rejected loudly, never silently ignored): aggregations
(count/near/timeframe), base64/windash/cidr modifiers, correlation rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
ATTACK_TECH_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
LEVELS = ("informational", "low", "medium", "high", "critical")
#: Sigma's rule statuses; ``unsupported`` is a rule that cannot work as shipped (here: a field no
#: shipped enrichment sets), so it is tested but neither counted as coverage nor deployed
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
OPS = {"contains", "startswith", "endswith", "re"}


class RuleError(ValueError):
    """A rule file is malformed or uses an unsupported construct."""


@dataclass(frozen=True)
class Matcher:
    field: str | None  # None = keyword search over every string value
    op: str  # equals | contains | startswith | endswith | re | null
    values: tuple[Any, ...]
    match_all: bool = False


# A selection is a list of alternatives (OR); an alternative is a list of Matchers (AND).
Selection = list[list[Matcher]]


@dataclass
class Rule:
    path: Path
    slug: str
    title: str
    level: str
    tags: list[str]
    logsource: dict[str, Any]
    selections: dict[str, Selection]
    condition: tuple  # AST
    raw: dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def det_id(self) -> str:
        return f"det:{self.slug}"

    @property
    def status(self) -> str:
        return str(self.raw.get("status", "experimental"))

    @property
    def deployable(self) -> bool:
        """Compiled into an engine bundle and counted as coverage: not ``unsupported`` (inert)
        and not ``deprecated``."""
        return self.status not in ("unsupported", "deprecated")

    @property
    def attack_techniques(self) -> list[str]:
        return sorted(t.split(".", 1)[1].upper() for t in self.tags if ATTACK_TECH_RE.match(t))

    @property
    def attack_tactics(self) -> list[str]:
        return sorted(
            t.split(".", 1)[1].replace("_", "-")
            for t in self.tags
            if t.startswith("attack.") and not ATTACK_TECH_RE.match(t)
        )


# ---------------------------------------------------------------- loading
def _parse_selection(name: str, body: Any) -> Selection:
    if isinstance(body, dict):
        return [_parse_map(name, body)]
    if isinstance(body, list):
        if body and all(isinstance(x, dict) for x in body):
            return [_parse_map(name, x) for x in body]
        if body and all(isinstance(x, (str, int)) for x in body):
            return [[Matcher(None, "contains", tuple(str(x) for x in body))]]
    raise RuleError(f"selection {name!r}: unsupported shape {type(body).__name__}")


def _parse_map(name: str, body: dict) -> list[Matcher]:
    out = []
    for key, val in body.items():
        parts = str(key).split("|")
        fld, mods = parts[0], parts[1:]
        match_all = False
        op = "equals"
        for m in mods:
            if m == "all":
                match_all = True
            elif m in OPS:
                op = m
            else:
                raise RuleError(f"selection {name!r}: unsupported modifier {m!r} on {fld!r}")
        if val is None:
            out.append(Matcher(fld, "null", ()))
            continue
        vals = tuple(val) if isinstance(val, list) else (val,)
        if not vals:
            raise RuleError(f"selection {name!r}: empty value list for {fld!r}")
        if op == "re":
            for v in vals:
                re.compile(str(v))
        out.append(Matcher(fld, op, vals, match_all))
    if not out:
        raise RuleError(f"selection {name!r}: empty")
    return out


_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


def parse_condition(text: str, names: list[str]) -> tuple:
    if re.search(r"\||\bnear\b|\bcount\b", text):
        raise RuleError(f"aggregation conditions are not supported: {text!r}")
    toks = _TOKEN_RE.findall(text)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        t = toks[pos]
        pos += 1
        return t

    def expand(pattern: str) -> list[str]:
        if pattern == "them":
            hit = list(names)
        else:
            rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            hit = [n for n in names if rx.match(n)]
        if not hit:
            raise RuleError(f"condition pattern {pattern!r} matches no selection")
        return hit

    def or_expr():
        items = [and_expr()]
        while peek() == "or":
            take()
            items.append(and_expr())
        return items[0] if len(items) == 1 else ("or", items)

    def and_expr():
        items = [not_expr()]
        while peek() == "and":
            take()
            items.append(not_expr())
        return items[0] if len(items) == 1 else ("and", items)

    def not_expr():
        if peek() == "not":
            take()
            return ("not", not_expr())
        return atom()

    def atom():
        t = peek()
        if t is None:
            raise RuleError(f"unexpected end of condition: {text!r}")
        if t == "(":
            take()
            e = or_expr()
            if peek() != ")":
                raise RuleError(f"missing ')' in condition: {text!r}")
            take()
            return e
        if t in ("1", "all", "any") and pos + 1 < len(toks) and toks[pos + 1] == "of":
            q = take()
            take()
            if peek() is None:
                raise RuleError(f"quantifier without target: {text!r}")
            members = [("sel", n) for n in expand(take())]
            join = "and" if q == "all" else "or"
            return members[0] if len(members) == 1 else (join, members)
        take()
        if t not in names:
            raise RuleError(f"condition references unknown selection {t!r}")
        return ("sel", t)

    ast = or_expr()
    if pos != len(toks):
        raise RuleError(f"trailing tokens in condition {text!r}: {toks[pos:]}")
    return ast


def load_rule(path: Path, text: str | None = None) -> Rule:
    """The rule at ``path``; with ``text``, that text stands for the file's (a caller that has
    already read it safely, such as the module loader, passes it so the file is read once)."""
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8") if text is None else text)
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuleError(f"{path}: top level must be a mapping")
    slug = Path(path).stem
    if not SLUG_RE.match(slug):
        raise RuleError(f"{path}: file stem {slug!r} is not a valid det slug")
    if "det" in raw and raw["det"] != f"det:{slug}":
        raise RuleError(f"{path}: 'det' field {raw['det']!r} != det:{slug}")
    for req in ("title", "logsource", "detection", "level", "tags"):
        if req not in raw:
            raise RuleError(f"{path}: missing required key {req!r}")
    if raw["level"] not in LEVELS:
        raise RuleError(f"{path}: level {raw['level']!r} not in {LEVELS}")
    det = dict(raw["detection"])
    cond = det.pop("condition", None)
    if not isinstance(cond, str):
        raise RuleError(f"{path}: detection.condition must be a single string")
    if "timeframe" in det:
        raise RuleError(f"{path}: timeframe/aggregation is not supported")
    sels = {n: _parse_selection(n, b) for n, b in det.items()}
    if not sels:
        raise RuleError(f"{path}: no selections")
    try:
        ast = parse_condition(cond, list(sels))
    except RuleError as exc:
        raise RuleError(f"{path}: {exc}") from exc
    return Rule(
        Path(path),
        slug,
        str(raw["title"]),
        raw["level"],
        list(raw["tags"]),
        dict(raw["logsource"]),
        sels,
        ast,
        raw,
    )


def load_rules(root: Path) -> list[Rule]:
    """Load ``<root>/sigma/<tactic>/<slug>.yml`` sorted by slug."""
    rules = sorted(
        (load_rule(p) for p in Path(root, "sigma").glob("*/*.yml")), key=lambda r: r.slug
    )
    seen: dict[str, Path] = {}
    for r in rules:
        if r.slug in seen:
            raise RuleError(f"duplicate det slug {r.slug!r}: {seen[r.slug]} and {r.path}")
        seen[r.slug] = r.path
    return rules


# ------------------------------------------------------------- evaluation
def load_mapping(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return dict(data.get("fields", {}))


def _lookup(event: dict, dotted: str) -> list[Any]:
    """Return the values at a dotted path (flat dotted keys also honoured)."""
    if dotted in event:
        cur: Any = event[dotted]
    else:
        cur = event
        for part in dotted.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return []
    return list(cur) if isinstance(cur, list) else [cur]


def _wild(pattern: str) -> re.Pattern:
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(rx + r"\Z", re.IGNORECASE | re.DOTALL)


def _one(op: str, actual: Any, expected: Any) -> bool:
    if op == "equals" and isinstance(expected, (int, float)) and not isinstance(expected, bool):
        return str(actual) == str(expected)
    if op == "equals" and isinstance(expected, bool):
        return str(actual).lower() == str(expected).lower()
    a, e = str(actual), str(expected)
    if op == "equals":
        return bool(_wild(e).match(a))
    if op == "contains":
        return e.casefold() in a.casefold()
    if op == "startswith":
        return a.casefold().startswith(e.casefold())
    if op == "endswith":
        return a.casefold().endswith(e.casefold())
    if op == "re":
        return re.search(e, a) is not None
    raise RuleError(f"unknown op {op}")


def _strings(event: Any) -> list[str]:
    if isinstance(event, dict):
        return [s for v in event.values() for s in _strings(v)]
    if isinstance(event, list):
        return [s for v in event for s in _strings(v)]
    return [str(event)]


def match_matcher(m: Matcher, event: dict, mapping: dict[str, str]) -> bool:
    if m.field is None:
        hay = _strings(event)
        return any(_one(m.op, h, v) for v in m.values for h in hay)
    actual = _lookup(event, mapping.get(m.field, m.field))
    if m.op == "null":
        return not actual or all(a is None for a in actual)
    if not actual:
        return False
    hit = lambda v: any(a is not None and _one(m.op, a, v) for a in actual)  # noqa: E731
    return all(hit(v) for v in m.values) if m.match_all else any(hit(v) for v in m.values)


def eval_selection(sel: Selection, event: dict, mapping: dict[str, str]) -> bool:
    return any(all(match_matcher(m, event, mapping) for m in alt) for alt in sel)


def eval_ast(ast: tuple, results: dict[str, bool]) -> bool:
    kind = ast[0]
    if kind == "sel":
        return results[ast[1]]
    if kind == "not":
        return not eval_ast(ast[1], results)
    if kind == "and":
        return all(eval_ast(a, results) for a in ast[1])
    if kind == "or":
        return any(eval_ast(a, results) for a in ast[1])
    raise RuleError(f"bad AST node {kind}")


def rule_matches(rule: Rule, event: dict, mapping: dict[str, str] | None = None) -> bool:
    mapping = mapping or {}
    results = {n: eval_selection(s, event, mapping) for n, s in rule.selections.items()}
    return eval_ast(rule.condition, results)
