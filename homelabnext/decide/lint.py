# SPDX-License-Identifier: Apache-2.0
"""``hnx decide lint``: every decision spec in the repository is complete and well-formed.

A *decision spec* is any YAML or JSON file whose top level has both ``question_set`` and
``decision_table``.  Without paths the lint finds them itself: every such file git tracks, plus
any that sit untracked in the work tree (those fail ``in-git``).  Files under a ``negative/`` or
``_frozen/`` directory are deliberate counter-examples or frozen baselines and are skipped.

Rules (each problem is reported as ``<rule>: <detail>``):

``schema``         valid against ``schemas/registers/decision_spec.json`` (K-02).
``complete``       :func:`~homelabnext.decide.spec.parse_spec` accepts it: question set, decision
                   table, tiers in order, error direction, ``on_error: escalate``, latency budget
                   and audit sample are all present and sane (K-02).
``audit-sample``   ``sample_audit_pct`` is above 0: a spec nobody samples is never audited (K-02).
``in-git``         the file is tracked by git (K-02; discovery mode only).
``single-axis``    each question asks one thing (K-03).  Mechanically: the text ends with its only
                   ``?``, has no ``;``, and no standalone ``and``, ``or`` or ``and/or`` - the words
                   that join two questions into one.  A question needing them is two questions.
                   The same text twice in one set is also refused.
``labels``         a question's own ``labels`` are 2 to :data:`MAX_LABELS` distinct values (K-03).
                   A plain-string question answers with the decision table's labels, at most 3.
``pairwise``       a ``compare: [a, b]`` question names two different slots, writes both as
                   ``{a}`` and ``{b}`` in its text, and its mirror - the same text with the slots
                   swapped, ``compare: [b, a]``, the same labels - is also in the set, so position
                   bias cancels out.  A text with two ``{slot}`` placeholders must declare
                   ``compare`` (K-03).
``inline``         a spec whose ``callers`` include ``inline`` uses only the fast tiers (``floor``,
                   ``small``) before the implicit human escalation; its ``latency_budget_ms`` is at
                   most :data:`INLINE_BUDGET_MS` (the K-01 inline p95); every model tier sets a
                   ``timeout_ms`` within that budget (K-04).

Exit codes: 0 clean, 1 a rule failed, 2 bad input (unreadable file, missing dependency),
100 the specs could not be enumerated (no git).
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .spec import SpecError, parse_spec

MAX_LABELS = 5
INLINE_BUDGET_MS = 1000
FAST_TIERS = ("floor", "small")
SPEC_SUFFIXES = (".yml", ".yaml", ".json")
SKIP_PARTS = ("negative", "_frozen")

_JOINERS = re.compile(r"(?<![\w/])(?:and/or|and|or)(?![\w/])", re.I)
_SLOT = re.compile(r"\{([a-z][a-z0-9_]*)\}")


class LintError(Exception):
    """The lint could not run (exit 2) or could not enumerate specs (exit 100)."""

    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Problem:
    path: str
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}: {self.rule}: {self.detail}"


# ---------------------------------------------------------------- one document
def lint_doc(doc: Any) -> list[tuple[str, str]]:
    """``(rule, detail)`` for every problem in one decision-spec document (empty = clean)."""
    out = [("schema", e) for e in _schema_errors(doc)]
    try:
        spec = parse_spec(doc)
    except SpecError as exc:
        return out + [("complete", p) for p in exc.problems]
    if not spec.sample_audit_pct > 0:
        out.append(("audit-sample", "sample_audit_pct must be above 0"))
    out += _questions(spec)
    out += _inline(spec)
    return out


def _questions(spec) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for i, q in enumerate(spec.questions):
        where = f"question_set[{i}]"
        text = q.text.strip()
        if text.count("?") != 1 or not text.endswith("?"):
            out.append(("single-axis", f"{where}: one question, ending with its only '?'"))
        if ";" in text:
            out.append(("single-axis", f"{where}: ';' joins two questions"))
        joined = sorted({m.group(0).lower() for m in _JOINERS.finditer(text)})
        if joined:
            out.append(("single-axis", f"{where}: {'/'.join(joined)!r} asks about two things"))
        if text.casefold() in seen:
            out.append(("single-axis", f"{where}: asked twice"))
        seen.add(text.casefold())
        if q.labels:
            if not 2 <= len(q.labels) <= MAX_LABELS:
                out.append(
                    ("labels", f"{where}: {len(q.labels)} labels; allowed 2 to {MAX_LABELS}")
                )
            if len({x.casefold() for x in q.labels}) != len(q.labels):
                out.append(("labels", f"{where}: duplicate labels"))
        out += _pairwise(spec, i, q)
    return out


def _pairwise(spec, i: int, q) -> list[tuple[str, str]]:
    where = f"question_set[{i}]"
    slots = set(_SLOT.findall(q.text))
    if not q.compare:
        if len(slots) >= 2:
            return [("pairwise", f"{where}: compares {sorted(slots)} but declares no compare")]
        return []
    if len(q.compare) != 2 or q.compare[0] == q.compare[1]:
        return [("pairwise", f"{where}: compare names two different slots")]
    a, b = q.compare
    if slots != {a, b}:
        return [("pairwise", f"{where}: text must write both slots as {{{a}}} and {{{b}}}")]
    mirror = _swap(q.text, a, b)
    for other in spec.questions:
        if other.compare == (b, a) and other.text == mirror and other.labels == q.labels:
            return []
    return [
        ("pairwise", f"{where}: not asked in both orders; add {mirror!r} with compare [{b}, {a}]")
    ]


def _swap(text: str, a: str, b: str) -> str:
    return _SLOT.sub(lambda m: {a: f"{{{b}}}", b: f"{{{a}}}"}.get(m.group(1), m.group(0)), text)


def _inline(spec) -> list[tuple[str, str]]:
    if not spec.inline:
        return []
    out: list[tuple[str, str]] = []
    slow = [t.name for t in spec.tiers if t.name not in FAST_TIERS]
    if slow:
        out.append(
            ("inline", f"inline callers may only use {FAST_TIERS}, then escalate; has {slow}")
        )
    if spec.latency_budget_ms > INLINE_BUDGET_MS:
        out.append(
            (
                "inline",
                f"latency_budget_ms {spec.latency_budget_ms} > {INLINE_BUDGET_MS} for inline",
            )
        )
    for t in spec.tiers:
        if t.name == "floor":
            continue
        if t.timeout_ms is None or t.timeout_ms > min(spec.latency_budget_ms, INLINE_BUDGET_MS):
            out.append(("inline", f"tier {t.name}: needs a timeout_ms within the inline budget"))
    return out


def _schema_errors(doc: Any) -> list[str]:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - exercised only without the core extra
        raise LintError(
            "hnx decide lint needs jsonschema: pip install 'homelabnext[core]'"
        ) from exc
    v = Draft202012Validator(_schema(), registry=_registry())
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}"
        for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    ]


_CACHE: dict[str, Any] = {}


def _schema() -> dict:
    if "schema" not in _CACHE:
        from homelabnext import paths

        f = paths.schema_file("registers", "decision_spec.json")
        _CACHE["schema"] = json.loads(f.read_text(encoding="utf-8"))
    return _CACHE["schema"]


def _registry():
    if "registry" not in _CACHE:
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012

        from homelabnext import paths

        reg = Registry()
        for f in sorted((paths.schemas_dir() / "ids").glob("*.json")):
            d = json.loads(f.read_text(encoding="utf-8"))
            reg = reg.with_resource(d["$id"], Resource.from_contents(d, DRAFT202012))
        _CACHE["registry"] = reg
    return _CACHE["registry"]


# ---------------------------------------------------------------- files and discovery
def load(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    import yaml

    return yaml.safe_load(text)


def is_spec(doc: Any) -> bool:
    return isinstance(doc, dict) and "question_set" in doc and "decision_table" in doc


def _git(root: Path, *args: str) -> list[str]:
    try:
        res = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise LintError(f"cannot list decision specs: {exc}", 100) from exc
    if res.returncode != 0:
        raise LintError(f"cannot list decision specs: {res.stderr.strip()}", 100)
    return [p for p in res.stdout.split("\0") if p]


def _candidate(rel: str) -> bool:
    parts = Path(rel).parts
    return rel.endswith(SPEC_SUFFIXES) and not any(p in SKIP_PARTS for p in parts)


def _spec_or_none(path: Path) -> Any:
    """The document if ``path`` is a decision spec.  A file that never mentions both keys is not
    parsed at all, so the scan stays cheap and unrelated broken files are other gates' concern."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if "question_set" not in text or "decision_table" not in text:
        return None
    try:
        doc = load(path)
    except Exception as exc:
        raise LintError(f"{path}: unreadable: {exc}") from exc
    return doc if is_spec(doc) else None


def discover(root: Path) -> tuple[list[Path], list[Path]]:
    """``(tracked, untracked)`` decision specs under ``root`` (untracked = not ignored, not added)."""
    tracked = [root / p for p in _git(root, "--cached") if _candidate(p)]
    others = [root / p for p in _git(root, "--others", "--exclude-standard") if _candidate(p)]
    return (
        [p for p in tracked if p.is_file() and _spec_or_none(p) is not None],
        [p for p in others if _spec_or_none(p) is not None],
    )


def _expand(paths: Iterable[Path]) -> list[Path]:
    """Explicit files as given; a directory contributes the decision specs inside it."""
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            found = sorted(f for f in p.rglob("*") if f.suffix in SPEC_SUFFIXES and f.is_file())
            out += [f for f in found if _spec_or_none(f) is not None]
        elif p.is_file():
            out.append(p)
        else:
            raise LintError(f"{p}: no such file or directory")
    return out


def lint_paths(paths: Sequence[Path], *, root: Path | None = None) -> tuple[int, list[Problem]]:
    """Lint ``paths`` (files or directories), or every spec in the git tree at ``root``.

    Returns ``(number of specs linted, problems)``.
    """
    problems: list[Problem] = []
    if paths:
        files = _expand(paths)
    else:
        base = root or Path.cwd()
        tracked, untracked = discover(base)
        problems += [
            Problem(_rel(p, base), "in-git", "decision spec is not tracked by git")
            for p in untracked
        ]
        files = [*tracked, *untracked]
    for f in files:
        try:
            doc = load(f)
        except Exception as exc:
            raise LintError(f"{f}: unreadable: {exc}") from exc
        where = _rel(f, root or Path.cwd())
        problems += [Problem(where, rule, detail) for rule, detail in lint_doc(doc)]
    return len(files), problems


def _rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)
