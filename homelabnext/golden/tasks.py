# SPDX-License-Identifier: Apache-2.0
"""Golden-task file format (YAML).

::

    suite: classifier-smoke
    role: fast-classifier          # default alias; the runner can override
    pass_score: 1.0                # a task passes at or above this score
    tasks:
      - id: rollback-present       # slug, unique in the suite
        system: "Answer with JSON."          # optional
        prompt: "Change plan: ... rollback: revert the commit."
        params: {temperature: 0}             # optional request params
        weight: 1                            # optional, default 1
        expect:                              # expected structure + scoring function
          scorer: json_fields                # exact|one_of|contains|regex|json_fields|json_schema|max_length
          fields: {label: accept}

A **tool-using** suite (``schemas/agent/golden_task`` 1.1; the Code Mode golden harness,
:mod:`homelabnext.golden.agentic`, ``docs/codemode.md`` CM-6) poses every task once per mode and
adds, on the suite, ``profile``, ``modes`` (``mcp``, ``codemode``), ``grant`` (the broker actions
its agent is granted) and ``max_turns``; on a task, ``fixtures`` (``action -> target -> result``,
what the fake broker answers), ``inject`` (``{action, target, field}``: where the G-02 pass puts
each corpus case) and ``checks`` (trace scorers, :data:`~.scorers.TRACE_SCORERS`)::

    suite: codemode-triage
    profile: profile:triage
    modes: [mcp, codemode]
    grant: [service.status]
    tasks:
      - id: stopped-services
        prompt: "Which of svc:dhcp and svc:queue are not running?"
        fixtures:
          service.status:
            svc:dhcp: {service: svc:dhcp, state: stopped, params: {}}
            svc:queue: {service: svc:queue, state: running, params: {}}
        expect: {scorer: json_fields, fields: {not_running: [svc:dhcp]}}
        checks:
          - {scorer: broker_calls, max: 2}
          - {scorer: turns, max: {mcp: 4, codemode: 3}}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scorers import ScoreError, validate_check, validate_expect

SLUG = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
ACTION = re.compile(r"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$")
TARGET = re.compile(r"^svc:[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
FIELD = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
PROFILE = re.compile(r"^profile:[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
#: the two ways a tool-using task is posed (``docs/codemode.md``, CM-6)
MODES = ("mcp", "codemode")
DEFAULT_MAX_TURNS = 8
MAX_TURNS = 32


class TaskError(ValueError):
    pass


@dataclass(frozen=True)
class Task:
    id: str
    prompt: str
    expect: dict
    system: str = ""
    params: dict = field(default_factory=dict)
    weight: float = 1.0
    tags: tuple[str, ...] = ()
    #: tool-using tasks only: ``{action: {target: result}}``, the injection placement and checks
    fixtures: dict = field(default_factory=dict)
    inject: dict | None = None
    checks: tuple[dict, ...] = ()

    def messages(self) -> list[dict]:
        msgs = [{"role": "system", "content": self.system}] if self.system else []
        return [*msgs, {"role": "user", "content": self.prompt}]


@dataclass(frozen=True)
class Suite:
    name: str
    tasks: tuple[Task, ...]
    role: str | None = None
    pass_score: float = 1.0
    #: tool-using suites only (empty ``modes`` is a plain completion suite)
    profile: str | None = None
    modes: tuple[str, ...] = ()
    grant: tuple[str, ...] = ()
    max_turns: int = DEFAULT_MAX_TURNS


def parse_suite(doc: Any) -> Suite:
    problems: list[str] = []
    if not isinstance(doc, dict):
        raise TaskError("suite must be a mapping")
    modes, grant, max_turns, suite_problems = _tool_suite(doc)
    problems += suite_problems
    tool_suite = bool(modes) or "modes" in doc
    name = doc.get("suite")
    if not isinstance(name, str) or not SLUG.match(name):
        problems.append("suite: must be a slug")
    raw = doc.get("tasks")
    if not isinstance(raw, list) or not raw:
        problems.append("tasks: must be a non-empty list")
        raw = []
    tasks: list[Task] = []
    seen: set[str] = set()
    for i, t in enumerate(raw):
        where = f"tasks[{i}]"
        if not isinstance(t, dict):
            problems.append(f"{where}: must be a mapping")
            continue
        tid = t.get("id")
        if not isinstance(tid, str) or not SLUG.match(tid):
            problems.append(f"{where}: id must be a slug")
            continue
        where = f"task {tid}"
        if tid in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(tid)
        if not isinstance(t.get("prompt"), str) or not t["prompt"].strip():
            problems.append(f"{where}: prompt missing")
        exp = t.get("expect")
        if not isinstance(exp, dict):
            problems.append(f"{where}: expect missing")
            continue
        try:
            validate_expect(exp)
        except ScoreError as exc:
            problems.append(f"{where}: {exc}")
        w = t.get("weight", 1)
        if not isinstance(w, (int, float)) or isinstance(w, bool) or w <= 0:
            problems.append(f"{where}: weight must be > 0")
            continue
        tool_problems = _tool_task_problems(t, tool_suite)
        if tool_problems:
            problems += [f"{where}: {p}" for p in tool_problems]
            continue
        tasks.append(
            Task(
                id=tid,
                prompt=str(t.get("prompt", "")),
                expect=dict(exp),
                system=str(t.get("system", "")),
                params=dict(t.get("params") or {}),
                weight=float(w),
                tags=tuple(t.get("tags") or ()),
                fixtures={a: dict(by) for a, by in (t.get("fixtures") or {}).items()},
                inject=dict(t["inject"]) if t.get("inject") else None,
                checks=tuple(dict(c) for c in t.get("checks") or ()),
            )
        )
    ps = doc.get("pass_score", 1.0)
    if not isinstance(ps, (int, float)) or not 0 < ps <= 1:
        problems.append("pass_score: must be in (0, 1]")
        ps = 1.0
    if tool_suite:
        grants = set(grant)
        for t in tasks:
            stray = sorted(set(t.fixtures) - grants)
            if stray:
                problems.append(f"task {t.id}: fixtures for actions outside the grant: {stray}")
    if problems:
        raise TaskError("invalid golden suite:\n  - " + "\n  - ".join(problems))
    return Suite(
        str(name),
        tuple(tasks),
        doc.get("role"),
        float(ps),
        profile=doc.get("profile") if tool_suite else None,
        modes=modes,
        grant=grant,
        max_turns=max_turns,
    )


def _tool_suite(doc: dict) -> tuple[tuple[str, ...], tuple[str, ...], int, list[str]]:
    """``(modes, grant, max_turns, problems)`` of a suite's tool-using fields."""
    problems: list[str] = []
    if "modes" not in doc:
        stray = [k for k in ("grant", "max_turns") if k in doc]
        return (), (), DEFAULT_MAX_TURNS, [f"{k}: only in a suite with modes" for k in stray]
    modes = doc.get("modes")
    if (
        not isinstance(modes, list)
        or not modes
        or len(set(map(str, modes))) != len(modes)
        or any(m not in MODES for m in modes)
    ):
        problems.append(f"modes: a non-empty list of distinct modes from {list(MODES)}")
        modes = []
    profile = doc.get("profile")
    if not (isinstance(profile, str) and PROFILE.match(profile)):
        problems.append("profile: a tool-using suite names its agent profile (profile:<slug>)")
    grant = doc.get("grant")
    if (
        not isinstance(grant, list)
        or not grant
        or len(set(map(str, grant))) != len(grant)
        or not all(isinstance(a, str) and ACTION.match(a) and len(a) <= 128 for a in grant)
    ):
        problems.append("grant: a non-empty list of distinct broker action names")
        grant = []
    elif any(a.startswith("codemode.") for a in grant):
        problems.append("grant: codemode.* is the harness's to grant, never a suite's")
    turns = doc.get("max_turns", DEFAULT_MAX_TURNS)
    if not isinstance(turns, int) or isinstance(turns, bool) or not 1 <= turns <= MAX_TURNS:
        problems.append(f"max_turns: an integer from 1 to {MAX_TURNS}")
        turns = DEFAULT_MAX_TURNS
    return tuple(modes), tuple(grant), int(turns), problems


def _tool_task_problems(t: dict, tool_suite: bool) -> list[str]:
    """Problems of a task's ``fixtures``, ``inject`` and ``checks``."""
    keys = [k for k in ("fixtures", "inject", "checks") if k in t]
    if not tool_suite:
        return [f"{k}: only in a suite with modes" for k in keys]
    out: list[str] = []
    fixtures = t.get("fixtures") or {}
    if not isinstance(fixtures, dict):
        return ["fixtures: a mapping of action -> target -> result"]
    for action, by_target in fixtures.items():
        if not (isinstance(action, str) and ACTION.match(action)):
            out.append(f"fixtures: {str(action)[:80]!r} is not an action name")
            continue
        if not isinstance(by_target, dict) or not by_target:
            out.append(f"fixtures.{action}: a non-empty mapping of target -> result")
            continue
        for target, result in by_target.items():
            if not (isinstance(target, str) and TARGET.match(target)):
                out.append(f"fixtures.{action}: {str(target)[:80]!r} is not a svc: target")
            elif not isinstance(result, dict):
                out.append(f"fixtures.{action}.{target}: the result is a mapping")
    inject = t.get("inject")
    if inject is not None:
        if not isinstance(inject, dict) or set(inject) != {"action", "target", "field"}:
            out.append("inject: exactly {action, target, field}")
        elif not (
            isinstance(inject["field"], str)
            and FIELD.match(inject["field"])
            and isinstance((fixtures.get(inject["action"]) or {}).get(inject["target"]), dict)
        ):
            out.append("inject: names a field of one fixture result (action, target)")
    checks = t.get("checks", [])
    if not isinstance(checks, list):
        return [*out, "checks: a list"]
    for i, c in enumerate(checks):
        try:
            validate_check(c)
        except ScoreError as exc:
            out.append(f"checks[{i}]: {exc}")
    return out


def load_suite(path: str | Path) -> Suite:
    import yaml

    return parse_suite(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
