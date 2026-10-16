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
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scorers import ScoreError, validate_expect

SLUG = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


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

    def messages(self) -> list[dict]:
        msgs = [{"role": "system", "content": self.system}] if self.system else []
        return [*msgs, {"role": "user", "content": self.prompt}]


@dataclass(frozen=True)
class Suite:
    name: str
    tasks: tuple[Task, ...]
    role: str | None = None
    pass_score: float = 1.0


def parse_suite(doc: Any) -> Suite:
    problems: list[str] = []
    if not isinstance(doc, dict):
        raise TaskError("suite must be a mapping")
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
        tasks.append(
            Task(
                id=tid,
                prompt=str(t.get("prompt", "")),
                expect=dict(exp),
                system=str(t.get("system", "")),
                params=dict(t.get("params") or {}),
                weight=float(w),
                tags=tuple(t.get("tags") or ()),
            )
        )
    ps = doc.get("pass_score", 1.0)
    if not isinstance(ps, (int, float)) or not 0 < ps <= 1:
        problems.append("pass_score: must be in (0, 1]")
        ps = 1.0
    if problems:
        raise TaskError("invalid golden suite:\n  - " + "\n  - ".join(problems))
    return Suite(str(name), tuple(tasks), doc.get("role"), float(ps))


def load_suite(path: str | Path) -> Suite:
    import yaml

    return parse_suite(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
