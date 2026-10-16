# SPDX-License-Identifier: Apache-2.0
"""Golden run report."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TaskResult:
    task_id: str
    score: float
    passed: bool
    detail: str
    output: str = ""
    error: str = ""
    latency_ms: float = 0.0
    weight: float = 1.0


@dataclass
class Report:
    suite: str
    role: str
    model_id: str
    pass_score: float
    results: list[TaskResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(r.passed for r in self.results)

    @property
    def errors(self) -> int:
        return sum(bool(r.error) for r in self.results)

    @property
    def weighted_score(self) -> float:
        total = sum(r.weight for r in self.results)
        return sum(r.score * r.weight for r in self.results) / total if total else 0.0

    @property
    def ok(self) -> bool:
        return bool(self.results) and self.passed == len(self.results)

    def to_dict(self, *, timing: bool = False) -> dict:
        """Deterministic summary; latencies are included only on request (golden files omit)."""
        tasks = []
        for r in self.results:
            row = {
                "id": r.task_id,
                "score": round(r.score, 4),
                "passed": r.passed,
                "detail": r.detail,
            }
            if r.error:
                row["error"] = r.error
            if timing:
                row["latency_ms"] = round(r.latency_ms, 2)
            tasks.append(row)
        return {
            "suite": self.suite,
            "role": self.role,
            "model_id": self.model_id,
            "total": len(self.results),
            "passed": self.passed,
            "errors": self.errors,
            "weighted_score": round(self.weighted_score, 4),
            "tasks": tasks,
        }

    def render_text(self) -> str:
        d = self.to_dict()
        lines = [
            f"golden suite {d['suite']} on mdl:{d['role']} ({d['model_id']}): "
            f"{d['passed']}/{d['total']} passed, weighted score {d['weighted_score']:.3f}"
        ]
        for t in d["tasks"]:
            mark = "PASS" if t["passed"] else "FAIL"
            lines.append(f"  {mark} {t['id']}  {t['score']:.2f}  {t.get('error') or t['detail']}")
        return "\n".join(lines) + "\n"
