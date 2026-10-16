# SPDX-License-Identifier: Apache-2.0
"""Decision-spec model (``schemas/registers/decision_spec.json`` 1.1)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

IMPACTS = ("low", "medium", "high", "critical")
TIER_ORDER = ("floor", "small", "large", "llm")  # a human is always the implicit last stop
LABELS = ("accept", "reject", "escalate")
SAFETY_LABELS = ("raise", "hold")


class SpecError(ValueError):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid decision spec:\n  - " + "\n  - ".join(problems))


def impact_rank(name: str) -> int:
    return IMPACTS.index(name)


def max_impact(a: str, b: str) -> str:
    return a if impact_rank(a) >= impact_rank(b) else b


@dataclass(frozen=True)
class TierSpec:
    name: str
    min_confidence: float
    model_role: str | None = None
    timeout_ms: int | None = None
    acts: bool = False


@dataclass(frozen=True)
class DecisionSpec:
    id: str
    version: int
    question_set: tuple[str, ...]
    decision_table: tuple[tuple[str, str], ...]
    tiers: tuple[TierSpec, ...]
    error_direction: str
    latency_budget_ms: int
    sample_audit_pct: float
    safety: bool = False
    default_min_confidence: float = 0.9
    impact_keywords_file: str | None = None
    impact_floor: str = "low"

    @property
    def automatic_tiers(self) -> tuple[TierSpec, ...]:
        return self.tiers

    @property
    def interim(self) -> str:
        """What holds while a human decides.  Never an answer: ``hold`` (closed) or ``allow``."""
        return "hold" if self.error_direction == "fail-closed" else "allow"


def parse_spec(doc: Any) -> DecisionSpec:
    p: list[str] = []
    if not isinstance(doc, dict):
        raise SpecError(["spec must be a mapping"])
    for key in (
        "id",
        "version",
        "question_set",
        "decision_table",
        "tiers",
        "error_direction",
        "on_error",
        "latency_budget_ms",
        "sample_audit_pct",
    ):
        if key not in doc:
            p.append(f"missing {key}")
    if p:
        raise SpecError(p)
    if doc["on_error"] != "escalate":
        p.append("on_error must be 'escalate': a fault never answers")
    if doc["error_direction"] not in ("fail-open", "fail-closed"):
        p.append("error_direction must be fail-open or fail-closed")
    dmin = float(doc.get("default_min_confidence", 0.9))
    if not 0 <= dmin <= 1:
        p.append("default_min_confidence out of range")
    safety = bool(doc.get("safety", False))
    impact = doc.get("impact") or {}
    floor = impact.get("floor", "low")
    if floor not in IMPACTS:
        p.append(f"impact.floor {floor!r} not in {IMPACTS}")
        floor = "low"
    tiers: list[TierSpec] = []
    last = -1
    for i, t in enumerate(doc["tiers"]):
        name = t.get("name")
        if name not in TIER_ORDER:
            p.append(f"tiers[{i}]: unknown tier {name!r}")
            continue
        if TIER_ORDER.index(name) <= last:
            p.append(f"tiers[{i}]: {name} out of order (floor, small, large, llm)")
        last = TIER_ORDER.index(name)
        conf = t.get("min_confidence", 1.0 if name == "floor" else dmin)
        if not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
            p.append(f"tiers[{i}]: min_confidence out of range")
            conf = 1.0
        if name in ("small", "large", "llm") and not t.get("model_role"):
            p.append(f"tiers[{i}]: model tier {name} needs model_role")
        if safety and name != "floor" and t.get("acts"):
            p.append(f"tiers[{i}]: a safety spec's model tiers may only raise, never act")
        tiers.append(
            TierSpec(
                name, float(conf), t.get("model_role"), t.get("timeout_ms"), bool(t.get("acts"))
            )
        )
    if not tiers:
        p.append("tiers: empty")
    table = tuple((str(r["when"]), str(r["then"])) for r in doc["decision_table"])
    for _, then in table:
        if then not in LABELS:
            p.append(f"decision_table: {then!r} not in {LABELS}")
    if p:
        raise SpecError(p)
    return DecisionSpec(
        id=str(doc["id"]),
        version=int(doc["version"]),
        question_set=tuple(doc["question_set"]),
        decision_table=table,
        tiers=tuple(tiers),
        error_direction=doc["error_direction"],
        latency_budget_ms=int(doc["latency_budget_ms"]),
        sample_audit_pct=float(doc["sample_audit_pct"]),
        safety=safety,
        default_min_confidence=dmin,
        impact_keywords_file=impact.get("keywords_file"),
        impact_floor=floor,
    )


def load_spec(path: str | Path) -> DecisionSpec:
    import json

    text = Path(path).read_text(encoding="utf-8")
    if str(path).endswith((".yml", ".yaml")):
        import yaml

        return parse_spec(yaml.safe_load(text))
    return parse_spec(json.loads(text))
