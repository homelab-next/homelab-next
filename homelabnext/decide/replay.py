# SPDX-License-Identifier: Apache-2.0
"""Replay gate: re-run a recorded decision set against a candidate cascade.

The report states coverage (share decided without a human), the error rate on the gold-labelled
subset, per-tier counts, impact under-calls, and the change against a baseline.  The gate has
one rule that no option can waive: **a tier marked ``acts`` must make zero wrong answers on the
gold set** (a wrong answer from a tier that clears its confidence threshold is a confident error,
and an acting tier turns it into an action).  Safety specs additionally require zero impact
under-calls.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .cascade import Cascade
from .spec import impact_rank
from .tiers import Item


@dataclass(frozen=True)
class Record:
    """One recorded decision input with its gold answer and (optionally) the baseline's answer."""

    id: str
    item: Item
    gold: str | None = None
    gold_impact: str | None = None
    baseline_verdict: str | None = None  # "human" when the baseline escalated
    baseline_tier: str | None = None

    def to_dict(self) -> dict:
        d = {"id": self.id, "text": self.item.text, "impact": self.item.impact}
        for k in ("gold", "gold_impact", "baseline_verdict", "baseline_tier"):
            if getattr(self, k) is not None:
                d[k] = getattr(self, k)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Record:
        return cls(
            id=str(d["id"]),
            item=Item(str(d["id"]), str(d["text"]), d.get("impact", "low"), d.get("fields", {})),
            gold=d.get("gold"),
            gold_impact=d.get("gold_impact"),
            baseline_verdict=d.get("baseline_verdict"),
            baseline_tier=d.get("baseline_tier"),
        )


def dump_records(records: Iterable[Record], path: str | Path) -> None:
    Path(path).write_text(
        "".join(json.dumps(r.to_dict(), sort_keys=True) + "\n" for r in records), encoding="utf-8"
    )


def load_records(path: str | Path) -> list[Record]:
    return [
        Record.from_dict(json.loads(line))
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@dataclass
class TierStats:
    answered: int = 0
    wrong: int = 0
    acts: bool = False


@dataclass
class ReplayReport:
    spec_id: str
    safety: bool
    n: int
    verdicts: dict[str, tuple[str, str]]  # id -> (verdict, tier)
    automatic: int
    gold_n: int
    gold_auto: int
    wrong: int
    impact_under: int
    per_tier: dict[str, TierStats] = field(default_factory=dict)
    wrong_ids: tuple[str, ...] = ()

    @property
    def coverage(self) -> float:
        return self.automatic / self.n if self.n else 0.0

    @property
    def error_rate(self) -> float:
        return self.wrong / self.gold_auto if self.gold_auto else 0.0

    @property
    def acting_wrong(self) -> int:
        return sum(s.wrong for s in self.per_tier.values() if s.acts)

    def to_dict(self) -> dict:
        return {
            "spec": self.spec_id,
            "records": self.n,
            "automatic": self.automatic,
            "escalated": self.n - self.automatic,
            "coverage": round(self.coverage, 4),
            "gold_records": self.gold_n,
            "gold_automatic": self.gold_auto,
            "wrong": self.wrong,
            "error_rate": round(self.error_rate, 4),
            "acting_tier_wrong": self.acting_wrong,
            "impact_under_calls": self.impact_under,
            "per_tier": {
                k: {"answered": v.answered, "wrong": v.wrong, "acts": v.acts}
                for k, v in sorted(self.per_tier.items())
            },
            "wrong_ids": list(self.wrong_ids),
        }


def replay(records: list[Record], cascade: Cascade) -> ReplayReport:
    spec = cascade.spec
    per_tier = {t.name: TierStats(acts=t.acts and not spec.safety) for t in spec.automatic_tiers}
    verdicts: dict[str, tuple[str, str]] = {}
    automatic = gold_n = gold_auto = wrong = under = 0
    wrong_ids: list[str] = []
    for r in records:
        d = cascade.decide(r.item)
        verdicts[r.id] = (d.verdict, d.tier)
        if r.gold is not None:
            gold_n += 1
        if r.gold_impact is not None and impact_rank(d.impact) < impact_rank(r.gold_impact):
            under += 1
        if d.escalated:
            continue
        automatic += 1
        per_tier[d.tier].answered += 1
        if r.gold is not None:
            gold_auto += 1
            if d.verdict != r.gold:
                wrong += 1
                per_tier[d.tier].wrong += 1
                wrong_ids.append(r.id)
    return ReplayReport(
        spec.id, spec.safety, len(records), verdicts, automatic, gold_n, gold_auto, wrong,
        under, per_tier, tuple(wrong_ids),
    )  # fmt: skip


def baseline_from_records(records: list[Record], spec_id: str = "baseline") -> ReplayReport:
    """Rebuild a report from the answers recorded in the decision set itself."""
    verdicts: dict[str, tuple[str, str]] = {}
    automatic = gold_n = gold_auto = wrong = 0
    wrong_ids: list[str] = []
    per_tier: dict[str, TierStats] = {}
    for r in records:
        v = r.baseline_verdict or "human"
        verdicts[r.id] = (v, r.baseline_tier or ("human" if v == "human" else "unknown"))
        if r.gold is not None:
            gold_n += 1
        if v == "human":
            continue
        automatic += 1
        st = per_tier.setdefault(verdicts[r.id][1], TierStats())
        st.answered += 1
        if r.gold is not None:
            gold_auto += 1
            if v != r.gold:
                wrong += 1
                st.wrong += 1
                wrong_ids.append(r.id)
    return ReplayReport(
        spec_id, False, len(records), verdicts, automatic, gold_n, gold_auto, wrong, 0,
        per_tier, tuple(wrong_ids),
    )  # fmt: skip


def compare(candidate: ReplayReport, baseline: ReplayReport) -> dict:
    changed = sorted(
        i for i, v in candidate.verdicts.items() if baseline.verdicts.get(i, ("", ""))[0] != v[0]
    )
    base_wrong, cand_wrong = set(baseline.wrong_ids), set(candidate.wrong_ids)
    return {
        "coverage_baseline": round(baseline.coverage, 4),
        "coverage_candidate": round(candidate.coverage, 4),
        "coverage_delta": round(candidate.coverage - baseline.coverage, 4),
        "error_rate_baseline": round(baseline.error_rate, 4),
        "error_rate_candidate": round(candidate.error_rate, 4),
        "error_rate_delta": round(candidate.error_rate - baseline.error_rate, 4),
        "verdicts_changed": len(changed),
        "newly_wrong": sorted(cand_wrong - base_wrong),
        "newly_right": sorted(base_wrong - cand_wrong),
    }


@dataclass(frozen=True)
class GateResult:
    passed: bool
    failures: tuple[str, ...]
    comparison: dict | None = None

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "failures": list(self.failures),
            "comparison": self.comparison,
        }


def gate(
    report: ReplayReport,
    baseline: ReplayReport | None = None,
    *,
    min_coverage: float | None = None,
    max_error_rate_increase: float = 0.0,
    allow_coverage_regression: bool = True,
) -> GateResult:
    fails: list[str] = []
    # Hard rule, not configurable: acting tiers make no confident errors on the gold set.
    for name, st in sorted(report.per_tier.items()):
        if st.acts and st.wrong:
            fails.append(
                f"acting tier {name!r} made {st.wrong} wrong answer(s) on the gold set "
                "(zero confident errors required)"
            )
    if report.safety and report.impact_under:
        fails.append(f"safety spec under-called impact on {report.impact_under} record(s)")
    if report.gold_n == 0:
        fails.append("no gold-labelled records: cannot show zero confident errors")
    if min_coverage is not None and report.coverage < min_coverage:
        fails.append(f"coverage {report.coverage:.4f} below required {min_coverage}")
    cmp = None
    if baseline is not None:
        cmp = compare(report, baseline)
        if cmp["error_rate_delta"] > max_error_rate_increase:
            fails.append(f"error rate rose by {cmp['error_rate_delta']} versus baseline")
        if not allow_coverage_regression and cmp["coverage_delta"] < 0:
            fails.append(f"coverage fell by {-cmp['coverage_delta']} versus baseline")
    return GateResult(not fails, tuple(fails), cmp)
