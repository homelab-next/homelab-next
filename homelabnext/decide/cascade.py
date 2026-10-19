# SPDX-License-Identifier: Apache-2.0
"""The decision cascade.

Tiers run in the spec's order (deterministic floor, small classifier, larger classifier, LLM),
and a human is always the last stop.  The rules, none of which a tier can change:

1. A tier **answers** only when its confidence is at or above its threshold; otherwise the item
   **escalates** to the next tier.  Abstaining, an ``escalate`` label, or a label outside the
   spec's vocabulary is not an answer.
2. A tier that raises, times out or returns a malformed answer **escalates**.  It never answers,
   and a fault never lowers anything (``on_error: escalate``).
3. The **impact tier** starts at the highest of the declared impact, the spec floor and the
   deterministic keyword scan.  Any tier may raise it; **no tier may lower it**.  A proposed lower
   impact is ignored and recorded in the trace.
4. In a **safety** spec tiers may only ``raise`` the impact or ``hold`` it.  They can never approve
   (``accept``), and a raise is applied even below the confidence threshold, because raising is the
   safe direction.
5. In a **noise gate** (``noise_gate`` in the spec) an automatic answer with a de-escalating label
   stands only with **corroboration**: one of the spec's named corroborators (deterministic checks
   the caller supplies) returns a reference for the item, and the decision carries it.  Without
   one the answer is ``uncorroborated`` and the item escalates (K-08).
6. If every automatic tier declines, or the latency budget is spent, the decision is ``human``:
   escalated, ``acted`` false, with an ``interim`` posture (``hold`` for fail-closed, ``allow`` for
   fail-open) that is explicitly not an answer.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .impact_scan import ImpactScanner
from .spec import IMPACTS, LABELS, SAFETY_LABELS, DecisionSpec, TierSpec, impact_rank, max_impact
from .tiers import Item, Tier, TierAnswer, TierError, TierInvalidOutput, TierTimeout

#: ``corroborator(item) -> evidence or None``.  Must be deterministic: the same item gives the
#: same evidence, so the reference a de-escalation carries can be recomputed and audited.
Corroborator = Callable[[Item], "str | None"]


class CascadeConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Step:
    tier: str
    outcome: str  # answered | below-threshold | abstained | escalated | error | timeout | invalid
    #               | uncorroborated | budget
    label: str | None = None
    confidence: float | None = None
    detail: str = ""

    def to_dict(self) -> dict:
        d = {"tier": self.tier, "outcome": self.outcome}
        if self.label is not None:
            d["label"] = self.label
        if self.confidence is not None:
            d["confidence"] = round(self.confidence, 4)
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass(frozen=True)
class Decision:
    item_id: str
    verdict: str  # a spec label (or raise/hold in a safety spec), or "human"
    tier: str  # tier that answered, "human" when escalated all the way
    confidence: float
    impact: str
    base_impact: str
    escalated: bool
    acted: bool
    interim: str | None
    audit: bool
    trace: tuple[Step, ...] = field(default_factory=tuple)
    corroboration: str | None = None  # noise gates: the reference a de-escalation stands on

    @property
    def automatic(self) -> bool:
        return not self.escalated

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "verdict": self.verdict,
            "tier": self.tier,
            "confidence": round(self.confidence, 4),
            "impact": self.impact,
            "base_impact": self.base_impact,
            "escalated": self.escalated,
            "acted": self.acted,
            "interim": self.interim,
            "audit": self.audit,
            "trace": [s.to_dict() for s in self.trace],
            **({"corroboration": self.corroboration} if self.corroboration else {}),
        }


def audit_selected(spec_id: str, item_id: str, pct: float) -> bool:
    """Deterministic sample: the same item and spec always give the same answer."""
    h = int.from_bytes(hashlib.sha256(f"{spec_id}:{item_id}".encode()).digest()[:4], "big")
    return (h % 10000) < pct * 100


class Cascade:
    def __init__(
        self,
        spec: DecisionSpec,
        tiers: dict[str, Tier],
        scanner: ImpactScanner | None = None,
        clock: Callable[[], float] = time.monotonic,
        corroborators: dict[str, Corroborator] | None = None,
    ):
        missing = [t.name for t in spec.automatic_tiers if t.name not in tiers]
        if missing:
            raise CascadeConfigError(f"spec {spec.id}: no implementation for tiers {missing}")
        self.corroborators = dict(corroborators or {})
        if spec.noise_gate is not None:
            absent = [c for c in spec.noise_gate.corroborators if c not in self.corroborators]
            if absent:
                raise CascadeConfigError(
                    f"spec {spec.id}: no implementation for corroborators {absent}"
                )
        self.spec = spec
        self.tiers = tiers
        self.scanner = scanner
        self.clock = clock
        self._labels = SAFETY_LABELS if spec.safety else LABELS

    # ---------------------------------------------------------------- helpers
    def _call(self, ts: TierSpec, item: Item) -> TierAnswer:
        tier = self.tiers[ts.name]
        if ts.timeout_ms is None:
            return tier.decide(item)
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        fut = pool.submit(tier.decide, item)
        try:
            return fut.result(timeout=ts.timeout_ms / 1000)
        except concurrent.futures.TimeoutError as exc:
            raise TierTimeout(f"no answer within {ts.timeout_ms} ms") from exc
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def _base_impact(self, item: Item) -> tuple[str, str]:
        base = item.impact if item.impact in IMPACTS else "low"
        detail = ""
        base = max_impact(base, self.spec.impact_floor)
        if self.scanner is not None:
            res = self.scanner.scan(item.text)
            if res.tier:
                base = max_impact(base, res.tier)
                detail = f"keyword scan: {res.tier} ({', '.join(res.keywords)})"
        return base, detail

    def corroborate(self, item: Item) -> tuple[str | None, str]:
        """``(reference, detail)``: the first corroborator with evidence wins, in spec order.

        The reference is ``<corroborator>:<evidence>``.  A corroborator that raises gives no
        evidence (a broken check never de-escalates anything)."""
        gate = self.spec.noise_gate
        tried: list[str] = []
        for name in gate.corroborators if gate else ():
            try:
                evidence = self.corroborators[name](item)
            except Exception as exc:
                tried.append(f"{name}: {type(exc).__name__}")
                continue
            if evidence:
                return f"{name}:{evidence}", ""
            tried.append(f"{name}: no evidence")
        return None, "no corroboration (" + ", ".join(tried) + ")"

    # ---------------------------------------------------------------- decide
    def decide(self, item: Item) -> Decision:
        spec = self.spec
        start = self.clock()
        base, scan_detail = self._base_impact(item)
        impact = base
        steps: list[Step] = []
        if scan_detail:
            steps.append(Step("impact-scan", "answered", detail=scan_detail))
        for ts in spec.automatic_tiers:
            if (self.clock() - start) * 1000 > spec.latency_budget_ms:
                steps.append(Step(ts.name, "budget", detail="latency budget spent"))
                break
            try:
                ans = self._call(ts, item)
            except TierTimeout as exc:
                steps.append(Step(ts.name, "timeout", detail=str(exc)))
                continue
            except TierInvalidOutput as exc:
                steps.append(Step(ts.name, "invalid", detail=str(exc)))
                continue
            except TierError as exc:
                steps.append(Step(ts.name, "error", detail=str(exc)))
                continue
            except Exception as exc:  # any tier fault escalates
                steps.append(Step(ts.name, "error", detail=f"{type(exc).__name__}: {exc}"))
                continue
            if ans.label is None:
                steps.append(Step(ts.name, "abstained", detail=ans.rationale))
                continue
            conf = ans.confidence
            ok_conf = isinstance(conf, (int, float)) and not isinstance(conf, bool)
            if not ok_conf or not 0.0 <= conf <= 1.0:
                steps.append(Step(ts.name, "invalid", ans.label, None, f"confidence {conf!r}"))
                continue
            if ans.label not in self._labels:
                steps.append(
                    Step(ts.name, "invalid", ans.label, conf, f"label not in {list(self._labels)}")
                )
                continue
            note = ""
            if ans.impact is not None:
                if ans.impact not in IMPACTS:
                    steps.append(
                        Step(ts.name, "invalid", ans.label, conf, f"impact {ans.impact!r}")
                    )
                    continue
                if impact_rank(ans.impact) < impact_rank(impact):
                    note = f"ignored proposed lower impact {ans.impact} (keeping {impact})"
                else:
                    impact = ans.impact
            if spec.safety and ans.label == "raise" and ans.impact is None:
                steps.append(Step(ts.name, "invalid", ans.label, conf, "raise without an impact"))
                continue
            if ans.label == "escalate":
                steps.append(Step(ts.name, "escalated", ans.label, conf, note))
                continue
            raise_applied = spec.safety and ans.label == "raise"
            if conf >= ts.min_confidence:
                ref = None
                if spec.noise_gate is not None and ans.label in spec.noise_gate.deescalate:
                    ref, why = self.corroborate(item)
                    if ref is None:
                        steps.append(Step(ts.name, "uncorroborated", ans.label, conf, why))
                        continue
                steps.append(Step(ts.name, "answered", ans.label, conf, note))
                return self._finish(item, ans.label, ts, conf, impact, base, steps, ref)
            detail = f"below threshold {ts.min_confidence}"
            if raise_applied:
                detail += "; raise applied anyway (safe direction)"
            steps.append(
                Step(
                    ts.name,
                    "below-threshold",
                    ans.label,
                    conf,
                    "; ".join([detail, note]) if note else detail,
                )
            )
        return self._finish(item, "human", None, 0.0, impact, base, steps)

    def _finish(
        self,
        item: Item,
        verdict: str,
        ts: TierSpec | None,
        conf: float,
        impact: str,
        base: str,
        steps: list[Step],
        corroboration: str | None = None,
    ) -> Decision:
        escalated = ts is None
        spec = self.spec
        acted = bool(ts and ts.acts and not spec.safety)
        return Decision(
            item_id=item.id,
            verdict=verdict,
            tier="human" if ts is None else ts.name,
            confidence=conf,
            impact=impact,
            base_impact=base,
            escalated=escalated,
            acted=acted,
            interim=spec.interim if escalated else None,
            audit=(not escalated) and audit_selected(spec.id, item.id, spec.sample_audit_pct),
            trace=tuple(steps),
            corroboration=corroboration,
        )
