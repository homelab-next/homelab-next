# SPDX-License-Identifier: Apache-2.0
"""Required safety specs (K-15): present, safety-only, and passing their cases.

Four decision specs must exist under :data:`SPECS_DIR` and pass their synthetic case sets:
:data:`REQUIRED`.  Each is a ``safety: true`` spec (tiers may only ``raise`` the impact or
``hold`` it, never approve or act) with a deterministic keyword list and a ``<id>.cases.yml``.

The case runner builds each spec's cascade from deterministic parts only:

* the **floor** raises to the keyword scan's tier when the spec's keyword list matches;
* each model tier is a :class:`FakeSafetyTier` that "knows" the phrases the case file lists
  under ``fake_tiers`` (``raise`` with an impact, or ``hold``) and abstains on anything else.

So a passing run proves the specs are live and wired (keywords, thresholds, tier order, the
cascade's raise-only rules) against fakes - not that a real model classifies well.  Every case,
whatever it expects, must also satisfy the safety invariants: nothing ``acted``, the decided
impact never below the requester's declared impact, the verdict one of ``raise``, ``hold`` or
``human``.

``hnx decide safety [--dir DIR]``: exit 0 every required spec passes, 1 a spec is missing,
malformed or fails a case, 2 bad input.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .cascade import Cascade
from .impact_scan import ImpactScanner
from .spec import IMPACTS, DecisionSpec, SpecError, impact_rank, load_spec
from .tiers import CallableTier, Item, TierAnswer

SPECS_DIR = Path(__file__).resolve().parent / "safety_specs"
REQUIRED = ("sensitive-content", "hostile-content", "purpose-consistency", "disclosure-risk")
VERDICTS = ("raise", "hold", "human")


class FakeSafetyTier:
    """Deterministic stand-in for a model tier: raises or holds on known phrases, else abstains."""

    def __init__(self, name: str, raise_: dict[str, str], hold: list[str], conf: float = 0.95):
        self.name = name
        self.raise_ = {k.lower(): v for k, v in raise_.items()}
        self.hold = [h.lower() for h in hold]
        self.conf = conf

    def decide(self, item: Item) -> TierAnswer:
        low = item.text.lower()
        for phrase, impact in self.raise_.items():
            if phrase in low:
                return TierAnswer("raise", self.conf, impact, f"knows {phrase!r}")
        for phrase in self.hold:
            if phrase in low:
                return TierAnswer("hold", self.conf, "low", f"knows {phrase!r}")
        return TierAnswer(None, rationale="unknown")


def scan_floor(scanner: ImpactScanner) -> CallableTier:
    """The deterministic floor of a safety spec: a keyword hit raises to that hit's tier."""

    def fn(item: Item) -> TierAnswer:
        res = scanner.scan(item.text)
        if res.tier is None:
            return TierAnswer(None)
        return TierAnswer("raise", 1.0, res.tier, f"keywords {list(res.keywords)}")

    return CallableTier("floor", fn, deterministic=True)


@dataclass
class SpecResult:
    spec: str
    cases: int = 0
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.cases > 0 and not self.failures


def _load_yaml(path: Path) -> Any:
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def build_cascade(spec: DecisionSpec, spec_dir: Path, fake_tiers: dict) -> Cascade:
    if not spec.impact_keywords_file:
        raise SpecError(["a safety spec needs impact.keywords_file (its deterministic floor)"])
    scanner = ImpactScanner.load(spec_dir / spec.impact_keywords_file)
    tiers: dict[str, Any] = {}
    for ts in spec.tiers:
        if ts.name == "floor":
            tiers["floor"] = scan_floor(scanner)
            continue
        known = fake_tiers.get(ts.name) or {}
        raise_ = {str(r["phrase"]): str(r["impact"]) for r in known.get("raise") or []}
        tiers[ts.name] = FakeSafetyTier(ts.name, raise_, list(known.get("hold") or []))
    return Cascade(spec, tiers, scanner)


def run_cases(spec: DecisionSpec, spec_dir: Path, doc: Any) -> SpecResult:
    out = SpecResult(spec.id)
    if not isinstance(doc, dict) or not isinstance(doc.get("cases"), list) or not doc["cases"]:
        out.failures.append("case file needs a non-empty 'cases' list")
        return out
    if doc.get("spec") != spec.id:
        out.failures.append(f"case file is for {doc.get('spec')!r}, not {spec.id!r}")
    cascade = build_cascade(spec, spec_dir, doc.get("fake_tiers") or {})
    for c in doc["cases"]:
        cid = c.get("id", "?")
        exp = c.get("expect") or {}
        declared = c.get("impact", "low")
        if exp.get("verdict") not in VERDICTS or exp.get("impact") not in IMPACTS:
            out.failures.append(f"{cid}: expect needs verdict in {VERDICTS} and an impact")
            continue
        out.cases += 1
        d = cascade.decide(Item(cid, str(c.get("text", "")), declared))
        got = {"verdict": d.verdict, "impact": d.impact, "tier": d.tier}
        want = {"verdict": exp["verdict"], "impact": exp["impact"]}
        if "tier" in exp:
            want["tier"] = exp["tier"]
        diff = {k: (want[k], got[k]) for k in want if want[k] != got[k]}
        if diff:
            out.failures.append(
                f"{cid}: "
                + ", ".join(f"{k} expected {w!r}, got {g!r}" for k, (w, g) in diff.items())
            )
        if d.acted:
            out.failures.append(f"{cid}: a safety decision acted")
        if d.verdict not in VERDICTS:
            out.failures.append(f"{cid}: verdict {d.verdict!r} is not a safety verdict")
        if declared in IMPACTS and impact_rank(d.impact) < impact_rank(declared):
            out.failures.append(f"{cid}: impact lowered from {declared} to {d.impact}")
    return out


def check(spec_dir: Path = SPECS_DIR, required: tuple[str, ...] = REQUIRED) -> list[SpecResult]:
    """One result per required spec (a missing or malformed spec is a failed result)."""
    results: list[SpecResult] = []
    for name in required:
        res = SpecResult(name)
        results.append(res)
        spec_file, cases_file = spec_dir / f"{name}.yml", spec_dir / f"{name}.cases.yml"
        for f in (spec_file, cases_file):
            if not f.is_file():
                res.failures.append(f"missing {f.name}")
        if res.failures:
            continue
        try:
            spec = load_spec(spec_file)
        except SpecError as exc:
            res.failures += [f"spec: {p}" for p in exc.problems]
            continue
        if spec.id != name:
            res.failures.append(f"spec id {spec.id!r} does not match its file name")
        if not spec.safety:
            res.failures.append("not a safety spec (safety: true is required)")
            continue
        try:
            got = run_cases(spec, spec_dir, _load_yaml(cases_file))
        except (SpecError, ValueError, KeyError, TypeError, OSError) as exc:
            res.failures.append(f"cannot run cases: {exc}")
            continue
        res.cases, res.failures = got.cases, res.failures + got.failures
    return results


def main(spec_dir: Path | None = None) -> int:
    results = check(spec_dir or SPECS_DIR)
    for r in results:
        print(f"{'PASS' if r.ok else 'FAIL'} {r.spec}: {r.cases} case(s)")
        for f in r.failures:
            print(f"  - {f}")
    bad = sum(not r.ok for r in results)
    print(f"decide safety: {len(results)} required spec(s), {bad} failing")
    return 1 if bad else 0
