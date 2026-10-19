# SPDX-License-Identifier: Apache-2.0
"""Pinned models and the evaluation they must pass (G-11, with the K-12 replay gate).

Every binding in the role table is pinned by ``version`` and ``digest`` (sha256 of the weights).
The **evaluation report** is a function of those pins, the golden suites and the decision spec
and gold set the replay gate uses (:func:`inputs_of`).  It holds:

* one golden-suite run per suite, against the suite's role;
* the K-12 replay of the synthetic gold set through the change-review cascade, with its gate.

``hnx golden pins check`` fails when a binding is unpinned, when a pinned role is evaluated by
nothing, when the stored report is **stale** (a pin, a suite, the spec or the runner changed
since it was produced; the roles whose pins changed are named), or when it does not pass.  So
changing a model is: change the pin, rerun the evaluation, commit the new report with it.

CI runs the evaluation against :class:`FakeGoldenModel`, a deterministic rule-based completer,
and also re-runs it to prove the stored fake report is exactly reproducible.  The fake proves the
harness and the pin tracking, **not** that a model is good: before a real model change, run the
same evaluation live (``make models-eval``: golden suites and replay through the model-role
resolver) and keep that report with the change.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from homelabnext.registry.models import RoleTable, normalize_role

from .report import Report
from .runner import Completer, run_suite
from .tasks import Suite, load_suite

REPORT_FORMAT = "hnx-model-eval/1"
#: Bump when the evaluation, the scorers or the fake change behaviour: it is a pinned input.
EVAL_VERSION = 1
EXAMPLES = Path(__file__).resolve().parent / "examples"
DEFAULT_SUITES = (EXAMPLES / "classifier_smoke.yml",)
GOLD_N, GOLD_SEED = 200, 7

#: ``completer_for(role) -> (completer, model id)``
CompleterFactory = Callable[[str], "tuple[Completer, str]"]


def _digest(obj: Any) -> str:
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class FakeGoldenModel:
    """Deterministic CI completer: answers the shipped golden tasks by fixed rules.

    It reads only the last user message: a rollback marker or a revert gives ``accept``, an
    explicit ``NO-ROLLBACK`` gives ``reject`` (both as classifier JSON), anything else a one-word
    greeting.  It stands in for every role, so a stored fake report changes only when an input does.
    """

    name = "fake-golden"

    def __call__(self, messages: list[dict], params: dict) -> str:
        text = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        low = text.lower()
        if "no-rollback" in low:
            return json.dumps({"label": "reject", "confidence": 0.95})
        if "rollback" in low or "revert" in low:
            return json.dumps({"label": "accept", "confidence": 0.95})
        return "Hello"


def fake_factory(role: str) -> tuple[Completer, str]:
    return FakeGoldenModel(), f"{FakeGoldenModel.name}:{normalize_role(role)}"


# ---------------------------------------------------------------- inputs and coverage
def _decide_inputs() -> dict:
    from homelabnext.decide.evalset import EXAMPLES as DECIDE_EXAMPLES

    return {
        "spec": _file_digest(DECIDE_EXAMPLES / "decision_spec.yml"),
        "impact_keywords": _file_digest(DECIDE_EXAMPLES / "impact_keywords.yml"),
        "gold": {"n": GOLD_N, "seed": GOLD_SEED},
    }


def _replay_roles() -> set[str]:
    from homelabnext.decide.evalset import EXAMPLES as DECIDE_EXAMPLES
    from homelabnext.decide.spec import load_spec

    spec = load_spec(DECIDE_EXAMPLES / "decision_spec.yml")
    return {normalize_role(t.model_role) for t in spec.tiers if t.model_role}


def inputs_of(table: RoleTable, suite_paths: Sequence[Path]) -> dict:
    """What the report is a function of; any change here makes a stored report stale."""
    pinned = {
        "eval": EVAL_VERSION,
        "pins": table.pins(),
        "suites": {
            load_suite(p).name: _file_digest(p) for p in sorted(suite_paths, key=lambda p: p.name)
        },
        "decide": _decide_inputs(),
    }
    return {**pinned, "digest": _digest(pinned)}


def coverage_problems(table: RoleTable, suites: Sequence[Suite]) -> list[str]:
    """Every role must be evaluated by a golden suite or by the replay gate's cascade."""
    covered = {normalize_role(s.role) for s in suites if s.role} | _replay_roles()
    p = [f"mdl:{r} is pinned but nothing evaluates it" for r in sorted(set(table.roles) - covered)]
    p += [
        f"mdl:{r} is evaluated but not in the role table"
        for r in sorted(covered - set(table.roles))
    ]
    return p


# ---------------------------------------------------------------- run
def run_eval(
    table: RoleTable,
    suite_paths: Sequence[Path],
    factory: CompleterFactory,
    *,
    model_name: str,
    replay_tiers: Mapping[str, Any] | None = None,
) -> dict:
    """Golden suites and the K-12 replay -> one report (no clock: latencies are not stored).

    ``replay_tiers`` replaces the cascade's simulated model tiers (live runs pass ModelTiers).
    """
    from homelabnext.decide.evalset import demo_cascade, generate_gold_set
    from homelabnext.decide.replay import gate, replay

    golden: dict[str, dict] = {}
    for p in sorted(suite_paths, key=lambda p: p.name):
        suite = load_suite(p)
        role = suite.role or ""
        completer, model_id = factory(role)
        rep: Report = run_suite(suite, completer, role=role, model_id=model_id)
        golden[suite.name] = {**rep.to_dict(), "ok": rep.ok}
    cascade = demo_cascade()
    if replay_tiers:
        cascade.tiers.update(replay_tiers)
    rep = replay(generate_gold_set(GOLD_N, GOLD_SEED), cascade)
    g = gate(rep)
    return {
        "format": REPORT_FORMAT,
        "model": {"name": model_name},
        "inputs": inputs_of(table, suite_paths),
        "golden": golden,
        "replay": {"report": rep.to_dict(), "gate": g.to_dict()},
        "summary": {
            "suites": len(golden),
            "suites_passed": sum(v["ok"] for v in golden.values()),
            "replay_passed": g.passed,
            "ok": all(v["ok"] for v in golden.values()) and g.passed,
        },
    }


# ---------------------------------------------------------------- check
def _stale(want: dict, have: Any) -> list[str]:
    if not isinstance(have, dict):
        return ["inputs"]
    out = [k for k in ("eval", "suites", "decide") if have.get(k) != want[k]]
    hp = have.get("pins") if isinstance(have.get("pins"), dict) else {}
    changed = sorted(r for r in set(want["pins"]) | set(hp) if want["pins"].get(r) != hp.get(r))
    out += [f"pin mdl:{r}" for r in changed]
    if not out and have != want:
        out.append("digest")
    return out


def check_report(report: Any, table: RoleTable, suite_paths: Sequence[Path]) -> list[str]:
    """Problems with the pinned table and its stored evaluation report (empty = pass)."""
    suites = [load_suite(p) for p in suite_paths]
    p = table.unpinned() + coverage_problems(table, suites)
    if not isinstance(report, Mapping) or report.get("format") != REPORT_FORMAT:
        return [*p, f"not a {REPORT_FORMAT} report"]
    stale = _stale(inputs_of(table, suite_paths), report.get("inputs"))
    if stale:
        p.append(
            "evaluation report is stale: changed since it was produced: "
            + ", ".join(stale)
            + "; rerun the evaluation (make models-report, and make models-eval live) and commit it"
        )
    s = report.get("summary", {})
    if not s.get("ok"):
        p.append(
            f"evaluation did not pass: {s.get('suites_passed')}/{s.get('suites')} suites, "
            f"replay gate {'passed' if s.get('replay_passed') else 'failed'}"
        )
    return p


def load_report(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dump_report(report: Mapping[str, Any], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
