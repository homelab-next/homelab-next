# SPDX-License-Identifier: Apache-2.0
"""Pinned models and the evaluation they must pass (G-11, with the K-12 replay gate).

Every binding in the role table is pinned by ``version`` and ``digest`` (sha256 of the weights).
The **evaluation report** is a function of those pins, the golden suites and the decision spec
and gold set the replay gate uses (:func:`inputs_of`).  It holds:

* one golden-suite run per suite, against the suite's role;
* the K-12 replay of the synthetic gold set through the change-review cascade, with its gate;
* the egress canary (:mod:`homelabnext.golden.canary`) for **every binding** of every role, each
  entry recording the pin it ran against, the role's sampling params, its ``kind``, the output
  budget it ran at and whether it ran **live** (a real model through the resolver) or against the
  **fake** (:func:`fake_canary_factory`).  A chat binding's budget is the role's own
  ``params.max_tokens`` when it declares one (:func:`canary_budget`): a reasoning model that
  thinks before it answers would otherwise fill the suite's small default with reasoning and
  answer nothing, which the canary must count as inconclusive, so the canary would judge a budget
  the role never runs at.

**Decision roles** (``kind: decision``: a model that answers noul questions on
``POST /v1/systemone`` and refuses chat) are evaluated through a *decider*, never a completer: a
decision suite (``kind: decision``, :func:`homelabnext.golden.runner.run_decision_suite`) scores
each answer against a probability band, and the binding's canary entry is
:func:`homelabnext.golden.canary.run_decision_canary` (``kind: decision``).  A suite applies to
a table only when the table has its role and of its kind (a chat suite to any role but a decision
one, a decision suite to a decision role); one that does not apply is not run, so an overlay that
keeps a subset of the roles, or makes one a decision role, is evaluated by the suites that fit it.
The K-12 replay evaluates the cascade's roles that the table has as chat roles.

``hnx golden pins check`` fails when a binding is unpinned, when a pinned role is evaluated by
nothing, when the stored report is **stale** (a pin, a suite, the spec, the canary's code or the
role params changed since it was produced; the roles whose pins changed are named), when it does
not pass, or when a canary entry does not validate against the current suite and binding
(:func:`canary_problems`: every binding present with its own pin and params, every task present
with at least the suite's samples, the totals and ``ok`` recomputed).  ``--require-live`` also
fails a canary entry that ran against the fake.  So changing a model is: change the pin, rerun
the evaluation, commit the new report with it.

CI runs the evaluation against :class:`FakeGoldenModel`, a deterministic rule-based completer,
and also re-runs it to prove the stored fake report is exactly reproducible.  The fake proves the
harness and the pin tracking, **not** that a model is good: before a real model change, run the
same evaluation live (``make models-eval``: golden suites and replay through the model-role
resolver) and keep that report with the change.  A fake canary passes by construction (the fake
completes each prefilled call harmlessly and otherwise answers), so a fake report satisfies the
default check for any rebind; only ``--require-live`` makes the check refuse a binding no real
canary has run against, and even then the report is evidence a reviewer reads, not a proof (a
committed file can be edited; the check validates its shape, not its provenance).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import Any

from homelabnext import paths
from homelabnext.registry.models import Binding, RoleTable, normalize_role

from .report import Report
from .runner import Completer, Decider, run_decision_suite, run_suite
from .tasks import Suite, load_suite

REPORT_FORMAT = "hnx-model-eval/1"
#: Bump when the evaluation, the scorers or the fake change behaviour: it is a pinned input.
EVAL_VERSION = 3
EXAMPLES = Path(__file__).resolve().parent / "examples"
DEFAULT_SUITES = (EXAMPLES / "classifier_smoke.yml", EXAMPLES / "decision_smoke.yml")
GOLD_N, GOLD_SEED = 200, 7

#: ``completer_for(role) -> (completer, model id)``
CompleterFactory = Callable[[str], "tuple[Completer, str]"]
#: ``canary_for(role, binding) -> (completer, mode)``; the factory, not a model name, says the mode
CanaryFactory = Callable[[str, Binding], "tuple[Completer, str]"]
#: ``decider_for(role) -> (decider, model id)``: a decision suite's
DeciderFactory = Callable[[str], "tuple[Decider, str]"]
#: ``decision_canary_for(role, binding) -> (decider, mode)``: a decision binding's canary
DecisionCanaryFactory = Callable[[str, Binding], "tuple[Decider, str]"]
CANARY_MODES = ("live", "fake")
#: what a canary entry and a suite run are: a chat completion or a decision (noul questions)
EVAL_KINDS = ("chat", "decision")


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


class FakeGoldenDecider:
    """Deterministic CI decider for the shipped decision suite: reads only the state, and answers
    every question with 0.95 when the state names a rollback or a revert (and not
    ``NO-ROLLBACK``), else 0.05.  It proves the harness, not a model."""

    name = "fake-golden-decider"

    def __call__(self, questions: Mapping[str, str], state: str | None) -> dict[str, float]:
        low = (state or "").lower()
        yes = "no-rollback" not in low and ("rollback" in low or "revert" in low)
        return dict.fromkeys(questions, 0.95 if yes else 0.05)


def fake_decider_factory(role: str) -> tuple[Decider, str]:
    return FakeGoldenDecider(), f"{FakeGoldenDecider.name}:{normalize_role(role)}"


def pin_digest(pin: Mapping[str, Any]) -> str:
    """A binding's pin (backend, model id, version, digest) as one digest: what a canary entry
    records, so the report names the binding without repeating its model id."""
    return _digest(dict(pin))


def report_digest(report: Any) -> str:
    """An evaluation report as one digest (canonical JSON, so formatting does not change it): what
    a module swap's model-role leg pins as its evidence."""
    return _digest(report)


def fake_canary_factory(role: str, binding: Binding) -> tuple[Completer, str]:
    """The canary's CI stand-in for every binding: the benign scripted model, marked ``fake``."""
    from .canary import benign_model

    return benign_model, "fake"


def fake_decision_canary_factory(role: str, binding: Binding) -> tuple[Decider, str]:
    """The decision canary's CI stand-in for every decision binding, marked ``fake``."""
    from .canary import benign_decider

    return benign_decider, "fake"


def canary_budget(role: Any, suite: Any) -> int:
    """The output budget (``max_tokens`` per reply) the egress canary gives a chat binding of
    ``role``: the role's own ``params.max_tokens`` when it declares one, else the suite's
    ``max_tokens``.  Every call through the role sends its params, so the canary judges the replies
    the role really gets.  A budget under 16 tokens cannot hold a tool call, and one that does not
    fit the role's ``max_context_tokens`` cannot be served: both are refused (``ValueError``)."""
    params = role.params if isinstance(role.params, Mapping) else {}
    budget = params.get("max_tokens")
    if budget is None:
        return int(suite.max_tokens)
    if isinstance(budget, bool) or not isinstance(budget, int) or budget < 16:
        raise ValueError(f"params.max_tokens {budget!r}: the canary needs an integer of 16 or more")
    ceiling = getattr(role, "max_context_tokens", None)
    if ceiling is not None and budget >= ceiling:
        raise ValueError(
            f"params.max_tokens {budget} does not fit max_context_tokens {ceiling}: "
            "the canary cannot run at it"
        )
    return budget


def eval_kind(role_kind: str) -> str:
    """How a role of ``role_kind`` is evaluated: ``decision`` for a decision role, else ``chat``."""
    return "decision" if role_kind == "decision" else "chat"


def applies(suite: Suite, table: RoleTable) -> bool:
    """Whether ``suite`` evaluates a role of ``table``: a suite with no role applies to any table
    (as a chat suite); one with a role applies when the table has it, a decision suite to a
    decision role and a chat suite to any other."""
    if not suite.role:
        return suite.kind == "chat"
    r = table.roles.get(normalize_role(suite.role))
    return r is not None and eval_kind(r.kind) == suite.kind


# ---------------------------------------------------------------- inputs and coverage
def _decide_inputs() -> dict:
    from homelabnext.decide.evalset import EXAMPLES as DECIDE_EXAMPLES

    return {
        "spec": _file_digest(DECIDE_EXAMPLES / "decision_spec.yml"),
        "impact_keywords": _file_digest(DECIDE_EXAMPLES / "impact_keywords.yml"),
        "gold": {"n": GOLD_N, "seed": GOLD_SEED},
    }


def _replay_roles(table: RoleTable | None = None) -> set[str]:
    """The roles the K-12 replay's cascade names; with ``table``, only those the table has as
    chat roles (a decision role answers no chat, so the cascade's tiers cannot ask it)."""
    from homelabnext.decide.evalset import EXAMPLES as DECIDE_EXAMPLES
    from homelabnext.decide.spec import load_spec

    spec = load_spec(DECIDE_EXAMPLES / "decision_spec.yml")
    roles = {normalize_role(t.model_role) for t in spec.tiers if t.model_role}
    if table is None:
        return roles
    return {r for r in roles if r in table.roles and eval_kind(table.roles[r].kind) == "chat"}


def inputs_of(table: RoleTable, suite_paths: Sequence[Path]) -> dict:
    """What the report is a function of; any change here makes a stored report stale."""
    pinned = {
        "eval": EVAL_VERSION,
        "pins": table.pins(),
        "suites": {
            load_suite(p).name: _file_digest(p) for p in sorted(suite_paths, key=lambda p: p.name)
        },
        "decide": _decide_inputs(),
        "canary": _canary_inputs(table),
        "kinds": {name: r.kind for name, r in sorted(table.roles.items())},
        "code": _code_inputs(),
    }
    return {**pinned, "digest": _digest(pinned)}


def _code_inputs() -> dict:
    """The code that decides a suite's and a decision canary's verdicts (the loader, the runner
    and its ``one_probability``, the scorers, the model client the probes go through), by digest: a change there makes a stored report
    stale even when nobody bumps :data:`EVAL_VERSION` (the canary's own code is in its inputs)."""
    here = Path(__file__).resolve().parent
    out = {name: _file_digest(here / f"{name}.py") for name in ("runner", "scorers", "tasks")}
    # the client the decision canary probes chat with (ModelClient.chat_probe, decide)
    out["registry.models"] = _file_digest(here.parent / "registry" / "models.py")
    return out


def _canary_inputs(table: RoleTable) -> dict:
    from homelabnext.modules.egress import METADATA

    from . import canary

    return {
        "version": canary.CANARY_VERSION,
        "suite": _file_digest(canary.DEFAULT_SUITE),
        "code": _file_digest(Path(canary.__file__)),
        "metadata": _digest(sorted(map(str, METADATA))),
        "params": {name: dict(r.params) for name, r in sorted(table.roles.items())},
    }


def coverage_problems(table: RoleTable, suites: Sequence[Suite]) -> list[str]:
    """Every role must be evaluated by a golden suite of its kind (:func:`applies`) or, a chat
    role, by the replay gate's cascade.  A suite or a cascade tier for a role the table does not
    have is not run (an overlay keeps a subset of the roles), so it is no problem."""
    covered = {normalize_role(s.role) for s in suites if s.role and applies(s, table)}
    covered |= _replay_roles(table)
    return [
        f"mdl:{r} is pinned but nothing evaluates it"
        + (" (a decision role needs a decision suite: kind: decision)"
           if table.roles[r].kind == "decision" else "")
        for r in sorted(set(table.roles) - covered)
    ]  # fmt: skip


# ---------------------------------------------------------------- run
def run_eval(
    table: RoleTable,
    suite_paths: Sequence[Path],
    factory: CompleterFactory,
    *,
    model_name: str,
    replay_tiers: Mapping[str, Any] | None = None,
    canary_factory: CanaryFactory = fake_canary_factory,
    decider_factory: DeciderFactory = fake_decider_factory,
    decision_canary_factory: DecisionCanaryFactory = fake_decision_canary_factory,
) -> dict:
    """Golden suites, the K-12 replay and the egress canary of every binding -> one report (no
    clock: latencies are not stored).

    ``replay_tiers`` replaces the cascade's simulated model tiers (live runs pass ModelTiers);
    ``canary_factory`` gives each binding's canary completer and whether it is live.  A decision
    role goes through ``decider_factory`` (its suites) and ``decision_canary_factory`` (its
    bindings' canary) instead; only the suites that :func:`applies` to the table run.
    """
    from homelabnext.decide.evalset import demo_cascade, generate_gold_set
    from homelabnext.decide.replay import gate, replay

    golden: dict[str, dict] = {}
    for p in sorted(suite_paths, key=lambda p: p.name):
        suite = load_suite(p)
        if not applies(suite, table):
            continue
        role = suite.role or ""
        rep: Report
        if suite.kind == "decision":
            decider, model_id = decider_factory(role)
            rep = run_decision_suite(suite, decider, role=role, model_id=model_id)
        else:
            completer, model_id = factory(role)
            rep = run_suite(suite, completer, role=role, model_id=model_id)
        golden[suite.name] = {**rep.to_dict(), "kind": suite.kind, "ok": rep.ok}
    from .canary import load_suite as load_canary
    from .canary import run_canary, run_decision_canary

    canary_suite = load_canary()
    canary: dict[str, dict] = {}
    for role, r in sorted(table.roles.items()):
        entries = []
        kind = eval_kind(r.kind)
        budget = canary_budget(r, canary_suite) if kind == "chat" else None
        budgeted = replace(canary_suite, max_tokens=budget) if budget else canary_suite
        for b, pin in zip(r.bindings, table.pins()[role], strict=True):
            ident = pin_digest(pin)
            if kind == "decision":
                decider, mode = decision_canary_factory(role, b)
                run_one = partial(run_decision_canary, canary_suite, decider)
            else:
                completer, mode = canary_factory(role, b)
                run_one = partial(run_canary, budgeted, completer)
            if mode not in CANARY_MODES:
                raise ValueError(f"canary factory mode {mode!r}: one of {CANARY_MODES}")
            rep_c = run_one(role=role, model_id=ident)
            entries.append(
                {
                    "backend": pin["backend"],
                    "version": pin["version"],
                    "pin": ident,
                    "params": dict(r.params),
                    "kind": kind,
                    "mode": mode,
                    "report": rep_c,
                    **({"max_tokens": budget} if budget else {}),
                }
            )
        canary[role] = {
            "bindings": entries,
            "ok": all(e["report"]["summary"]["ok"] for e in entries),
        }
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
        "canary": canary,
        "summary": {
            "suites": len(golden),
            "suites_passed": sum(v["ok"] for v in golden.values()),
            "replay_passed": g.passed,
            "canary_passed": sum(c["ok"] for c in canary.values()),
            "ok": all(v["ok"] for v in golden.values())
            and g.passed
            and all(c["ok"] for c in canary.values()),
        },
    }


# ---------------------------------------------------------------- check
def _stale(want: dict, have: Any) -> list[str]:
    if not isinstance(have, dict):
        return ["inputs"]
    out = [
        k for k in ("eval", "suites", "decide", "canary", "kinds", "code") if have.get(k) != want[k]
    ]
    hp = have.get("pins") if isinstance(have.get("pins"), dict) else {}
    changed = sorted(r for r in set(want["pins"]) | set(hp) if want["pins"].get(r) != hp.get(r))
    out += [f"pin mdl:{r}" for r in changed]
    if not out and have != want:
        out.append("digest")
    return out


def check_report(
    report: Any, table: RoleTable, suite_paths: Sequence[Path], *, require_live: bool = False
) -> list[str]:
    """Problems with the pinned table and its stored evaluation report (empty = pass).
    ``require_live``: a canary entry that ran against the fake is a problem too."""
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
    p += canary_problems(report, table, require_live=require_live)
    p += golden_problems(report, table, suites)
    s = report.get("summary", {})
    if not s.get("ok"):
        p.append(
            f"evaluation did not pass: {s.get('suites_passed')}/{s.get('suites')} suites, "
            f"replay gate {'passed' if s.get('replay_passed') else 'failed'}"
        )
    return p


def golden_problems(
    report: Mapping[str, Any], table: RoleTable, suites: Sequence[Suite]
) -> list[str]:
    """The report holds a passing run of exactly the suites that apply to the table
    (:func:`applies`), each of its suite's kind and with every task passed (recounted from its
    tasks), and no run of a suite that does not apply: a suite cannot be left out of a report
    whose summary says ok."""
    golden = report.get("golden")
    if not isinstance(golden, Mapping):
        return ["the report has no golden suite runs"]
    want = {s.name: s for s in suites if applies(s, table)}
    out = [f"golden suite {n}: not in the report; it applies to this table" for n in sorted(
        set(want) - set(golden))]  # fmt: skip
    out += [
        f"golden suite {n}: in the report, but it does not apply to this table"
        for n in sorted(set(golden) - set(want))
    ]
    for name in sorted(set(want) & set(golden)):
        g = golden[name]
        tasks = g.get("tasks") if isinstance(g, Mapping) else None
        if not isinstance(tasks, list):
            out.append(f"golden suite {name}: malformed")
            continue
        if g.get("kind", "chat") != want[name].kind:
            out.append(
                f"golden suite {name}: ran as {g.get('kind', 'chat')!r}, the suite is "
                f"{want[name].kind!r}; rerun it"
            )
        ids = [t.get("id") for t in tasks if isinstance(t, Mapping)]
        if sorted(map(str, ids)) != sorted(t.id for t in want[name].tasks):
            out.append(f"golden suite {name}: its tasks are not the suite's; rerun it")
        failed = [
            str(t.get("id"))
            for t in tasks
            if not (isinstance(t, Mapping) and t.get("passed") is True)
        ]
        summary = report.get("summary")
        if (
            (failed or g.get("ok") is not True)
            and isinstance(summary, Mapping)
            and summary.get("ok")
        ):
            out.append(
                f"golden suite {name}: did not pass ({', '.join(failed) or 'not ok'}), but the "
                "summary says ok"
            )
    return out


def canary_problems(
    report: Mapping[str, Any], table: RoleTable, *, require_live: bool = False
) -> list[str]:
    """The rebind gate: every binding of every role has an egress canary entry that validates
    against the current suite, code and binding, and passed (recomputed, never read from the
    entry); with ``require_live``, every entry ran live."""
    from . import canary as cn

    suite = cn.load_suite(cn.DEFAULT_SUITE)
    canary = report.get("canary") if isinstance(report.get("canary"), Mapping) else {}
    pins = table.pins()
    out: list[str] = [
        f"mdl:{role}: a canary entry for a role the table does not have; the report is not this "
        "table's"
        for role in sorted(set(map(str, canary)) - set(table.roles))
    ]
    for role, r in sorted(table.roles.items()):
        c = canary.get(role)
        entries = c.get("bindings") if isinstance(c, Mapping) else None
        if not isinstance(entries, list):
            out.append(f"mdl:{role}: no egress canary in the report; every binding must pass it")
            continue
        if len(entries) != len(pins[role]):
            out.append(
                f"mdl:{role}: {len(entries)} canary entries for {len(pins[role])} binding(s); "
                "every binding must be canaried"
            )
        for pin, e in zip(pins[role], entries, strict=False):
            where = f"mdl:{role} -> {pin['backend']} {pin['model_id']}"
            out += [f"{where}: {p}" for p in _entry_problems(e, pin, dict(r.params), suite)]
            if eval_kind(r.kind) == "chat" and isinstance(e, Mapping):
                try:
                    want = canary_budget(r, suite)
                except ValueError as exc:
                    out.append(f"{where}: {exc}")
                else:
                    if e.get("max_tokens", suite.max_tokens) != want:
                        out.append(
                            f"{where}: the canary ran at an output budget of "
                            f"{e.get('max_tokens', suite.max_tokens)} tokens, the role's is {want}; "
                            "rerun it"
                        )
            if isinstance(e, Mapping) and e.get("kind", "chat") != eval_kind(r.kind):
                out.append(
                    f"{where}: the canary ran as a {e.get('kind', 'chat')!r} binding, the role is "
                    f"{eval_kind(r.kind)!r}; rerun it"
                )
            if require_live and isinstance(e, Mapping) and e.get("mode") != "live":
                out.append(
                    f"{where}: the canary ran against the {e.get('mode')!r} model; a live run is "
                    "required (make models-eval, then commit its report)"
                )
    return out


def _entry_problems(e: Any, pin: dict, params: dict, suite: Any) -> list[str]:
    from . import canary as cn

    if not isinstance(e, Mapping) or not isinstance(e.get("report"), Mapping):
        return ["not a canary entry"]
    out: list[str] = []
    if e.get("pin") != pin_digest(pin) or (e.get("backend"), e.get("version")) != (
        pin["backend"],
        pin["version"],
    ):
        out.append("the canary ran against a different pin; rerun it for this binding")
    if e.get("params") != params:
        out.append("the canary ran with different role params; rerun it")
    if e.get("mode") not in CANARY_MODES:
        out.append(f"canary mode {e.get('mode')!r}: one of {CANARY_MODES}")
    rep = e["report"]
    want = {
        "format": cn.REPORT_FORMAT,
        "version": cn.CANARY_VERSION,
        "suite": suite.name,
        "model_id": pin_digest(pin),
    }
    out += [
        f"canary {k} {rep.get(k)!r}, expected {v!r}" for k, v in want.items() if rep.get(k) != v
    ]
    tasks = rep.get("tasks")
    if not isinstance(tasks, Mapping):
        return [*out, "the canary report has no tasks"]
    ids = {t.id for t in suite.tasks}
    shape: list[str] = []
    if missing := sorted(ids - set(tasks)):
        shape.append(f"canary tasks missing: {', '.join(missing)}")
    if extra := sorted(set(tasks) - ids):
        shape.append(f"canary tasks not in the suite: {', '.join(extra)}")
    for tid in sorted(ids & set(tasks)):
        t = tasks[tid]
        n = t.get("samples") if isinstance(t, Mapping) else None
        f = t.get("failed") if isinstance(t, Mapping) else None
        if not (
            isinstance(n, int) and isinstance(f, int) and isinstance(t.get("findings"), Mapping)
        ):
            shape.append(f"canary task {tid}: malformed")
        elif n < suite.samples:
            shape.append(f"canary task {tid}: {n} samples, the suite asks for {suite.samples}")
        elif not 0 <= f <= n:
            shape.append(f"canary task {tid}: {f} failed of {n} samples")
        else:
            shape += [f"canary task {tid}: {p}" for p in _task_problems(t, f)]
    if shape:
        return out + shape
    s = cn.summarise(tasks)
    if rep.get("summary") != s:
        out.append("the canary summary does not match its tasks")
    if not s["ok"]:
        out.append(
            f"the egress canary failed {s['failed']}/{s['samples']} samples; this binding may "
            "not be bound (hnx golden canary for the findings)"
        )
    return out


def _task_problems(t: Mapping[str, Any], failed: int) -> list[str]:
    """A task's finding counts and kept failures agree with its ``failed`` count (a sample's
    kinds are counted once per sample, and the first failing samples are kept in full)."""
    from .canary import KEEP_FAILURES

    found, kept = t["findings"], t.get("failures")
    if not isinstance(kept, list):
        return ["failures: not a list"]
    out = []
    if failed == 0:
        if found:
            out.append("findings counted, but no sample failed")
        if kept:
            out.append("failing samples kept, but no sample failed")
        return out
    if not found:
        out.append(f"{failed} failed, but no finding is counted")
    bad = sorted(k for k, n in found.items() if not (isinstance(n, int) and 1 <= n <= failed))
    if bad:
        out.append(f"finding counts out of range 1..{failed}: {', '.join(map(str, bad))}")
    if len(kept) != min(failed, KEEP_FAILURES):
        out.append(
            f"{len(kept)} failing samples kept for {failed} failed "
            f"(expected {min(failed, KEEP_FAILURES)})"
        )
    elif not all(isinstance(k, Mapping) and (k.get("findings") or k.get("error")) for k in kept):
        out.append("a kept failing sample names no finding and no error")
    return out


def _example_pins() -> Any:
    """The shipped example role table's pins, which mark a report as the repository's own CI
    example; None when no example table is installed (then no table is the example)."""
    try:
        return RoleTable.load(paths.example_file("model_roles.json")).pins()
    except paths.ResourceNotFound:
        return None


def fake_canary_on_a_real_table(report: Any, table: RoleTable) -> str | None:
    """A problem when the table is not the shipped example (its pins differ) and every canary
    entry in the report ran against the fake: a real lab's check then proves nothing about its
    models, so it must check a live report with ``--require-live``.  None otherwise."""
    example = _example_pins()
    if example is not None and example == table.pins():
        return None
    canary = report.get("canary") if isinstance(report, Mapping) else None
    entries = [
        e
        for c in (canary.values() if isinstance(canary, Mapping) else ())
        if isinstance(c, Mapping) and isinstance(c.get("bindings"), list)
        for e in c["bindings"]
    ]
    if entries and all(isinstance(e, Mapping) and e.get("mode") == "fake" for e in entries):
        return (
            "this role table is not the shipped example, and every egress canary in the report "
            "ran against the fake; run the evaluation live (make models-eval) and check that "
            "report with --require-live (MODELS_CHECK_FLAGS=--require-live)"
        )
    return None


def load_report(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dump_report(report: Mapping[str, Any], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
