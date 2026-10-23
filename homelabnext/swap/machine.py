# SPDX-License-Identifier: Apache-2.0
"""The swap state machine: nine steps, each with pre-conditions, an action, post-conditions, a
dry-run and an evidence artefact; every transition is written to the swap record.

Guarantees (each has a test):

* Steps run strictly in order; ``advance`` only ever works on ``current_step``.
* A failed pre- or post-condition **refuses to advance**: the step stays unfinished, the failure is
  recorded (transition ``gate-failed``, evidence artefact written) and :class:`GateFailed` is
  raised. Re-running ``advance`` retries the same step.
* ``--dry-run`` evaluates pre-conditions and describes the action; it writes nothing.
* The cutover is atomic: if its post-conditions fail, the previous route is restored at once
  (transition ``cutover-reverted``) so ``route.flipped`` is true only while the cutover holds.
* ``rollback`` is allowed at any point before ``decommission-check`` has passed; it restores the
  prior route, restarts the old component, stops the mirror and records the reason.
* The record is validated against its schema before every write and written atomically.
* Time is injected (``clock``); nothing here reads the wall clock, the network or the registry
  except through the :class:`~homelabnext.swap.backend.Backend`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import record as rec
from .backend import Backend, Outcome
from .record import STEPS

Clock = Callable[[], datetime]
ADR_REF = re.compile(r"^docs/adr/[0-9]{4}-[a-z0-9-]+\.md$")


class SwapError(Exception):
    """Base class of runner errors."""


class GateFailed(SwapError):
    def __init__(self, result: AdvanceResult):
        self.result = result
        bad = [f"{g.phase}:{g.id}: {g.detail}" for g in result.gates if not g.passed]
        super().__init__(f"step {result.step!r} refused to advance: " + "; ".join(bad))


class RollbackRefused(SwapError):
    """Rollback is not possible (swap not active, or decommission already passed)."""


@dataclass(frozen=True)
class Gate:
    id: str
    phase: str  # pre | post
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "phase": self.phase,
            "passed": self.passed,
            "detail": self.detail[:500],
        }


@dataclass
class AdvanceResult:
    step: str
    passed: bool
    gates: list[Gate]
    dry_run: bool = False
    plan: list[str] = field(default_factory=list)
    evidence_ref: str | None = None
    next_step: str | None = None
    reverted: bool = False


@dataclass
class StepSpec:
    name: str
    title: str
    pre: str  # human text for `plan` and docs
    action: str
    post: str
    evidence_kind: str


STEP_SPECS: dict[str, StepSpec] = {
    s.name: s
    for s in (
        StepSpec(
            "declare",
            "Declare the swap and prove the incumbent",
            "from and to adapters differ; route before and after differ",
            "run the incumbent's conformance suite and record the route before the flip",
            "incumbent conformance passes",
            "incumbent-conformance",
        ),
        StepSpec(
            "shadow-start",
            "Stand the candidate up beside the incumbent",
            "declare passed",
            "run the candidate's conformance suite; start it in shadow mode and backfill history",
            "candidate conformance passes; shadow is running",
            "candidate-conformance",
        ),
        StepSpec(
            "dual-write",
            "Mirror production writes to both",
            "shadow-start passed",
            "start the mirror (same idempotency keys on both sides; the incumbent never blocks)",
            "mirror running; unresolved divergences within budget",
            "mirror-status",
        ),
        StepSpec(
            "parity-compare",
            "Compare results between the two",
            "dual-write passed",
            "run the parity tools (query results, tables, events, notifications)",
            "parity holds on at least the configured number of rows; divergences within budget",
            "parity-report",
        ),
        StepSpec(
            "soak",
            "Soak for the declared window",
            "parity-compare passed and plan.soak_hours have elapsed since it passed",
            "re-run parity at the end of the window",
            "parity still holds; divergences within budget",
            "soak-parity",
        ),
        StepSpec(
            "cutover",
            "Cut over: flip the registry alias",
            "soak passed",
            "apply the flip (one registry row), run the canary, stop the old component",
            "route applied; canary green. On failure the old route is restored at once",
            "cutover",
        ),
        StepSpec(
            "rollback-window",
            "Hold the rollback window",
            "cutover passed and plan.rollback_window_hours have elapsed since it passed",
            "re-verify the route; stop the mirror (forward-only from here)",
            "canary green; old component retained (stopped, not destroyed); mirror stopped",
            "window-check",
        ),
        StepSpec(
            "decommission-check",
            "Decommission check",
            "rollback-window passed",
            "scan registry, inventory, tree for references to the retired component",
            "no references remain",
            "decommission-scan",
        ),
        StepSpec(
            "close",
            "Record and close",
            "decommission-check passed; an ADR reference is supplied",
            "write the closure (ADR reference, optional lesson reference)",
            "closure recorded; swap closed",
            "closure",
        ),
    )
}


def utcnow() -> datetime:
    return datetime.now(UTC)


class _Ctx:
    def __init__(self, doc: dict[str, Any], backend: Backend, now: datetime, closure: dict | None):
        self.doc = doc
        self.backend = backend
        self.now = now
        self.closure = closure or {}
        self.details: dict[str, Any] = {}

    @property
    def plan(self) -> dict[str, Any]:
        return self.doc["plan"]

    def step(self, name: str) -> dict[str, Any]:
        return next(s for s in self.doc["steps"] if s["name"] == name)

    def elapsed_since(self, step: str) -> timedelta:
        done = self.step(step).get("finished_at")
        return self.now - rec.parse_stamp(done) if done else timedelta(0)


def _g(phase: str, gid: str, ok: bool, detail: str = "") -> Gate:
    return Gate(gid, phase, bool(ok), detail)


def _out(
    phase: str, gid: str, o: Outcome, store: dict[str, Any] | None = None, key: str = ""
) -> Gate:
    if store is not None:
        store[key or gid] = {"ok": o.ok, "detail": o.detail, "data": o.data}
    return Gate(gid, phase, o.ok, o.detail)


def _safe(fn: Callable[[], Outcome]) -> Outcome:
    try:
        return fn()
    except NotImplementedError as exc:
        return Outcome(False, f"not implemented: {exc}")
    except Exception as exc:
        return Outcome(False, f"{type(exc).__name__}: {exc}")


def _window(ctx: _Ctx, since: str, hours: float, gid: str) -> Gate:
    need = timedelta(hours=hours)
    got = ctx.elapsed_since(since)
    if got >= need:
        return _g("pre", gid, True, f"{got} elapsed (needs {need})")
    return _g("pre", gid, False, f"{need - got} still to wait (needs {need} since {since} passed)")


# ---------------------------------------------------------------- per-step logic
def _pre(ctx: _Ctx, name: str) -> list[Gate]:
    d = ctx.doc
    if name == "declare":
        return [
            _g("pre", "adapters-differ", d["from_adapter"] != d["to_adapter"]),
            _g(
                "pre",
                "route-changes",
                d["route"]["before"] != d["route"]["after"],
                "the flip would change nothing"
                if d["route"]["before"] == d["route"]["after"]
                else "",
            ),
        ]
    if name == "soak":
        return [_window(ctx, "parity-compare", float(ctx.plan["soak_hours"]), "soak-elapsed")]
    if name == "rollback-window":
        return [_window(ctx, "cutover", float(ctx.plan["rollback_window_hours"]), "window-elapsed")]
    if name == "close":
        ref = ctx.closure.get("adr_ref")
        ok = isinstance(ref, str) and bool(ADR_REF.match(ref))
        return [
            _g(
                "pre",
                "adr-reference",
                ok,
                "" if ok else "give the ADR that records the product pick: docs/adr/NNNN-slug.md",
            )
        ]
    return []


def _run_and_post(ctx: _Ctx, name: str) -> list[Gate]:
    """Run the step's action and return its post-condition gates (also fills ctx.details)."""
    b, plan, d = ctx.backend, ctx.plan, ctx.details
    gates: list[Gate] = []
    if name == "declare":
        gates.append(
            _out("post", "incumbent-conformance", _safe(lambda: b.conformance("old")), d, "old")
        )
    elif name == "shadow-start":
        gates.append(
            _out("post", "candidate-conformance", _safe(lambda: b.conformance("new")), d, "new")
        )
        gates.append(_out("post", "shadow-started", _safe(b.shadow_start), d, "shadow"))
    elif name == "dual-write":
        gates.append(_out("post", "mirror-running", _safe(b.start_mirror), d, "mirror"))
        gates.append(_divergence_gate(ctx))
    elif name in ("parity-compare", "soak"):
        p = _safe(b.parity)
        gates.append(_out("post", "parity-holds", p, d, "parity"))
        if name == "parity-compare":
            rows = int(p.data.get("rows_compared", 0)) if p.ok else 0
            need = int(plan["min_parity_rows"])
            gates.append(
                _g("post", "enough-rows", rows >= need, f"{rows} rows compared (needs >= {need})")
            )
        gates.append(_divergence_gate(ctx))
    elif name == "cutover":
        gates += _cutover(ctx)
    elif name == "rollback-window":
        target = ctx.doc["route"]["after"]
        gates.append(
            _out("post", "canary-green", _safe(lambda: b.verify_route(target)), d, "canary")
        )
        st = _safe(b.old_state)
        retained = st.ok and st.data.get("state") == "stopped"
        d["old_state"] = {"ok": st.ok, "detail": st.detail, "data": st.data}
        gates.append(
            _g("post", "old-retained", retained, f"old component state: {st.data.get('state')}")
        )
        gates.append(_out("post", "mirror-stopped", _safe(b.stop_mirror), d, "stop_mirror"))
    elif name == "decommission-check":
        gates.append(_out("post", "no-references", _safe(b.decommission_scan), d, "scan"))
    elif name == "close":
        d["closure"] = dict(ctx.closure)
        gates.append(_g("post", "closure-recorded", True, str(ctx.closure.get("adr_ref"))))
    return gates


def _divergence_gate(ctx: _Ctx) -> Gate:
    st = _safe(ctx.backend.mirror_status)
    ctx.details["mirror_status"] = {"ok": st.ok, "detail": st.detail, "data": st.data}
    budget = int(ctx.plan["max_divergences"])
    unresolved = int(st.data.get("unresolved", 0)) if st.ok else -1
    ok = st.ok and unresolved <= budget
    return _g(
        "post",
        "divergences-within-budget",
        ok,
        st.detail or f"{unresolved} unresolved (budget {budget})",
    )


def _cutover(ctx: _Ctx) -> list[Gate]:
    b, d = ctx.backend, ctx.details
    before, after = ctx.doc["route"]["before"], ctx.doc["route"]["after"]
    applied = _safe(lambda: b.apply_route(after))
    gates = [_out("post", "route-applied", applied, d, "apply")]
    if not applied.ok:
        return gates
    ctx.doc["route"]["flipped"] = True
    canary = _safe(lambda: b.verify_route(after))
    gates.append(_out("post", "canary-green", canary, d, "canary"))
    if canary.ok:
        stopped = _safe(b.stop_old)
        gates.append(_out("post", "old-stopped", stopped, d, "stop_old"))
        if stopped.ok:
            return gates
    # a failed post-condition: put the old route (and the old component) back at once
    started = _safe(b.start_old)  # first, so the old component runs when it is primary again
    back = _safe(lambda: b.apply_route(before))
    d["revert"] = {
        "ok": back.ok,
        "detail": back.detail,
        "start_old": {"ok": started.ok, "detail": started.detail},
    }
    if back.ok:
        ctx.doc["route"]["flipped"] = False
        ctx.details["reverted"] = True
        if not started.ok:
            gates.append(_g("post", "revert", False, f"old route restored, but {started.detail}"))
    else:
        # the route stays on the candidate: stop the old component again, as cutover left it
        stopped = _safe(b.stop_old)
        d["revert"]["stop_old"] = {"ok": stopped.ok, "detail": stopped.detail}
        why = f"could not restore the old route: {back.detail}"
        if not started.ok:
            why += f"; {started.detail}"
        gates.append(_g("post", "revert", False, why))
    return gates


def _describe(ctx: _Ctx, name: str) -> list[str]:
    spec = STEP_SPECS[name]
    lines = [f"action: {spec.action}", f"post: {spec.post}"]
    if name == "cutover":
        o = _safe(lambda: ctx.backend.preview_route(ctx.doc["route"]["after"]))
        lines.append(o.detail.rstrip() if o.ok else f"flip preview unavailable: {o.detail}")
    return lines


# ---------------------------------------------------------------- the runner
class SwapRunner:
    def __init__(
        self,
        record_path: str | Path,
        backend: Backend,
        *,
        evidence_dir: str | Path | None = None,
        clock: Clock = utcnow,
        actor: str = "operator",
    ):
        self.path = Path(record_path)
        self.backend = backend
        self.clock = clock
        self.actor = actor
        self._evidence_dir = Path(evidence_dir) if evidence_dir else None

    # ---------------------------------------------------------------- creation / reading
    @classmethod
    def create(
        cls,
        record_path: str | Path,
        backend: Backend,
        *,
        swap_id: str,
        capability: str,
        from_adapter: str,
        to_adapter: str,
        service: str,
        before: dict[str, Any],
        after: dict[str, Any],
        plan: dict[str, Any] | None = None,
        registry: str | None = None,
        evidence_dir: str | Path | None = None,
        clock: Clock = utcnow,
        actor: str = "operator",
    ) -> SwapRunner:
        if Path(record_path).exists():
            raise SwapError(f"{record_path} already exists; refusing to overwrite a swap record")
        now = rec.stamp(clock())
        doc = rec.new_record(
            swap_id=swap_id,
            capability=capability,
            from_adapter=from_adapter,
            to_adapter=to_adapter,
            service=service,
            before=before,
            after=after,
            now=now,
            actor=actor,
            plan=plan,
            registry=registry,
        )
        rec.save(record_path, doc)
        return cls(record_path, backend, evidence_dir=evidence_dir, clock=clock, actor=actor)

    def record(self) -> dict[str, Any]:
        return rec.load(self.path)

    @property
    def evidence_dir(self) -> Path:
        if self._evidence_dir is not None:
            return self._evidence_dir
        return self.path.parent / (self.record()["swap_id"] + ".evidence")

    def status(self) -> dict[str, Any]:
        d = self.record()
        return {
            "swap_id": d["swap_id"],
            "status": d["status"],
            "current_step": d["current_step"],
            "flipped": d["route"]["flipped"],
            "steps": {s["name"]: s["status"] for s in d["steps"]},
            "transitions": len(d["transitions"]),
        }

    # ---------------------------------------------------------------- advance
    def advance(
        self, *, dry_run: bool = False, closure: dict[str, Any] | None = None
    ) -> AdvanceResult:
        doc = self.record()
        if doc["status"] != "active":
            raise SwapError(f"swap {doc['swap_id']} is {doc['status']}; nothing to advance")
        name = doc["current_step"]
        now = self.clock()
        ctx = _Ctx(doc, self.backend, now, closure)
        pre = _pre(ctx, name)
        if dry_run:
            return AdvanceResult(
                name, all(g.passed for g in pre), pre, dry_run=True, plan=_describe(ctx, name)
            )

        step = ctx.step(name)
        step["attempts"] += 1
        step.setdefault("started_at", rec.stamp(now))
        gates = list(pre)
        if all(g.passed for g in pre):
            gates += _run_and_post(ctx, name)
        ok = all(g.passed for g in gates)
        reverted = bool(ctx.details.get("reverted"))

        ref = self._write_evidence(
            doc, name, step["attempts"], rec.stamp(now), ok, gates, ctx.details
        )
        step["evidence"].append(ref)
        step["gates"] = [g.to_dict() for g in gates]
        at = rec.stamp(now)
        nxt: str | None = None
        if ok:
            step["status"] = "passed"
            step["finished_at"] = at
            i = STEPS.index(name)
            if name == "close":
                doc["status"] = "closed"
                doc["current_step"] = None
                doc["closure"] = {
                    "at": at,
                    **{k: ctx.closure[k] for k in ("adr_ref", "lesson_ref") if ctx.closure.get(k)},
                }
            else:
                nxt = STEPS[i + 1]
                doc["current_step"] = nxt
            rec.append_transition(
                doc, at=at, event="step-passed", step=name, actor=self.actor, note=ref["summary"]
            )
            if name == "close":
                rec.append_transition(
                    doc, at=at, event="closed", step="close", actor=self.actor, note="swap closed"
                )
        else:
            step["status"] = "failed"
            failed = "; ".join(f"{g.id}: {g.detail}" for g in gates if not g.passed)
            if reverted:
                rec.append_transition(
                    doc,
                    at=at,
                    event="cutover-reverted",
                    step=name,
                    actor=self.actor,
                    note="post-conditions failed; old route restored",
                )
            rec.append_transition(
                doc, at=at, event="gate-failed", step=name, actor=self.actor, note=failed
            )
        rec.save(self.path, doc)
        result = AdvanceResult(
            name, ok, gates, evidence_ref=ref["ref"], next_step=nxt, reverted=reverted
        )
        if not ok:
            raise GateFailed(result)
        return result

    def _write_evidence(
        self,
        doc: dict[str, Any],
        name: str,
        attempt: int,
        at: str,
        ok: bool,
        gates: list[Gate],
        details: dict[str, Any],
    ) -> dict[str, Any]:
        body = {
            "swap_id": doc["swap_id"],
            "step": name,
            "attempt": attempt,
            "at": at,
            "ok": ok,
            "gates": [g.to_dict() for g in gates],
            "details": details,
        }
        text = json.dumps(body, indent=2, sort_keys=True, default=str) + "\n"
        d = self._evidence_dir or self.path.parent / (doc["swap_id"] + ".evidence")
        d.mkdir(parents=True, exist_ok=True)
        fname = f"{name}.{attempt:02d}.json"
        (d / fname).write_text(text, encoding="utf-8")
        failed = [g.id for g in gates if not g.passed]
        summary = (
            f"{name} passed ({len(gates)} gates)"
            if ok
            else f"{name} refused: failed {', '.join(failed)}"
        )
        return {
            "kind": STEP_SPECS[name].evidence_kind,
            "ref": fname,
            "sha256": rec.sha256_text(text),
            "summary": summary,
        }

    # ---------------------------------------------------------------- rollback / notes
    def rollback(self, reason: str, *, abandon_parked: bool = False) -> dict[str, Any]:
        """Restore the prior route.  Writes parked for the old component are replayed into it
        first; while one is refused the rollback stops (and the old component is stopped again).
        ``abandon_parked`` drops those writes on purpose: they are listed, rows included, in the
        rollback evidence."""
        doc = self.record()
        reason = (reason or "").strip()
        if doc["status"] != "active":
            raise RollbackRefused(
                f"swap is {doc['status']}; only an active swap can be rolled back"
            )
        if self._passed(doc, "decommission-check"):
            raise RollbackRefused(
                "decommission-check has passed: the old component is gone, so there is nothing to "
                "roll back to; plan a new swap instead"
            )
        if len(reason) < 10:
            raise RollbackRefused("a rollback needs a reason of at least 10 characters")
        now = rec.stamp(self.clock())
        before = doc["route"]["before"]
        was_flipped = doc["route"]["flipped"]
        actions: list[str] = []
        problems: list[str] = []

        def do(label: str, fn: Callable[[], Outcome], required: bool = True) -> None:
            o = _safe(fn)
            first = o.detail.splitlines()[0] if o.detail else ""
            actions.append(
                f"{label}: {'ok' if o.ok else 'FAILED'}" + (f" ({first})" if first else "")
            )
            if required and not o.ok:
                problems.append(f"{label}: {o.detail}")

        # start the old component first: its parked writes replay while it is still secondary,
        # and it is never primary while stopped (a write in between would fail)
        from_step = doc["current_step"]
        step = next(s for s in doc["steps"] if s["name"] == from_step)
        if abandon_parked:
            first = _safe(self.backend.start_old)
            do("start old component", lambda: first, required=False)
            if not first.ok:
                gone = _safe(lambda: self.backend.discard_parked(reason))
                do("abandon parked writes", lambda: gone)
                dropped = list(gone.data.get("discarded") or [])
                if dropped:  # (also those dropped before the old component became unreachable)
                    # the dropped rows are evidence at once, before any later step can fail
                    fname = self._evidence(
                        doc, step, "abandoned-parked", "abandon",
                        {"swap_id": doc["swap_id"], "from_step": from_step, "reason": reason,
                         "at": now, "abandoned_parked": dropped},
                        f"{len(dropped)} parked writes abandoned for the rollback",
                    )  # fmt: skip
                    rec.append_transition(
                        doc, at=now, event="note", step=from_step, actor=self.actor,
                        note=f"rollback abandoned {len(dropped)} parked writes ({fname})",
                    )  # fmt: skip
                    rec.save(self.path, doc)
                do("start old component", self.backend.start_old)
        else:
            do("start old component", self.backend.start_old)
        restored = False
        if was_flipped:
            before_n = len(problems)
            do("restore route", lambda: self.backend.apply_route(before))
            restored = len(problems) == before_n
        do("verify route", lambda: self.backend.verify_route(before))
        do("stop mirror", self.backend.stop_mirror, required=False)
        if problems and was_flipped and not restored:
            # the route stays on the candidate: put the old component back as cutover left it
            do("stop old component again", self.backend.stop_old, required=False)
        if problems:
            rec.append_transition(
                doc,
                at=now,
                event="note",
                step=doc["current_step"],
                actor=self.actor,
                # the actions first (an abandon among them), so the 500-character note keeps them
                note="rollback incomplete; actions: " + "; ".join(actions),
            )
            rec.save(self.path, doc)
            raise SwapError("rollback incomplete, fix and retry: " + "; ".join(problems))
        body = {
            "swap_id": doc["swap_id"],
            "from_step": from_step,
            "reason": reason,
            "actions": actions,
            "at": now,
        }
        self._evidence(doc, step, "rollback", "rollback", body, f"rolled back from {from_step}")
        doc["rollback"] = {
            "at": now,
            "from_step": from_step,
            "reason": reason[:500],
            "restored_route": was_flipped,
            "actions": [a[:200] for a in actions],
        }
        doc["status"] = "rolled_back"
        doc["current_step"] = None
        doc["route"]["flipped"] = False
        rec.append_transition(
            doc, at=now, event="rolled-back", step=from_step, actor=self.actor, note=reason
        )
        rec.save(self.path, doc)
        return doc

    def _evidence(
        self,
        doc: dict[str, Any],
        step: dict[str, Any],
        kind: str,
        prefix: str,
        body: dict[str, Any],
        summary: str,
    ) -> str:
        """Write ``body`` as an evidence file (``0600``: it may hold rows) and hash it into
        ``step``'s evidence; returns the file name."""
        from homelabnext.state import atomic_write_text

        text = json.dumps(body, indent=2, sort_keys=True) + "\n"
        d = self._evidence_dir or self.path.parent / (doc["swap_id"] + ".evidence")
        d.mkdir(parents=True, exist_ok=True)
        fname = f"{prefix}.{len(doc['transitions']) + 1:03d}.json"
        atomic_write_text(d / fname, text, mode=0o600)
        step["evidence"].append(
            {"kind": kind, "ref": fname, "sha256": rec.sha256_text(text), "summary": summary}
        )
        return fname

    def note(self, text: str) -> None:
        doc = self.record()
        rec.append_transition(
            doc,
            at=rec.stamp(self.clock()),
            event="note",
            step=doc["current_step"],
            actor=self.actor,
            note=text,
        )
        rec.save(self.path, doc)

    @staticmethod
    def _passed(doc: dict[str, Any], name: str) -> bool:
        return any(s["name"] == name and s["status"] == "passed" for s in doc["steps"])


def plan_text(doc: dict[str, Any] | None = None) -> str:
    """The nine-step checklist as text (for `hnx swap plan` and docs)."""
    out = []
    for i, name in enumerate(STEPS, 1):
        s = STEP_SPECS[name]
        mark = ""
        if doc is not None:
            st = next(x["status"] for x in doc["steps"] if x["name"] == name)
            mark = f" [{st}]"
        out.append(f"{i}. {name}{mark}: {s.title}")
        out.append(f"     pre:  {s.pre}")
        out.append(f"     do:   {s.action}")
        out.append(f"     post: {s.post}")
        out.append(f"     evidence: {s.evidence_kind}")
    return "\n".join(out) + "\n"
