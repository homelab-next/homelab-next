# SPDX-License-Identifier: Apache-2.0
"""What the two Python actions of the rendered StackStorm pack run (``docs/stackstorm.md``).

StackStorm decides *when* a workflow pack runs; this module is *what* one run does, with the same
semantics as the offline runner (:mod:`homelabnext.workflows.runner`), so a pack behaves on
StackStorm the way its fixtures say.  The rendered pack's ``admit.py`` and ``step.py`` are
two-line shims over :func:`admit` and :func:`step`; nothing else runs on StackStorm.

:func:`admit` (the first task of every rendered workflow):

* builds the ``homelabnext.schedule.fired`` event for a CronTimer firing (its id derives from the
  schedule and the firing time, so a re-fired timer is the same event), or takes the webhook body;
* validates the event against its schema and re-checks the pack's own trigger - defence in depth
  behind the rule's criteria, and the one place the trigger semantics live;
* **coalesces**: with ``coalesce = {key, window_s}`` the first event of a key opens a window in the
  StackStorm datastore (``homelabnext.coalesce.<hash>``, TTL ``window_s``); every later event of
  that key inside the window ends the run ``coalesced`` before any step runs.  The datastore has no
  compare-and-set, so two events in the same instant can both pass: the bound that holds anyway is
  the controller's idempotency key and the pack's own trigger (``docs/stackstorm.md``).

:func:`step` runs one pack step:

* a step whose ``when`` does not hold is skipped (output ``null``), exactly as offline;
* ``enrich`` ``pick`` / ``extract-iocs`` are computed (pure functions of the event);
* ``action`` builds the broker request with :func:`runner.action_request` - the same request id
  and digest ``hnx workflows run`` prints.  In ``shadow`` mode that request is recorded with
  result ``shadow`` and **nothing is sent**.  In ``live`` mode it goes to the broker's Unix socket:
  a risky action (the broker manifest's ``execute``/``privileged`` tier or ``requires_approval``)
  is *submitted* - the broker holds it and emits ``homelabnext.decision.requested`` - and any other
  action is *called*.  StackStorm holds no credential for any target; the broker decides, runs the
  pinned handler and audits.
* ``lookup``, ``decide`` and ``prompt`` steps are not run on StackStorm yet; the renderer refuses a
  pack that has one (``st2-step``), so :class:`UnsupportedStep` here is a defect, not a path.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from conformance.protocols.broker import Denied
from homelabnext.broker import request_digest
from homelabnext.events.envelope import build_event, event_problems

from .runner import _enrich, action_request, holds, resolve, triggered

SCHEDULE_EVENT = "homelabnext.schedule.fired"
SCHEDULE_SOURCE = "svc:automation"
ST2_ENRICH_OPS = ("pick", "extract-iocs")
ST2_STEP_KINDS = ("enrich", "action")
MODES = ("shadow", "live")
SHADOW_REASON = "st2-shadow"
COALESCE_PREFIX = "homelabnext.coalesce."


class UnsupportedStep(ValueError):
    """A step kind the StackStorm runtime does not run (the renderer refuses such packs)."""


class KeyValue(Protocol):
    def get(self, name: str) -> str | None: ...
    def set(self, name: str, value: str, ttl: int) -> None: ...


class Broker(Protocol):
    def call(
        self, action: str, params: Mapping[str, Any] | None = None, *, target: str | None = None
    ) -> Any: ...
    def submit(
        self, action: str, params: Mapping[str, Any] | None = None, *, target: str | None = None
    ) -> dict[str, Any]: ...


class ActionServiceKV:
    """:class:`KeyValue` over a StackStorm Python action's ``action_service`` (system scope)."""

    def __init__(self, action_service: Any) -> None:
        self.svc = action_service

    def get(self, name: str) -> str | None:
        return self.svc.get_value(name, local=False)

    def set(self, name: str, value: str, ttl: int) -> None:
        self.svc.set_value(name, value, ttl=ttl, local=False)


# ---------------------------------------------------------------- admit
def utc_stamp(value: str) -> str:
    """RFC 3339 UTC seconds from a CronTimer ``executed_at`` (``2026-01-01 06:05:00.123456`` or
    an ISO form; a naive time is UTC, as StackStorm's timers are)."""
    t = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=UTC)
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def schedule_event(schedule: str, fired_at: str, cron: str | None = None) -> dict[str, Any]:
    """The ``homelabnext.schedule.fired`` event of one firing; same firing, same id."""
    at = utc_stamp(fired_at)
    data: dict[str, Any] = {"schedule": schedule, "fired_at": at}
    if cron:
        data["cron"] = cron
    return build_event(
        SCHEDULE_EVENT,
        SCHEDULE_SOURCE,
        data,
        dedupe_key=f"{schedule}@{at}",
        subject=schedule,
        time=at,
        severity="info",
    )


def coalesce_name(pack: str, value: Any) -> str:
    h = hashlib.sha256(f"{pack}\0{value!r}".encode()).hexdigest()[:32]
    return COALESCE_PREFIX + h


def admit(
    *,
    pack: str,
    trigger: Mapping[str, Any],
    event: Mapping[str, Any] | None = None,
    schedule: Mapping[str, Any] | None = None,
    coalesce: Mapping[str, Any] | None = None,
    kv: KeyValue | None = None,
) -> dict[str, Any]:
    """``{admitted, reason, event, ...}``; ``reason``: admitted | invalid-event | not-triggered |
    coalesced.  Only an admitted run goes on to its steps."""
    if event is None:
        if not schedule:
            return {"admitted": False, "reason": "invalid-event", "problems": ["no event"]}
        try:
            ev = schedule_event(schedule["id"], schedule["fired_at"], schedule.get("cron"))
        except (KeyError, TypeError, ValueError) as exc:
            return {"admitted": False, "reason": "invalid-event", "problems": [str(exc)]}
    else:
        ev = dict(event)
    problems = event_problems(ev)
    if problems:
        return {"admitted": False, "reason": "invalid-event", "problems": problems}
    if not triggered({"trigger": trigger}, ev):
        return {"admitted": False, "reason": "not-triggered", "event_id": ev.get("id")}
    out: dict[str, Any] = {"admitted": True, "reason": "admitted", "event": ev}
    if coalesce:
        if kv is None:
            raise ValueError("coalesce needs the StackStorm datastore")
        value = resolve(coalesce["key"], {"event": ev, "steps": {}})
        name = coalesce_name(pack, value)
        first = kv.get(name)
        if first is not None:
            return {
                "admitted": False,
                "reason": "coalesced",
                "event_id": ev.get("id"),
                "coalesced_into": first,
                "key": value,
            }
        kv.set(name, str(ev.get("id")), int(coalesce["window_s"]))
        out["coalesce"] = {"key": value, "window_s": int(coalesce["window_s"])}
    return out


# ---------------------------------------------------------------- one step
def run_step(
    *,
    pack: str,
    actor: str,
    step: Mapping[str, Any],
    event: Mapping[str, Any],
    steps: Mapping[str, Any] | None = None,
    calls: Sequence[Mapping[str, Any]] | None = None,
    mode: str = "shadow",
    risky: bool = True,
    digest: str | None = None,
    broker: Broker | None = None,
) -> dict[str, Any]:
    """Run ``step`` for ``event``; returns ``{steps, calls, skipped}`` with this step's output
    added to ``steps`` and, for an action, its call record appended to ``calls``."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, not {mode!r}")
    outputs = dict(steps or {})
    made = [dict(c) for c in calls or ()]
    scope = {"event": dict(event), "steps": outputs}
    sid, kind = step["id"], step["kind"]
    if not holds(step.get("when"), scope):
        outputs[sid] = None
        return {"steps": outputs, "calls": made, "skipped": True}
    if kind == "enrich" and step.get("op") in ST2_ENRICH_OPS:
        outputs[sid] = _enrich(step, scope, {})
        return {"steps": outputs, "calls": made, "skipped": False}
    if kind != "action":
        raise UnsupportedStep(
            f"step {sid!r}: {kind} {step.get('op', '')} does not run on StackStorm"
        )
    req = action_request({"pack": pack, "actor": actor}, step, scope)
    req["digest"] = request_digest(req)
    rec: dict[str, Any] = {
        "step": sid,
        "action": req["action"],
        "params": req["params"],
        "mode": mode,
        "request_id": req["request_id"],
        "request_digest": req["digest"],
    }
    if "target" in req:
        rec["target"] = req["target"]
    if digest:
        rec["pack_digest"] = digest
    if mode == "shadow":
        rec.update(result="shadow", reason=SHADOW_REASON)
    elif broker is None:
        raise ValueError("live mode needs a broker")
    else:
        try:
            if risky:
                got = broker.submit(req["action"], req["params"], target=req.get("target"))
                rec["broker_request_id"] = got.get("request_id")
                held = bool(got.get("awaiting_approval"))
                rec.update(
                    result="held" if held else "submitted",
                    reason="awaiting-approval" if held else str(got.get("state", "submitted")),
                )
            else:
                broker.call(req["action"], req["params"], target=req.get("target"))
                rec.update(result="executed", reason="allowed")
        except Denied as exc:
            rec.update(result="denied", reason=str(getattr(exc, "reason", "denied")))
    outputs[sid] = {"result": rec["result"], "reason": rec["reason"]}
    made.append(rec)
    return {"steps": outputs, "calls": made, "skipped": False}


BrokerFactory = Callable[[str], Broker]


def _socket_broker(socket_path: str) -> Broker:
    from homelabnext.broker.client import BrokerClient

    return BrokerClient(socket_path)


def step(
    config: Mapping[str, Any], *, broker_factory: BrokerFactory = _socket_broker, **params: Any
) -> dict[str, Any]:
    """The ``homelabnext.step`` action: :func:`run_step` with the broker from the pack config.

    Shadow mode never opens the socket, so a shadow rule works on a host with no broker at all.
    """
    broker = None
    if params.get("mode", "shadow") == "live":
        broker = broker_factory(str(config["broker_socket"]))
    return run_step(broker=broker, **params)
