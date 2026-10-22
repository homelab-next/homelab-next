# SPDX-License-Identifier: Apache-2.0
"""What the two Python actions of the rendered StackStorm pack run (``docs/stackstorm.md``).

StackStorm decides *when* a workflow pack runs; this module is *what* one run does, with the same
semantics as the offline runner (:mod:`homelabnext.workflows.runner`), so a pack behaves on
StackStorm the way its fixtures say.  The rendered pack's ``admit.py`` and ``step.py`` are
two-line shims over :func:`admit` and :func:`step`; nothing else runs on StackStorm.

**What crosses StackStorm is text it cannot render.**  StackStorm renders every action parameter
that contains ``{{`` or ``{%`` with an unsandboxed Jinja environment (datastore reads, and code on
the action runner), and an event is written by its producer -- a proposal's title by any agent
that may file one.  So the rule hands the webhook body over JSON- then URL-encoded, the workflow
passes on only text this module encoded (:func:`encode`: ``{``, ``%`` and ``<`` are ``%XX``), and
only Python decodes it (:func:`decode`).  No event field is ever an Orquesta or Jinja expression.

**What a run does comes from the installed pack, not from a parameter.**  Both actions take the
pack name (and :func:`step` the step id); the pack document, its digest, the mode its rule was
rendered with (the promotion state), each step's risk, the coalesce window and the schedule are
read from ``pinned/<pack>.json`` beside the actions (:func:`load_pinned`, digest re-checked).  So
``st2 run homelabnext.step`` can run only a pinned step, only in the mode it was promoted to; who
may run the pack's actions at all is StackStorm RBAC's (``docs/stackstorm.md``).

:func:`admit` (the first task of every rendered workflow):

* builds the ``homelabnext.schedule.fired`` event for a CronTimer firing (its id derives from the
  schedule and the firing time, so a re-fired timer is the same event), or takes the webhook body;
* validates the event against its schema and re-checks the pack's own trigger - defence in depth
  behind the rule's criteria, and the one place the trigger semantics live.  The trigger of every
  event-triggered pack pins ``$event.source`` (``st2-source``), so an event that names another
  producer is ``not-triggered``;
* **drops a redelivery**: an event id this pack already took (within :data:`DEDUPE_WINDOW_S`,
  ``homelabnext.seen.<hash of pack and id>``) ends the run ``duplicate``.  A StackStorm webhook
  starts one run per POST and ignores ``Idempotency-Key``; the bridge is at-least-once;
* **coalesces**: with ``coalesce = {key, window_s}`` the first event of a key opens a window in the
  StackStorm datastore (``homelabnext.coalesce.<hash of pack, source and key>``, TTL
  ``window_s``); every later event of that key inside the window ends the run ``coalesced`` before
  any step runs.  The datastore has no
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
* a held request is recorded in the datastore (:func:`submitted_name`) with its pack, step and
  fingerprint; the built-in approved-run pack's one ``broker-run`` step (:func:`run_approved`)
  runs such a request once a person approved it, and nothing else;
* ``lookup``, ``decide`` and ``prompt`` steps are not run on StackStorm yet; the renderer refuses a
  pack that has one (``st2-step``), so :class:`UnsupportedStep` here is a defect, not a path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from conformance.protocols.broker import BrokerError, Denied
from homelabnext.agent.digest import digest_of
from homelabnext.broker import request_digest
from homelabnext.broker.state import is_id
from homelabnext.events.envelope import build_event, event_problems

from .runner import _enrich, action_request, holds, resolve, triggered

SCHEDULE_EVENT = "homelabnext.schedule.fired"
SCHEDULE_SOURCE = "svc:automation"
ST2_ENRICH_OPS = ("pick", "extract-iocs")
ST2_STEP_KINDS = ("enrich", "action")
MODES = ("shadow", "live")
SHADOW_REASON = "st2-shadow"
COALESCE_PREFIX = "homelabnext.coalesce."
SEEN_PREFIX = "homelabnext.seen."
#: how long an admitted event id is remembered (or the coalesce window, when that is longer): a
#: StackStorm webhook dedupes nothing, so a redelivery from the bridge is dropped here
DEDUPE_WINDOW_S = 86400
_PACK_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
#: the built-in pack of the approved-run rule (``docs/stackstorm.md``): it is rendered from the
#: binding, never from ``workflows/packs/``, and its one step is the only ``broker-run`` step
APPROVED_RUN = "approved-run"
RUN_STEP_KIND = "broker-run"
DECISION_EVENT = "homelabnext.decision.returned"
BROKER_SOURCE = "svc:broker"
#: ``homelabnext.submitted.<hash of the broker request id>``: what a live step submitted, for
#: which pack and step, so the approved-run rule runs only those (and only for this long)
SUBMITTED_PREFIX = "homelabnext.submitted."
SUBMITTED_TTL_S = 7 * 86400
#: the pack config key (a datastore secret, ``st2kv.system.homelabnext.kv_key``) that keys the
#: datastore names above, so nobody without it can compute one to forge or pre-seed
KV_KEY = "kv_key"
KV_KEY_DATASTORE = "homelabnext.kv_key"
KV_KEY_MIN = 32
_KEYED_PREFIXES = (SEEN_PREFIX, COALESCE_PREFIX, SUBMITTED_PREFIX)

log = logging.getLogger("homelabnext.st2_runtime")


class UnsupportedStep(ValueError):
    """A step kind the StackStorm runtime does not run (the renderer refuses such packs)."""


class PinError(ValueError):
    """``pinned/<pack>.json`` is missing, is not the pack asked for, or fails its digest."""


# ---------------------------------------------------------------- the encoded hand-over
def encode(value: Any) -> str:
    """JSON, then every byte but ``A-Za-z0-9_.-~`` percent-encoded: no template marker survives."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return urllib.parse.quote(text, safe="")


def decode(text: Any) -> Any:
    """The inverse of :func:`encode`, and of the rule's ``to_json_string | urlencode``.  Raises
    ValueError on anything else (an object StackStorm would already have rendered included)."""
    if not isinstance(text, str):
        raise ValueError("an encoded value is a string")
    return json.loads(urllib.parse.unquote(text, errors="strict"))


def load_pinned(pinned_dir: str | os.PathLike[str], pack: str) -> dict[str, Any]:
    """The rendered ``pinned/<pack>.json``, its pack document re-checked against its digest."""
    if not isinstance(pack, str) or not _PACK_NAME.fullmatch(pack):
        raise PinError(f"{pack!r} is not a pack name")
    path = Path(pinned_dir) / (pack.replace("-", "_") + ".json")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PinError(f"{pack}: no pinned document ({exc.__class__.__name__})") from None
    if (
        not isinstance(doc, dict)
        or not isinstance(doc.get("pack"), dict)
        or doc["pack"].get("pack") != pack
        or doc.get("mode") not in MODES
        or not isinstance(doc.get("risky"), dict)
    ):
        raise PinError(f"{pack}: the pinned document is not this pack's")
    if digest_of(doc["pack"]) != doc.get("digest"):
        raise PinError(f"{pack}: the pinned pack does not match its digest")
    return doc


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
    def status(self, request_id: str) -> dict[str, Any]: ...
    def run(self, request_id: str) -> Any: ...


class ActionServiceKV:
    """:class:`KeyValue` over a StackStorm Python action's ``action_service`` (system scope).

    The runtime's own names (``homelabnext.seen.*``, ``.coalesce.*``, ``.submitted.*``) are
    stored under an HMAC of the name keyed with the pack config's ``kv_key`` (a datastore secret):
    their inputs (a schedule's event id, a broker request id) are predictable, so with a plain hash
    anyone allowed to write the datastore could compute a name and pre-seed it (suppress an event)
    or forge a submit record.  Without a key of at least ``KV_KEY_MIN`` characters nothing is read
    or written."""

    def __init__(self, action_service: Any, config: Mapping[str, Any] | None = None) -> None:
        key = (config or {}).get(KV_KEY)
        if not isinstance(key, str) or len(key) < KV_KEY_MIN:
            raise ValueError(
                f"the pack config's {KV_KEY} (st2kv.system.{KV_KEY_DATASTORE}, encrypted) is not "
                f"set to a secret of at least {KV_KEY_MIN} characters"
            )
        self.svc = action_service
        self._key = key.encode("utf-8")

    def stored_name(self, name: str) -> str:
        for prefix in _KEYED_PREFIXES:
            if name.startswith(prefix):
                mac = hmac.new(self._key, name.encode("utf-8"), hashlib.sha256)
                return prefix + mac.hexdigest()[:32]
        return name

    def get(self, name: str) -> str | None:
        return self.svc.get_value(self.stored_name(name), local=False)

    def set(self, name: str, value: str, ttl: int) -> None:
        self.svc.set_value(self.stored_name(name), value, ttl=ttl, local=False)


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


def seen_name(pack: str, event_id: Any) -> str:
    h = hashlib.sha256(f"{pack}\0{event_id!r}".encode()).hexdigest()[:32]
    return SEEN_PREFIX + h


def coalesce_name(pack: str, source: Any, value: Any) -> str:
    h = hashlib.sha256(f"{pack}\0{source!r}\0{value!r}".encode()).hexdigest()[:32]
    return COALESCE_PREFIX + h


def admit(
    *,
    pack: str,
    pinned_dir: str | os.PathLike[str],
    event: str | None = None,
    fired_at: str | None = None,
    kv: KeyValue | None = None,
) -> dict[str, Any]:
    """The ``homelabnext.admit`` action: :func:`admit_event` for the pinned pack, the event taken
    URL-encoded (a webhook rule) or built from ``fired_at`` (a CronTimer rule), and the admitted
    event handed on encoded."""
    pin = load_pinned(pinned_dir, pack)
    doc = pin["pack"]
    schedule = ev = None
    if "schedule" in pin:
        if fired_at is None or event is not None:
            return {"admitted": False, "reason": "invalid-event", "problems": ["not a firing"]}
        schedule = dict(pin["schedule"], fired_at=fired_at)
    else:
        try:
            ev = decode(event)
        except ValueError:
            return {"admitted": False, "reason": "invalid-event", "problems": ["not encoded"]}
        if not isinstance(ev, dict):
            return {"admitted": False, "reason": "invalid-event", "problems": ["not an object"]}
    got = admit_event(
        pack=pack,
        trigger=doc["trigger"],
        event=ev,
        schedule=schedule,
        coalesce=pin.get("coalesce"),
        kv=kv,
    )
    if got["admitted"]:
        got["event"] = encode(got["event"])
    return got


def admit_event(
    *,
    pack: str,
    trigger: Mapping[str, Any],
    event: Mapping[str, Any] | None = None,
    schedule: Mapping[str, Any] | None = None,
    coalesce: Mapping[str, Any] | None = None,
    kv: KeyValue | None = None,
) -> dict[str, Any]:
    """``{admitted, reason, event, ...}``; ``reason``: admitted | invalid-event | not-triggered |
    duplicate | coalesced.  Only an admitted run goes on to its steps.  With the datastore
    (``kv``, always given by the rendered ``admit`` action) an event id already admitted for this
    pack is a ``duplicate``: a webhook does not dedupe, and the bridge delivers at least once."""
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
    if kv is not None:
        # StackStorm starts one run per webhook POST, whatever its Idempotency-Key: the event id
        # is the dedupe key, remembered for a day (or the coalesce window, when longer)
        seen = seen_name(pack, ev.get("id"))
        if kv.get(seen) is not None:
            return {"admitted": False, "reason": "duplicate", "event_id": ev.get("id")}
        window = int(coalesce["window_s"]) if coalesce else 0
        kv.set(seen, str(ev.get("id")), max(DEDUPE_WINDOW_S, window))
    if coalesce:
        if kv is None:
            raise ValueError("coalesce needs the StackStorm datastore")
        value = resolve(coalesce["key"], {"event": ev, "steps": {}})
        name = coalesce_name(pack, ev.get("source"), value)
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
    kv: KeyValue | None = None,
) -> dict[str, Any]:
    """Run ``step`` for ``event``; returns ``{steps, calls, skipped}`` with this step's output
    added to ``steps`` and, for an action, its call record appended to ``calls``.  A risky action
    the broker holds is recorded in the datastore (``kv``, :func:`submitted_name`) with its pack,
    step and request fingerprint: the approved-run rule runs nothing else."""
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
                if held and kv is not None and is_id(got.get("request_id")):
                    record = {
                        "pack": pack,
                        "step": sid,
                        "action": req["action"],
                        "fingerprint": fingerprint(req),
                        "event_id": event.get("id"),
                    }
                    kv.set(submitted_name(got["request_id"]), encode(record), SUBMITTED_TTL_S)
                    rec["recorded"] = True
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


# ---------------------------------------------------------------- the approved-run rule
def pinned_sources(trigger: Mapping[str, Any]) -> list[str]:
    """The producers a trigger pins (``$event.source`` ``equals``)."""
    return [
        c["equals"]
        for c in trigger.get("where", [])
        if c["ref"] == "$event.source" and isinstance(c.get("equals"), str)
    ]


def approved_run_pack(actor: str, source: str = BROKER_SOURCE) -> dict[str, Any]:
    """The built-in pack of the approved-run rule: on ``decision.returned`` from the broker with
    an ``accept`` by a person, one ``broker-run`` step for ``$event.data.decision_id``."""
    return {
        "pack": APPROVED_RUN,
        "version": 1,
        "description": (
            "Run a request StackStorm submitted for a bound pack once the broker records its "
            "approval"
        ),
        "actor": actor,
        "trigger": {
            "event": DECISION_EVENT,
            "where": [
                {"ref": "$event.source", "equals": source},
                {"ref": "$event.data.verdict", "equals": "accept"},
                {"ref": "$event.data.tier_used", "equals": "human"},
            ],
        },
        "steps": [{"id": "run", "kind": RUN_STEP_KIND, "request": "$event.data.decision_id"}],
    }


def fingerprint(request: Mapping[str, Any]) -> str:
    """What a request asks for (action, target, params): the same for the request a step built
    and the one the broker stored for it."""
    return digest_of(
        {
            "action": request.get("action"),
            "target": request.get("target"),
            "params": request.get("params"),
        }
    )


def submitted_name(request_id: str) -> str:
    return SUBMITTED_PREFIX + hashlib.sha256(request_id.encode()).hexdigest()[:32]


def run_approved(
    *,
    actor: str,
    event: Mapping[str, Any],
    pinned_dir: str | os.PathLike[str],
    kv: KeyValue,
    mode: str,
    broker: Broker | None = None,
) -> dict[str, Any]:
    """The approved-run step: ask the broker to run ``event.data.decision_id`` exactly once.

    It runs only a request a live step of a bound pack submitted and recorded
    (:func:`submitted_name`), still asking for the same thing (:func:`fingerprint`), owned by this
    pack's actor, still pending and approved; anything else is ``refused`` with a reason, logged,
    and the broker is not asked to run it.  The broker re-decides anyway (the approval's digest,
    expiry and single use, the owner): a forged event costs a refusal, never a run.  Shadow mode
    checks the record and stops before the socket."""
    rid = (event.get("data") or {}).get("decision_id")
    rec: dict[str, Any] = {"step": "run", "action": "broker.run", "mode": mode}

    def refuse(reason: str, **extra: Any) -> dict[str, Any]:
        log.warning("approved-run: not running %r: %s", str(rid)[:80], reason)
        rec.update(result="refused", reason=reason, **extra)
        return rec

    if not is_id(rid):
        return refuse("invalid-request-id")
    rec["broker_request_id"] = rid
    raw = kv.get(submitted_name(rid))
    if raw is None:
        return refuse("not-st2-submitted")
    try:
        sub = decode(raw)
        pack, sid = sub["pack"], sub["step"]
        pin = load_pinned(pinned_dir, pack)
    except (ValueError, KeyError, TypeError):  # PinError is a ValueError
        return refuse("pack-not-bound")
    step = next((s for s in pin["pack"]["steps"] if s["id"] == sid), None)
    if (
        pack == APPROVED_RUN
        or step is None
        or step["kind"] != "action"
        or step["action"] != sub.get("action")
        or not pin["risky"].get(sid)
    ):
        return refuse("step-not-bound")
    rec.update(pack=pack, pack_step=sid, run_action=step["action"])
    if pin["mode"] != "live":
        return refuse("pack-not-live")
    if mode == "shadow":
        rec.update(result="shadow", reason=SHADOW_REASON)
        return rec
    if broker is None:
        raise ValueError("live mode needs a broker")
    try:
        detail = broker.status(rid)
    except Denied as exc:  # another caller's request reads as not-owner
        return refuse(str(getattr(exc, "reason", "denied")))
    req = detail.get("request") or {}
    if req.get("actor") != actor:
        return refuse("other-caller")
    if fingerprint(req) != sub.get("fingerprint"):
        return refuse("request-mismatch")
    if detail.get("state") != "pending":
        return refuse("not-pending", state=detail.get("state"))
    approvals = detail.get("approvals") or []
    if not approvals or approvals[-1].get("decision") != "approved":
        return refuse("not-approved")
    try:
        broker.run(rid)
    except Denied as exc:
        reason = str(getattr(exc, "reason", "denied"))
        log.warning("approved-run: the broker refused to run %r: %s", rid, reason)
        rec.update(result="denied", reason=reason)
        return rec
    except BrokerError as exc:
        reason = str(getattr(exc, "reason", "") or "broker-error")
        log.warning("approved-run: running %r failed: %s", rid, reason)
        rec.update(result="error", reason=reason)
        return rec
    rec.update(result="executed", reason="approved")
    return rec


BrokerFactory = Callable[[str], Broker]


def _socket_broker(socket_path: str) -> Broker:
    from homelabnext.broker.client import BrokerClient

    return BrokerClient(socket_path)


def step(
    config: Mapping[str, Any],
    *,
    pack: str,
    step: str,
    event: str,
    state: str = "",
    pinned_dir: str | os.PathLike[str],
    broker_factory: BrokerFactory = _socket_broker,
    kv: KeyValue | None = None,
) -> dict[str, Any]:
    """The ``homelabnext.step`` action: step ``step`` of the pinned ``pack``, for the encoded
    ``event`` (re-checked against the pack's trigger), after the encoded ``state`` of the steps
    before it.  Mode, risk, actor and digest come from the pinned document.  Returns ``{state,
    skipped, result}``, ``state`` encoded for the next step.

    Shadow mode never opens the socket, so a shadow rule works on a host with no broker at all.
    """
    pin = load_pinned(pinned_dir, pack)
    doc = pin["pack"]
    found = [s for s in doc["steps"] if s["id"] == step]
    if len(found) != 1:
        raise PinError(f"{pack}: no step {step!r}")
    ev = decode(event)
    if not isinstance(ev, dict) or event_problems(ev) or not triggered(doc, ev):
        raise ValueError(f"{pack}: the event is not one the pack triggers on")
    prior = decode(state) if state else {"steps": {}, "calls": []}
    if not isinstance(prior, dict):
        raise ValueError("state is not an encoded object")
    if found[0]["kind"] == RUN_STEP_KIND:
        return _approved_run_step(config, pin, ev, prior, pinned_dir, broker_factory, kv)
    broker = None
    if pin["mode"] == "live":
        broker = broker_factory(str(config["broker_socket"]))
    out = run_step(
        pack=pack,
        actor=doc["actor"],
        step=found[0],
        event=ev,
        steps=prior.get("steps"),
        calls=prior.get("calls"),
        mode=pin["mode"],
        risky=bool(pin["risky"].get(step, True)),
        digest=pin["digest"],
        broker=broker,
        kv=kv,
    )
    made = out["calls"][len(prior.get("calls") or ()) :]
    return {
        "state": encode({"steps": out["steps"], "calls": out["calls"]}),
        "skipped": out["skipped"],
        "result": made[0]["result"] if made else None,
    }


def _approved_run_step(config, pin, ev, prior, pinned_dir, broker_factory, kv) -> dict[str, Any]:
    """Step ``run`` of the built-in approved-run pack, and of nothing else: a ``broker-run``
    step anywhere but the exact built-in document is a pin error."""
    doc = pin["pack"]
    sources = pinned_sources(doc["trigger"])
    builtin = approved_run_pack(doc["actor"], sources[0]) if len(sources) == 1 else None
    if doc["pack"] != APPROVED_RUN or doc != builtin:
        raise PinError(f"{doc['pack']}: a {RUN_STEP_KIND} step is the approved-run rule's only")
    if kv is None:
        raise ValueError("the approved-run step needs the StackStorm datastore")
    broker = broker_factory(str(config["broker_socket"])) if pin["mode"] == "live" else None
    rec = run_approved(
        actor=doc["actor"],
        event=ev,
        pinned_dir=pinned_dir,
        kv=kv,
        mode=pin["mode"],
        broker=broker,
    )
    steps = dict(prior.get("steps") or {}, run={"result": rec["result"], "reason": rec["reason"]})
    calls = [*(prior.get("calls") or []), rec]
    return {
        "state": encode({"steps": steps, "calls": calls}),
        "skipped": False,
        "result": rec["result"],
    }
