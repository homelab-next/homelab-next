# SPDX-License-Identifier: Apache-2.0
"""The two tiers of agent activity and the session view derived from the summary tier.

* **Summary** (``schemas/status/agent_activity.schema.json``): who, where, which model, which tool
  *name*, the outcome and the counts.  Public: it is on the normal hub pages, in ``status.json``
  and, as ``homelabnext.agent.activity``, on the shared bus.
* **Detail** (``schemas/status/agent_activity_detail.schema.json``): the prompt, command, tool
  input and output, error text and an approval's gated payload.  Private: redacted and capped
  before storage (:mod:`.store`), shown only behind the trusted front door (:mod:`.auth`), never
  on the bus.

A **session** is every summary event with one ``session_id``; its state is derived at read time
from the last event and an injected clock (never stored), so a session that stops reporting turns
``stuck`` on time without anything having to run:

========== ====================================================================================
``done``     the last event is ``session_end``
``errored``  the last event is an ``error`` or has outcome ``error``
``waiting``  the agent handed back to the operator: ``stop``, a ``notification``, or an approval
             request still pending
``stuck``    otherwise, when nothing arrived for the session's ``stuck_after_s`` (a model's
             threshold beats its runtime's, which beats the default)
``working``  otherwise
========== ====================================================================================
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import cache
from typing import Any

from homelabnext import paths

from ..model import iso, parse_iso

SUMMARY_SCHEMA = "agent_activity.schema.json"
DETAIL_SCHEMA = "agent_activity_detail.schema.json"
ACTIVITY_EVENT = "homelabnext.agent.activity"
#: the private text fields of a detail record (``approval.payload`` is the sixth)
DETAIL_TEXT = ("prompt", "command", "tool_input", "tool_output", "error")
#: the keys only the detail tier may carry: a summary event holding one of them is refused
DETAIL_KEYS = frozenset({*DETAIL_TEXT, "approval", "truncated", "redactions"})
SESSION_STATES = ("working", "waiting", "stuck", "errored", "done")
#: worst first, for sorting and for the hub's attention items
SESSION_SEVERITY = {"errored": 4, "stuck": 3, "waiting": 1, "working": 0, "done": -1}
DEFAULT_STUCK_AFTER_S = 900


@cache
def _validator(name: str):
    import jsonschema
    from referencing import Registry as RefRegistry
    from referencing import Resource
    from referencing.jsonschema import DRAFT202012

    refs: RefRegistry = RefRegistry()
    docs = {}
    for family, fname in (("ids", "common.schema.json"), ("status", name)):
        doc = json.loads(paths.schema_file(family, fname).read_text(encoding="utf-8"))
        docs[fname] = doc
        refs = refs.with_resource(
            doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
        )
    return jsonschema.Draft202012Validator(docs[name], registry=refs)


def _problems(name: str, doc: Any) -> list[str]:
    errs = sorted(
        _validator(name).iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path]
    )
    return [f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:200]}" for e in errs]


def summary_problems(doc: Any) -> list[str]:
    """Schema problems of one summary event (empty = valid).  A detail key is always one."""
    out = _problems(SUMMARY_SCHEMA, doc)
    if isinstance(doc, Mapping):
        out += [f"{k}: a detail field in the summary tier" for k in sorted(DETAIL_KEYS & set(doc))]
    return out


def detail_problems(doc: Any) -> list[str]:
    """Schema problems of one detail record (empty = valid)."""
    return _problems(DETAIL_SCHEMA, doc)


@dataclass(frozen=True)
class Thresholds:
    """When a working session counts as stuck: model beats runtime beats default."""

    default: float = DEFAULT_STUCK_AFTER_S
    runtimes: Mapping[str, float] = field(default_factory=dict)
    models: Mapping[str, float] = field(default_factory=dict)

    def for_session(self, runtime: str | None, model: str | None) -> float:
        if model and model in self.models:
            return float(self.models[model])
        if runtime and runtime in self.runtimes:
            return float(self.runtimes[runtime])
        return float(self.default)


_IDENTITY = ("runtime", "surface", "host", "project", "model", "agent", "parent_session_id")


def session_state(last: Mapping[str, Any], idle_s: float, stuck_after_s: float) -> str:
    """The state of a session whose newest event is ``last`` (see the module docstring)."""
    kind, outcome = last.get("kind"), last.get("outcome")
    if kind == "session_end":
        return "done"
    if kind == "error" or outcome == "error":
        return "errored"
    if kind in ("stop", "notification") or (
        kind == "approval_request" and outcome in (None, "pending")
    ):
        return "waiting"
    return "stuck" if idle_s >= stuck_after_s else "working"


def derive_sessions(
    events: Iterable[Mapping[str, Any]], now: float, thresholds: Thresholds | None = None
) -> list[dict[str, Any]]:
    """One row per session from its summary events (any order), worst state first, then the
    most recently active.  Every value is from the summary tier."""
    thresholds = thresholds or Thresholds()
    by_session: dict[str, list[Mapping[str, Any]]] = {}
    for ev in events:
        by_session.setdefault(ev["session_id"], []).append(ev)
    rows = []
    for sid, evs in by_session.items():
        evs = sorted(evs, key=lambda e: (parse_iso(e["time"]), e["event_id"]))
        last = evs[-1]
        row: dict[str, Any] = {"session_id": sid}
        for k in _IDENTITY:  # the newest value of each identity field wins
            vals = [e[k] for e in evs if e.get(k)]
            row[k] = vals[-1] if vals else None
        kinds = [e["kind"] for e in evs]
        tools = [e["tool"] for e in evs if e.get("tool")]
        costs = [e["cost_usd"] for e in evs if e.get("cost_usd") is not None]
        last_t = parse_iso(last["time"])
        idle = max(0.0, now - last_t)
        stuck_after = thresholds.for_session(row["runtime"], row["model"])
        row.update(
            first_seen=evs[0]["time"],
            last_seen=last["time"],
            last_kind=last["kind"],
            last_outcome=last.get("outcome"),
            last_tool=tools[-1] if tools else None,
            events=len(evs),
            tool_calls=max(kinds.count("tool_start"), kinds.count("tool_end")),
            denials=sum(1 for e in evs if e.get("outcome") == "denied"),
            approvals=kinds.count("approval_request"),
            errors=sum(1 for e in evs if e["kind"] == "error" or e.get("outcome") == "error"),
            prompts=kinds.count("prompt"),
            tokens_in=sum(int(e.get("tokens_in") or 0) for e in evs),
            tokens_out=sum(int(e.get("tokens_out") or 0) for e in evs),
            cost_usd=round(sum(costs), 6) if costs else None,
            idle_s=int(idle),
            stuck_after_s=int(stuck_after),
            state=session_state(last, idle, stuck_after),
        )
        rows.append(row)
    return sorted(
        rows,
        key=lambda r: (-SESSION_SEVERITY[r["state"]], -parse_iso(r["last_seen"]), r["session_id"]),
    )


def state_counts(sessions: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    out = dict.fromkeys(SESSION_STATES, 0)
    for s in sessions:
        out[s["state"]] += 1
    return out


def bus_event(summary: Mapping[str, Any], source: str) -> dict[str, Any]:
    """The ``homelabnext.agent.activity`` envelope for one summary event: the summary tier only,
    by construction (a detail key raises).  The id derives from the event id, so a re-send is a
    duplicate."""
    from homelabnext.events.envelope import build_event

    leaked = DETAIL_KEYS & set(summary)
    if leaked:
        raise ValueError(f"detail fields never go on the bus: {sorted(leaked)}")
    return build_event(
        ACTIVITY_EVENT,
        source,
        dict(summary),
        dedupe_key=f"agent-activity/{summary['event_id']}",
        time=summary["time"],
        subject=f"{summary['runtime']}/{summary['session_id']}"[:256],
        severity="medium" if summary.get("outcome") == "error" else "info",
    )


__all__ = [
    "ACTIVITY_EVENT",
    "DETAIL_KEYS",
    "DETAIL_TEXT",
    "SESSION_STATES",
    "Thresholds",
    "bus_event",
    "derive_sessions",
    "detail_problems",
    "iso",
    "session_state",
    "state_counts",
    "summary_problems",
]
