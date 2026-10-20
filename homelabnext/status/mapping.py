# SPDX-License-Identifier: Apache-2.0
"""The mapping engine: a source's payload -> status drafts (an observation without its times).

Two ways to map, chosen per source in the registry (``mapping:``):

**Declarative selectors.**  A selector is a small JSONPath-like path: an optional ``$`` root, keys
separated by ``.``, ``[*]`` (or ``*``) for every element of a list or every value of a mapping,
``[N]`` for one list element.  ``items`` selects the items (absent: the whole payload is one
item); ``item``, ``state`` and ``summary`` are relative to each item, and ``@key`` is the item's
key when the items came from a mapping (its index for a list).  The raw state is lower-cased text
(``true``/``false`` for booleans) looked up in ``states``; a raw value that is already a state
word passes through; anything else is ``unknown`` -- an unmapped value is never read as healthy.

**Built-in mappers** (``builtin:``) for the sources this repository already has:

* ``invariants-results`` -- an invariants results document (``hnx invariants run --out``): one
  item per criterion; pass -> ok, fail -> fail, error and skip -> unknown; links ``inv:<id>``.
* ``records-lanes`` -- the records lanes (``homelabnext.records``): ``inbox`` and
  ``approved-not-completed``, each a live-work count with the oldest age; ``warn`` when the oldest
  is older than ``warn_after_s``.
* ``broker-pending`` -- requests waiting for an approval (a list of broker requests, or
  ``{"requests": [...]}``): ``pending-approvals``, a live-work count with the oldest age.

and for products whose one endpoint says it all (``poll-http-json``; the product kinds that need
more than one request are collectors, :mod:`.products`):

* ``orchestrator-queue`` -- the LLM orchestrator's ``GET /admin/queue-summary``
  (``store.QueueSummary``: ``by_state``, ``active``, ``oldest_queued_age_seconds``): ``queued``
  (live work, warn when the oldest has waited over ``warn_after_s``), ``running`` (live work, per
  agent) and ``history`` (the all-time totals, informational).
* ``agentmetry-audit`` -- Agentmetry's ``GET /api/v1/audit/status`` (its freshness badge):
  ``audit-trail``, warn when the audit export is off, has no event yet, or its last event is older
  than ``warn_after_s`` (silent hook failure).

A payload the mapping cannot read raises :class:`MappingError`; the scheduler turns that into the
source's error, exactly like a timeout, so one malformed source never touches another.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .model import parse_iso

STATE_WORDS = ("ok", "warn", "fail", "unknown")
MAX_SUMMARY = 300
_TOKEN = re.compile(r"\[(\*|\d+)\]|([^.\[\]]+)")
_ITEM_BAD = re.compile(r"[^A-Za-z0-9._:/@-]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


class MappingError(ValueError):
    """The payload does not have the shape the mapping expects."""


@dataclass(frozen=True)
class Draft:
    """What a mapper says about one item; the hub adds the source, the times and the expiry."""

    item: str
    state: str
    summary: str
    module: str | None = None
    link: str | None = None
    value: float | None = None
    work: bool = False


# ---------------------------------------------------------------- selectors
def _tokens(selector: str) -> list[str]:
    s = selector.strip()
    if s.startswith("$"):
        s = s[1:].lstrip(".")
    out: list[str] = []
    pos = 0
    while pos < len(s):
        if s[pos] == ".":
            pos += 1
            continue
        m = _TOKEN.match(s, pos)
        if not m:
            raise MappingError(f"bad selector {selector!r} at {pos}")
        idx, name = m.group(1), m.group(2)
        out.append(name if idx is None else ("*" if idx == "*" else f"[{idx}]"))
        pos = m.end()
    return out


def select_pairs(value: Any, selector: str) -> list[tuple[str, Any]]:
    """Every ``(key, match)`` the selector reaches (an empty list when nothing matches)."""
    cur: list[tuple[str, Any]] = [("", value)]
    for tok in _tokens(selector):
        nxt: list[tuple[str, Any]] = []
        for _, v in cur:
            if tok == "*":
                if isinstance(v, Mapping):
                    nxt += [(str(k), x) for k, x in v.items()]
                elif isinstance(v, list):
                    nxt += [(str(i), x) for i, x in enumerate(v)]
            elif tok.startswith("[") and tok.endswith("]"):
                i = int(tok[1:-1])
                if isinstance(v, list) and i < len(v):
                    nxt.append((str(i), v[i]))
            elif isinstance(v, Mapping) and tok in v:
                nxt.append((tok, v[tok]))
        cur = nxt
    return cur


def select_one(value: Any, selector: str | None, *, key: str = "") -> Any:
    """The first match of ``selector`` (``@key`` is ``key``), or None."""
    if not selector:
        return None
    if selector == "@key":
        return key
    hits = select_pairs(value, selector)
    return hits[0][1] if hits else None


def _items(payload: Any, selector: str | None) -> list[tuple[str, Any]]:
    if not selector:
        return [("", payload)]
    hits = select_pairs(payload, selector)
    wildcard = _tokens(selector)[-1:] == ["*"]
    if wildcard:
        return hits  # an empty list is an empty set of items, not a defect
    if not hits:
        raise MappingError(f"items selector {selector!r} matched nothing")
    if len(hits) == 1 and isinstance(hits[0][1], list):
        return [(str(i), x) for i, x in enumerate(hits[0][1])]
    if len(hits) == 1 and isinstance(hits[0][1], Mapping):
        return [(str(k), x) for k, x in hits[0][1].items()]
    return hits


# ---------------------------------------------------------------- helpers
def raw_text(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bool):
        return "true" if raw else "false"
    return str(raw).strip().lower()


def map_state(raw: Any, states: Mapping[str, str] | None) -> str:
    text = raw_text(raw)
    table = {str(k).lower(): v for k, v in (states or {}).items()}
    if text in table:
        return table[text]
    return text if text in STATE_WORDS else "unknown"


def clean_summary(text: Any) -> str:
    s = _CONTROL.sub(" ", "" if text is None else str(text)).strip()
    return s if len(s) <= MAX_SUMMARY else s[: MAX_SUMMARY - 3] + "..."


def clean_item(text: Any, fallback: str) -> str:
    s = _ITEM_BAD.sub("-", raw_text(text) if isinstance(text, bool) else str(text or "")).strip("-")
    s = s.lstrip("._:/@-")[:128]
    return s or fallback


def age_text(seconds: float) -> str:
    s = int(max(0, seconds))
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


# ---------------------------------------------------------------- declarative
def apply_declarative(payload: Any, mapping: Mapping[str, Any], fallback_item: str) -> list[Draft]:
    out: list[Draft] = []
    for key, entry in _items(payload, mapping.get("items")):
        raw = select_one(entry, mapping.get("state"), key=key)
        name = select_one(entry, mapping.get("item"), key=key)
        summary = select_one(entry, mapping.get("summary"), key=key)
        out.append(
            Draft(
                item=clean_item(name if name is not None else key, fallback_item),
                state=map_state(raw, mapping.get("states")),
                summary=clean_summary(summary if summary is not None else raw_text(raw)),
            )
        )
    return out


# ---------------------------------------------------------------- built-ins
_INV_STATES = {"pass": "ok", "fail": "fail", "error": "unknown", "skip": "unknown"}


def invariants_results(payload: Any, mapping: Mapping[str, Any], now: float) -> list[Draft]:
    if not isinstance(payload, Mapping) or not str(payload.get("schema", "")).startswith(
        "homelabnext.invariants.results/"
    ):
        raise MappingError("not an invariants results document (schema homelabnext.invariants.*)")
    results = payload.get("results")
    if not isinstance(results, Mapping):
        raise MappingError("invariants results: 'results' is not a mapping")
    out = []
    for cid in sorted(results):
        r = results[cid] if isinstance(results[cid], Mapping) else {}
        status = raw_text(r.get("status"))
        evidence = str(r.get("evidence") or status).strip().splitlines()
        out.append(
            Draft(
                item=clean_item(cid, "criterion"),
                state=_INV_STATES.get(status, "unknown"),
                summary=clean_summary(f"{status}: {evidence[0] if evidence else ''}"),
                link=f"inv:{cid}",
            )
        )
    return out


def _count_item(
    item: str, noun: str, created: list[float], now: float, warn_after_s: float | None
) -> Draft:
    n = len(created)
    if not n:
        return Draft(item=item, state="ok", summary=f"no {noun}s", value=0, work=True)
    oldest = now - min(created)
    late = warn_after_s is not None and oldest > warn_after_s
    plural = noun if n == 1 else noun + "s"
    return Draft(
        item=item,
        state="warn" if late else "ok",
        summary=f"{n} {plural}, oldest {age_text(oldest)}" + (" (over the limit)" if late else ""),
        value=n,
        work=True,
    )


def _created(entries: Any, *fields: str) -> list[float]:
    if not isinstance(entries, list):
        raise MappingError("expected a list of entries")
    out = []
    for e in entries:
        raw = next((e.get(f) for f in fields if isinstance(e, Mapping) and e.get(f)), None)
        if raw is None:
            raise MappingError(f"entry without {' or '.join(fields)}")
        try:
            out.append(parse_iso(str(raw)))
        except ValueError as exc:
            raise MappingError(f"bad timestamp {raw!r}") from exc
    return out


def records_lanes(payload: Any, mapping: Mapping[str, Any], now: float) -> list[Draft]:
    if not isinstance(payload, Mapping) or not {"inbox", "approved"} <= set(payload):
        raise MappingError("records lanes: expected {'inbox': [...], 'approved': [...]}")
    warn = mapping.get("warn_after_s")
    return [
        _count_item("inbox", "note", _created(payload["inbox"], "created"), now, warn),
        _count_item(
            "approved-not-completed", "note", _created(payload["approved"], "created"), now, warn
        ),
    ]


def broker_pending(payload: Any, mapping: Mapping[str, Any], now: float) -> list[Draft]:
    reqs = payload.get("requests") if isinstance(payload, Mapping) else payload
    created = _created(reqs, "created", "created_at")
    return [_count_item("pending-approvals", "request", created, now, mapping.get("warn_after_s"))]


def _int(value: Any) -> int:
    return int(value) if isinstance(value, int | float) and not isinstance(value, bool) else 0


def orchestrator_queue(payload: Any, mapping: Mapping[str, Any], now: float) -> list[Draft]:
    """``GET /admin/queue-summary`` of the LLM orchestrator (``internal/store`` QueueSummary)."""
    if not isinstance(payload, Mapping) or not isinstance(payload.get("by_state"), Mapping):
        raise MappingError("orchestrator queue summary: expected {'by_state': {...}, ...}")
    by_state = payload["by_state"]
    queued, running = _int(by_state.get("queued")), _int(by_state.get("running"))
    oldest = payload.get("oldest_queued_age_seconds")
    warn = mapping.get("warn_after_s")
    late = isinstance(oldest, int | float) and warn is not None and oldest > warn
    q_summary = f"{queued} queued job" + ("" if queued == 1 else "s")
    if queued and isinstance(oldest, int | float):
        q_summary += f", oldest {age_text(oldest)}" + (" (over the limit)" if late else "")
    per_agent = sorted(
        (str(e.get("agent_key")), _int(e.get("count")))
        for e in payload.get("active") or []  # a Go nil slice arrives as null
        if isinstance(e, Mapping) and e.get("state") == "running"
    )
    r_summary = f"{running} running job" + ("" if running == 1 else "s")
    if per_agent:
        r_summary += ": " + ", ".join(f"{a} {n}" for a, n in per_agent)
    totals = ", ".join(
        f"{state} {_int(by_state[state])}"
        for state in sorted(by_state)
        if state not in ("queued", "running")
    )
    return [
        Draft(
            "queued", "warn" if late else "ok", clean_summary(q_summary), value=queued, work=True
        ),
        Draft("running", "ok", clean_summary(r_summary), value=running, work=True),
        Draft("history", "ok", clean_summary(f"all time: {totals or 'no finished jobs'}")),
    ]


def agentmetry_audit(payload: Any, mapping: Mapping[str, Any], now: float) -> list[Draft]:
    """``GET /api/v1/audit/status`` of Agentmetry: is its audit trail being written at all."""
    if not isinstance(payload, Mapping) or "enabled" not in payload:
        raise MappingError("agentmetry audit status: expected {'enabled': ..., ...}")
    if not payload["enabled"]:
        return [Draft("audit-trail", "warn", "audit export is disabled: nothing is being recorded")]
    last = payload.get("last_event_utc")
    if not last:
        return [Draft("audit-trail", "warn", "audit export is on but has recorded no event yet")]
    try:
        age = now - parse_iso(str(last))
    except ValueError:
        return [
            Draft("audit-trail", "unknown", clean_summary(f"unreadable last event time {last!r}"))
        ]
    warn = mapping.get("warn_after_s")
    late = warn is not None and age > warn
    sources = payload.get("by_source") if isinstance(payload.get("by_source"), Mapping) else {}
    mix = ", ".join(f"{k} {_int(v)}" for k, v in sorted(sources.items()))
    summary = f"last event {age_text(age)} ago" + (" (over the limit)" if late else "")
    if mix:
        summary += f"; recent {_int(payload.get('recent'))}: {mix}"
    return [Draft("audit-trail", "warn" if late else "ok", clean_summary(summary), value=age)]


Builtin = Callable[[Any, Mapping[str, Any], float], list[Draft]]
BUILTINS: dict[str, Builtin] = {
    "invariants-results": invariants_results,
    "records-lanes": records_lanes,
    "broker-pending": broker_pending,
    "orchestrator-queue": orchestrator_queue,
    "agentmetry-audit": agentmetry_audit,
}


def apply_mapping(
    payload: Any, mapping: Mapping[str, Any], *, now: float, fallback_item: str
) -> list[Draft]:
    """Map ``payload`` with a source's ``mapping`` (built-in or declarative)."""
    name = mapping.get("builtin")
    if name is not None:
        fn = BUILTINS.get(name)
        if fn is None:
            raise MappingError(f"unknown builtin mapper {name!r}")
        return fn(payload, mapping, now)
    if "state" not in mapping:
        raise MappingError("a declarative mapping needs a state selector")
    return apply_declarative(payload, mapping, fallback_item)
