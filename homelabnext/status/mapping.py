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

and for the scheduled jobs (``poll-file`` over a directory of last-run records):

* ``job-last-run`` -- the records the shared writer of role ``last_run`` leaves on each host
  (``schemas/status/last_run.schema.json``): one item ``<job id>@<host>`` per record
  (``timer:aide/scan@web-1``), whose ``value`` is the age of the run's start in seconds, so the
  Schedule page can date the run.  A failed run (systemd's result other than ``success``) is
  fail; a run whose next one is overdue -- its next calendar time after this start, plus the
  timer's randomized delay, plus this run's duration, has passed -- is warn; else ok.  A
  calendar this repository cannot read exactly (no ``UTC`` token, a shorthand) falls back to
  ``warn_after_s`` past the start, or no lateness at all without one.

and for data freshness (``poll-http-json``, an age judged against ``warn_after_s`` and
``fail_after_s``):

* ``table-snapshot-age`` -- a lake catalog's REST ``LoadTableResult``: the age of the table's
  newest snapshot, one item (``mapping.item``).
* ``backup-snapshot-age`` -- a Proxmox Backup Server datastore's snapshot list: one item per backup
  group, the age of its newest snapshot; a failed verification is ``fail``.
* ``drill-records`` -- the role ``restore_drill`` records file (``drills.json``; ADR-0042): one
  item per guest and per exported application, the age of the last verified drill against two
  age limits (overdue warn, stale fail); a record whose ``last_failure`` is newer than its
  ``last_verified`` is ``fail``, and a record that was never verified and carries no failure is
  ``unknown`` (the drill has not touched it yet), so an empty file does not read green.

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
    #: the raw flags of a reading that has them (a NUT ``ups.status``); None: not that kind
    flags: tuple[str, ...] | None = None


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
    """``GET /admin/queue-summary`` of the LLM orchestrator.

    The shape is ``QueueSummary`` in ``orchestrator/internal/store``.
    """
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


LAST_RUN_SCHEMA = "homelabnext.status.last-run/1"


def _last_run_problems(doc: Any) -> list[str]:
    from .model import schema_problems

    return schema_problems("last_run.schema.json", doc)


def _late(rec: Mapping[str, Any], start: float, now: float, mapping: Mapping[str, Any]):
    """(due time or None, how it was judged) for one record."""
    from datetime import UTC, datetime

    from .maps import cadence

    finished = rec.get("finished_at")
    took = max(0.0, parse_iso(finished) - start) if finished else 0.0
    cal = cadence.from_oncalendar(str(rec["on_calendar"]))
    if cal is not None:
        nxt = cadence.next_run(cal, datetime.fromtimestamp(start, UTC))
        if nxt is not None:
            return nxt.timestamp() + int(rec.get("randomized_delay_s") or 0) + took, ""
    warn = mapping.get("warn_after_s")
    if warn is not None:
        return start + float(warn), ""
    return None, f"; lateness not judged (calendar {rec['on_calendar']!r} is not read exactly)"


def _ago(seconds: float) -> str:
    return f"{age_text(seconds)} ago"


#: how far in the future a record's ``started_at`` may be (clock skew) before it is not believed
LAST_RUN_SKEW_S = 300


def job_last_run(payload: Any, mapping: Mapping[str, Any], now: float) -> list[Draft]:
    """Last-run records (a list, one record, or what :class:`~.collectors.FileCollector` reads
    from a record directory: ``{"records": [...], "unreadable": [...], "hosts": [...]}``).

    A record read from ``<dir>/<host>/`` belongs to that host: one naming another host is invalid
    (else host A could write a newer, passing record for host B and mask B's failure).  A record
    that starts more than :data:`LAST_RUN_SKEW_S` in the future is ``unknown`` and never the
    newest of its job and host (else it would mask every real record until that time)."""
    from .model import iso

    if isinstance(payload, Mapping) and "records" in payload:
        records, unreadable = payload.get("records") or [], payload.get("unreadable") or []
        dirs = list(payload.get("hosts") or [])
    else:
        records, unreadable = (payload if isinstance(payload, list) else [payload]), []
        dirs = []
    dirs += [None] * (len(records) - len(dirs))
    best: dict[str, tuple[float, Draft]] = {}
    out: list[Draft] = []
    for name, why in unreadable:
        out.append(Draft(clean_item(f"unreadable/{name}", "unreadable"), "unknown",
                         clean_summary(f"{name}: {why}")))  # fmt: skip
    for rec, where in zip(records, dirs, strict=True):
        problems = _last_run_problems(rec)
        if not problems and where is not None and rec["host"] != where:
            problems = [f"its host is not {where}, the directory it was shipped to"]
        if problems:
            label = rec.get("job") if isinstance(rec, Mapping) else None
            out.append(Draft(clean_item(f"invalid/{label or 'record'}", "invalid"), "unknown",
                             clean_summary(f"not a last-run record: {problems[0]}")))  # fmt: skip
            continue
        start = parse_iso(rec["started_at"])
        item = clean_item(f"{rec['job']}@{rec['host']}", "job")
        if start > now + LAST_RUN_SKEW_S:
            future = Draft(item, "unknown", clean_summary(f"started in the future ({iso(start)})"))
            best.setdefault(item, (float("-inf"), future))
            continue
        due, judged = _late(rec, start, now, mapping)
        late = due is not None and now > due
        if rec["running"]:
            state = "warn" if late else "ok"
            summary = f"running since {iso(start)} ({_ago(now - start)})"
        else:
            took = (
                age_text(parse_iso(rec["finished_at"]) - start) if rec.get("finished_at") else "?"
            )
            status = rec.get("exit_status")
            how = rec.get("result") or "unknown"
            if how != "success":
                how = f"failed: {how}" + (f" (exit status {status})" if status else "")
            state = "fail" if rec.get("result") != "success" else ("warn" if late else "ok")
            summary = f"{how}; started {iso(start)} ({_ago(now - start)}), took {took}"
        if late:
            summary = f"overdue since {iso(due)}: " + summary
        elif due is not None:
            summary += f"; next due by {iso(due)}"
        draft = Draft(item, state, clean_summary(summary + judged), value=max(0, int(now - start)))
        if item not in best or start > best[item][0]:  # the same job and host twice: the newest
            best[item] = (start, draft)
    return out + [d for _, d in sorted(best.values(), key=lambda x: x[1].item)]


def _age_state(age: float, mapping: Mapping[str, Any]) -> tuple[str, str]:
    """(state, suffix) of an age against ``warn_after_s``/``fail_after_s``; past neither is ok."""
    fail, warn = mapping.get("fail_after_s"), mapping.get("warn_after_s")
    if fail is not None and age > fail:
        return "fail", f" (over the {age_text(fail)} limit)"
    if warn is not None and age > warn:
        return "warn", f" (over the {age_text(warn)} limit)"
    return "ok", ""


def table_snapshot_age(payload: Any, mapping: Mapping[str, Any], now: float) -> list[Draft]:
    """``GET /v1/namespaces/<ns>/tables/<table>`` of the lake catalog's REST API (``LoadTableResult``:
    ``metadata.snapshots[].timestamp-ms``): how long ago the table last committed a snapshot.
    One item, ``mapping.item`` (default ``table``).  A table with no snapshot is ``warn`` (nothing
    ever landed); a snapshot dated in the future is ``unknown``."""
    meta = payload.get("metadata") if isinstance(payload, Mapping) else None
    if not isinstance(meta, Mapping):
        raise MappingError("catalog table: expected a LoadTableResult with a 'metadata' object")
    item = clean_item(mapping.get("item"), "table")
    snaps = meta.get("snapshots")
    stamps = [
        s["timestamp-ms"]
        for s in (snaps if isinstance(snaps, list) else [])
        if isinstance(s, Mapping)
        and isinstance(s.get("timestamp-ms"), int | float)
        and not isinstance(s.get("timestamp-ms"), bool)
    ]
    if not stamps:
        return [Draft(item, "warn", "no snapshot: no data has ever been committed to this table")]
    age = now - max(stamps) / 1000.0
    if age < -300:
        return [Draft(item, "unknown", "newest snapshot is dated in the future")]
    state, over = _age_state(max(0.0, age), mapping)
    n = len(stamps)
    summary = f"last commit {age_text(age)} ago{over}; {n} snapshot" + ("" if n == 1 else "s")
    return [Draft(item, state, clean_summary(summary), value=max(0, int(age)))]


def drill_records(payload: Any, mapping: Mapping[str, Any], now: float) -> list[Draft]:
    """Restore-drill records (``/var/lib/homelabnext/restore-drill/drills.json``, written by role
    ``restore_drill`` on the backup host; ADR-0042 decision 3's record shape).

    The file has two mappings, each keyed by an id and holding its last pass and last failure:

    * ``guests``: one entry per guest, ``{name, last_verified?, snapshot?, last_failure?, failure?}``
    * ``services``: one entry per application export the drill restored (X-07), same time fields

    One item per entry (``<guest id>`` / ``export:<app>``), with the age of ``last_verified``
    against two limits from the mapping, ``warn_after_s`` (overdue: a drill due for its next run)
    and ``fail_after_s`` (stale: a drill older than the retention target, ADR-0042 "90 days");
    the mapper's defaults are those two (30 and 90 days).  A guest whose ``last_failure`` is newer
    than its ``last_verified``, or that has never verified (and is flagged as a drill target by
    a ``failure``), is ``fail``.  An entry that was never verified and has no failure is
    ``unknown`` (the drill has not touched it yet), so an empty record file does not read green.

    ``value`` is the age in seconds of the last verified drill, so the hub dates the item.
    No dumped content is ever carried, as the records do not carry any; the summary names the
    drill's snapshot and the age against the chosen limits only."""
    if not isinstance(payload, Mapping):
        raise MappingError("drill records: expected a mapping document")
    guests = payload.get("guests")
    services = payload.get("services")
    if not isinstance(guests, Mapping) and not isinstance(services, Mapping):
        raise MappingError(
            "drill records: neither 'guests' nor 'services' is a mapping; is this a drills.json?"
        )
    warn_after = mapping.get("warn_after_s")
    fail_after = mapping.get("fail_after_s")
    limits = {
        "warn_after_s": 30 * 86400 if warn_after is None else warn_after,
        "fail_after_s": 90 * 86400 if fail_after is None else fail_after,
    }
    out: list[Draft] = []
    for prefix, group in (("", guests), ("export:", services)):
        if not isinstance(group, Mapping):
            continue
        for key in sorted(group):
            row = group[key] if isinstance(group[key], Mapping) else {}
            item = clean_item(f"{prefix}{key}", "drill")
            verified = row.get("last_verified")
            failed = row.get("last_failure")
            fail_t = parse_iso(str(failed)) if isinstance(failed, str) else None
            if not isinstance(verified, str):
                if fail_t is not None and row.get("failure"):
                    summary = f"never verified; last failure {age_text(now - fail_t)} ago: {str(row['failure'])[:160]}"
                    out.append(Draft(item, "fail", clean_summary(summary)))
                else:
                    out.append(
                        Draft(
                            item, "unknown", clean_summary("not drilled yet (no record of a pass)")
                        )
                    )
                continue
            try:
                ok_t = parse_iso(verified)
            except ValueError as exc:
                raise MappingError(
                    f"drill records: {key}: unreadable last_verified ({exc})"
                ) from None
            age = max(0.0, now - ok_t)
            if fail_t is not None and fail_t >= ok_t:
                summary = (
                    f"the last drill FAILED {age_text(now - fail_t)} ago"
                    f" (last pass was {age_text(age)} ago): {str(row.get('failure', ''))[:120]}"
                )
                out.append(Draft(item, "fail", clean_summary(summary), value=max(0, int(age))))
                continue
            state, over = _age_state(age, limits)
            snap = row.get("snapshot") if isinstance(row.get("snapshot"), str) else ""
            summary = f"last verified {age_text(age)} ago{over}"
            if snap:
                summary += f"; snapshot {snap}"
            out.append(Draft(item, state, clean_summary(summary), value=max(0, int(age))))
    return out


def backup_snapshot_age(payload: Any, mapping: Mapping[str, Any], now: float) -> list[Draft]:
    """``GET /api2/json/admin/datastore/<store>/snapshots`` of a Proxmox Backup Server
    (``{"data": [{"backup-type", "backup-id", "backup-time", "verification"?}]}``): one item per
    backup group, ``<type>/<id>``, its newest snapshot's age against the limits; a newest
    snapshot whose verification failed is ``fail`` whatever its age."""
    rows = payload.get("data") if isinstance(payload, Mapping) else None
    if not isinstance(rows, list):
        raise MappingError("pbs snapshots: expected {'data': [...]}")
    newest: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        t = row.get("backup-time")
        if not (isinstance(t, int | float) and not isinstance(t, bool)):
            continue
        key = f"{row.get('backup-type')}/{row.get('backup-id')}"
        if key not in newest or t > newest[key]["backup-time"]:
            newest[key] = row
    if not newest:
        return [Draft("snapshots", "fail", "the datastore lists no snapshot at all")]
    out: list[Draft] = []
    for key in sorted(newest):
        row = newest[key]
        age = now - row["backup-time"]
        state, over = _age_state(max(0.0, age), mapping)
        ver = row.get("verification")
        vstate = ver.get("state") if isinstance(ver, Mapping) else None
        summary = f"newest snapshot {age_text(age)} ago{over}"
        if vstate == "failed":
            state, summary = "fail", summary + "; its verification FAILED"
        elif vstate:
            summary += f"; verified {vstate}"
        out.append(
            Draft(clean_item(key, "group"), state, clean_summary(summary), value=max(0, int(age)))
        )
    return out


Builtin = Callable[[Any, Mapping[str, Any], float], list[Draft]]
BUILTINS: dict[str, Builtin] = {
    "invariants-results": invariants_results,
    "records-lanes": records_lanes,
    "broker-pending": broker_pending,
    "orchestrator-queue": orchestrator_queue,
    "agentmetry-audit": agentmetry_audit,
    "job-last-run": job_last_run,
    "table-snapshot-age": table_snapshot_age,
    "backup-snapshot-age": backup_snapshot_age,
    "drill-records": drill_records,
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
