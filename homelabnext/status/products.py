# SPDX-License-Identifier: Apache-2.0
"""Product collectors (ADR-0013 stage 2): the status kinds that read a product's own API.

Each kind is a collector (``collect(spec, ctx)``, registered in :data:`PRODUCT_COLLECTORS`) that
GETs the polled registry service through :func:`.collectors.fetch_json` -- the capability alias,
the source's credential by secret name, a bounded read -- and a pure mapper from the product's
response to drafts, so every mapping is tested offline against recorded or source-verified
responses (``tests/status/fixtures/``).  What each reads, and where the shape was verified:

``poll-prometheus``
    ``GET <path>?query=<mapping.query>`` (``/api/v1/query``, an instant query): each series of the
    result vector is an item named by the label ``mapping.item`` (else the metric name), its value
    judged by ``mapping.thresholds`` (``warn``/``fail`` at or ``above`` -- or at or ``below`` --
    a number); a scalar is one item.  Or ``mapping.builtin: prometheus-alerts`` over
    ``GET /api/v1/alerts``: every *firing* alert is an item, ``fail`` or ``warn`` by its
    ``severity`` label; pending and resolved alerts are not listed by Prometheus as firing, so
    they drop out.  Shape: Prometheus ``web/api/v1/api.go`` (``QueryData``, ``Alert``) and a
    real v2.54.1.
``poll-uptime-kuma``
    The public status page, no login: ``GET /api/status-page/<slug>`` (the monitors of its public
    groups) and ``GET /api/status-page/heartbeat/<slug>`` (each monitor's latest heartbeats and
    its 24-hour uptime).  Each monitor is an item: up ok, down fail, pending warn, maintenance
    unknown; a pinned incident is one more item.  Shape: Uptime Kuma 1.23
    ``server/routers/status-page-router.js`` and a real 1.23.16.
``poll-stackstorm``
    ``GET <path>?limit=..&sort_desc=true&timestamp_gt=<window start>`` (``/api/v1/executions``)
    and ``?status=running``, with ``St2-Api-Key`` from the secret store: each action with a
    failed, timed-out or abandoned execution in the window is a ``fail`` item; the running count
    is live work.  Shape: StackStorm ``st2common/openapi.yaml``, ``ActionExecutionAPI`` and the
    ``LIVEACTION_STATUS_*`` constants.
``poll-nifi``
    ``GET /nifi-api/flow/status`` (``controllerStatus``) and ``GET /nifi-api/flow/bulletin-board``
    (``bulletinBoard.bulletins``), optionally with a bearer token: queued flowfiles (live work,
    ``mapping.thresholds`` on the count), invalid components ``fail``, stopped ``warn``, and one
    item per component with ERROR (``fail``) or WARNING (``warn``) bulletins.  Shape: NiFi
    ``ControllerStatusDTO``, ``BulletinBoardEntity`` and ``BulletinEntity``/``BulletinDTO``.

A response the mapper cannot read raises :class:`.mapping.MappingError` (the source's error,
like a timeout); a value the mapper does not know is ``unknown``, never ``ok``.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from .mapping import Draft, MappingError, age_text, clean_item, clean_summary, raw_text
from .model import iso, parse_iso

if TYPE_CHECKING:
    from .collectors import CollectContext
    from .model import SourceSpec

KUMA_STATUS = {0: "down", 1: "up", 2: "pending", 3: "maintenance"}  # src/util.ts DOWN..MAINTENANCE
KUMA_STATES = {"up": "ok", "down": "fail", "pending": "warn", "maintenance": "unknown"}
ST2_STATUSES = (
    "requested",
    "scheduled",
    "delayed",
    "running",
    "succeeded",
    "failed",
    "timeout",
    "abandoned",
    "canceling",
    "canceled",
    "pending",
    "pausing",
    "paused",
    "resuming",
)  # st2common/constants/action.py LIVEACTION_STATUSES
ST2_STATES = {"failed": "fail", "timeout": "fail", "abandoned": "fail"}
ST2_DEFAULT_WINDOW_S = 3600
ST2_MAX_LIMIT = 100  # api.max_page_size: the most a non-admin key may ask for
NIFI_STATES = {
    "invalid": "fail",
    "stopped": "warn",
    "disabled": "ok",
    "sync-failure": "warn",
    "error": "fail",
    "warning": "warn",
}
#: Prometheus alert ``severity`` label -> state; anything else (or no label) is fail
ALERT_SEVERITIES = {
    "critical": "fail",
    "error": "fail",
    "page": "fail",
    "high": "fail",
    "warning": "warn",
    "warn": "warn",
    "medium": "warn",
    "low": "warn",
    "info": "warn",
    "none": "ok",  # the always-firing-by-design convention (Watchdog, InfoInhibitor)
}
_SLUG_PATH = re.compile(
    r"^(?P<prefix>(?:/[^?]*)?)/api/status-page/(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)$"
)


# ---------------------------------------------------------------- helpers
def _num(v: float) -> str:
    return f"{v:g}"


def _float(raw: Any) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return math.nan


def threshold_state(value: float, thresholds: Mapping[str, Any] | None) -> tuple[str, str]:
    """``(state, note)`` for ``value`` against ``{warn?, fail?, direction: above|below}``; NaN is
    unknown, and no thresholds at all is unknown (a number alone says nothing is healthy)."""
    if math.isnan(value) or not thresholds:
        return "unknown", ""
    below = thresholds.get("direction") == "below"
    word = "at or below" if below else "at or above"
    for state in ("fail", "warn"):
        bound = thresholds.get(state)
        if bound is not None and (value <= bound if below else value >= bound):
            return state, f" ({state} {word} {_num(float(bound))})"
    return "ok", ""


def _digest(labels: Mapping[str, Any]) -> str:
    text = ",".join(f"{k}={labels[k]}" for k in sorted(labels))
    return hashlib.sha256(text.encode()).hexdigest()[:8]


def _unique(drafts: list[tuple[str, Mapping[str, Any], Draft]]) -> list[Draft]:
    """Items that share a name are told apart by a digest of their labels (stable per series)."""
    counts: dict[str, int] = {}
    for name, _, _ in drafts:
        counts[name] = counts.get(name, 0) + 1
    out = []
    for name, labels, d in drafts:
        item = name if counts[name] == 1 else clean_item(f"{name}@{_digest(labels)}", name)
        out.append(Draft(item, d.state, d.summary, d.module, d.link, d.value, d.work))
    return out


def _table(defaults: Mapping[str, str], mapping: Mapping[str, Any]) -> dict[str, str]:
    return {**defaults, **{str(k).lower(): v for k, v in (mapping.get("states") or {}).items()}}


def _mapping(doc: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(doc, Mapping):
        raise MappingError(f"{what}: expected an object")
    return doc


# ---------------------------------------------------------------- Prometheus
def _prom_data(payload: Any) -> Mapping[str, Any]:
    doc = _mapping(payload, "prometheus")
    if doc.get("status") != "success":
        raise MappingError(
            f"prometheus: {doc.get('errorType') or 'error'}: {clean_summary(doc.get('error'))}"
        )
    return _mapping(doc.get("data"), "prometheus data")


def prometheus_query(payload: Any, mapping: Mapping[str, Any], fallback_item: str) -> list[Draft]:
    """An instant-query response (``resultType`` vector or scalar) -> one item per series."""
    data = _prom_data(payload)
    kind, result = data.get("resultType"), data.get("result")
    thresholds = mapping.get("thresholds")
    label = mapping.get("item")
    if kind == "scalar":
        if not isinstance(result, list) or len(result) != 2:
            raise MappingError("prometheus: a scalar result is [time, value]")
        series = [({}, result)]
    elif kind == "vector":
        if not isinstance(result, list):
            raise MappingError("prometheus: a vector result is a list")
        series = [(_mapping(r, "series").get("metric") or {}, r.get("value")) for r in result]
    else:
        raise MappingError(
            f"prometheus: an instant query must return a vector or scalar, not {kind}"
        )
    if not series and mapping.get("empty"):
        state = mapping["empty"]
        return [Draft(fallback_item, state, "the query returned no series")]
    drafts = []
    for labels, sample in series:
        if not isinstance(labels, Mapping):
            raise MappingError("prometheus: a series' metric is a label set")
        # a native histogram sample ("histogram", not "value") has no single value to judge
        value = _float(sample[1]) if isinstance(sample, list) and len(sample) == 2 else math.nan
        name = labels.get(label) if label else labels.get("__name__")
        item = clean_item(name if name is not None else fallback_item, fallback_item)
        state, note = threshold_state(value, thresholds)
        shown = "no single value" if math.isnan(value) else _num(value)
        summary = f"{label}={name}: {shown}" if label and name is not None else shown
        drafts.append(
            (
                item,
                labels,
                Draft(
                    item,
                    state,
                    clean_summary(summary + note),
                    value=None if math.isnan(value) else value,
                ),
            )
        )
    return _unique(drafts)


def prometheus_alerts(payload: Any, mapping: Mapping[str, Any], fallback_item: str) -> list[Draft]:
    """``/api/v1/alerts`` -> one item per firing alert, fail or warn by its ``severity`` label."""
    alerts = _prom_data(payload).get("alerts")
    if not isinstance(alerts, list):
        raise MappingError("prometheus: data.alerts is not a list")
    table = _table(ALERT_SEVERITIES, mapping)
    label = mapping.get("item")
    drafts = []
    for a in alerts:
        a = _mapping(a, "alert")
        if raw_text(a.get("state")) != "firing":
            continue  # pending: still inside its `for:`; Prometheus decides when it is real
        labels = a.get("labels") if isinstance(a.get("labels"), Mapping) else {}
        notes = a.get("annotations") if isinstance(a.get("annotations"), Mapping) else {}
        name = str(labels.get("alertname") or fallback_item)
        if label and labels.get(label) is not None:
            name = f"{name}:{labels[label]}"
        severity = raw_text(labels.get("severity"))
        text = notes.get("summary") or notes.get("description") or "firing"
        since = str(a.get("activeAt") or "")[:19]
        summary = f"{severity or 'no severity'}: {text}" + (f" (since {since}Z)" if since else "")
        item = clean_item(name, fallback_item)
        drafts.append(
            (item, labels, Draft(item, table.get(severity, "fail"), clean_summary(summary)))
        )
    return _unique(drafts)


class PrometheusCollector:
    """``poll-prometheus``: an instant query, or ``builtin: prometheus-alerts``."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        from .collectors import fetch_json

        if spec.mapping.get("builtin") == "prometheus-alerts":
            return prometheus_alerts(fetch_json(spec, ctx), spec.mapping, spec.id)
        query = {"query": str(spec.mapping.get("query", ""))}
        return prometheus_query(fetch_json(spec, ctx, query=query), spec.mapping, spec.id)


# ---------------------------------------------------------------- Uptime Kuma
def kuma_heartbeat_path(path: str) -> str:
    """``.../api/status-page/<slug>`` -> ``.../api/status-page/heartbeat/<slug>``."""
    m = _SLUG_PATH.match(path)
    if not m:
        raise MappingError(f"{path!r} is not /api/status-page/<slug>")
    return f"{m['prefix']}/api/status-page/heartbeat/{m['slug']}"


def uptime_kuma(
    page: Any, beats: Any, mapping: Mapping[str, Any], now: float, fallback_item: str
) -> list[Draft]:
    """A status page and its heartbeat list -> one item per public monitor (+ a pinned incident)."""
    page = _mapping(page, "uptime kuma status page")
    beats = _mapping(beats, "uptime kuma heartbeats")
    groups = page.get("publicGroupList")
    beat_lists = beats.get("heartbeatList")
    uptimes = beats.get("uptimeList") if isinstance(beats.get("uptimeList"), Mapping) else {}
    if not isinstance(groups, list) or not isinstance(beat_lists, Mapping):
        raise MappingError("uptime kuma: expected publicGroupList and heartbeatList")
    table = _table(KUMA_STATES, mapping)
    seen: set[str] = set()
    drafts = []
    for group in groups:
        for mon in _mapping(group, "group").get("monitorList") or []:
            mon = _mapping(mon, "monitor")
            mid = str(mon.get("id"))
            if mid in seen:  # one monitor may sit in two groups
                continue
            seen.add(mid)
            history = beat_lists.get(mid) or []
            last = history[-1] if isinstance(history, list) and history else None
            if not isinstance(last, Mapping):
                state, summary = "unknown", "no heartbeat yet"
            else:
                word = KUMA_STATUS.get(last.get("status"), raw_text(last.get("status")))
                state = table.get(word, "unknown")
                parts = [word]
                uptime = uptimes.get(f"{mid}_24")
                if isinstance(uptime, int | float):
                    parts.append(f"{uptime * 100:.2f}% over 24h")
                if isinstance(last.get("ping"), int | float):
                    parts.append(f"{last['ping']} ms")
                summary = ", ".join(parts)
                if last.get("time"):
                    try:
                        ago = now - parse_iso(str(last["time"]).replace(" ", "T"))
                        summary += f", last beat {age_text(ago)} ago"
                    except ValueError:
                        pass
            name = str(mon.get("name") or mid)
            drafts.append(
                (name, {"id": mid}, Draft(clean_item(name, fallback_item), state, summary))
            )
    out = _unique([(d.item, labels, d) for _, labels, d in drafts])
    incident = page.get("incident")
    if isinstance(incident, Mapping):
        state = "fail" if raw_text(incident.get("style")) == "danger" else "warn"
        title = incident.get("title") or "incident"
        out.append(Draft("incident", state, clean_summary(f"pinned incident: {title}")))
    return out


class UptimeKumaCollector:
    """``poll-uptime-kuma``: the public status page and its heartbeats (no login)."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        from .collectors import fetch_json

        page = fetch_json(spec, ctx)
        beats = fetch_json(spec, ctx, path=kuma_heartbeat_path(spec.path or ""))
        return uptime_kuma(page, beats, spec.mapping, ctx.clock(), spec.id)


# ---------------------------------------------------------------- StackStorm
def _st2_window(mapping: Mapping[str, Any]) -> int:
    return int(mapping.get("window_s") or ST2_DEFAULT_WINDOW_S)


def stackstorm(
    recent: Any, running: Any, mapping: Mapping[str, Any], now: float, fallback_item: str
) -> list[Draft]:
    """Executions in the window and the running ones -> per-action failure items + live work."""
    if not isinstance(recent, list) or not isinstance(running, list):
        raise MappingError("stackstorm: /executions returns a list of executions")
    window = _st2_window(mapping)
    limit = int(mapping.get("limit") or ST2_MAX_LIMIT)
    table = _table(ST2_STATES, mapping)
    bad: dict[str, list[Mapping[str, Any]]] = {}
    seen = 0
    for ex in recent:
        ex = _mapping(ex, "execution")
        try:
            started = parse_iso(str(ex.get("start_timestamp")))
        except ValueError:
            raise MappingError(
                f"stackstorm: execution {ex.get('id')} has no start_timestamp"
            ) from None
        if now - started > window:
            continue  # the server filters by timestamp_gt too; this keeps a fake honest
        seen += 1
        status = raw_text(ex.get("status"))
        if table.get(status, "ok") != "ok":
            ref = str((ex.get("action") or {}).get("ref") or fallback_item)
            bad.setdefault(ref, []).append(ex)
    span = age_text(window)
    out = []
    for ref in sorted(bad):
        exs = sorted(bad[ref], key=lambda e: str(e.get("start_timestamp")))
        counts: dict[str, int] = {}
        for e in exs:
            counts[raw_text(e.get("status"))] = counts.get(raw_text(e.get("status")), 0) + 1
        states = [table[s] for s in counts]
        latest = exs[-1]
        what = ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
        out.append(
            Draft(
                clean_item(ref, fallback_item),
                "fail" if "fail" in states else "warn" if "warn" in states else "unknown",
                clean_summary(
                    f"{what} in the last {span}; latest {raw_text(latest.get('status'))} "
                    f"{latest.get('id')} at {latest.get('start_timestamp')}"
                ),
                value=len(exs),
            )
        )
    capped = " (the newest only: raise limit or narrow the window)" if len(recent) >= limit else ""
    failed = sum(len(v) for v in bad.values())
    out.append(
        Draft(
            "executions",
            "ok",
            f"{seen} execution(s) in the last {span}, {failed} failed{capped}",
            value=seen,
        )
    )
    n = len(running)
    more = "+" if n >= ST2_MAX_LIMIT else ""
    out.append(Draft("running", "ok", f"{n}{more} running execution(s)", value=n, work=True))
    return out


class StackStormCollector:
    """``poll-stackstorm``: recent executions (failures) and the running ones (live work)."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        from .collectors import fetch_json

        now = ctx.clock()
        light = {"exclude_attributes": "result,trigger_instance"}  # outputs can be large
        limit = str(spec.mapping.get("limit") or ST2_MAX_LIMIT)
        since = iso(now - _st2_window(spec.mapping))
        recent = fetch_json(
            spec,
            ctx,
            query={"limit": limit, "sort_desc": "true", "timestamp_gt": since, **light},
        )
        running = fetch_json(
            spec, ctx, query={"status": "running", "limit": str(ST2_MAX_LIMIT), **light}
        )
        return stackstorm(recent, running, spec.mapping, now, spec.id)


# ---------------------------------------------------------------- NiFi
def nifi_bulletin_path(path: str) -> str:
    """``.../flow/status`` -> ``.../flow/bulletin-board``."""
    if not path.endswith("/flow/status"):
        raise MappingError(f"{path!r} does not end in /flow/status")
    return path[: -len("/status")] + "/bulletin-board"


def _count(status: Mapping[str, Any], key: str) -> int | None:
    v = status.get(key)
    return int(v) if isinstance(v, int | float) and not isinstance(v, bool) else None


def nifi(status: Any, board: Any, mapping: Mapping[str, Any], fallback_item: str) -> list[Draft]:
    """Controller status and the bulletin board -> queue, component and bulletin items."""
    cs = _mapping(_mapping(status, "nifi status").get("controllerStatus"), "controllerStatus")
    table = _table(NIFI_STATES, mapping)
    queued = _count(cs, "flowFilesQueued")
    if queued is None:
        raise MappingError("nifi: controllerStatus.flowFilesQueued is missing")
    q_state, note = threshold_state(float(queued), mapping.get("thresholds"))
    if not mapping.get("thresholds"):
        q_state, note = "ok", ""
    out = [
        Draft(
            "queued",
            q_state,
            clean_summary(f"{queued} flowfile(s) queued ({cs.get('queued') or queued}){note}"),
            value=queued,
            work=True,
        ),
        Draft(
            "running",
            "ok",
            f"{_count(cs, 'runningCount') or 0} running component(s), "
            f"{_count(cs, 'activeThreadCount') or 0} active thread(s)",
            value=_count(cs, "activeThreadCount") or 0,
            work=True,
        ),
    ]
    for item, key, noun in (
        ("invalid", "invalidCount", "invalid component"),
        ("stopped", "stoppedCount", "stopped component"),
        ("disabled", "disabledCount", "disabled component"),
        ("sync-failure", "syncFailureCount", "versioned group that failed to sync"),
    ):
        n = _count(cs, key)
        if n is None:
            continue  # syncFailureCount is null without flow registry clients
        state = table.get(item, "unknown") if n else "ok"
        out.append(Draft(item, state, f"{n} {noun}" + ("" if n == 1 else "s"), value=n))
    bulletins = _mapping(
        _mapping(board, "nifi bulletin board").get("bulletinBoard"), "bulletinBoard"
    )
    entries = bulletins.get("bulletins")
    if not isinstance(entries, list):
        raise MappingError("nifi: bulletinBoard.bulletins is not a list")
    by_source: dict[str, list[Mapping[str, Any]]] = {}
    unreadable = 0
    for e in entries:
        b = _mapping(e, "bulletin entity").get("bulletin")
        if not isinstance(b, Mapping):  # canRead false: the entity carries no bulletin
            unreadable += 1
            continue
        level = raw_text(b.get("level"))
        if table.get(level, "ok") == "ok":
            continue  # INFO and DEBUG are not attention
        name = str(b.get("sourceName") or b.get("sourceId") or fallback_item)
        by_source.setdefault(name, []).append(b)
    for name in sorted(by_source):
        bs = sorted(by_source[name], key=lambda b: _float(b.get("id")))
        levels = {raw_text(b.get("level")) for b in bs}
        state = "fail" if any(table[lv] == "fail" for lv in levels) else "warn"
        latest = bs[-1]
        out.append(
            Draft(
                clean_item(f"bulletin:{name}", fallback_item),
                state,
                clean_summary(
                    f"{len(bs)} {'/'.join(sorted(levels))} bulletin(s); latest: "
                    f"{latest.get('message') or ''}"
                ),
                value=len(bs),
            )
        )
    hidden = f", {unreadable} not readable by this credential" if unreadable else ""
    out.append(
        Draft(
            "bulletins",
            "ok",
            f"{len(entries)} bulletin(s) on the board{hidden}",
            value=len(entries),
        )
    )
    return out


class NiFiCollector:
    """``poll-nifi``: the controller status and the bulletin board."""

    def collect(self, spec: SourceSpec, ctx: CollectContext) -> list[Draft]:
        from .collectors import fetch_json

        status = fetch_json(spec, ctx)
        limit = str(spec.mapping.get("limit") or 100)
        board = fetch_json(
            spec, ctx, path=nifi_bulletin_path(spec.path or ""), query={"limit": limit}
        )
        return nifi(status, board, spec.mapping, spec.id)


PRODUCT_COLLECTORS = {
    "poll-prometheus": PrometheusCollector(),
    "poll-uptime-kuma": UptimeKumaCollector(),
    "poll-stackstorm": StackStormCollector(),
    "poll-nifi": NiFiCollector(),
}


# ---------------------------------------------------------------- registry rules
_PROM_QUERY_KEYS = {"module", "query", "item", "thresholds", "empty"}
_PROM_ALERT_KEYS = {"module", "builtin", "states", "item"}
_KIND_KEYS: dict[str, set[str]] = {
    "poll-uptime-kuma": {"module", "states"},
    "poll-stackstorm": {"module", "states", "window_s", "limit"},
    "poll-nifi": {"module", "states", "thresholds", "limit"},
}
_STATE_WORDS: dict[str, tuple[str, ...]] = {
    "poll-uptime-kuma": tuple(KUMA_STATES),
    "poll-stackstorm": ST2_STATUSES,
    "poll-nifi": tuple(NIFI_STATES),
}
_PATHS: dict[str, tuple[Callable[[str], bool], str]] = {
    "poll-uptime-kuma": (lambda p: bool(_SLUG_PATH.match(p)), "/api/status-page/<slug>"),
    "poll-stackstorm": (lambda p: p.endswith("/executions"), "a path ending in /executions"),
    "poll-nifi": (lambda p: p.endswith("/flow/status"), "a path ending in /flow/status"),
}


def source_problems(src: Mapping[str, Any], where: str) -> list[str]:
    """Registry rules for a product kind the schema cannot state (``hnx registry validate``)."""
    kind = src["kind"]
    mapping = src.get("mapping") or {}
    path = (src.get("target") or {}).get("path", "")
    problems = []
    if "?" in path:
        problems.append(f"{where}: {kind} builds its own query string (no '?' in target.path)")
    if kind == "poll-prometheus":
        if mapping.get("builtin") == "prometheus-alerts":
            allowed, want = _PROM_ALERT_KEYS, "/api/v1/alerts"
        elif "builtin" in mapping:
            return [f"{where}: poll-prometheus takes builtin prometheus-alerts or a query"]
        else:
            allowed, want = _PROM_QUERY_KEYS, "/api/v1/query"
            if "query" not in mapping:
                problems.append(
                    f"{where}: poll-prometheus needs mapping.query (or builtin prometheus-alerts)"
                )
            if "thresholds" not in mapping:
                problems.append(
                    f"{where}: a query mapping needs thresholds (a value alone is not a state)"
                )
        if path and not path.split("?")[0].endswith(want):
            problems.append(f"{where}: this mapping reads {want} (target.path is {path})")
    else:
        allowed = _KIND_KEYS[kind]
        check, want = _PATHS[kind]
        if path and not check(path.split("?")[0]):
            problems.append(f"{where}: {kind} needs target.path {want}")
        words = set(_STATE_WORDS[kind])
        for k in mapping.get("states") or {}:
            if str(k).lower() not in words:
                problems.append(f"{where}: states key {k!r} is not one of {sorted(words)}")
    extra = sorted(set(mapping) - allowed)
    if extra:
        problems.append(f"{where}: {kind} mapping takes only {sorted(allowed)} (not {extra})")
    th = mapping.get("thresholds") or {}
    if th and not ({"warn", "fail"} & set(th)):
        problems.append(f"{where}: thresholds need warn or fail")
    return problems
