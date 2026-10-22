# SPDX-License-Identifier: Apache-2.0
"""Schedule: every scheduled thing the repository knows, with its cadence in plain words and,
where a status source says so, its last and next run.

Sources of truth, all read from the checkout and never copied:

* **role timers** -- each ``<U>.timer`` (or ``.timer.j2``) a role or profile ships: its
  ``OnCalendar=`` with a ``{{ var }}`` resolved from the role's ``defaults/main.yml`` (then
  ``vars/main.yml``), its ``RandomizedDelaySec=`` and ``Description=``; the scripts it runs are
  the catalogued ones whose header names the trigger ``timer:<role>/<U>``
  (``docs/scripts/catalog.json``, ``hnx scripts``);
* **fleet units** -- every entry of a fleet_units spec (the globs ``hnx scripts reality`` reads),
  ``on_calendar`` and, for a retired unit, what replaced it;
* **CI schedules** -- each ``.github/workflows/*.yml`` with an ``on: schedule`` (cron, UTC) and
  the jobs it runs;
* **workflow packs** -- ``workflows/packs/*.yml``: event-driven, so the cadence is the event;
* **status collectors** -- every status source of the registry with its interval (or, for a
  pushed one, its staleness window).

Last and next run come from the hub's own state, never guessed: a collector's last run is its
last poll (``status.json`` ``sources[].last_attempt``) and its next is that plus its interval;
any other job's last run is the newest observation whose ``item`` is the job's id (a status
source that reports ``timer:aide/scan`` reports that timer), and its next run is computed from
its calendar when the expression is one :mod:`.cadence` reads exactly (UTC).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from homelabnext.status.model import parse_iso

from . import cadence, svg

KINDS = ("timer", "fleet-unit", "ci", "pack", "collector")
KIND_TITLES = {
    "timer": "Role timers",
    "fleet-unit": "Fleet units",
    "ci": "CI schedules",
    "pack": "Workflow packs (event-driven)",
    "collector": "Status collectors",
}
FLEET_SPECS = ("**/fleet_units.yml", "**/fleet_units/*.yml")
_VAR = re.compile(r"^\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$")
_KEY = re.compile(r"^(\w+)=(.*)$")
_PUSHED = {"push-event"}
#: test fixtures are not the lab's schedule
_SKIP = ("tests/", "tools/tests/", "conformance/fixtures/")


def _yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _seconds(text: str) -> int | None:
    """A systemd time span (``15min``, ``1h``, ``30``, ``2h 30min``) in seconds, or None."""
    units = {"": 1, "s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hr": 3600, "d": 86400}
    total = 0
    for n, unit in re.findall(r"(\d+)\s*([a-z]*)", text.strip()):
        if unit not in units:
            return None
        total += int(n) * units[unit]
    return total or None


def _unit_keys(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if m := _KEY.match(line.strip()):
            out.setdefault(m[1], []).append(m[2].strip())
    return out


def _role_vars(owner_dir: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for rel in ("defaults/main.yml", "vars/main.yml"):  # role vars beat role defaults
        p = owner_dir / rel
        doc = _yaml(p) if p.is_file() else None
        if isinstance(doc, dict):
            out.update(doc)
    return out


def gather_timers(root: Path, files: Sequence[str]) -> list[dict[str, Any]]:
    """The role and profile timers of the checkout (``files``: its repository-relative paths)."""
    out = []
    for rel in files:
        parts = rel.split("/")
        base = parts[-1].removesuffix(".j2")
        if not base.endswith(".timer"):
            continue
        if rel.startswith("ansible/roles/") and len(parts) > 3:
            owner, owner_dir = parts[2], root / "ansible" / "roles" / parts[2]
        elif rel.startswith("profiles/") and len(parts) > 2:
            owner, owner_dir = parts[1], root / "profiles" / parts[1]
        else:
            continue
        keys = _unit_keys((root / rel).read_text(encoding="utf-8"))
        variables = _role_vars(owner_dir)
        exprs, problems = [], []
        for raw in keys.get("OnCalendar", []):
            if m := _VAR.match(raw):
                val = variables.get(m[1])
                if not isinstance(val, str):
                    problems.append(f"{rel}: OnCalendar {raw} names no string default")
                    continue
                exprs.append(val)
            else:
                exprs.append(raw)
        other = sorted(k for k in keys if k.startswith("On") and k != "OnCalendar")
        problems += [f"{rel}: {k}= is not a calendar; the next run is not computed" for k in other]
        delay = keys.get("RandomizedDelaySec", [None])[-1]
        unit = base.removesuffix(".timer")
        out.append(
            {
                "id": f"timer:{owner}/{unit}",
                "owner": owner,
                "what": (keys.get("Description") or [""])[-1],
                "calendars": exprs,
                "delay_s": _seconds(delay) if delay else None,
                "path": rel,
                "problems": problems,
            }
        )
    return sorted(out, key=lambda r: r["id"])


def gather_fleet_units(root: Path, files: Sequence[str]) -> list[dict[str, Any]]:
    import fnmatch

    out = []
    for rel in files:
        if rel.startswith(_SKIP) or not any(
            fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, g.removeprefix("**/"))
            for g in FLEET_SPECS
        ):
            continue
        entries = _yaml(root / rel) or []
        for e in entries if isinstance(entries, list) else []:
            if not isinstance(e, dict) or not e.get("name"):
                continue
            cal = e.get("on_calendar") or []
            out.append(
                {
                    "id": f"fleet-unit:{e['name']}",
                    "what": str(e.get("description") or ""),
                    "calendars": [cal] if isinstance(cal, str) else [str(c) for c in cal],
                    "delay_s": int(e["randomized_delay_sec"])
                    if str(e.get("randomized_delay_sec", "")).isdigit()
                    else None,
                    "retired": e.get("replaced_by"),
                    "path": rel,
                }
            )
    return sorted(out, key=lambda r: r["id"])


def gather_ci(root: Path) -> list[dict[str, Any]]:
    wdir = root / ".github" / "workflows"
    out = []
    for wf in sorted([*wdir.glob("*.yml"), *wdir.glob("*.yaml")]) if wdir.is_dir() else []:
        doc = _yaml(wf) or {}
        on = doc.get("on", doc.get(True, {}))  # YAML 1.1 reads a bare `on:` key as True
        sched = on.get("schedule") if isinstance(on, dict) else None
        if not sched:
            continue
        out.append(
            {
                "id": f"ci:{wf.stem}",
                "what": str(doc.get("name") or wf.stem),
                "crons": [str(s["cron"]) for s in sched if isinstance(s, dict) and s.get("cron")],
                "jobs": sorted(doc.get("jobs") or {}),
                "path": wf.relative_to(root).as_posix(),
            }
        )
    return out


def gather_packs(root: Path) -> list[dict[str, Any]]:
    out = []
    for p in sorted((root / "workflows" / "packs").glob("*.yml")):
        doc = _yaml(p) or {}
        out.append(
            {
                "id": f"pack:{doc.get('pack', p.stem)}",
                "what": " ".join(str(doc.get("description") or "").split()),
                "event": (doc.get("trigger") or {}).get("event"),
                "actor": doc.get("actor"),
                "path": p.relative_to(root).as_posix(),
            }
        )
    return out


def gather_scripts(root: Path) -> dict[str, list[str]]:
    """Trigger -> the catalogued script ids it runs (``docs/scripts/catalog.json``)."""
    p = root / "docs" / "scripts" / "catalog.json"
    if not p.is_file():
        return {}
    out: dict[str, list[str]] = {}
    for s in json.loads(p.read_text(encoding="utf-8")).get("scripts") or ():
        for t in s.get("trigger") or ():
            out.setdefault(t, []).append(s["id"])
    return {k: sorted(v) for k, v in out.items()}


def gather(root: str | Path, registry: Any = None) -> dict[str, Any]:
    """Everything the page needs from a checkout and a registry (built once per process)."""
    from homelabnext.scripts.catalog import tracked_files

    r = Path(root)
    files = tracked_files(r)
    collectors = []
    if registry is not None:
        from homelabnext.status.model import sources_from_registry

        collectors = [s.describe() for s in sources_from_registry(registry)]
    return {
        "timers": gather_timers(r, files),
        "fleet_units": gather_fleet_units(r, files),
        "ci": gather_ci(r),
        "packs": gather_packs(r),
        "scripts": gather_scripts(r),
        "collectors": collectors,
    }


# ------------------------------------------------------------------------------- build
def _iso(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _last_by_item(observations: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    out: dict[str, Mapping[str, Any]] = {}
    for o in observations:
        prev = out.get(o["item"])
        if prev is None or parse_iso(o["observed_at"]) > parse_iso(prev["observed_at"]):
            out[o["item"]] = o
    return out


def _calendar_row(
    base: Mapping[str, Any], exprs: Sequence[str], dialect: str, now: datetime | None
) -> dict[str, Any]:
    described = [cadence.describe(x, dialect) for x in exprs]
    nexts = [cadence.next_run(c, now) for _, c in described if c is not None and now is not None]
    nexts = [n for n in nexts if n is not None]
    computable = bool(described) and all(c is not None for _, c in described)
    return {
        **base,
        "cadence": "; ".join(w for w, _ in described) or "no calendar",
        "expression": "; ".join(exprs),
        "next_run": _iso(min(nexts)) if nexts and computable else None,
    }


def build(
    inputs: Mapping[str, Any],
    *,
    now: str | None = None,
    sources: Sequence[Mapping[str, Any]] = (),
    observations: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """The schedule view-model.  ``now``: the time next runs are computed after (``status.json``
    ``generated_at``; without it none is); ``sources``/``observations``: the hub's, for last
    runs."""
    at = datetime.fromtimestamp(parse_iso(now), UTC) if now else None
    scripts = inputs.get("scripts") or {}
    rows: list[dict[str, Any]] = []
    problems: list[str] = []
    for t in inputs.get("timers") or ():
        row = _calendar_row(
            {
                "id": t["id"],
                "kind": "timer",
                "what": t["what"],
                "where": f"role {t['owner']}",
                "runs": scripts.get(t["id"], []),
                "path": t["path"],
            },
            t["calendars"],
            "systemd",
            at,
        )
        if t.get("delay_s"):
            row["cadence"] += f", up to {_span(t['delay_s'])} later (randomized)"
        problems += t.get("problems") or []
        rows.append(row)
    for u in inputs.get("fleet_units") or ():
        row = _calendar_row(
            {
                "id": u["id"],
                "kind": "fleet-unit",
                "what": u["what"],
                "where": u["path"],
                "runs": scripts.get(u["id"], []),
                "path": u["path"],
            },
            u["calendars"],
            "systemd",
            at,
        )
        if u.get("retired"):
            row.update(cadence=f"retired: replaced by {u['retired']}", next_run=None)
        elif u.get("delay_s"):
            row["cadence"] += f", up to {_span(u['delay_s'])} later (randomized)"
        rows.append(row)
    for c in inputs.get("ci") or ():
        runs = sorted({s for j in c["jobs"] for s in scripts.get(f"ci:{c['id'][3:]}/{j}", [])})
        rows.append(
            _calendar_row(
                {
                    "id": c["id"],
                    "kind": "ci",
                    "what": c["what"],
                    "where": f"jobs {', '.join(c['jobs'])}",
                    "runs": runs,
                    "path": c["path"],
                },
                c["crons"],
                "cron",
                at,
            )
        )
    for p in inputs.get("packs") or ():
        rows.append(
            {
                "id": p["id"],
                "kind": "pack",
                "what": p["what"],
                "where": f"as {p['actor']}",
                "runs": [],
                "path": p["path"],
                "expression": p["event"] or "",
                "cadence": f"on each {p['event']} event" if p["event"] else "no trigger",
                "next_run": None,
            }
        )
    polled = {s["id"]: s for s in sources}
    for s in inputs.get("collectors") or ():
        live = polled.get(s["id"], {})
        pushed = s["kind"] in _PUSHED
        last = live.get("last_ok") if pushed else live.get("last_attempt")
        nxt = None
        if last and not pushed:
            nxt = _iso(
                datetime.fromtimestamp(parse_iso(last), UTC) + timedelta(seconds=s["interval_s"])
            )
        cad = (
            f"pushed by the service; stale after {_span(s['stale_after_s'])} of silence"
            if pushed
            else f"{cadence.interval_words(s['interval_s'])} (hnx status collect)"
        )
        rows.append(
            {
                "id": f"status:{s['id']}",
                "kind": "collector",
                "what": s["what"],
                "where": f"svc:{s['service']} ({s['kind']})",
                "runs": [],
                "path": None,
                "expression": f"interval_s {s['interval_s']}",
                "cadence": cad,
                "next_run": nxt,
                "last_run": last,
                "state": live.get("state"),
            }
        )
    seen = _last_by_item(observations)
    for row in rows:
        if row["kind"] == "collector":
            continue
        o = seen.get(row["id"])
        row["last_run"] = o["observed_at"] if o else None
        row["state"] = o["state"] if o else None
    groups = [
        {"kind": k, "title": KIND_TITLES[k], "rows": [r for r in rows if r["kind"] == k]}
        for k in KINDS
    ]
    return {
        "now": now,
        "groups": groups,
        "counts": {k: sum(1 for r in rows if r["kind"] == k) for k in KINDS},
        "problems": problems,
    }


def _span(seconds: int) -> str:
    """``900`` -> ``15 minutes``, ``60`` -> ``1 minute``."""
    w = cadence.interval_words(int(seconds)).removeprefix("every ")
    return w if w[0].isdigit() else f"1 {w}"


# ------------------------------------------------------------------------------ render
def _when(v: str | None, none: str) -> str:
    return svg.e(v) if v else f'<span class="muted">{svg.e(none)}</span>'


def render(vm: Mapping[str, Any]) -> str:
    c = vm["counts"]
    head = (
        '<p class="chips">'
        + "".join(f"<b>{c[k]} {svg.e(KIND_TITLES[k].lower())}</b>" for k in KINDS)
        + "</p>"
        + (
            f'<p class="muted">next runs computed after {svg.e(vm["now"])} (UTC)</p>'
            if vm["now"]
            else '<p class="muted">no time given: next runs are not computed</p>'
        )
    )
    probs = "".join(f"<li>{svg.e(p)}</li>" for p in vm["problems"])
    parts = [head, f'<ul class="fail">{probs}</ul>' if probs else ""]
    for g in vm["groups"]:
        parts.append(f"<h3>{svg.e(g['title'])}</h3>")
        parts.append(
            svg.table(
                g["title"],
                ("Job", "What", "Cadence", "Last run", "Next run", "Where", "Runs"),
                [
                    (
                        svg.code(r["id"])
                        + (
                            f' <span class="s {svg.e(r["state"])}">{svg.e(r["state"])}</span>'
                            if r.get("state")
                            else ""
                        ),
                        svg.e(r["what"]),
                        svg.e(r["cadence"])
                        + (
                            f'<br><code class="muted">{svg.e(r["expression"])}</code>'
                            if r["expression"]
                            else ""
                        ),
                        _when(r.get("last_run"), "not reported"),
                        _when(
                            r["next_run"], "on its event" if r["kind"] == "pack" else "not computed"
                        ),
                        svg.e(r["where"]),
                        svg.codes(r["runs"]) if r["runs"] else '<span class="muted">-</span>',
                    )
                    for r in g["rows"]
                ],
            )
        )
    return "".join(parts)
