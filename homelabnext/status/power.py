# SPDX-License-Identifier: Apache-2.0
"""UPS status sources generated from the site model, and the "UPS on battery" notification.

The site lists its UPSes (``power.ups``: ``id``, ``model``, ``monitored_by``, ``nut_name``) and
every device names the UPS feeding it (:mod:`homelabnext.power`).  The registry says where upsd
runs: a ``poll-nut`` source **without** ``mapping.ups`` on the upsd service is a template.
:func:`expand` turns it into one source per site UPS with ``monitored_by: nut`` and a
``nut_name`` -- id ``<template id>-<ups id>``, the template's interval, timeout, credential and
TLS settings, ``mapping.ups`` = the ``nut_name`` -- and records on each what that UPS feeds:
the devices (router, switches, edge, hypervisors, physical hosts) and, through the power
inheritance, every guest (a VM or container is as protected as its hypervisor).  A ``poll-nut``
source that already names a site UPS's ``nut_name`` is kept as declared and gains the same
facts.  Without a site the template is an ordinary source over every UPS upsd lists.

:func:`notify` is the state-diffed "UPS on battery" message, through the same shared Notifier
the hub pages with: one key per UPS, ``on-battery`` (warn) and ``low-battery`` (crit, on
battery with LB) page, line power (OL or BYPASS without OB) is ``ok`` and sends the one "back
on line power" recovery.  The state comes from the observation's structured ``flags`` (from the
NUT mapper), never from its summary.  The body lists what the UPS feeds, so the reader knows
which guests are on borrowed time.  No reading is held, neither paged nor recovered: a stale
source (an unreachable upsd during a power cut is not a recovery), an ``unknown`` status (the
driver dropped: ``DATA-STALE``, ``DRIVER-NOT-CONNECTED``; ``WAIT``; no ``ups.status``) and a
status without a line or battery flag.

:func:`states` reads the UPS states back out of a ``status.json`` document for the Topology
map's UPS badges.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from homelabnext import power as pw
from homelabnext.notify.core_pairs import UPS_ON_BATTERY

from .model import SourceSpec

PREFIX = "status-power"
ON_BATTERY_TITLE, RECOVERY_TITLE = UPS_ON_BATTERY


class PowerError(ValueError):
    """The site's UPSes cannot be turned into sources (ambiguous template, id clash)."""


def fed_by(
    site: Mapping[str, Any],
    nodes: Mapping[str, Mapping[str, Any]] | None = None,
    guests: Sequence[Mapping[str, Any]] = (),
) -> dict[str, dict[str, list[str]]]:
    """UPS id -> ``{"devices": [node ids], "guests": [guest names]}``: the devices it feeds
    (declared or by ``power.default``) and every guest drawing from it, its own or inherited."""
    facts = pw.site_power(site)
    if facts is None:
        return {}
    raws = list(guests)
    specs = pw.hypervisors(dict(nodes or {}), raws)
    hosts = {str(g["id"]).removeprefix("guest:"): g for g in raws if g.get("kind") == "host"}
    resolved = pw.resolve(facts, specs, hosts)
    out = {
        u: {"devices": [n for n in fed if not n.startswith("guest:")], "guests": []}
        for u, fed in pw.feeds(resolved, facts["ups"]).items()
    }
    for g in sorted(raws, key=lambda r: str(r["id"])):
        got = pw.of_guest(g, resolved)
        for u in got[1]["ups"] if got else []:
            if u in out:
                out[u]["guests"].append(str(g["id"]).removeprefix("guest:"))
    return out


def expand(
    specs: Sequence[SourceSpec],
    site: Mapping[str, Any],
    *,
    nodes: Mapping[str, Mapping[str, Any]] | None = None,
    guests: Sequence[Mapping[str, Any]] = (),
) -> list[SourceSpec]:
    """``specs`` with the site's NUT UPSes as sources (sorted by id).  Raises
    :class:`PowerError` on two templates or a generated id that is already a source."""
    facts = pw.site_power(site)
    if facts is None:
        return list(specs)
    nut = [s for s in specs if s.kind == "poll-nut"]
    templates = [s for s in nut if not s.mapping.get("ups")]
    named = {str(s.mapping["ups"]): s for s in nut if s.mapping.get("ups")}
    wanted = {
        uid: u
        for uid, u in facts["ups"].items()
        if u.get("monitored_by") == "nut" and u.get("nut_name")
    }
    feeds = fed_by(site, nodes, guests)
    template_ids = {t.id for t in templates}
    out = [s for s in specs if s.id not in template_ids]
    pending = {uid: u for uid, u in wanted.items() if str(u["nut_name"]) not in named}
    if pending and len(templates) > 1:
        ids = ", ".join(t.id for t in templates)
        raise PowerError(
            f"poll-nut sources {ids} all read every UPS: name each UPS (mapping.ups) or keep one"
        )
    if not pending:
        out += templates  # nothing left to expand: a template still reads every UPS
    ids = {s.id for s in out}
    for uid, u in wanted.items():
        fact = _fact(uid, u, feeds.get(uid))
        if str(u["nut_name"]) in named:
            spec = named[str(u["nut_name"])]
            out = [replace(s, power=fact) if s is spec else s for s in out]
            continue
        if not templates:
            continue
        t = templates[0]
        sid = f"{t.id}-{uid}"
        if sid in ids:
            raise PowerError(f"site UPS {uid}: source id {sid} is already registered")
        ids.add(sid)
        model = f" ({u['model']})" if u.get("model") else ""
        out.append(
            replace(
                t,
                id=sid,
                mapping={**t.mapping, "ups": str(u["nut_name"])},
                what=(
                    f"UPS {uid}{model} through NUT: on battery is warn, low battery or replace "
                    f"battery is fail; feeds {_count(fact)}."
                ),
                power=fact,
            )
        )
    return sorted(out, key=lambda s: s.id)


def _fact(uid: str, ups: Mapping[str, Any], fed: Mapping[str, list[str]] | None) -> dict[str, Any]:
    fed = fed or {"devices": [], "guests": []}
    return {
        "ups": uid,
        "model": ups.get("model"),
        "devices": list(fed["devices"]),
        "guests": list(fed["guests"]),
    }


def _count(fact: Mapping[str, Any]) -> str:
    d, g = len(fact["devices"]), len(fact["guests"])
    return f"{d} device{'s' if d != 1 else ''} and {g} guest{'s' if g != 1 else ''}"


def load(
    specs: Sequence[SourceSpec], site_path: str | Path, guests_dir: str | Path | None = None
) -> list[SourceSpec]:
    """:func:`expand` over a site file and, when given, a guest directory (with its
    ``_nodes.yml``) for the power inheritance.  Raises :class:`PowerError`."""
    from homelabnext.compute.model import ComputeError
    from homelabnext.network.loader import SiteError, load_site

    try:
        if guests_dir:
            from .maps.topology import inputs

            site, guests, _, nodes = inputs(guests_dir, site_path)
            raws = [g.raw for g in guests]
        else:
            site, raws, nodes = load_site(site_path), [], {}
    except (ComputeError, SiteError) as exc:
        raise PowerError(str(exc)) from None
    if not isinstance(site, Mapping):
        raise PowerError(f"{site_path}: expected a mapping")
    return expand(specs, site, nodes=nodes, guests=raws)


# ---------------------------------------------------------------- the notification
def _ups_rows(
    specs: Mapping[str, SourceSpec], observations: Iterable[Mapping[str, Any]]
) -> list[tuple[SourceSpec, str, Mapping[str, Any]]]:
    """``(source, UPS label, its status observation)`` of every poll-nut status item."""
    out = []
    for row in observations:
        spec = specs.get(str(row.get("source")))
        if spec is None or spec.kind != "poll-nut":
            continue
        item = str(row.get("item"))
        if item == "status":
            label = str((spec.power or {}).get("ups") or spec.mapping.get("ups") or spec.id)
        elif item.endswith(":status"):
            label = item.removesuffix(":status")
        else:
            continue
        out.append((spec, label, row))
    return out


#: the flags that put the load on line power (BYPASS: mains, without battery protection)
LINE_POWER = {"OL", "BYPASS"}


def power_state(flags: Iterable[str] | None) -> str | None:
    """``on-battery``, ``low-battery`` or ``ok`` from a status item's ``ups.status`` flags;
    None (no reading) unless a battery (OB) or line-power (OL, BYPASS) flag is present."""
    got = {str(f).upper() for f in flags or ()}
    if "OB" in got:
        return "low-battery" if "LB" in got else "on-battery"
    return "ok" if got & LINE_POWER else None


def body(spec: SourceSpec, label: str, row: Mapping[str, Any]) -> str:
    fact = spec.power
    text = f"UPS {label} is on battery: {row.get('summary')}."
    if fact is None:
        return text + " What it feeds is not known (no site model given to the hub)."
    devices = ", ".join(fact["devices"]) or "no device"
    guests = ", ".join(fact["guests"]) or "no guest"
    return f"{text} It feeds {devices}; guests on it: {guests}."


def notify(
    notifier: Any,
    specs: Mapping[str, SourceSpec],
    observations: Iterable[Mapping[str, Any]],
    dead: Iterable[str] = (),
) -> list[str]:
    """Report each UPS's power state to the state-diffed Notifier; the keys a message was sent
    for.  ``dead``: stale sources, held (neither paged nor recovered)."""
    from homelabnext.notify import Message

    if not notifier.is_registered(ON_BATTERY_TITLE):
        notifier.register_pair(ON_BATTERY_TITLE, RECOVERY_TITLE)
    held = set(dead)
    sent = []
    for spec, label, row in _ups_rows(specs, observations):
        state = power_state(row.get("flags"))
        if spec.id in held or row.get("state") in ("stale", "unknown") or state is None:
            continue
        key = f"{PREFIX}/{spec.id}/{label}"
        msg = Message(
            key=key,
            title=ON_BATTERY_TITLE,
            body=body(spec, label, row),
            level="crit" if state == "low-battery" else "warn",
            tags=("status", "power", label),
        )
        if notifier.report(key, state, msg):
            sent.append(key)
    return sent


# ---------------------------------------------------------------- the topology badges
def states(doc: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Site UPS id -> ``{state, summary, flags, observed_at, source}`` from a status document (its
    ``sources`` name the UPS a generated source reads)."""
    if not doc:
        return {}
    by_source = {s["id"]: s["ups"] for s in doc.get("sources") or [] if s.get("ups")}
    out: dict[str, dict[str, Any]] = {}
    for row in doc.get("observations") or []:
        ups = by_source.get(row.get("source"))
        if ups and row.get("item") == "status":
            out[ups] = {
                "state": row.get("state"),
                "summary": row.get("summary"),
                "flags": row.get("flags"),
                "observed_at": row.get("observed_at"),
                "source": row.get("source"),
            }
    return out
