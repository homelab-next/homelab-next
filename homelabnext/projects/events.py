# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.project.changed`` events (``schemas/events/project.changed.schema.json``).

One event per item version.  The id is a pure function of the item's identity and version
(:func:`homelabnext.events.envelope.derive_event_id`): ``<uid>:v<version>`` for the Markdown
store, ``wp:<id>:v<lockVersion>`` for OpenProject, so a version seen twice (a webhook and a poll,
a re-run of ``hnx projects feed``) is one event and the forwarder drops the copy.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from homelabnext.events.envelope import build_event

from .model import Change, Link

__all__ = ["EVENT_TYPE", "SOURCES", "change_event", "change_events"]

EVENT_TYPE = "homelabnext.project.changed"
#: the envelope ``source`` per origin
SOURCES = {"markdown": "cap:projects", "openproject": "svc:openproject"}


def change_event(
    change: Change,
    *,
    origin: str = "markdown",
    links: Sequence[Link] | None = None,
    time: str | None = None,
    lock_version: int | None = None,
) -> dict[str, Any]:
    """The event for one change.  ``origin="openproject"`` needs ``change.ref`` (``wp:<id>``)
    and the work package's ``lock_version``: the dedupe key is ``wp:<id>:v<lockVersion>``."""
    if origin not in SOURCES:
        raise ValueError(f"origin must be one of {', '.join(SOURCES)}")
    if origin == "openproject":
        if not change.ref or lock_version is None:
            raise ValueError("an OpenProject change needs its ref (wp:<id>) and lockVersion")
        key = f"{change.ref}:v{lock_version}"
    else:
        key = f"{change.uid}:v{change.version}"
    data: dict[str, Any] = {
        "uid": change.uid,
        "kind": change.kind,
        "version": change.version,
        "op": change.op,
        "status": change.status,
        "origin": origin,
    }
    if change.title:
        data["title"] = change.title[:200]
    if change.kind != "project":
        data["project"] = change.project
    if change.ref:
        data["ref"] = change.ref
    if links is not None:
        data["links"] = [{"relation": lk.relation, "target": lk.target} for lk in links]
    return build_event(
        EVENT_TYPE,
        SOURCES[origin],
        data,
        dedupe_key=key,
        subject=f"project:{change.project or change.uid}",
        severity="info",
        time=_rfc3339(time or change.at),
    )


def _rfc3339(at: str) -> str:
    """``2026-10-21T12:00:00.123456Z`` -> ``2026-10-21T12:00:00Z`` (the envelope's form)."""
    return at.split(".", 1)[0].rstrip("Z") + "Z" if at else at


def change_events(
    changes: Iterable[Change], *, origin: str = "markdown", items: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Events for a batch of changes; ``items`` (uid -> :class:`~.model.WorkItem`) adds the links
    of a change that is the item's current version.  Repeated versions of one item yield one event."""
    out: dict[str, dict[str, Any]] = {}
    for ch in changes:
        it = (items or {}).get(ch.uid)
        same = it is not None and it.version == ch.version  # links only as of that version
        ev = change_event(ch, origin=origin, links=it.links if same else None)
        out.setdefault(ev["id"], ev)
    return list(out.values())
