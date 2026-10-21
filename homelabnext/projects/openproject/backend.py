# SPDX-License-Identifier: Apache-2.0
"""The ``projects`` contract on OpenProject: a backend for :class:`~homelabnext.projects.ProjectStore`.

Mapping (one OpenProject project, ``work_project``, holds the work; ``docs/projects.md``):

==================== ===============================================================================
contract             OpenProject
==================== ===============================================================================
item                 a work package of type ``Project``, ``Step`` or ``Task``
``uid``              custom field **External key** (Text, filterable)
``version``          ``lockVersion + 1``; every write is a ``PATCH`` quoting the ``lockVersion``
                     read, so a concurrent edit is HTTP 409, :class:`~..model.Conflict`
project / parent     the work package parent: a step's (and a task's) is its project's work package,
                     or the parent item's when it has one
``status``           the status of that name (``To do``, ``In progress``, ...; config)
title, description,  ``subject``, ``description`` (markdown), ``dueDate``
due
``external_key``,    custom field **hnx state** (Long text): a small JSON document, which also carries
assignee, result,    a digest of the links so that a link change bumps ``lockVersion`` and
closed on, order     ``updatedAt`` (OpenProject does not bump them for a relation)
``blocks``,          relations of those types, from the item
``precedes``
``supports``, ...    a ``relates`` relation to the record's work package in the Strategy project,
                     the label in the relation's ``description`` (there are no custom relation
                     types)
change feed          ``updatedAt`` poll, cursor ``<time>|<wp:id:vN,...>`` (the versions already
                     reported at that second: OpenProject's times have second precision)
==================== ===============================================================================

Every operation reads the work project's work packages and their relations once (homelab sized:
tens to hundreds of items).  Work packages without an External key (made by hand in the UI) are
not items until adopted (:func:`homelabnext.projects.openproject.feed.adopt`).
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterable, Mapping
from typing import Any

from ..model import DEPENDENCY_RELATIONS, LINK_RELATIONS, Change, InvalidField, NotFound
from .client import OpenProjectClient, filters
from .setup import OpenProjectConfig, Setup

__all__ = ["OpenProjectBackend", "wp_href", "wp_id"]

API = "/api/v3"


def wp_href(wp: int) -> str:
    return f"{API}/work_packages/{wp}"


def wp_id(href: Any) -> int | None:
    s = str(href or "")
    tail = s.rstrip("/").rsplit("/", 1)[-1]
    return int(tail) if s.startswith(f"{API}/work_packages/") and tail.isdigit() else None


def _link_id(wp: Mapping[str, Any], name: str) -> int | None:
    href = ((wp.get("_links") or {}).get(name) or {}).get("href")
    tail = str(href or "").rstrip("/").rsplit("/", 1)[-1]
    return int(tail) if tail.isdigit() else None


def _raw(value: Any) -> str:
    return str(value.get("raw") or "") if isinstance(value, Mapping) else str(value or "")


class OpenProjectBackend:
    def __init__(self, client: OpenProjectClient, cfg: OpenProjectConfig, setup: Setup) -> None:
        self.client, self.cfg, self.setup = client, cfg, setup
        self._lock = threading.RLock()
        self._ext = setup.fields["external_key"]
        self._state = setup.fields["state"]
        self._kinds = {setup.types[n]: k for k, n in cfg.work_types.items()}
        self._wp: dict[str, int] = {}  # uid -> work package id (work items)
        self._strategy: dict[str, int] = {}  # uid -> work package id (Strategy records)
        self.unadopted: list[int] = []

    def lock(self):
        return self._lock

    # ------------------------------------------------------------------ reading
    def _work_packages(self, project: int, **params: Any) -> list[dict[str, Any]]:
        return list(self.client.collect(f"{API}/projects/{project}/work_packages", **params))

    def strategy_uids(self) -> tuple[str, ...]:
        """The External keys of the Strategy project (what links may name)."""
        self._strategy = {}
        for wp in self._work_packages(self.setup.strategy_project):
            key = wp.get(self._ext)
            if key:
                self._strategy[str(key)] = int(wp["id"])
        return tuple(self._strategy)

    def _relations(self, ids: Iterable[int]) -> list[dict[str, Any]]:
        ids = sorted(set(ids))
        if not ids:
            return []
        return list(self.client.collect(f"{API}/relations", filters=filters(involved=("=", ids))))

    def load(self) -> dict[str, dict[str, Any]]:
        wps = self._work_packages(self.setup.work_project)
        self.strategy_uids()
        by_id: dict[int, dict[str, Any]] = {}
        self._wp, self.unadopted = {}, []
        for wp in wps:
            kind = self._kinds.get(_link_id(wp, "type") or -1)
            key = wp.get(self._ext)
            if kind is None:
                continue
            if not key:
                self.unadopted.append(int(wp["id"]))
                continue
            by_id[int(wp["id"])] = wp
            self._wp[str(key)] = int(wp["id"])
        uid_of = {i: str(wp[self._ext]) for i, wp in by_id.items()}
        strat_uid = {i: u for u, i in self._strategy.items()}
        links: dict[int, list[dict[str, str]]] = {i: [] for i in by_id}
        for rel in self._relations(by_id):
            src = wp_id(((rel.get("_links") or {}).get("from") or {}).get("href"))
            dst = wp_id(((rel.get("_links") or {}).get("to") or {}).get("href"))
            if src not in by_id:
                continue
            rtype, label = rel.get("type"), str(rel.get("description") or "")
            if rtype in DEPENDENCY_RELATIONS and dst in uid_of:
                links[src].append({"relation": rtype, "target": uid_of[dst]})
            elif rtype == "relates" and label in LINK_RELATIONS and dst in strat_uid:
                links[src].append({"relation": label, "target": strat_uid[dst]})
        return {uid_of[i]: self._doc(wp, by_id, uid_of, links[i]) for i, wp in by_id.items()}

    def _doc(self, wp, by_id, uid_of, links) -> dict[str, Any]:
        try:
            state = json.loads(_raw(wp.get(self._state)) or "{}")
        except ValueError:
            state = {}
        kind = self._kinds[_link_id(wp, "type") or -1]
        status_name = self.setup.status_name(_link_id(wp, "status") or -1)
        status = next((k for k, n in self.cfg.work_statuses.items() if n == status_name), "")
        if kind == "project":  # the two status sets share no name but Open/Closed
            status = {"Open": "open", "Closed": "closed"}.get(str(status_name), status)
        parent_wp = _link_id(wp, "parent")
        project = parent = None
        if kind != "project" and parent_wp in by_id:
            if self._kinds[_link_id(by_id[parent_wp], "type") or -1] == "project":
                project = uid_of[parent_wp]
            else:
                parent = uid_of[parent_wp]
                project = self._project_of(parent_wp, by_id, uid_of)
        return {
            "uid": str(wp[self._ext]),
            "kind": kind,
            "title": str(wp.get("subject") or ""),
            "status": status,
            "version": int(wp.get("lockVersion", 0)) + 1,
            "project": project,
            "parent": parent,
            "order": state.get("order"),
            "external_key": state.get("source_key"),
            "assignee": state.get("assignee"),
            "due": wp.get("dueDate"),
            "description": _raw(wp.get("description")),
            "result": state.get("result"),
            "closed_on": state.get("closed_on"),
            "links": links,
            "created": str(wp.get("createdAt") or ""),
            "updated": str(wp.get("updatedAt") or ""),
            "ref": f"wp:{wp['id']}",
        }

    def _project_of(self, wp: int, by_id, uid_of) -> str | None:
        seen = set()
        while wp in by_id and wp not in seen:
            seen.add(wp)
            if self._kinds[_link_id(by_id[wp], "type") or -1] == "project":
                return uid_of[wp]
            wp = _link_id(by_id[wp], "parent") or -1
        return None

    # ------------------------------------------------------------------ writing
    def _payload(self, doc: Mapping[str, Any]) -> dict[str, Any]:
        kind = doc["kind"]
        status = self.cfg.work_statuses[doc["status"]]
        up = doc.get("parent") or doc.get("project")
        state = {
            "source_key": doc.get("external_key"),
            "assignee": doc.get("assignee"),
            "result": doc.get("result"),
            "closed_on": doc.get("closed_on"),
            "order": doc.get("order"),
            "links": hashlib.sha256(
                json.dumps(sorted((x["relation"], x["target"]) for x in doc.get("links") or ())).encode()
            ).hexdigest()[:16],
        }  # fmt: skip
        return {
            "subject": doc["title"],
            "description": {"format": "markdown", "raw": doc.get("description") or ""},
            "dueDate": doc.get("due"),
            self._ext: doc["uid"],
            self._state: {"format": "markdown", "raw": json.dumps(state, sort_keys=True)},
            "_links": {
                "type": {"href": f"{API}/types/{self.setup.types[self.cfg.work_types[kind]]}"},
                "status": {"href": f"{API}/statuses/{self.setup.statuses[status]}"},
                "parent": {"href": wp_href(self._wp[up]) if up else None},
            },
        }

    def write(self, docs, changes):
        stored: dict[str, dict[str, Any]] = {}
        for doc, expected in docs:
            body = self._payload(doc)
            if expected is None:
                wp = self.client.post(
                    f"{API}/projects/{self.setup.work_project}/work_packages", body
                )
                self._wp[doc["uid"]] = int(wp["id"])
                old_links: list[dict[str, str]] = []
            else:
                wid = self._wp.get(doc["uid"])
                if wid is None:
                    raise NotFound(f"no work package for {doc['uid']}")
                body["lockVersion"] = expected - 1
                wp = self.client.patch(wp_href(wid), body)
                old_links = self._current_links(wid)
            self._sync_relations(int(wp["id"]), old_links, doc.get("links") or [])
            stored[doc["uid"]] = {
                **doc,
                "version": int(wp.get("lockVersion", 0)) + 1,
                "updated": str(wp.get("updatedAt") or doc.get("updated")),
            }
        return stored

    def _current_links(self, wid: int) -> list[dict[str, Any]]:
        out = []
        for rel in self._relations([wid]):
            ln = rel.get("_links") or {}
            if wp_id((ln.get("from") or {}).get("href")) == wid:
                out.append(rel)
        return out

    def _target_wp(self, link: Mapping[str, str]) -> int:
        table = self._strategy if link["relation"] in LINK_RELATIONS else self._wp
        wid = table.get(link["target"])
        if wid is None:
            raise NotFound(f"no work package for {link['target']}")
        return wid

    def _sync_relations(self, wid: int, current, wanted) -> None:
        def key_of_rel(rel) -> tuple[str, int | None]:
            to = wp_id(((rel.get("_links") or {}).get("to") or {}).get("href"))
            label = rel.get("type") if rel.get("type") != "relates" else rel.get("description")
            return str(label), to

        have = {key_of_rel(r): r for r in current}
        want = {(x["relation"], self._target_wp(x)): x for x in wanted}
        for k, rel in have.items():
            if k not in want and (k[0] in DEPENDENCY_RELATIONS or k[0] in LINK_RELATIONS):
                self.client.delete(f"{API}/relations/{rel['id']}")
        for (label, to), _x in want.items():
            if (label, to) in have:
                continue
            body = {
                "type": label if label in DEPENDENCY_RELATIONS else "relates",
                "description": "" if label in DEPENDENCY_RELATIONS else label,
                "_links": {"to": {"href": wp_href(to)}},
            }
            self.client.post(f"{wp_href(wid)}/relations", body)

    # ------------------------------------------------------------------ change feed
    def changes(self, cursor: str | None) -> tuple[list[Change], str]:
        if cursor is None:
            wps = [w for w in self._work_packages(self.setup.work_project) if w.get(self._ext)]
            return [], _cursor(wps, "", set())
        since, bar, seen_txt = cursor.partition("|")
        if not bar:
            raise InvalidField(f"not a cursor of this store: {cursor!r}")
        seen = set(filter(None, seen_txt.split(",")))
        params = {"sortBy": json.dumps([["updatedAt", "asc"]])}
        if since:  # an empty time: the store was empty, read from the beginning
            params["filters"] = filters(updatedAt=("<>d", [since, ""]))
        wps = self._work_packages(self.setup.work_project, **params)
        docs = self.load() if wps else {}
        out = []
        for wp in wps:
            if not wp.get(self._ext) or self._kinds.get(_link_id(wp, "type") or -1) is None:
                continue
            if f"wp:{wp['id']}:v{wp.get('lockVersion', 0)}" in seen:
                continue
            out.append(self.change_of(wp, docs.get(str(wp[self._ext]))))
        return out, _cursor(wps, since, seen)

    def change_of(self, wp: Mapping[str, Any], doc: Mapping[str, Any] | None = None) -> Change:
        """The contract change a work package's current state is (``op`` from what it shows);
        ``doc``: the item as :meth:`load` read it (for its project)."""
        kind = self._kinds[_link_id(wp, "type") or -1]
        status_id = _link_id(wp, "status") or -1
        name = self.setup.status_name(status_id)
        if kind == "project":
            status = {"Open": "open", "Closed": "closed"}.get(str(name), "")
        else:
            status = next((k for k, n in self.cfg.work_statuses.items() if n == name), "")
        lock = int(wp.get("lockVersion", 0))
        op = "created" if lock == 0 else "closed" if status_id in self.setup.closed else "updated"
        return Change(
            uid=str(wp[self._ext]), kind=kind, version=lock + 1, op=op, status=status,
            title=str(wp.get("subject") or ""), project=(doc or {}).get("project"),
            at=str(wp.get("updatedAt") or ""), by="svc:openproject", ref=f"wp:{wp['id']}",
        )  # fmt: skip


def _cursor(wps: list[Mapping[str, Any]], since: str, seen: set[str]) -> str:
    """``<latest updatedAt>|<wp:id:vN of every package at exactly that time>``."""
    latest = max([since, *(str(w.get("updatedAt") or "") for w in wps)])
    at = {f"wp:{w['id']}:v{w.get('lockVersion', 0)}" for w in wps if w.get("updatedAt") == latest}
    if latest == since:
        at |= seen
    return f"{latest}|{','.join(sorted(at))}"
