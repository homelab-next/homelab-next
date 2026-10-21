# SPDX-License-Identifier: Apache-2.0
"""What the adapter needs to exist in OpenProject, found by name, and ``doctor``.

OpenProject 17.9 has no API to create work package types, statuses or custom fields (``GET``
only): an administrator creates them once in the admin UI (the checklist in
``docs/projects.md``).  The adapter never hard-codes an id: :func:`discover` resolves every type,
status, custom field and project **by name** at start-up, and :func:`doctor` prints each missing
piece with the admin step that creates it.

The configuration (``openproject.yml``, every key but ``base_url`` optional)::

    base_url: https://openproject.example.internal
    token: secret:openproject/api-token     # a secret NAME; the value comes from the environment
    strategy_project: strategy              # identifier of the read-only Strategy project
    work_project: lab                       # identifier of the project the work items live in
    sync_user: hnx-sync                     # login of the service user
    viewer_roles: [Reader]                  # the only roles anyone else may hold in Strategy
"""

from __future__ import annotations

import dataclasses
import pathlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import yaml

from ..model import ProjectsError
from .client import ApiError, OpenProjectClient, filters

__all__ = [
    "CLOSED_STATUSES",
    "OpenProjectConfig",
    "Setup",
    "SetupError",
    "discover",
    "doctor",
    "load_config",
]

STRATEGY_TYPES = ("SO", "OO", "TO", "TT", "CCIR", "FFIR", "PIR", "RFI", "MOP", "MOE")
#: strategy record status -> OpenProject status name
STRATEGY_STATUSES = {
    "active": "Active",
    "achieved": "Achieved",
    "retired": "Retired",
    "answered": "Answered",
    "expired": "Expired",
    "no-find": "No-find",
    "open": "Open",
}
#: contract status -> OpenProject status name
WORK_STATUSES = {
    "open": "Open",
    "closed": "Closed",
    "blocked": "Blocked",
    "todo": "To do",
    "in_progress": "In progress",
    "done": "Done",
    "cancelled": "Cancelled",
}
CLOSED_STATUSES = frozenset(
    {"Closed", "Done", "Cancelled", "Achieved", "Retired", "Answered", "Expired", "No-find"}
)
WORK_TYPES = {"project": "Project", "step": "Step", "task": "Task"}
CUSTOM_FIELDS = {"external_key": "External key", "state": "hnx state"}


class SetupError(ProjectsError):
    """The instance lacks something the adapter needs (run ``hnx projects doctor``)."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("OpenProject is not set up: " + "; ".join(problems))


@dataclass(frozen=True)
class OpenProjectConfig:
    base_url: str
    token: str = "secret:openproject/api-token"
    strategy_project: str = "strategy"
    work_project: str = "lab"
    sync_user: str = "hnx-sync"
    viewer_roles: tuple[str, ...] = ("Reader",)
    allow_plaintext: bool = False
    strategy_types: tuple[str, ...] = STRATEGY_TYPES
    work_types: Mapping[str, str] = field(default_factory=lambda: dict(WORK_TYPES))
    strategy_statuses: Mapping[str, str] = field(default_factory=lambda: dict(STRATEGY_STATUSES))
    work_statuses: Mapping[str, str] = field(default_factory=lambda: dict(WORK_STATUSES))
    custom_fields: Mapping[str, str] = field(default_factory=lambda: dict(CUSTOM_FIELDS))

    def client(self, **kw: Any) -> OpenProjectClient:
        kw.setdefault("allow_plaintext", self.allow_plaintext)
        return OpenProjectClient(self.base_url, token=self.token, **kw)


_KEYS = {f.name for f in dataclasses.fields(OpenProjectConfig)}


def load_config(path: str | pathlib.Path | Mapping[str, Any]) -> OpenProjectConfig:
    doc = (
        path if isinstance(path, Mapping) else yaml.safe_load(pathlib.Path(path).read_text("utf-8"))
    )
    if not isinstance(doc, Mapping) or not doc.get("base_url"):
        raise ValueError("an OpenProject config is a mapping with at least base_url")
    unknown = sorted(set(doc) - _KEYS)
    if unknown:
        raise ValueError(f"unknown OpenProject config key(s): {', '.join(unknown)}")
    kw = dict(doc)
    for k in ("viewer_roles", "strategy_types"):
        if k in kw:
            kw[k] = tuple(kw[k])
    return OpenProjectConfig(**kw)


@dataclass
class Setup:
    """Ids resolved by name: ``types`` / ``statuses`` name -> id, ``closed`` status ids,
    ``fields`` contract key -> ``customFieldN`` per project, the two projects' ids, the user."""

    types: dict[str, int]
    statuses: dict[str, int]
    closed: frozenset[int]
    strategy_project: int
    work_project: int
    fields: dict[str, str]
    me: int
    problems: list[str] = field(default_factory=list)

    def type_name(self, type_id: int) -> str | None:
        return next((n for n, i in self.types.items() if i == type_id), None)

    def status_name(self, status_id: int) -> str | None:
        return next((n for n, i in self.statuses.items() if i == status_id), None)


def _by_name(client: OpenProjectClient, path: str) -> dict[str, dict[str, Any]]:
    return {str(e.get("name")): e for e in client.collect(path)}


def _schema_fields(client: OpenProjectClient, project: int, type_id: int) -> dict[str, str]:
    """custom field name -> ``customFieldN`` on one project and type's form."""
    doc = client.get(f"/api/v3/work_packages/schemas/{project}-{type_id}")
    return {
        str(v.get("name")): k
        for k, v in doc.items()
        if k.startswith("customField") and isinstance(v, Mapping)
    }


@dataclass(frozen=True)
class Finding:
    ok: bool
    what: str
    step: str = ""  # the one-time admin step that fixes it


def doctor(client: OpenProjectClient, cfg: OpenProjectConfig) -> list[Finding]:
    """Every precondition of the adapter, checked by name against the live instance."""
    out: list[Finding] = []

    def add(ok: bool, what: str, step: str) -> None:
        out.append(Finding(ok, what, "" if ok else step))

    try:
        me = client.get("/api/v3/users/me")
    except ApiError as exc:
        return [Finding(False, f"API reachable with the token ({exc})", "Admin > API and webhooks: "
                        f"enable API tokens; create a token for {cfg.sync_user} and deliver it as "
                        "the secret the config names")]  # fmt: skip
    add(
        me.get("login") == cfg.sync_user,
        f"the token belongs to {cfg.sync_user!r} (it belongs to {me.get('login')!r})",
        f"create the service user {cfg.sync_user} and use its API token",
    )
    types = _by_name(client, "/api/v3/types")
    for name in (*cfg.strategy_types, *cfg.work_types.values()):
        add(name in types, f"work package type {name!r}", f"Admin > Work packages > Types: create {name!r}")  # fmt: skip
    statuses = _by_name(client, "/api/v3/statuses")
    for name in sorted({*cfg.strategy_statuses.values(), *cfg.work_statuses.values()}):
        st = statuses.get(name)
        closed = name in CLOSED_STATUSES
        flag = "closed" if closed else "open"
        add(
            st is not None and bool(st.get("isClosed")) == closed,
            f"status {name!r} ({flag})",
            f"Admin > Work packages > Status: create {name!r}"
            + (" with 'closed' ticked" if closed else " (not closed)"),
        )
    projects = {}
    for role, ident, kinds in (
        ("Strategy", cfg.strategy_project, cfg.strategy_types),
        ("work", cfg.work_project, tuple(cfg.work_types.values())),
    ):
        try:
            p = client.get(f"/api/v3/projects/{ident}")
        except ProjectsError:
            add(False, f"{role} project {ident!r}", f"create the project with identifier {ident!r}")
            continue
        projects[role] = p
        enabled = {str(e.get("name")) for e in client.collect(f"/api/v3/projects/{p['id']}/types")}
        for name in kinds:
            if name in types:
                add(
                    name in enabled,
                    f"type {name!r} enabled in {ident!r}",
                    f"Project {ident!r} > Project settings > Work package types: enable {name!r}",
                )
        for name in kinds:
            if name not in types or name not in enabled:
                continue
            got = _schema_fields(client, p["id"], types[name]["id"])
            for cf in cfg.custom_fields.values():
                add(
                    cf in got,
                    f"custom field {cf!r} on {name!r} in {ident!r}",
                    f"Admin > Custom fields: create {cf!r} (External key: Text, 'used as a "
                    "filter', for all projects; hnx state: Long text), enable it on type "
                    f"{name!r} and in project {ident!r}",
                )
    _probe_filter(client, cfg, projects, types, add)
    if "Strategy" in projects:
        _strategy_permissions(client, cfg, projects["Strategy"], me, add)
    return out


def _probe_filter(client, cfg, projects, types, add) -> None:
    """The External key must be usable as an exact filter (the upsert looks records up by it)."""
    p = projects.get("Strategy")
    t = next((types[n] for n in cfg.strategy_types if n in types), None)
    if p is None or t is None:
        return
    cf = _schema_fields(client, p["id"], t["id"]).get(cfg.custom_fields["external_key"])
    if cf is None:
        return
    try:
        client.get(
            f"/api/v3/projects/{p['id']}/work_packages",
            filters=filters(**{cf: ("=", ["hnx-doctor-probe"])}),
            pageSize=1,
        )
        add(True, "External key is filterable", "")
    except ApiError:
        add(False, "External key is filterable", "Admin > Custom fields > External key: tick 'used as a filter'")  # fmt: skip


def _strategy_permissions(client, cfg, project, me, add) -> None:
    links = project.get("_links") or {}
    add(
        "createWorkPackage" in links,
        f"{cfg.sync_user} may create work packages in {cfg.strategy_project!r}",
        f"give {cfg.sync_user} a role with 'edit work packages' and 'manage work package "
        f"relations' in {cfg.strategy_project!r}",
    )
    members = client.collect("/api/v3/memberships", filters=filters(project=("=", [project["id"]])))
    others = []
    for m in members:
        ml = m.get("_links") or {}
        principal = str((ml.get("principal") or {}).get("href", ""))
        if principal.rstrip("/").rsplit("/", 1)[-1] == str(me.get("id")):
            continue
        roles = {str(r.get("title")) for r in ml.get("roles") or ()}
        if not roles <= set(cfg.viewer_roles):
            others.append(f"{(ml.get('principal') or {}).get('title')}: {', '.join(sorted(roles))}")
    add(
        not others,
        f"everyone else in {cfg.strategy_project!r} is a viewer ({', '.join(cfg.viewer_roles)})"
        + (f"; not: {'; '.join(others)}" if others else ""),
        f"Project {cfg.strategy_project!r} > Members: give everyone but {cfg.sync_user} only "
        f"{' or '.join(cfg.viewer_roles)} (view work packages): the repository owns these records",
    )


def discover(client: OpenProjectClient, cfg: OpenProjectConfig) -> Setup:
    """Resolve every id the adapter uses; :class:`SetupError` lists what is missing."""
    problems: list[str] = []
    types = {n: int(e["id"]) for n, e in _by_name(client, "/api/v3/types").items()}
    st = _by_name(client, "/api/v3/statuses")
    statuses = {n: int(e["id"]) for n, e in st.items()}
    closed = frozenset(int(e["id"]) for e in st.values() if e.get("isClosed"))
    for name in (*cfg.strategy_types, *cfg.work_types.values()):
        if name not in types:
            problems.append(f"no type {name!r}")
    for name in {*cfg.strategy_statuses.values(), *cfg.work_statuses.values()}:
        if name not in statuses:
            problems.append(f"no status {name!r}")
    ids = {}
    for ident in (cfg.strategy_project, cfg.work_project):
        try:
            ids[ident] = int(client.get(f"/api/v3/projects/{ident}")["id"])
        except ProjectsError:
            problems.append(f"no project {ident!r}")
    fields: dict[str, str] = {}
    if not problems:
        for ident, names in (
            (cfg.strategy_project, cfg.strategy_types),
            (cfg.work_project, tuple(cfg.work_types.values())),
        ):
            for name in names:
                got = _schema_fields(client, ids[ident], types[name])
                for key, cf in cfg.custom_fields.items():
                    if cf not in got:
                        problems.append(f"no custom field {cf!r} on {name!r} in {ident!r}")
                    elif fields.setdefault(key, got[cf]) != got[cf]:
                        problems.append(f"{cf!r} is two different fields")
    if problems:
        raise SetupError(problems)
    me = int(client.get("/api/v3/users/me")["id"])
    return Setup(
        types=types,
        statuses=statuses,
        closed=closed,
        strategy_project=ids[cfg.strategy_project],
        work_project=ids[cfg.work_project],
        fields=fields,
        me=me,
    )
