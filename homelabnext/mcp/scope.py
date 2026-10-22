# SPDX-License-Identifier: Apache-2.0
"""Scope for the MCP server: what a caller may see, derived from a compiled agent profile.

A scope is a set of ``context`` scope entries (an exact id, or a namespace ending in ``:`` or
``/``; :func:`homelabnext.context.in_scope`).  :func:`profile_scope` derives one from the
profile's grants -- the namespaces of what it is already allowed to use -- and
:func:`intersect` narrows a caller's request to it.  A request can only ever get narrower: an
entry the grant does not cover is dropped, and a namespace wider than the grant is replaced by
the granted entries inside it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from homelabnext.context import in_scope

from . import credentials

__all__ = [
    "SERVER_NAME",
    "ScopeError",
    "covers",
    "in_any",
    "intersect",
    "load_profile_scope",
    "profile_scope",
]

#: the server's catalog id: what a profile lists under ``grants.mcp``; its record
#: (``examples/mcp/hnx-catalog.yml``) classes every tool ``read``
SERVER_NAME = "hnx-catalog"


class ScopeError(Exception):
    """The profile cannot scope the server (unreadable, fails verification, not granted it)."""


def _is_namespace(entry: str) -> bool:
    return entry.endswith((":", "/"))


def covers(granted: Iterable[str], entry: str) -> bool:
    """True when everything ``entry`` names lies inside ``granted``.  An exact entry is covered
    by an equal entry or a namespace containing it; a namespace only by a namespace that is a
    prefix of it (an exact id never covers a namespace)."""
    for g in granted:
        if _is_namespace(g):
            if entry.startswith(g):
                return True
        elif not _is_namespace(entry) and entry == g:
            return True
    return False


def intersect(requested: Iterable[str], granted: Iterable[str]) -> frozenset[str]:
    """The part of ``requested`` that ``granted`` covers: never wider than either.

    Each requested entry is kept when the grant covers it; a requested namespace also admits the
    granted entries that lie inside it (``cap:`` against a grant of ``cap:lake-query`` gives
    ``cap:lake-query``)."""
    g = frozenset(granted)
    out: set[str] = set()
    for r in requested:
        if covers(g, r):
            out.add(r)
        elif _is_namespace(r):
            out |= {e for e in g if e.startswith(r)}
    return frozenset(out)


def profile_scope(profile: Mapping[str, Any], registry: Any) -> frozenset[str]:
    """The scope a compiled profile's grants imply.

    * the profile's own node (``profile:<name>``);
    * per granted capability ``cap:<x>``: the capability, its checks (``check:<x>/``) and its
      reference page (``doc:docs/capabilities/<x>.md``);
    * per granted MCP server ``<m>``: ``mcp:<m>``;
    * every registry service that provides a granted capability or exposes a granted MCP
      server: ``svc:<name>`` and its system page (``doc:docs/systems/<name>.md``).

    Nothing else: lessons, runbooks, other pages and other services stay out unless a caller
    without a profile scope asks for them."""
    grants = profile.get("grants") or {}
    caps = sorted(
        c.split(":", 1)[1] for c in grants.get("capabilities") or [] if str(c).startswith("cap:")
    )
    mcps = sorted(str(m) for m in grants.get("mcp") or [])
    out: set[str] = {str(profile["id"])}
    for cap in caps:
        out |= {f"cap:{cap}", f"check:{cap}/", f"doc:docs/capabilities/{cap}.md"}
    out |= {f"mcp:{m}" for m in mcps}
    for svc in registry.sorted_services():
        if svc.capability in caps or (svc.mcp and svc.mcp.get("name") in mcps):
            out |= {f"svc:{svc.name}", f"doc:docs/systems/{svc.name}.md"}
    return frozenset(out)


def load_profile_scope(path: str | Path, registry: Any) -> tuple[str, frozenset[str]]:
    """``(profile id, scope)`` from a compiled profile file.

    The profile must verify (schema, reader rule, grants within its ceiling, digest: the checks
    of :func:`homelabnext.agent.compiler.verify_profile`) and must be granted this server
    (``hnx-catalog`` in ``grants.mcp``): a profile that may not use it gets no scope at all."""
    from homelabnext.agent.compiler import verify_profile

    try:
        profile = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScopeError(f"cannot read profile {path}: {credentials.reason(exc)}") from None
    if not isinstance(profile, dict):
        raise ScopeError(f"{path}: a compiled profile is a JSON object")
    # verify_profile's own schema messages quote the values: a schema failure is worded safely
    problems = credentials.safe_schema_errors("agent", "profile", profile) or verify_profile(
        profile
    )
    if problems:
        raise ScopeError(f"{path}: profile does not verify: " + "; ".join(problems))
    if SERVER_NAME not in ((profile.get("grants") or {}).get("mcp") or []):
        raise ScopeError(
            f"{profile['id']} is not granted the {SERVER_NAME} MCP server (grants.mcp); "
            "grant it in the profile spec and recompile"
        )
    return str(profile["id"]), profile_scope(profile, registry)


def in_any(doc_id: str, scope: frozenset[str] | None) -> bool:
    """``doc_id`` is visible under ``scope`` (``None``: unscoped, everything is)."""
    return scope is None or in_scope(doc_id, scope)
