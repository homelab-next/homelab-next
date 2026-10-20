# SPDX-License-Identifier: Apache-2.0
"""The read-only tools of ``hnx mcp serve``, as plain functions over a source checkout.

Every tool returns a JSON-able dict built from the same code that generates the documentation
(the capability model of :mod:`homelabnext.sop.capabilities`, the registry loader, the knowledge
graph, the ``context`` reference store, the lesson review and the invariants results); nothing
parses generated Markdown.  :meth:`Catalog.dump` serialises a result deterministically (sorted
keys) and within :data:`MAX_RESULT_CHARS`, dropping trailing list items, and saying so, when a
result would not fit.

Nothing here writes, executes or reaches the network.  The only files read are the checkout's
own sources; a caller-supplied path is repo-relative, may not contain ``..`` or pass through a
symbolic link, and only :meth:`Catalog.get_schema` reads one -- a ``.json`` file under
``schemas/``.  A refusal is a :class:`CatalogError` whose message never repeats free text the
caller sent.  Sources are loaded once, on first use: restart the server to see later edits.
"""

from __future__ import annotations

import datetime as dt
import inspect
import json
import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from .scope import in_any, intersect

__all__ = [
    "MAX_HIT_CONTENT_CHARS",
    "MAX_ITEMS",
    "MAX_RESULT_CHARS",
    "TOOLS",
    "Catalog",
    "CatalogError",
]

#: the size cap of every serialised tool result, in characters
MAX_RESULT_CHARS = 262_144
#: ``context_for``: a hit's content longer than this is cut (its digest stays the full one)
MAX_HIT_CONTENT_CHARS = 32_768
#: most ids, paths, scope entries or kinds one call may pass
MAX_ITEMS = 64
#: ``related``: deepest neighbourhood and largest budget
MAX_DEPTH = 3
MAX_RELATED_BUDGET = 200
_MAX_ITEM_CHARS = 512

#: the server's whole tool list: every one reads, none changes anything (a test pins this)
TOOLS: dict[str, str] = {
    "context_for": (
        "Context for a task: the repository records (pages, lessons, runbooks, capabilities, "
        "services, checks ...) related to the files being edited and the task text, ranked "
        "relation first, with content and sha256 digest. `allowed` (mandatory) lists the ids "
        "and namespaces you may see, e.g. ['doc:docs/', 'cap:', 'lesson:']."
    ),
    "find_services": (
        "Registry services (name, capability, impl, owner, tags, depends_on, mcp), optionally "
        "filtered by capability and/or tag. Names only, never credentials."
    ),
    "get_contract": (
        "One capability's contract: operations (signature, params, returns, raises, doc), data "
        "shapes, constants, errors, schemas, conformance checks (id, level, assertion), "
        "features, adapters with recorded product limits, and the services using it."
    ),
    "get_schema": (
        "A JSON Schema from schemas/, by graph id (schema:schemas/...), path (with or without "
        "schemas/), $id URL or family/name shorthand (agent/profile)."
    ),
    "invariants_status": (
        "The committed invariants results: per criterion its statement, status (pass, fail, "
        "untested ...), when it was checked and, for anything not passing, the remediation."
    ),
    "lessons_due": (
        "What the lesson review should do as of `today` (YYYY-MM-DD, default the server's "
        "date): missing reviews, retire, incorporate, supersede, update, keep."
    ),
    "list_capabilities": (
        "Every conformance capability: purpose, operation count, MUST/SHOULD check counts and "
        "implementations (fake, adapters, registry services)."
    ),
    "related": (
        "The knowledge graph's ranked neighbourhood of node ids or repo-relative paths: nearest "
        "first, then strongest relation (docs/graph.md)."
    ),
}

_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_RECORD_ID = re.compile(r"(?<![\w-])(?:LL|RB)-(?:\d{3,}|NEW)(?![\w])")


class CatalogError(Exception):
    """A refused call: a malformed argument, an unknown name or something outside the scope."""


# --------------------------------------------------------------------------- argument checks


def _items(value: Any, what: str, *, required: bool = False) -> list[str]:
    if value is None:
        value = []
    if isinstance(value, str | bytes) or not isinstance(value, Iterable):
        raise CatalogError(f"{what} must be a list of strings")
    items = list(value)
    if len(items) > MAX_ITEMS:
        raise CatalogError(f"{what}: at most {MAX_ITEMS} entries")
    for i in items:
        if not isinstance(i, str) or not i or len(i) > _MAX_ITEM_CHARS:
            raise CatalogError(f"{what}: every entry is a non-empty string of at most 512 chars")
        if any(not c.isprintable() for c in i):
            raise CatalogError(f"{what}: entries may not contain control characters")
    if required and not items:
        raise CatalogError(f"{what} is required and may not be empty")
    return items


def _int(value: Any, what: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise CatalogError(f"{what} must be an integer between {lo} and {hi}")
    return value


def relpath(raw: str) -> str:
    """``raw`` as a normalised repo-relative POSIX path, or :class:`CatalogError`: no absolute
    path, no ``..``, no ``~``, no backslash, no control character."""
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_ITEM_CHARS:
        raise CatalogError("a path is a non-empty repo-relative string")
    if "\\" in raw or any(not c.isprintable() for c in raw):
        raise CatalogError("a path may not contain backslashes or control characters")
    p = PurePosixPath(raw.removeprefix("./"))
    if p.is_absolute() or raw.startswith("~") or ".." in p.parts:
        raise CatalogError("a path must stay inside the checkout (relative, no '..')")
    return p.as_posix()


def _no_symlink(base: Path, rel: str) -> Path:
    """``base/rel`` when no component of ``rel`` is a symbolic link and it resolves inside
    ``base``; else :class:`CatalogError`."""
    cur = base
    for part in PurePosixPath(rel).parts:
        cur = cur / part
        if os.path.islink(cur):
            raise CatalogError("a path may not pass through a symbolic link")
    full = cur.resolve()
    if not full.is_relative_to(base.resolve()):
        raise CatalogError("a path must stay inside the checkout")
    return full


# --------------------------------------------------------------------------- the catalog


class Catalog:
    """The tools over the checkout at ``root``.

    ``scope`` (from :func:`homelabnext.mcp.scope.load_profile_scope`) bounds every tool that
    names capabilities, services or register records: ``context_for`` intersects a call's
    ``allowed`` with it, ``related`` computes the neighbourhood over the in-scope nodes only, and
    ``list_capabilities``, ``get_contract``, ``find_services`` and ``lessons_due`` return only
    in-scope capabilities, services and records (an out-of-scope one reads like an unknown one).
    ``get_schema`` and ``invariants_status`` describe the repository's public contracts and are
    not scoped.  ``None`` means unscoped (``context_for`` still requires its own ``allowed``)."""

    def __init__(
        self,
        root: str | Path,
        *,
        registry_path: str | Path | None = None,
        scope: frozenset[str] | None = None,
        scope_source: str = "",
    ) -> None:
        self.root = Path(root).resolve()
        if not (self.root / "homelabnext").is_dir() or not (self.root / "schemas").is_dir():
            raise CatalogError(f"{self.root} is not a homelabnext source checkout")
        self.registry_path = (
            Path(registry_path) if registry_path else self.root / "examples" / "services.yml"
        )
        self.scope = scope
        self.scope_source = scope_source
        self._graph = None
        self._store = None
        self._caps: dict[str, Any] | None = None
        self._registry = None
        self._schema_ids: dict[str, str] | None = None

    # -- lazily loaded sources ----------------------------------------------------------------
    @property
    def registry(self):
        if self._registry is None:
            from homelabnext.registry.model import load

            self._registry = load(self.registry_path)
        return self._registry

    @property
    def graph(self):
        if self._graph is None:
            from homelabnext.graph import build

            self._graph = build(self.root)[0]
        return self._graph

    @property
    def store(self):
        if self._store is None:
            from homelabnext.context import ContextStore, documents_from_graph

            store = ContextStore()
            store.index(documents_from_graph(self.graph, self.root))
            self._store = store
        return self._store

    @property
    def capabilities(self) -> dict[str, Any]:
        if self._caps is None:
            from homelabnext.sop.capabilities import collect

            self._caps = {c.name: c for c in collect(self.root, self.registry)}
        return self._caps

    # -- serialisation ------------------------------------------------------------------------
    @staticmethod
    def dump(result: Mapping[str, Any], list_key: str | None = None) -> str:
        """``result`` as compact JSON with sorted keys, at most :data:`MAX_RESULT_CHARS`.

        When it is longer, trailing items of ``result[list_key]`` are dropped until it fits and
        ``truncated`` records how many; a result that cannot be made to fit is refused."""

        def enc(obj: Any) -> str:
            return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

        text = enc(result)
        if len(text) <= MAX_RESULT_CHARS:
            return text
        items = result.get(list_key) if list_key else None
        if isinstance(items, list) and items:
            out = dict(result)
            lo, hi = 0, len(items)  # the longest prefix that fits, by bisection
            while lo < hi:
                mid = (lo + hi + 1) // 2
                out[list_key] = items[:mid]
                out["truncated"] = {"dropped": len(items) - mid, "reason": "result size cap"}
                if len(enc(out)) <= MAX_RESULT_CHARS:
                    lo = mid
                else:
                    hi = mid - 1
            out[list_key] = items[:lo]
            out["truncated"] = {"dropped": len(items) - lo, "reason": "result size cap"}
            text = enc(out)
            if len(text) <= MAX_RESULT_CHARS:
                return text
        raise CatalogError(f"the result exceeds the {MAX_RESULT_CHARS}-character cap; narrow it")

    # -- scope ------------------------------------------------------------------------------
    def _sees(self, nid: str) -> bool:
        return in_any(nid, self.scope)

    def _svcs(self, names: Iterable[str]) -> list[str]:
        return [n for n in names if self._sees(f"svc:{n}")]

    def _visible_caps(self) -> dict[str, Any]:
        return {n: c for n, c in self.capabilities.items() if self._sees(f"cap:{n}")}

    # -- tools ------------------------------------------------------------------------------
    def list_capabilities(self) -> dict[str, Any]:
        from homelabnext.sop.capabilities import summary_data

        out = []
        for c in self._visible_caps().values():
            row = summary_data(c)
            impl = row["implementations"]
            row["implementations"] = {**impl, "services": self._svcs(impl["services"])}
            out.append(row)
        return {"capabilities": out}

    def get_contract(self, capability: str) -> dict[str, Any]:
        from homelabnext.sop.capabilities import contract_data

        name = capability.removeprefix("cap:") if isinstance(capability, str) else ""
        caps = self._visible_caps()
        c = caps.get(name)
        if c is None:
            raise CatalogError("no such capability; known: " + ", ".join(sorted(caps)))
        out = contract_data(c)
        svc = out["services"]
        out["services"] = {
            **svc,
            "providers": [p for p in svc["providers"] if self._sees(f"svc:{p['name']}")],
            "consumers": self._svcs(svc["consumers"]),
        }
        return out

    def _schema_index(self) -> dict[str, str]:
        if self._schema_ids is None:
            idx: dict[str, str] = {}
            base = self.root / "schemas"
            for p in sorted(base.rglob("*.json")):
                rel = p.relative_to(self.root).as_posix()
                if "/_frozen/" in rel or "/examples/" in rel or "/negative/" in rel:
                    continue
                try:
                    sid = json.loads(p.read_text(encoding="utf-8")).get("$id")
                except (OSError, ValueError, AttributeError):
                    continue
                if isinstance(sid, str):
                    idx.setdefault(sid, rel)
            self._schema_ids = idx
        return self._schema_ids

    def get_schema(self, id_or_path: str) -> dict[str, Any]:
        if not isinstance(id_or_path, str) or not id_or_path or len(id_or_path) > _MAX_ITEM_CHARS:
            raise CatalogError("give a schema id or a path under schemas/")
        rel = self._schema_index().get(id_or_path)
        if rel is None:
            raw = id_or_path.removeprefix("schema:")
            rel = relpath(raw)
            if not rel.startswith("schemas/"):
                rel = f"schemas/{rel}"
            if not rel.endswith(".json"):  # family/name shorthand: agent/profile
                rel += ".schema.json"
        base = self.root / "schemas"
        full = _no_symlink(self.root, rel)
        if not full.is_relative_to(base.resolve()) or full.suffix != ".json":
            raise CatalogError("only .json files under schemas/ are served")
        if not full.is_file():
            raise CatalogError("no such schema under schemas/")
        try:
            doc = json.loads(full.read_text(encoding="utf-8"))
        except ValueError:
            raise CatalogError("that file is not valid JSON") from None
        sid = doc.get("$id", "") if isinstance(doc, dict) else ""
        return {"path": rel, "id": sid, "schema": doc}

    def find_services(self, capability: str | None = None, tag: str | None = None) -> dict:
        for v, what in ((capability, "capability"), (tag, "tag")):
            if v is not None and (not isinstance(v, str) or len(v) > _MAX_ITEM_CHARS):
                raise CatalogError(f"{what} must be a string")
        cap = capability.removeprefix("cap:") if capability else None
        out = []
        for s in self.registry.sorted_services():
            if not self._sees(f"svc:{s.name}"):
                continue
            if cap is not None and s.capability != cap:
                continue
            if tag is not None and tag not in s.tags:
                continue
            out.append(
                {
                    "name": s.name,
                    "capability": s.capability,
                    "impl": s.impl,
                    "owner": s.owner,
                    "tags": list(s.tags),
                    "depends_on": self._svcs(s.upstreams),
                    "mcp": (s.mcp or {}).get("name", ""),
                }
            )
        return {"services": out}

    def _scoped_graph(self):
        g = self.graph
        if self.scope is None:
            return g
        from homelabnext.graph import Graph

        nodes = {i: n for i, n in g.nodes.items() if in_any(i, self.scope)}
        edges = [e for e in g.edges if e.src in nodes and e.dst in nodes]
        return Graph(nodes, edges)

    def related(
        self,
        ids_or_paths: list[str],
        depth: int = 2,
        budget: int = 25,
        include_inactive: bool = False,
    ) -> dict[str, Any]:
        from homelabnext.graph import related, seeds_for

        items = _items(ids_or_paths, "ids_or_paths", required=True)
        depth = _int(depth, "depth", 1, MAX_DEPTH)
        budget = _int(budget, "budget", 0, MAX_RELATED_BUDGET)
        if not isinstance(include_inactive, bool):
            raise CatalogError("include_inactive must be a boolean")
        g = self._scoped_graph()
        ids = [i for i in items if i in g.nodes]
        raw_paths = {i: relpath(i) for i in items if i not in g.nodes}  # raw -> normalised
        paths = sorted(set(raw_paths.values()))
        found = set(seeds_for(g, paths, include_inactive=include_inactive)) if paths else set()
        seeds = sorted(set(ids) | found)
        rel = related(g, seeds, budget=budget, max_depth=depth, include_inactive=include_inactive)
        resolved = {p for p in paths if seeds_for(g, [p], include_inactive=True)}
        return {
            "seeds": seeds,
            "unresolved": sorted(raw for raw, p in raw_paths.items() if p not in resolved),
            "related": [r.as_dict() for r in rel],
            "scoped": self.scope is not None,
        }

    def effective_scope(self, allowed: Iterable[str]) -> frozenset[str]:
        """A call's ``allowed``, narrowed to the server's profile scope (never widened)."""
        req = frozenset(allowed)
        return req if self.scope is None else intersect(req, self.scope)

    def context_for(
        self,
        task_text: str,
        paths: list[str] | None = None,
        allowed: list[str] | None = None,
        kinds: list[str] | None = None,
        budget: int = 10,
    ) -> dict[str, Any]:
        from homelabnext.context import MAX_BUDGET, MAX_QUERY_CHARS, ContextError, Query
        from homelabnext.graph import seeds_for

        req = _items(allowed, "allowed", required=True)
        rel = [relpath(p) for p in _items(paths, "paths")]
        kind_list = _items(kinds, "kinds")
        budget = _int(budget, "budget", 0, MAX_BUDGET)
        if not isinstance(task_text, str):
            raise CatalogError("task_text must be a string")
        if len(task_text) > MAX_QUERY_CHARS:
            raise CatalogError(f"task_text is longer than {MAX_QUERY_CHARS} characters")
        scope = self.effective_scope(req)
        seeds = seeds_for(self.graph, rel, task_text)
        q = Query(
            allowed=scope,
            text=task_text,
            seeds=tuple(seeds),
            kinds=frozenset(kind_list) if kind_list else None,
            budget=budget,
        )
        try:
            hits = self.store.query(q)
        except ContextError as exc:  # InvalidQuery: its message never echoes the text
            raise CatalogError(str(exc)) from None
        out = []
        for h in hits:
            item = {
                "id": h.id,
                "kind": h.kind,
                "title": h.title,
                "path": h.path,
                "score": h.score,
                "digest": h.digest,
                "snippet": h.snippet,
                "content": h.content[:MAX_HIT_CONTENT_CHARS],
            }
            if len(h.content) > MAX_HIT_CONTENT_CHARS:
                item["content_truncated"] = True
                item["content_chars"] = len(h.content)
            out.append(item)
        return {
            "scope": sorted(scope),
            "scoped_by": self.scope_source or None,
            "seeds": [s for s in seeds if in_any(s, scope)],
            "hits": out,
        }

    def lessons_due(self, today: str | None = None) -> dict[str, Any]:
        from homelabnext.registers.due import review
        from homelabnext.registers.render import load_sources

        day = None
        if today is not None:
            if not isinstance(today, str) or not _DATE.fullmatch(today):
                raise CatalogError("today must be a date, YYYY-MM-DD")
            try:
                day = dt.date.fromisoformat(today)
            except ValueError:
                raise CatalogError("today must be a valid date, YYYY-MM-DD") from None
        out = review(load_sources(self.root / "examples" / "registers"), day).as_json()
        if self.scope is None:
            return out

        def visible(rid: str) -> bool:
            return self._sees(("runbook:" if rid.startswith("RB-") else "lesson:") + rid)

        out["due"] = {a: [d for d in rows if visible(d["id"])] for a, rows in out["due"].items()}
        out["warnings"] = [
            w for w in out["warnings"] if all(visible(i) for i in _RECORD_ID.findall(w))
        ]
        return out

    def invariants_status(self) -> dict[str, Any]:
        """The invariants page's own verdict (:func:`homelabnext.registers.render.
        criterion_status` and :func:`~homelabnext.registers.render.invariants_verdict`), so the
        counts and ``all_hold`` here are the page's."""
        from homelabnext.registers.records import load_register
        from homelabnext.registers.render import ALL_HOLD, criterion_status, invariants_verdict
        from homelabnext.registers.schema import RegisterError, validate_invariants

        src = self.root / "examples" / "registers"
        try:
            reg = validate_invariants(load_register(src / "invariants.yml"))
        except RegisterError:
            raise CatalogError("the invariants register does not validate") from None
        rp = src / "invariants.results.json"
        results = json.loads(rp.read_text(encoding="utf-8")) if rp.is_file() else {}
        res = results.get("results") or {}
        rows, counts = [], {}
        for c in reg["criteria"]:
            r = res.get(c["id"]) or {}
            status = criterion_status(c, r)
            counts[status] = counts.get(status, 0) + 1
            row = {
                "id": c["id"],
                "statement": str(c.get("statement", "")).strip(),
                "evidence_kind": c.get("evidence", ""),
                "status": status,
                "checked_at": r.get("checked_at") or c.get("last_checked") or "",
            }
            if status != "pass":
                row["remediation"] = str(c.get("remediation", "")).strip()
            rows.append(row)
        verdict = invariants_verdict(counts)
        return {
            "source": "examples/registers/invariants.results.json",
            "last_run": results.get("last_run", ""),
            "verdict": verdict,
            "all_hold": verdict == ALL_HOLD,
            "counts": dict(sorted(counts.items())),
            "criteria": rows,
        }

    # -- dispatch -----------------------------------------------------------------------------
    def call(self, name: str, arguments: Mapping[str, Any] | None = None) -> str:
        """Run tool ``name`` with ``arguments`` and return its serialised result."""
        if name not in TOOLS:
            raise CatalogError(f"no such tool; tools: {', '.join(sorted(TOOLS))}")
        fn = getattr(self, name)
        args = dict(arguments or {})
        try:
            inspect.signature(fn).bind(**args)
        except TypeError:
            raise CatalogError(f"{name}: unexpected or missing arguments") from None
        return self.dump(fn(**args), _LIST_KEY.get(name))


#: the list a result may drop items from to fit the size cap
_LIST_KEY = {
    "context_for": "hits",
    "find_services": "services",
    "invariants_status": "criteria",
    "list_capabilities": "capabilities",
    "related": "related",
}
