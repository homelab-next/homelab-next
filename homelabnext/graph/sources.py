# SPDX-License-Identifier: Apache-2.0
"""The readers: one function per source family, each adding the nodes and edges its files state.

Every edge comes from a field of a source file (named in ``Edge.source``), never from prose
similarity.  Where a reader has to match names (a lesson's system tag against the registry, a
command line against the script catalog) the match is exact and the rule is in the reader's
docstring.  Readers run in :data:`READERS` order; references to paths are resolved at the end
(:meth:`Builder.finish`), once every node exists.

The registers (lessons, runbooks, invariants) are read through :func:`_register_entries` only, so
the storage format can change in one place.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote

from homelabnext.identity.uid import UID_PATTERN, is_uid

from .model import Edge, Node

# --------------------------------------------------------------------------- builder

_GIT_FILES = ("git", "-C")
_GIT_FILES_ARGS = ("ls-files", "-z", "--cached", "--others", "--exclude-standard")


@dataclass
class Builder:
    """Accumulates nodes and edges; records duplicate definitions instead of overwriting."""

    root: Path
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    duplicates: list[tuple[str, str, str]] = field(default_factory=list)  # (id, first, second)
    _declared: dict[str, dict[str, Any]] = field(default_factory=dict)
    _defined_at: dict[str, str] = field(default_factory=dict)
    _path_refs: list[tuple[str, str, str, str, str]] = field(default_factory=list)
    _files: list[str] | None = None

    # ---- nodes
    def define(self, nid: str, kind: str, title: str = "", path: str = "", source: str = "", **a):
        """A node exactly one place may define (a service, a lesson, a script).  A second
        definition is recorded as a duplicate (``hnx graph check`` fails on it)."""
        where = source or path
        if nid in self.nodes or nid in self._declared:
            self.duplicates.append((nid, self._defined_at.get(nid, "?"), where))
            return
        self._defined_at[nid] = where
        self.nodes[nid] = Node(nid, kind, title, path, _clean(a))

    def declare(self, nid: str, kind: str, source: str, title: str = "", path: str = "", **a):
        """A node several sources may name (a capability, a product, an MCP slug): the union of
        its declarations, ``declared_in`` listing every source."""
        if nid in self.nodes and nid not in self._declared:
            self.duplicates.append((nid, self._defined_at.get(nid, "?"), source))
            return
        d = self._declared.setdefault(
            nid, {"kind": kind, "title": "", "path": "", "attrs": {}, "in": set()}
        )
        if d["kind"] != kind:
            self.duplicates.append(
                (nid, f"{d['kind']} in {sorted(d['in'])}", f"{kind} in {source}")
            )
            return
        d["in"].add(source)
        d["title"] = d["title"] or title
        d["path"] = d["path"] or path
        for k, v in _clean(a).items():
            d["attrs"].setdefault(k, v)
        self._defined_at.setdefault(nid, source)
        attrs = dict(sorted({**d["attrs"], "declared_in": sorted(d["in"])}.items()))
        self.nodes[nid] = Node(nid, kind, d["title"], d["path"], attrs)

    def has(self, nid: str) -> bool:
        return nid in self.nodes

    # ---- edges
    def edge(self, src: str, dst: str, etype: str, source: str, **a) -> None:
        self.edges.append(Edge(src, dst, etype, source, _clean(a)))

    def path_ref(self, src: str, path: str, etype: str, source: str, policy: str = "exact"):
        """An edge to whatever node owns repo path ``path``, resolved by :meth:`finish`.

        ``exact``: the one node whose ``path`` is exactly this; ``owner``: else the node with the
        longest directory ``path`` containing it.  An existing file nothing owns makes no edge; a
        path that does not exist makes a dangling edge to ``file:<path>``."""
        self._path_refs.append((src, path, etype, source, policy))

    def finish(self) -> None:
        owners: dict[str, list[str]] = {}
        for n in self.nodes.values():
            if n.path:
                owners.setdefault(n.path, []).append(n.id)
        for src, path, etype, source, policy in self._path_refs:
            exact = owners.get(path, [])
            if len(exact) == 1:
                self.edge(src, exact[0], etype, source)
                continue
            if not (self.root / path).exists():
                self.edge(src, f"file:{path}", etype, source)
                continue
            if policy == "owner" and not exact:
                parent = PurePosixPath(path).parent
                while str(parent) not in (".", ""):
                    ids = owners.get(str(parent), [])
                    if len(ids) == 1:
                        self.edge(src, ids[0], etype, source)
                        break
                    parent = parent.parent
        self._path_refs.clear()

    # ---- files
    def files(self) -> list[str]:
        """Repo-relative paths git tracks or would track (not ignored), or every file when this
        is not a git checkout."""
        if self._files is None:
            try:
                out = subprocess.run(
                    [*_GIT_FILES, str(self.root), *_GIT_FILES_ARGS],
                    capture_output=True,
                    check=False,
                )
                names = out.stdout.decode().split("\0") if out.returncode == 0 else []
            except OSError:
                names = []
            if not names:
                names = [
                    p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file()
                ]
            self._files = sorted(n for n in names if n and (self.root / n).is_file())
        return self._files

    def rel(self, p: Path) -> str:
        return p.resolve().relative_to(self.root.resolve()).as_posix()


def _clean(a: dict[str, Any]) -> dict[str, Any]:
    """Attributes as JSON-stable values (dates to strings, tuples to lists), ``None`` dropped."""

    def norm(v: Any) -> Any:
        if isinstance(v, dict):
            return {str(k): norm(x) for k, x in sorted(v.items(), key=lambda kv: str(kv[0]))}
        if isinstance(v, list | tuple | set | frozenset):
            items = [norm(x) for x in v]
            return sorted(items, key=str) if isinstance(v, set | frozenset) else items
        if isinstance(v, str | int | float | bool):
            return v
        return str(v)

    return {k: norm(v) for k, v in sorted(a.items()) if v is not None and v != "" and v != []}


def _yaml(path: Path, merge_keys: bool = False) -> Any:
    """A YAML document; duplicate keys refused, dates kept as strings.  ``merge_keys``: plain
    ``safe_load`` for files that use ``<<:`` merges (compose files)."""
    import yaml

    from homelabnext._yaml import UniqueKeyStrDateLoader

    text = path.read_text(encoding="utf-8")
    if merge_keys:
        return yaml.safe_load(text)
    return yaml.load(text, Loader=UniqueKeyStrDateLoader)  # a SafeLoader subclass


def _register_entries(path: str | Path) -> list[dict[str, Any]]:
    """Every record of one register (lessons, runbooks or invariant criteria).

    The single seam to the register storage: ``homelabnext.registers.load_register`` reads a
    directory of one-record-per-file Markdown (lessons, runbooks) or a single YAML file
    (invariants), and returns the document the validators take.  Inactive records are kept: the
    graph marks them and its queries skip them.  Each record gains ``_path``, the file it lives in
    (``<uid>.md``), ``_key``, the id its node takes (a record's uid, a criterion's id), and
    ``_label``, the display number a record is shown with (``LL 3``, computed, never stored).
    """
    from homelabnext.registers import load_register
    from homelabnext.registers.schema import labels_of

    path = Path(path)
    data = load_register(path) or {}
    for key in ("lessons", "runbooks", "criteria"):
        if isinstance(data.get(key), list):
            out = [dict(e) for e in data[key] if isinstance(e, dict)]
            labels = labels_of(out) if key != "criteria" else {}
            for e in out:
                e["_key"] = str(e.get("uid") if key != "criteria" else e.get("id"))
                if key != "criteria":
                    e["_label"] = labels.get(e["_key"])
                    if path.is_dir() and (path / f"{e['_key']}.md").is_file():
                        e["_path"] = path / f"{e['_key']}.md"
            return out
    return []


# --------------------------------------------------------------------------- registry

REGISTRY = "examples/services.yml"


def read_registry(b: Builder) -> None:
    """``examples/services.yml``: services, hosts, zones, products (``impl``), MCP servers.

    svc -provides-> cap (``capability``), svc -runs-> product (``impl``), svc -runs_on-> host,
    host -in_zone-> zone, svc -depends_on-> svc (``upstreams``), svc -serves-> zone (``clients``),
    svc -exposes-> mcp (``mcp.name``)."""
    from homelabnext.registry.model import load

    reg = load(b.root / REGISTRY)
    src = REGISTRY
    for z in sorted(reg.zones.values(), key=lambda z: z.name):
        b.define(f"zone:{z.name}", "zone", z.description, src, f"{src}#zones.{z.name}")
    for h in sorted(reg.hosts.values(), key=lambda h: h.name):
        b.define(f"host:{h.name}", "host", h.role, src, f"{src}#hosts.{h.name}", role=h.role)
        b.edge(f"host:{h.name}", f"zone:{h.zone}", "in_zone", f"{src}#hosts.{h.name}.zone")
    for s in reg.sorted_services():
        sid, at = f"svc:{s.name}", f"{src}#services.{s.name}"
        b.define(
            sid,
            "svc",
            s.name,
            src,
            at,
            owner=s.owner,
            protocol=s.protocol,
            version=s.version,
            tags=list(s.tags),
            auth=s.auth,
        )
        b.declare(f"cap:{s.capability}", "cap", src)
        b.edge(sid, f"cap:{s.capability}", "provides", f"{at}.capability")
        if s.impl:
            b.declare(f"product:{s.impl}", "product", src, s.impl)
            b.edge(sid, f"product:{s.impl}", "runs", f"{at}.impl", version=s.version)
        b.edge(sid, f"host:{s.host}", "runs_on", f"{at}.host")
        for u in s.upstreams:
            b.edge(sid, f"svc:{u}", "depends_on", f"{at}.upstreams")
        for z in s.clients:
            b.edge(sid, f"zone:{z}", "serves", f"{at}.clients")
        if s.mcp and s.mcp.get("name"):
            b.declare(f"mcp:{s.mcp['name']}", "mcp", src, s.mcp["name"])
            b.edge(
                sid,
                f"mcp:{s.mcp['name']}",
                "exposes",
                f"{at}.mcp",
                transport=s.mcp.get("transport"),
            )


def read_status(b: Builder) -> None:
    """``examples/services.yml`` ``status_sources``: one ``status:<id>`` node per source (the
    status hub's menu, ADR-0013) so a tile can reach its service, capability and their pages.

    status -observes-> svc (the declaring service) and cap (its capability); status -polls-> svc
    when the source polls another registered service (``target.service``)."""
    from homelabnext.registry.model import load

    reg = load(b.root / REGISTRY)
    for s in reg.sorted_services():
        for i, src in enumerate(s.status_sources):
            at = f"{REGISTRY}#services.{s.name}.status_sources[{i}]"
            nid = f"status:{src['id']}"
            b.define(nid, "status", src["what"], REGISTRY, at, source_kind=src["kind"])
            b.edge(nid, f"svc:{s.name}", "observes", at)
            b.edge(nid, f"cap:{s.capability}", "observes", at)
            target = (src.get("target") or {}).get("service")
            if target and target != s.name:
                b.edge(nid, f"svc:{target}", "polls", f"{at}.target.service")


# --------------------------------------------------------------------------- compose

COMPOSE_GLOB = "compose/*/docker-compose.yml"


def _image_product(image: str, known: set[str]) -> str:
    """The product an image runs: the first repository path component that is a registry
    ``impl`` (``quay.io/lakekeeper/catalog`` -> ``lakekeeper``), else the last component
    (``dxflrs/garage`` -> ``garage``).  Local builds (``*:local``) run no product."""
    repo = image.split("@", 1)[0].rsplit(":", 1)[0] if ":" in image.split("/")[-1] else image
    repo = repo.split("@", 1)[0]
    if image.split("@", 1)[0].endswith(":local"):
        return ""
    parts = [p for p in repo.split("/") if p and "." not in p]
    return next((p for p in parts if p in known), parts[-1] if parts else "")


def read_compose(b: Builder) -> None:
    """``compose/<stack>/docker-compose.yml``: compose -runs-> product (its ``image``);
    compose -provides-> cap when the compose service is named after a capability (the
    lab-in-a-box convention: ``smoke.sh`` exports ``HNX_ENDPOINT_<CAP>`` for that service)."""
    known = {n.id.split(":", 1)[1] for n in b.nodes.values() if n.kind == "product"}
    for f in sorted(b.root.glob(COMPOSE_GLOB)):
        rel, stack = b.rel(f), f.parent.name
        doc = _yaml(f, merge_keys=True) or {}
        for name, spec in sorted((doc.get("services") or {}).items()):
            cid, at = f"compose:{stack}/{name}", f"{rel}#services.{name}"
            image = str((spec or {}).get("image", ""))
            b.define(cid, "compose", f"{stack}/{name}", rel, at, image=image.split("@", 1)[0])
            product = _image_product(image, known) if image else ""
            if product:
                b.declare(f"product:{product}", "product", rel, product)
                b.edge(cid, f"product:{product}", "runs", f"{at}.image")


# --------------------------------------------------------------------------- capabilities


def read_capabilities(b: Builder) -> None:
    """Capabilities and their conformance machinery, through ``homelabnext.sop.capabilities``.

    cap nodes are the union of the conformance list (and its extended suites), the registry,
    ``capabilities.yml``, ``tool_classes.yml`` and the inventory's ``cap_*`` groups.
    cap -checked_by-> check (the suite's specs), cap -faked_by-> adapter (``make_fake``),
    adapter -implements-> cap (target-file bindings, client adapters the contract imports, the
    fake), adapter -for-> product (a target file of a compose stack binds the capability that
    stack's same-named service provides), cap -loads_schema-> schema (``_schema_links``)."""
    from homelabnext.conform.registry import CAPABILITIES, EXTENDED, load_module
    from homelabnext.sop import capabilities as caps

    for name in CAPABILITIES:
        b.declare(f"cap:{name}", "cap", "homelabnext/conform/registry.py", conformance="core")
    for name in EXTENDED:
        b.declare(f"cap:{name}", "cap", "homelabnext/conform/registry.py", conformance="extended")
    listed = _yaml(b.root / "capabilities.yml") or {}
    for name in listed.get("capabilities") or ():
        b.declare(f"cap:{name}", "cap", "capabilities.yml")
    tc = _yaml(b.root / "homelabnext/agent/tool_classes.yml") or {}
    for cid, classes in sorted((tc.get("capabilities") or {}).items()):
        b.declare(cid, "cap", "homelabnext/agent/tool_classes.yml", classes=classes)
    inv = b.root / "ansible/inventory/example/hosts.yml"
    if inv.is_file():
        groups = ((_yaml(inv) or {}).get("all") or {}).get("children") or {}
        for g in sorted(groups):
            if g.startswith("cap_"):
                b.declare(f"cap:{g[4:].replace('_', '-')}", "cap", b.rel(inv))

    from homelabnext.registry.model import load

    collected = caps.collect(b.root, load(b.root / REGISTRY))
    compose_products = {
        e.src: e.dst for e in b.edges if e.type == "runs" and e.src.startswith("compose:")
    }

    def adapter(ref: str, cap: str, source: str, real: bool, path: str) -> str:
        aid = f"adapter:{ref}"
        b.declare(aid, "adapter", source, ref, path, real=real)
        b.edge(aid, f"cap:{cap}", "implements", source)
        return aid

    for c in collected:
        cid = f"cap:{c.name}"
        b.declare(cid, "cap", c.suite_module, c.summary)
        for chk in c.checks:
            b.define(
                f"check:{c.name}/{chk.id}",
                "check",
                chk.summary,
                _suite_file(c.suite_module),
                f"{c.suite_module}.SUITE",
                severity=chk.severity,
                requires=list(chk.requires),
            )
            b.edge(cid, f"check:{c.name}/{chk.id}", "checked_by", f"{c.suite_module}.SUITE")
        if c.fake[1]:
            ref = f"{c.fake[1]}:{c.fake[0]}"
            path = caps._module_file(c.fake[1], b.root)
            aid = adapter(ref, c.name, f"{c.suite_module}.make_fake", False, path)
            b.edge(cid, aid, "faked_by", f"{c.suite_module}.make_fake")
        for bd in c.bindings:
            source = bd.target_file or c.contract_module
            aid = adapter(bd.adapter, c.name, source, bd.real, bd.module_file)
            parts = PurePosixPath(bd.target_file).parts if bd.target_file else ()
            if len(parts) >= 3 and parts[0] == "compose" and parts[2] == "targets":
                product = compose_products.get(f"compose:{parts[1]}/{c.name}")
                if product:
                    b.edge(aid, product, "for", f"{bd.target_file} + compose/{parts[1]}")
        for schema, module in c.schemas:
            b.edge(cid, f"schema:{schema}", "loads_schema", module)
    for name in EXTENDED:
        smod = load_module(name, b.root)
        for spec in smod.SUITE.specs:
            b.define(
                f"check:{name}/{spec.id}",
                "check",
                spec.summary,
                _suite_file(smod.__name__),
                f"{smod.__name__}.SUITE",
                severity=spec.severity,
                requires=list(spec.requires),
            )
            b.edge(f"cap:{name}", f"check:{name}/{spec.id}", "checked_by", f"{smod.__name__}.SUITE")
        fake = caps._fake(smod, b.root)
        if fake[1]:
            ref = f"{fake[1]}:{fake[0]}"
            aid = adapter(
                ref, name, f"{smod.__name__}.make_fake", False, caps._module_file(fake[1], b.root)
            )
            b.edge(f"cap:{name}", aid, "faked_by", f"{smod.__name__}.make_fake")
    # compose services named after a capability provide it in their stack
    for n in list(b.nodes.values()):
        if n.kind == "compose":
            cap = n.id.split("/", 1)[1]
            if b.has(f"cap:{cap}"):
                b.edge(n.id, f"cap:{cap}", "provides", f"{n.path}#services.{cap}")


def _suite_file(module: str) -> str:
    return module.replace(".", "/") + ".py"


# --------------------------------------------------------------------------- schemas


def _refs(doc: Any) -> Iterable[str]:
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == "$ref" and isinstance(v, str):
                yield v
            else:
                yield from _refs(v)
    elif isinstance(doc, list):
        for v in doc:
            yield from _refs(v)


def read_schemas(b: Builder) -> None:
    """``schemas/<family>/*.json`` (not examples, negatives or frozen baselines):
    schema -refs-> schema for every ``$ref`` to another schema (by ``$id`` or relative path)."""
    docs: dict[str, dict[str, Any]] = {}
    for rel in b.files():
        p = PurePosixPath(rel)
        if len(p.parts) == 3 and p.parts[0] == "schemas" and p.suffix == ".json":
            try:
                doc = json.loads((b.root / rel).read_text(encoding="utf-8"))
            except ValueError:
                continue
            if isinstance(doc, dict):
                docs[rel] = doc
    by_id = {str(d["$id"]).rstrip("#"): rel for rel, d in docs.items() if "$id" in d}
    for rel, doc in sorted(docs.items()):
        b.define(
            f"schema:{rel}", "schema", str(doc.get("title", "")), rel, rel, schema_id=doc.get("$id")
        )
    for rel, doc in sorted(docs.items()):
        for ref in sorted(set(_refs(doc))):
            target = ref.split("#", 1)[0]
            if not target:
                continue
            if target in by_id:
                dst = by_id[target]
            elif "://" in target:
                dst = target
            else:
                dst = (PurePosixPath(rel).parent / target).as_posix()
            if dst != rel:
                b.edge(f"schema:{rel}", f"schema:{dst}", "refs", f"{rel}#$ref")


# --------------------------------------------------------------------------- pipelines


def read_pipelines(b: Builder) -> None:
    """What runs things: ``make:<target>`` (Makefile rules), ``ci:<workflow>/<job>``
    (``.github/workflows/*.yml``), ``pre-commit:<hook>`` (``.pre-commit-config.yaml``) and the
    Python packages ``pkg:homelabnext[.<sub>]``."""
    mk = b.root / "Makefile"
    if mk.is_file():
        text = mk.read_text(encoding="utf-8")
        targets = set(re.findall(r"^([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*:(?!=)", text, re.M))
        for t in sorted(targets - {".PHONY"}):
            b.define(f"make:{t}", "make", t, "Makefile", "Makefile")
    for f in sorted((b.root / ".github/workflows").glob("*.yml")):
        doc = _yaml(f) or {}
        for job in sorted(doc.get("jobs") or {}):
            b.define(f"ci:{f.stem}/{job}", "ci", f"{f.stem}/{job}", b.rel(f), b.rel(f))
    pc = b.root / ".pre-commit-config.yaml"
    if pc.is_file():
        for repo in (_yaml(pc) or {}).get("repos") or ():
            for hook in repo.get("hooks") or ():
                b.define(f"pre-commit:{hook['id']}", "pre-commit", hook["id"], b.rel(pc), b.rel(pc))
    pkg = b.root / "homelabnext"
    b.define("pkg:homelabnext", "pkg", "homelabnext", "homelabnext", "homelabnext/__init__.py")
    for d in sorted(pkg.iterdir()):
        if (d / "__init__.py").is_file():
            doc = ast.get_docstring(ast.parse((d / "__init__.py").read_text(encoding="utf-8")))
            title = (doc or "").strip().split("\n\n", 1)[0].replace("\n", " ")
            b.define(
                f"pkg:homelabnext.{d.name}",
                "pkg",
                title[:160],
                f"homelabnext/{d.name}",
                f"homelabnext/{d.name}/__init__.py",
            )
        elif d.suffix == ".py" and not d.name.startswith("_") and d.name != "cli.py":
            doc = ast.get_docstring(ast.parse(d.read_text(encoding="utf-8")))  # a public module
            title = (doc or "").strip().split("\n\n", 1)[0].replace("\n", " ")
            b.define(
                f"pkg:homelabnext.{d.stem}",
                "pkg",
                title[:160],
                f"homelabnext/{d.name}",
                f"homelabnext/{d.name}",
            )


def _cli_targets(root: Path) -> dict[str, str]:
    """``hnx <command>`` -> the package (``pkg:...``) or script path its handler dispatches to,
    read from the ``COMMANDS`` table of ``homelabnext/cli.py`` (never imported)."""
    tree = ast.parse((root / "homelabnext/cli.py").read_text(encoding="utf-8"))
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

    def target(node: ast.AST, seen: set[str]) -> str:
        for n in ast.walk(node):
            if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("homelabnext."):
                return "pkg:" + ".".join(n.module.split(".")[:2])
            if isinstance(n, ast.Call):
                fn = ast.unparse(n.func)
                args = [a.value for a in n.args if isinstance(a, ast.Constant)]
                if (
                    fn.endswith("import_module")
                    and args
                    and str(args[0]).startswith("homelabnext.")
                ):
                    return "pkg:" + ".".join(str(args[0]).split(".")[:2])
                if fn.endswith("checkout_tool") and args:
                    return f"path:tools/{args[0]}"
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                name = n.func.id
                if name in funcs and name not in seen:
                    t = target(funcs[name], seen | {name})
                    if t:
                        return t
        return ""

    out: dict[str, str] = {}
    for n in tree.body:
        value = n.value if isinstance(n, ast.AnnAssign | ast.Assign) else None
        names = [ast.unparse(t) for t in n.targets] if isinstance(n, ast.Assign) else []
        if isinstance(n, ast.AnnAssign):
            names = [ast.unparse(n.target)]
        if "COMMANDS" not in names or not isinstance(value, ast.Dict):
            continue
        for k, v in zip(value.keys, value.values, strict=True):
            if isinstance(k, ast.Constant) and isinstance(v, ast.Tuple) and len(v.elts) == 2:
                h = v.elts[1]
                node = funcs.get(h.id) if isinstance(h, ast.Name) else h
                t = target(node, {h.id} if isinstance(h, ast.Name) else set()) if node else ""
                if t:
                    out[str(k.value)] = t
    return out


@dataclass
class Commands:
    """Exact references a command line makes: catalogued script paths, ``python -m
    homelabnext.<pkg>`` / ``homelabnext.cli <command>`` / ``hnx <command>``, test files under
    ``tests/<pkg>/`` (the package they test, the layout Q-04 enforces) and ``make <target>``."""

    scripts: dict[str, str]  # path -> script id
    cli: dict[str, str]
    make: set[str]
    pkgs: set[str]

    def refs(self, text: str) -> list[str]:
        out: list[str] = []
        for path, sid in sorted(self.scripts.items()):
            if re.search(rf"(?<![\w/.-]){re.escape(path)}(?![\w/-])", text):
                out.append(sid)
        for mod, rest in re.findall(r"-m\s+(homelabnext(?:\.[a-z_]+)*)\b\s*([a-z][\w-]*)?", text):
            if mod == "homelabnext.cli":
                t = self.cli.get(rest, "")
                out.append(self._target(t)) if t else None
            else:
                out.append("pkg:" + ".".join(mod.split(".")[:2]))
        for cmd in re.findall(r"(?<![\w./-])hnx\s+([a-z][\w-]*)", text):
            if cmd in self.cli:
                out.append(self._target(self.cli[cmd]))
        for sub in re.findall(r"(?<![\w/.-])tests/([a-z_]+)/", text):
            if f"pkg:homelabnext.{sub}" in self.pkgs:
                out.append(f"pkg:homelabnext.{sub}")
        for t in re.findall(r"(?<![\w-])make\s+([a-z][\w-]*)", text):
            if t in self.make:
                out.append(f"make:{t}")
        return sorted(set(out))

    def _target(self, t: str) -> str:
        if t.startswith("path:"):
            return self.scripts.get(t[5:], f"file:{t[5:]}")
        return t


def _commands(b: Builder) -> Commands:
    scripts = {n.path: n.id for n in b.nodes.values() if n.kind == "script"}
    make = {n.id[5:] for n in b.nodes.values() if n.kind == "make"}
    pkgs = {n.id for n in b.nodes.values() if n.kind == "pkg"}
    return Commands(scripts, _cli_targets(b.root), make, pkgs)


# --------------------------------------------------------------------------- scripts

CATALOG = "docs/scripts/catalog.json"


def read_scripts(b: Builder) -> None:
    """``docs/scripts/catalog.json`` (generated from the script headers):
    script -triggered_by-> make/ci/pre-commit/compose/script/pkg/role (``trigger``; a ``timer:R/U``
    trigger is the role ``R`` that ships the timer),
    script -enforces-> inv (``invariant``), script -reads-> node (``inputs`` that are paths)."""
    cat = json.loads((b.root / CATALOG).read_text(encoding="utf-8"))
    for s in cat.get("scripts") or ():
        b.define(
            f"script:{s['id']}",
            "script",
            s.get("purpose", ""),
            s["path"],
            f"{CATALOG}#{s['id']}",
            script_kind=s.get("kind"),
            status=s.get("status"),
            owner=s.get("owner"),
        )
    for s in cat.get("scripts") or ():
        sid, at = f"script:{s['id']}", f"{CATALOG}#{s['id']}"
        for t in s.get("trigger") or ():
            kind, _, value = str(t).partition(":")
            if kind == "manual":
                continue
            if kind == "code":
                b.path_ref(sid, value, "triggered_by", f"{at}.trigger", policy="owner")
            elif kind in ("ci", "make", "pre-commit", "compose", "script"):
                b.edge(sid, f"{kind}:{value}", "triggered_by", f"{at}.trigger")
            elif kind in ("role", "timer"):  # a role's task file, or a timer the role ships
                b.edge(sid, f"role:{value.split('/', 1)[0]}", "triggered_by", f"{at}.trigger")
            else:
                b.edge(sid, f"trigger:{t}", "triggered_by", f"{at}.trigger")
        for inv in s.get("invariant") or ():
            b.edge(sid, f"inv:{inv}", "enforces", f"{at}.invariant")
        inputs = s.get("inputs")
        for p in inputs if isinstance(inputs, list) else ():
            b.path_ref(sid, str(p), "reads", f"{at}.inputs")


# --------------------------------------------------------------------------- registers

REGISTERS = "examples/registers"
_RECORD_REF = re.compile(rf"(?<![\w-])({UID_PATTERN})(?![\w-])")
_INV_REF = re.compile(r"(?<![\w-])([A-Z]-\d{2,})(?![\w-])")


def _id_refs(text: str, inv_ids: set[str], records: dict[str, str]) -> list[str]:
    """What a register text names: a record by its uid (``[[<uid>]]`` or bare; ``records`` maps
    a uid to its node id, and an unknown uid is ``record:<uid>``, which the integrity check
    reports as dangling) and an invariant by its id.  Code spans are quoted literals (``LL-040``
    in "two authors each added `LL-040`"), not references, and are skipped."""
    text = _CODE.sub("", text)
    # a uid no register record has stays a reference (``record:<uid>``): a dangling edge
    out = [records.get(u, f"record:{u}") for u in _RECORD_REF.findall(text)]
    out += [f"inv:{i}" for i in _INV_REF.findall(text) if i in inv_ids]
    return sorted(set(out))


def read_registers(b: Builder) -> None:
    """Lessons, runbooks and invariant criteria (``examples/registers/``).

    lesson/runbook -about-> system (``systems`` tags); system -resolves_to-> svc/cap/product
    when the tag is exactly that name (unresolved tags are reported, not failed);
    runbook -operates-> svc (a tag resolving to a service); lesson -controlled_by-> runbook/inv
    (an id named in ``preventive_control``); lesson/runbook -mentions-> lesson/runbook/inv (an id
    named in any other text field); lesson -verified_by-> script/pkg/make (the command in
    ``verification.observable``); runbook -invokes-> (commands in step ``do``/``verify``);
    inv -checks-> script/pkg/make (the ``observable`` command; ``plugin`` criteria: the package
    whose plugin registers that id)."""
    base = b.root / REGISTERS
    policy = _policy(base)
    lessons = _register_entries(base / "lessons")
    runbooks = _register_entries(base / "runbooks")
    criteria = _register_entries(base / "invariants.yml")
    ip = f"{REGISTERS}/invariants.yml"

    def rel(e, kind):
        f = e.get("_path")
        return f.relative_to(b.root).as_posix() if f else f"{REGISTERS}/{kind}"

    for e in lessons:
        lp = rel(e, "lessons")
        b.define(
            f"lesson:{e['_key']}",
            "lesson",
            str(e.get("title", "")),
            lp,
            lp,
            label=e.get("_label"),
            status=e.get("status"),
            lesson_kind=e.get("kind"),
            date=e.get("date"),
            recurrences=e.get("recurrences"),
            **_provenance(e, policy),
        )
    for e in runbooks:
        rp = rel(e, "runbooks")
        b.define(
            f"runbook:{e['_key']}",
            "runbook",
            str(e.get("title", "")),
            rp,
            rp,
            label=e.get("_label"),
            status=e.get("status"),
            **_provenance(e, policy),
        )
    for e in criteria:
        b.define(
            f"inv:{e['id']}",
            "inv",
            str(e.get("statement", "")),
            ip,
            f"{ip}#{e['id']}",
            evidence=e.get("evidence"),
            deferred=bool(e.get("deferred")) or None,
            **_provenance(e, policy),
        )
    inv_ids = {str(e["id"]) for e in criteria}
    records = {e["_key"]: f"lesson:{e['_key']}" for e in lessons}
    records.update({e["_key"]: f"runbook:{e['_key']}" for e in runbooks})
    cmds = _commands(b)
    resolved: dict[str, list[str]] = {}
    for n in b.nodes.values():
        if n.kind in ("svc", "cap", "product"):
            resolved.setdefault(n.id.split(":", 1)[1], []).append(n.id)

    def tags(nid: str, entry: dict[str, Any], at: str) -> None:
        for t in entry.get("systems") or ():
            b.declare(f"system:{t}", "system", at.split("#")[0], str(t))
            b.edge(nid, f"system:{t}", "about", f"{at}.systems")
            for target in sorted(resolved.get(str(t), ())):
                b.edge(f"system:{t}", target, "resolves_to", f"{at}.systems")
                if nid.startswith("runbook:") and target.startswith("svc:"):
                    b.edge(nid, target, "operates", f"{at}.systems")

    for e in lessons:
        nid, at = f"lesson:{e['_key']}", rel(e, "lessons")
        tags(nid, e, at)
        for ref in _id_refs(str(e.get("preventive_control") or ""), inv_ids, records):
            if ref != nid:
                b.edge(nid, ref, "controlled_by", f"{at}.preventive_control")
        for key in ("symptom", "contributing_factor", "root_cause", "open_reason", "notes"):
            for ref in _id_refs(str(e.get(key) or ""), inv_ids, records):
                if ref != nid:
                    b.edge(nid, ref, "mentions", f"{at}.{key}")
        for target in _listed(e.get("retired_by")):
            b.edge(nid, _retirer(b, target, inv_ids), "retired_by", f"{at}.retired_by")
        for target in _listed(e.get("superseded_by")):
            t = target if target.startswith("lesson:") else f"lesson:{target}"
            b.edge(nid, t, "superseded_by", f"{at}.superseded_by")
        for target in _listed(e.get("incorporated_into")):
            # a runbook (its uid, or a step of it: ``<uid>#1``) or a page section
            # (``docs/systems/<svc>.md#use``); the fragment names the place, not another node
            dest = target.split("#", 1)[0]
            if is_uid(dest.removeprefix("runbook:")):
                t = dest if dest.startswith("runbook:") else f"runbook:{dest}"
                b.edge(nid, t, "incorporated_into", f"{at}.incorporated_into")
            else:
                b.path_ref(nid, dest, "incorporated_into", f"{at}.incorporated_into")
        v = e.get("verification") if isinstance(e.get("verification"), dict) else {}
        for ref in cmds.refs(str(v.get("observable", ""))):
            b.edge(nid, ref, "verified_by", f"{at}.verification.observable")
    for e in runbooks:
        nid, at = f"runbook:{e['_key']}", rel(e, "runbooks")
        tags(nid, e, at)
        for ref in _id_refs(str(e.get("purpose") or ""), inv_ids, records):
            if ref != nid:
                b.edge(nid, ref, "mentions", f"{at}.purpose")
        for ll in _listed(e.get("from_lessons")):
            t = ll if ll.startswith("lesson:") else f"lesson:{ll}"
            b.edge(nid, t, "from_lesson", f"{at}.from_lessons")
        for i, st in enumerate(e.get("steps") or (), 1):
            for ll in _listed(st.get("from_lessons")) if isinstance(st, dict) else ():
                t = ll if ll.startswith("lesson:") else f"lesson:{ll}"
                b.edge(nid, t, "from_lesson", f"{at}.steps[{i}].from_lessons")
            text = f"{st.get('do', '')}\n{st.get('verify', '')}" if isinstance(st, dict) else ""
            for ref in cmds.refs(text):
                b.edge(nid, ref, "invokes", f"{at}.steps[{i}]")
            for ref in _id_refs(text, inv_ids, records):
                if ref != nid:
                    b.edge(nid, ref, "mentions", f"{at}.steps[{i}]")
    plugins = _plugin_owners(b)
    for e in criteria:
        nid, at = f"inv:{e['id']}", f"{ip}#{e['id']}"
        for ref in cmds.refs(str(e.get("observable") or "")):
            b.edge(nid, ref, "checks", f"{at}.observable")
        if e.get("plugin"):
            pid = str(e["plugin"])
            b.edge(nid, plugins.get(pid, f"plugin:{pid}"), "checks", f"{at}.plugin")


def _provenance(e: dict[str, Any], policy: Any = None) -> dict[str, Any]:
    """``author`` and a compact summary of a record's ``reviews`` (reviewer identities are not
    nodes): ``reviewed`` lists each tier with a *current, valid, passing* review -- ``agent_check``
    (an agent's ``check``), ``audit`` (an ``audit`` review) and ``human`` (a human's review
    of any role) -- and ``review_count`` counts every review.  Absent fields: nothing.

    "Current and valid" is the register validation's own judgement of the loaded record
    (:func:`homelabnext.registers.schema.review_evaluation`: its reviews as derived from the
    sidecar events, against :func:`~homelabnext.registers.schema.record_digest_of`), with
    ``policy`` (the register's ``review-policy.yml``) when there is one: a review of an earlier
    content, a self-review, an audit by a checker, an agent in a human slot or a malformed
    review counts for no tier, so ``require_reviews`` can trust the attr."""
    from homelabnext.registers.schema import review_evaluation

    reviews = e.get("reviews")
    ev = review_evaluation({k: v for k, v in e.items() if not k.startswith("_")}, policy=policy)
    tiers = set()
    for r in ev.current:
        if r["kind"] == "agent" and r["role"] == "check":
            tiers.add("agent_check")
        if r["role"] == "audit":
            tiers.add("audit")
        if r["kind"] == "human":
            tiers.add("human")
    return {
        "author": e.get("author"),
        "reviewed": sorted(tiers) or None,
        "review_count": len(reviews) if isinstance(reviews, list) and reviews else None,
    }


def _policy(base: Path) -> Any:
    """The register's review policy (``review-policy.yml`` in or beside ``base``), or None when
    there is none or it does not load (the identity rules that need no policy still apply)."""
    from homelabnext.registers.render import find_policy
    from homelabnext.reviews import ReviewError, load_policy

    path = find_policy(base)
    try:
        return load_policy(path) if path else None
    except ReviewError:
        return None


def _listed(v: Any) -> list[str]:
    return [str(v)] if isinstance(v, str) else [str(x) for x in v or () if x]


def _retirer(b: Builder, target: str, inv_ids: set[str]) -> str:
    """What a ``retired_by`` value names: ``inv:<id>`` or a bare criterion id, else a test file
    (``test:<path>``; a path that does not exist is the dangling ``file:<path>``)."""
    if target.startswith("inv:"):
        return target
    if _INV_REF.fullmatch(target):
        return f"inv:{target}"
    path = target.split("::", 1)[0]
    if (b.root / path).is_file():
        b.declare(f"test:{path}", "test", "retired_by", path, path)
        return f"test:{path}"
    return f"file:{path}"


def _plugin_owners(b: Builder) -> dict[str, str]:
    """Invariant plugin id -> the package whose ``plugins/`` module names it as a string literal
    (``Check("X-01", ...)``, ``CHECK_ID = "X-09"``, the ``SERVER_ONLY`` table)."""
    out: dict[str, str] = {}
    for rel in b.files():
        p = PurePosixPath(rel)
        if p.parts[:1] == ("homelabnext",) and "plugins" in p.parts and p.suffix == ".py":
            text = (b.root / rel).read_text(encoding="utf-8")
            for pid in re.findall(r"\"([A-Z]-\d{2,})\"", text):
                out.setdefault(pid, f"pkg:homelabnext.{p.parts[1]}")
    return out


def record_aliases(root: Path):
    """The legacy code -> uid maps of the registers and the strategy (``aliases.yml``)."""
    from homelabnext.identity.aliases import load_aliases

    return load_aliases(root / REGISTERS, root / STRATEGY)


# --------------------------------------------------------------------------- strategy

STRATEGY = "examples/strategy"
_STRATEGY_NODE = {"objectives": "objective", "measures": "measure", "requirements": "req"}
_STRATEGY_NODE["rfis"] = "rfi"


def read_strategy(b: Builder) -> None:
    """The strategy-to-task records (``examples/strategy/``, :mod:`homelabnext.strategy`).

    ``strategy:<name>``, ``objective:<uid>``, ``measure:<uid>``, ``req:<uid>``, ``rfi:<uid>``,
    each with its ``status``, its ``type`` (``level`` for an objective, as before) and its
    computed display number (``label``: ``OO 1.2``); objective -child_of-> objective
    (``parent``) or the strategy (an SO); objective -measured_by-> measure (the measure's
    ``parent``); measure -binds-> inv/status (``source`` ``invariant:`` / ``status:``);
    req -child_of-> req (a PIR's optional ``parent``); req -supports-> objective; req -serves->
    req (FFIR -> CCIR, PIR -> CCIR/FFIR); rfi -raised_by-> measure/req; req/rfi -tasked_to->
    profile/human, only where ``tasked_to`` names a principal the keyring defines (a role or a
    tag is not a node)."""
    from homelabnext.strategy.records import load_tree

    root = b.root / STRATEGY
    if not (root / "strategy.md").is_file():
        return
    tree = load_tree(root)
    policy = _policy(root)
    sid = None
    if tree.strategy is not None:
        s, at = tree.strategy, b.rel(tree.paths["strategy"])
        sid = f"strategy:{s.get('name')}"
        b.define(sid, "strategy", str(s.get("title", "")), at, at, status=s.get("status"))

    def nid(uid) -> str:
        kind = tree.kind_of(str(uid))
        return f"{_STRATEGY_NODE.get(str(kind), 'unknown')}:{uid}"

    for kind, key, e in tree.items():
        if kind == "strategy":
            continue
        at = b.rel(tree.paths[key])
        content = {k: v for k, v in e.items() if k != "values"}
        b.define(
            f"{_STRATEGY_NODE[kind]}:{key}",
            _STRATEGY_NODE[kind],
            str(e.get("title", "")),
            at,
            at,
            label=tree.label(key),
            status=e.get("status"),
            level=e.get("type") if kind == "objectives" else None,
            record_type=e.get("type"),
            triage=e.get("triage"),
            **_provenance(content, policy),
        )
    for kind, key, e in tree.items():
        if kind == "strategy":
            continue
        me, at = f"{_STRATEGY_NODE[kind]}:{key}", b.rel(tree.paths[key])
        if kind == "objectives":
            if e.get("parent"):
                b.edge(me, nid(e["parent"]), "child_of", f"{at}#parent")
            elif sid:
                b.edge(me, sid, "child_of", f"{at}#type")
        elif kind == "measures":
            if e.get("parent"):  # the objective lists nothing: the measure names its parent
                b.edge(nid(e["parent"]), me, "measured_by", f"{at}#parent")
            src, _, arg = str(e.get("source") or "").partition(":")
            target = {"invariant": f"inv:{arg}", "status": f"status:{arg.split('/')[0]}"}
            if src in target:
                b.edge(me, target[src], "binds", f"{at}#source")
        elif kind == "requirements":
            if e.get("parent"):
                b.edge(me, nid(e["parent"]), "child_of", f"{at}#parent")
            for o in _listed(e.get("supports")):
                b.edge(me, nid(o), "supports", f"{at}#supports")
            for r in _listed(e.get("serves")):
                b.edge(me, nid(r), "serves", f"{at}#serves")
        else:
            b.edge(me, nid(e.get("raised_by")), "raised_by", f"{at}#raised_by")
        for t in _listed(e.get("tasked_to")):
            if b.has(t) and b.nodes[t].kind in ("profile", "human"):
                b.edge(me, t, "tasked_to", f"{at}#tasked_to")


# --------------------------------------------------------------------------- agent

KEYRING_SOURCES = "examples/keyring/sources.yml"


def read_agent(b: Builder) -> None:
    """Agent profiles, parts, model roles, context manifests, the broker and the keyring.

    profile -uses-> skill/persona (``parts.skills``, ``persona``), profile -uses_model-> mdl
    (``model_role``); skill/persona/cap parts exist where a compiled profile's ``provenance``
    records them; mdl -backed_by-> svc (``bindings[].backend``), mdl -falls_back_to-> mdl;
    manifest -uses-> skill/persona/mcp (``skills``, ``persona``, ``tools``); broker -defines->
    action; principal -grants-> cap/mcp/action/svc/broker (``examples/keyring/keyring.json``,
    with ``level``); mcp slugs come from ``tool_classes.yml`` and the registry."""
    tc_rel = "homelabnext/agent/tool_classes.yml"
    tc = _yaml(b.root / tc_rel) or {}
    for slug, classes in sorted((tc.get("mcp") or {}).items()):
        b.declare(f"mcp:{slug}", "mcp", tc_rel, slug, classes=classes)

    roles_rel = "examples/model_roles.json"
    roles = json.loads((b.root / roles_rel).read_text(encoding="utf-8")).get("roles") or {}
    for name, spec in sorted(roles.items()):
        mid, at = f"mdl:{name}", f"{roles_rel}#roles.{name}"
        b.define(
            mid,
            "mdl",
            str(spec.get("description", name))[:160],
            roles_rel,
            at,
            tier=spec.get("tier"),
        )
        for bind in spec.get("bindings") or ():
            if bind.get("backend"):
                b.edge(mid, str(bind["backend"]), "backed_by", f"{at}.bindings")
        if spec.get("fallback"):
            b.edge(mid, str(spec["fallback"]), "falls_back_to", f"{at}.fallback")

    src_path = b.root / KEYRING_SOURCES
    srcs = _yaml(src_path) or {}
    profile_files: list[Path] = []
    for pattern in srcs.get("profiles") or ():
        profile_files += sorted(src_path.parent.glob(pattern))
    for f in profile_files:
        rel = b.rel(f)
        doc = json.loads(f.read_text(encoding="utf-8"))
        pid = str(doc["id"])
        b.define(
            pid,
            "profile",
            pid.split(":", 1)[1],
            rel,
            rel,
            data_tier=doc.get("data_tier"),
            reads_untrusted=doc.get("reads_untrusted"),
            tier=(doc.get("grants") or {}).get("tier"),
        )
        for p in doc.get("provenance") or ():
            kind = str(p.get("id", "")).split(":", 1)[0]
            if p.get("source") == "parts-library" and kind in ("skill", "persona", "cap"):
                b.declare(str(p["id"]), kind, f"{rel}#provenance", str(p["id"]).split(":", 1)[1])
        parts = doc.get("parts") or {}
        for s in parts.get("skills") or ():
            b.edge(pid, str(s), "uses", f"{rel}#parts.skills")
        for c in parts.get("capabilities") or ():
            b.edge(pid, str(c), "uses", f"{rel}#parts.capabilities")
        if doc.get("persona"):
            b.edge(pid, str(doc["persona"]), "uses", f"{rel}#persona")
        if doc.get("model_role"):
            b.edge(pid, str(doc["model_role"]), "uses_model", f"{rel}#model_role")

    broker_rel = ""
    if srcs.get("broker"):
        bf = (src_path.parent / srcs["broker"]).resolve()
        broker_rel = b.rel(bf)
        man = json.loads(bf.read_text(encoding="utf-8"))
        bid = f"broker:{man['manifest_id']}"
        b.define(
            bid, "broker", str(man["manifest_id"]), broker_rel, broker_rel, mode=man.get("mode")
        )
        for a in man.get("actions") or ():
            aid = f"action:{a['action']}"
            b.define(
                aid,
                "action",
                str(a["action"]),
                broker_rel,
                f"{broker_rel}#actions.{a['action']}",
                tier=a.get("tier"),
                requires_approval=a.get("requires_approval"),
            )
            b.edge(bid, aid, "defines", f"{broker_rel}#actions")

    kr_rel = f"{PurePosixPath(KEYRING_SOURCES).parent}/{srcs.get('out', 'keyring.json')}"
    kr = json.loads((b.root / kr_rel).read_text(encoding="utf-8"))
    for p in kr.get("principals") or ():
        pid, kind = str(p["principal"]), str(p.get("kind", ""))
        if not b.has(pid):
            node_kind = {"agent": "profile", "network": "zone"}.get(kind, kind)
            b.define(pid, node_kind, pid.split(":", 1)[1], kr_rel, f"{kr_rel}#principals")
        for g in p.get("grants") or ():
            res = str(g["resource"])
            if res.startswith("approve:"):
                res = "broker:" + res.split(":", 1)[1]
            b.edge(
                pid,
                res,
                "grants",
                f"{kr_rel}#principals.{pid}",
                level=g.get("level"),
                approval=g.get("approval") or None,
            )

    from homelabnext.agent import readers

    for f in readers._candidates(b.root):
        if f.suffix != ".json":
            continue
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except ValueError:
            continue
        if readers._kind(doc) != "manifest":
            continue
        rel = b.rel(f)
        mid = f"manifest:{doc['id']}"
        b.define(mid, "manifest", str(doc["id"]), rel, rel)
        for s in doc.get("skills") or ():
            b.edge(mid, str(s), "uses", f"{rel}#skills")
        if doc.get("persona"):
            b.edge(mid, str(doc["persona"]), "uses", f"{rel}#persona")
        for t in doc.get("tools") or ():
            b.edge(mid, f"mcp:{t}", "uses", f"{rel}#tools")


# --------------------------------------------------------------------------- customization


def read_customizations(b: Builder) -> None:
    """``profiles/*/customization.yml``: custom -applies_to-> cap/svc/host (``scope``),
    custom -governed_by-> adr (``contract``), custom -links-> lesson/runbook (``links``: a
    record's uid; a legacy code resolves through ``examples/registers/aliases.yml``, with a
    deprecation warning)."""
    from homelabnext.identity.aliases import load_aliases, resolve

    aliases = load_aliases(b.root / REGISTERS)
    for f in sorted(b.root.glob("profiles/*/customization.yml")):
        rel = b.rel(f)
        doc = _yaml(f) or {}
        cid = str(doc.get("id", f"custom:{f.parent.name}"))
        b.define(
            cid,
            "custom",
            str(doc.get("title", "")),
            b.rel(f.parent),
            rel,
            custom_kind=doc.get("kind"),
            owner=doc.get("owner"),
        )
        scope = doc.get("scope") or {}
        for c in scope.get("capabilities") or ():
            b.edge(cid, str(c), "applies_to", f"{rel}#scope.capabilities")
        for key, prefix in (("services", "svc:"), ("hosts", "host:")):
            for v in scope.get(key) or ():
                v = str(v)
                b.edge(
                    cid,
                    v if v.startswith(prefix) else prefix + v,
                    "applies_to",
                    f"{rel}#scope.{key}",
                )
        if doc.get("contract"):
            b.edge(cid, str(doc["contract"]), "governed_by", f"{rel}#contract")
        links = doc.get("links") or {}
        for key, prefix in (("lesson", "lesson:"), ("runbook", "runbook:")):
            vals = links.get(key)
            for v in [vals] if isinstance(vals, str) else vals or ():
                # a uid; a legacy code (LL-001) resolves through the registers' alias map
                uid = resolve(str(v), aliases, f"{rel}#links.{key}")
                b.edge(cid, f"{prefix}{uid}", "links", f"{rel}#links.{key}")


# --------------------------------------------------------------------------- ansible


def read_ansible(b: Builder) -> None:
    """``ansible/roles/*`` and ``ansible/playbooks/*.yml``: playbook -targets-> cap (a
    ``cap_<name>`` host group), playbook -applies-> role."""
    for d in sorted((b.root / "ansible/roles").glob("*/")):
        if d.is_dir():
            b.define(f"role:{d.name}", "role", d.name, b.rel(d), b.rel(d))
    for f in sorted((b.root / "ansible/playbooks").glob("*.yml")):
        rel = b.rel(f)
        b.define(f"playbook:{f.stem}", "playbook", f.stem, rel, rel)
        for i, play in enumerate(_yaml(f) or ()):
            if not isinstance(play, dict):
                continue
            hosts = play.get("hosts")
            for h in [hosts] if isinstance(hosts, str) else hosts or ():
                h = str(h)
                if h.startswith("cap_"):
                    b.edge(
                        f"playbook:{f.stem}",
                        f"cap:{h[4:].replace('_', '-')}",
                        "targets",
                        f"{rel}#[{i}].hosts",
                    )
            for r in play.get("roles") or ():
                name = r.get("role") if isinstance(r, dict) else r
                b.edge(f"playbook:{f.stem}", f"role:{name}", "applies", f"{rel}#[{i}].roles")


# --------------------------------------------------------------------------- docs

GRAPH_DIR = "docs/graph"
_FENCE = re.compile(r"^(`{3,}|~{3,}).*?^\1[ \t]*$", re.M | re.S)
_CODE = re.compile(r"`[^`\n]*`")
_MD_LINK = re.compile(r"\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_WIKI = re.compile(r"\[\[([^\]|#]*)(?:#[^\]|]*)?(?:\|[^\]]*)?\]\]")
_ADR = re.compile(r"^docs/adr/(\d{4})-(.+)\.md$")


def _doc_files(b: Builder) -> list[str]:
    skip = ("tests/", f"{GRAPH_DIR}/")
    return [
        f
        for f in b.files()
        if f.endswith(".md")
        and not f.startswith(skip)
        and not {"examples", "negative"} & set(PurePosixPath(f).parts)
    ]


def doc_id(rel: str) -> str:
    m = _ADR.match(rel)
    return f"adr:{m.group(2)}" if m else f"doc:{rel}"


def _title(text: str) -> str:
    m = re.search(r"^#\s+(.+)$", text, re.M)
    return m.group(1).strip() if m else ""


def read_docs(b: Builder) -> None:
    """Markdown pages: ``doc:<path>`` (``adr:<slug>`` for ``docs/adr/NNNN-<slug>.md``).

    doc -documents-> svc (``docs/systems/<service>.md``) / cap (``docs/capabilities/<cap>.md``);
    doc -links-> any node owning the target of a relative Markdown link or a ``[[wiki-link]]``
    in a page under ``docs/`` (code spans and fenced blocks are skipped).  A link to a file that
    does not exist is a dangling edge."""
    docs = _doc_files(b)
    for rel in docs:
        text = (b.root / rel).read_text(encoding="utf-8")
        m = _ADR.match(rel)
        b.define(
            doc_id(rel), "adr" if m else "doc", _title(text), rel, rel, number=m and m.group(1)
        )
        p = PurePosixPath(rel)
        if p.parts[:2] == ("docs", "systems") and b.has(f"svc:{p.stem}"):
            b.edge(doc_id(rel), f"svc:{p.stem}", "documents", rel)
        if p.parts[:2] == ("docs", "capabilities") and b.has(f"cap:{p.stem}"):
            b.edge(doc_id(rel), f"cap:{p.stem}", "documents", rel)
    by_stem: dict[str, list[str]] = {}
    for rel in docs:
        if rel.startswith("docs/"):
            by_stem.setdefault(PurePosixPath(rel).stem, []).append(rel)
    records = {
        PurePosixPath(f).stem: f
        for f in b.files()
        if f.endswith(".md") and is_uid(PurePosixPath(f).stem)
    }
    for rel in docs:
        if not rel.startswith("docs/"):
            continue
        text = (b.root / rel).read_text(encoding="utf-8")
        text = _CODE.sub("", _FENCE.sub("", text))
        src = doc_id(rel)
        here = PurePosixPath(rel).parent
        targets: set[str] = set()
        for raw in _MD_LINK.findall(text):
            if re.match(r"^[a-z][a-z0-9+.-]*:", raw, re.I) or raw.startswith("#"):
                continue
            target = unquote(raw.split("#", 1)[0].split("?", 1)[0])
            if target:
                targets.add(_norm(here / target))
        for raw in _WIKI.findall(text):
            raw = raw.strip().rstrip("\\")  # a table cell escapes the pipe: [[a/b\\|label]]
            if not raw:
                continue
            if is_uid(raw) and (hit := records.get(raw)):  # a record: [[<uid>|PIR 2.1 ...]]
                targets.add(hit)
                continue
            cand = [f"docs/{raw}.md", f"docs/{raw}"]
            hit = next((c for c in cand if (b.root / c).is_file()), "")
            if not hit and "/" not in raw and len(by_stem.get(raw, [])) == 1:
                hit = by_stem[raw][0]
            targets.add(hit or f"docs/{raw}.md")
        for t in sorted(targets):
            if t != rel:
                b.path_ref(src, t, "links", rel)


def _norm(p: PurePosixPath) -> str:
    out: list[str] = []
    for part in p.parts:
        if part == "..":
            if out:
                out.pop()
            else:
                out.append("..")
        elif part != ".":
            out.append(part)
    return "/".join(out).rstrip("/") or "."


# --------------------------------------------------------------------------- order

#: reader order matters only where a reader matches names an earlier one defined
READERS: tuple[tuple[str, Callable[[Builder], None]], ...] = (
    ("registry", read_registry),
    ("status", read_status),
    ("compose", read_compose),
    ("capabilities", read_capabilities),
    ("schemas", read_schemas),
    ("pipelines", read_pipelines),
    ("scripts", read_scripts),
    ("registers", read_registers),
    ("agent", read_agent),
    ("strategy", read_strategy),
    ("customizations", read_customizations),
    ("ansible", read_ansible),
    ("docs", read_docs),
)
