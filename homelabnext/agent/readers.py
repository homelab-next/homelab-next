# SPDX-License-Identifier: Apache-2.0
"""Readers cannot act (checklist G-03): classify grants, refuse readers that hold dangerous ones.

A profile that **reads raw or untrusted content** (``reads_untrusted``: feed items, alerts, mail,
web pages, anything an outsider can write) can be steered by that content, so it must not hold a
tool that turns a persuaded model into an action: shell/exec, file-write, network egress, or
credentials.  Work that needs both is split into a reader that reports and an actor that receives
the reader's validated structured output and acts through allowlisted broker actions (G-04).

Why ``reads_untrusted`` is declared rather than derived: nothing in a profile says what it reads.
``data_tier`` says where data may *go* (local or cloud), not where it comes from; ``memory_scopes``
name stores, not their trust; and the context manifest, whose ``source: input`` sections are the
untrusted ones, is bound to a persona, not to a profile.  So the profile declares it, and an
absent declaration counts as ``true`` (fail closed): an actor has to say ``reads_untrusted:
false`` to hold an acting tool.  A ceiling policy may also mark a profile a reader, which the spec
cannot undo.  :func:`manifest_problems` applies the same rule to a context manifest, where it *is*
derivable: a manifest with any ``source: input`` section feeds untrusted content.

The classification is data, not code: ``tool_classes.yml`` next to this module maps every
capability and broker tier to capability classes and lists the classes a reader may not hold; its
``mcp`` section is derived from the MCP catalog (:mod:`homelabnext.mcp.servers`, ADR-0024): a
server's classes are the union of its tools'.  A grant missing from that table is refused for a
reader (unknown is never assumed safe), and :func:`grant_problems` refuses, for every profile, an
MCP server the catalog does not hold, a retired or draft one, and a local-only server granted to a
profile whose data may go to the cloud.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from functools import cache
from pathlib import Path
from typing import Any

from .errors import SpecError

DEFAULT_CLASSES = Path(__file__).with_name("tool_classes.yml")
KINDS = ("mcp", "capabilities", "tiers")
#: catalog statuses a profile may be granted (an allowlist; ``deprecated`` with a note): the same
#: as :data:`homelabnext.mcp.servers.GRANTABLE`
GRANTABLE = ("active", "deprecated")
#: the data tiers a catalog server may declare (``schemas/platform/mcp_server.schema.json``)
DATA_TIERS = ("local-only", "cloud-allowed")


class ToolClasses:
    """The classification table: ``{mcp, capabilities, tiers}`` -> classes, plus the reader ban."""

    def __init__(
        self,
        doc: Mapping[str, Any],
        source: str = "tool classes",
        catalog: Mapping[str, Mapping[str, Any]] | None = None,
        catalog_source: str | None = None,
    ) -> None:
        #: per MCP server of the catalog the table was derived from: status, reason, data_tier
        #: (``None`` when the table states its own ``mcp`` section: then its keys are the catalog)
        self.catalog = dict(catalog) if catalog is not None else None
        self.catalog_source = catalog_source or source
        if not isinstance(doc, Mapping):
            raise SpecError(f"{source}: expected a mapping")
        classes = doc.get("classes")
        if not isinstance(classes, Mapping) or not classes:
            raise SpecError(f"{source}: 'classes' must map each class to its description")
        self.source = source
        self.classes = dict(classes)
        self.reader_forbidden = frozenset(doc.get("reader_forbidden") or ())
        if not self.reader_forbidden:
            raise SpecError(f"{source}: 'reader_forbidden' is empty (that would allow everything)")
        self.table: dict[str, dict[str, tuple[str, ...]]] = {}
        unknown: set[str] = set(self.reader_forbidden) - set(self.classes)
        for kind in KINDS:
            entries = doc.get(kind) or {}
            if not isinstance(entries, Mapping):
                raise SpecError(f"{source}: '{kind}' must be a mapping of name -> [classes]")
            self.table[kind] = {}
            for name, cls in entries.items():
                if not isinstance(cls, list) or not cls:
                    raise SpecError(f"{source}: {kind}.{name} must list at least one class")
                unknown |= set(cls) - set(self.classes)
                self.table[kind][str(name)] = tuple(sorted(set(cls)))
        if unknown:
            raise SpecError(f"{source}: undeclared classes {sorted(unknown)}")

    @classmethod
    def load(cls, path: str | Path | None = None, catalog: str | Path | None = None) -> ToolClasses:
        """The table at ``path`` (default: the packaged ``tool_classes.yml``).  Without an ``mcp``
        section of its own, the section is derived from the MCP catalog at ``catalog`` (default:
        :func:`homelabnext.mcp.servers.default_dir`, so a private overlay's catalog is used where
        its examples directory is)."""
        import yaml

        p = Path(path) if path else DEFAULT_CLASSES
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(doc, Mapping) or "mcp" in doc:
            return cls(doc, source=str(p))
        from homelabnext.mcp import servers

        try:
            cat = servers.load_cached(catalog)
        except servers.CatalogError as exc:
            raise SpecError(f"{p}: its mcp section comes from the MCP catalog: {exc}") from None
        return cls.from_catalog(cat, doc, str(p))

    @classmethod
    def from_catalog(
        cls, cat: Any, doc: Mapping[str, Any] | None = None, source: str | None = None
    ) -> ToolClasses:
        """The table ``doc`` (default: the packaged one) with its ``mcp`` section derived from the
        loaded catalog ``cat`` (:class:`homelabnext.mcp.servers.Catalog`).  A catalog that is not
        sound (a record that fails its schema, an id that is not its file name, two records with
        one id) is refused: a grant judged against it could be judged against a shadow record."""
        import yaml

        from homelabnext.mcp import servers

        if doc is None:
            source = source or str(DEFAULT_CLASSES)
            doc = yaml.safe_load(DEFAULT_CLASSES.read_text(encoding="utf-8")) or {}
        bad = servers.integrity_problems(cat)
        if bad:
            more = f" (+{len(bad) - 5} more)" if len(bad) > 5 else ""
            raise SpecError(
                f"the MCP catalog {cat.root} is not valid, so no grant can be judged against it: "
                + "; ".join(bad[:5])
                + more
                + " (hnx mcp catalog check)"
            )
        meta = {
            sid: {
                "status": rec.get("status"),
                "reason": rec.get("reason"),
                "data_tier": rec.get("data_tier"),
                "replaced_by": rec.get("replaced_by"),
            }
            for sid, rec in cat
        }
        return cls(
            {**doc, "mcp": cat.classes()},
            source=f"{source or 'tool classes'} + the MCP catalog {cat.root}",
            catalog=meta,
            catalog_source=f"the MCP catalog {cat.root}",
        )

    def classify(self, kind: str, name: str) -> tuple[str, ...] | None:
        """Classes of one grant, or ``None`` if the table does not know it."""
        return self.table[kind].get(name)


@cache
def default_classes() -> ToolClasses:
    return ToolClasses.load()


def table_vocabulary(path: str | Path | None = None) -> list[str]:
    """The capability classes ``tool_classes.yml`` declares (without reading the catalog)."""
    import yaml

    doc = yaml.safe_load(Path(path or DEFAULT_CLASSES).read_text(encoding="utf-8")) or {}
    return sorted((doc.get("classes") or {}) if isinstance(doc, Mapping) else ())


def grant_problems(
    grants: Mapping[str, Any],
    classes: ToolClasses | None = None,
    who: str = "profile",
    data_tier: str | None = None,
) -> list[str]:
    """MCP grants the catalog does not allow, for any profile (reader or actor): a server the
    catalog does not hold, a retired or draft one, and a ``local-only`` server granted to a
    profile whose ``data_tier`` is ``cloud-allowed`` (its context may go to a cloud model)."""
    classes = classes or default_classes()
    problems: list[str] = []
    for name in _names(grants.get("mcp")):
        if classes.catalog is None:
            if classes.classify("mcp", name) is None:
                problems.append(
                    f"{who} names MCP server {name!r}, which is not in {classes.source} "
                    "(grant a catalog id)"
                )
            continue
        meta = classes.catalog.get(name)
        if meta is None:
            problems.append(
                f"{who} names MCP server {name!r}, which is not in {classes.catalog_source} "
                "(add a record, or grant a catalog id)"
            )
            continue
        status = meta.get("status")
        if status == "retired":
            problems.append(
                f"{who} is granted MCP server {name!r}, which is retired: {meta.get('reason')}"
            )
        elif status == "draft":
            problems.append(
                f"{who} is granted MCP server {name!r}, which is a draft (not reviewed; "
                "make it active first)"
            )
        elif status not in GRANTABLE:  # an allowlist: an unknown status is never grantable
            problems.append(
                f"{who} is granted MCP server {name!r}, whose status {status!r} is not "
                f"grantable (only {', '.join(GRANTABLE)})"
            )
        server_tier = meta.get("data_tier")
        if server_tier not in DATA_TIERS:
            problems.append(
                f"{who} is granted MCP server {name!r}, which declares no known data_tier "
                f"({server_tier!r}): what it returns could reach any model"
            )
        elif data_tier is not None and data_tier != "local-only" and server_tier == "local-only":
            problems.append(
                f"{who} may send its context to the cloud (data_tier {data_tier}) but is "
                f"granted MCP server {name!r}, whose data is local-only"
            )
    return problems


def grant_notes(
    grants: Mapping[str, Any], classes: ToolClasses | None = None, who: str = "profile"
) -> list[str]:
    """Warnings, not refusals: every granted MCP server that is ``deprecated``, with its reason
    and the server to grant instead (``replaced_by``)."""
    classes = classes or default_classes()
    out: list[str] = []
    for name in _names(grants.get("mcp")):
        meta = (classes.catalog or {}).get(name) or {}
        if meta.get("status") == "deprecated":
            instead = meta.get("replaced_by")
            out.append(
                f"{who} is granted MCP server {name!r}, which is deprecated: {meta.get('reason')}"
                + (f"; grant {instead!r} instead" if instead else "")
            )
    return out


def reader_problems(
    grants: Mapping[str, Any], classes: ToolClasses | None = None, who: str = "profile"
) -> list[str]:
    """Every grant a reader may not hold (empty list = an acceptable reader).

    ``grants`` has ``mcp``, ``capabilities`` and optionally ``tier``.
    """
    classes = classes or default_classes()
    problems: list[str] = []
    wanted: list[tuple[str, str, str]] = [
        *(("mcp", "mcp server", n) for n in _names(grants.get("mcp"))),
        *(("capabilities", "capability", n) for n in _names(grants.get("capabilities"))),
    ]
    if grants.get("tier") is not None:
        wanted.append(("tiers", "tier", str(grants["tier"])))
    for kind, label, name in wanted:
        got = classes.classify(kind, name)
        if got is None:
            problems.append(
                f"{who} reads untrusted content but holds {label} {name!r}, which is not "
                f"classified in {classes.source} (unknown is refused for a reader)"
            )
            continue
        bad = sorted(set(got) & classes.reader_forbidden)
        if bad:
            problems.append(
                f"{who} reads untrusted content but holds {label} {name!r} ({', '.join(bad)}): "
                "readers cannot act; split it into a reader and an actor"
            )
    return problems


def is_reader(doc: Mapping[str, Any]) -> bool:
    """A profile or spec reads untrusted content unless it says ``reads_untrusted: false``."""
    return doc.get("reads_untrusted", True) is not False


def profile_problems(doc: Mapping[str, Any], classes: ToolClasses | None = None) -> list[str]:
    """Catalog problems (:func:`grant_problems`, every profile) and reader problems (readers) for
    any agent-profile shape: a spec, a compiled ``agent/profile`` (grants under ``grants``) or the
    lean ``platform/agent_profile`` (``mcp``/``capabilities`` at the top).
    """
    if "reads_untrusted" in doc and not isinstance(doc["reads_untrusted"], bool):
        return ["reads_untrusted must be true or false"]
    grants = doc.get("grants") if isinstance(doc.get("grants"), Mapping) else doc
    who = str(doc.get("id", "profile"))
    tier = doc.get("data_tier") if isinstance(doc.get("data_tier"), str) else None
    problems = grant_problems(grants, classes, who, tier)
    if not is_reader(doc):
        return problems
    return problems + reader_problems(grants, classes, who)


def manifest_problems(doc: Mapping[str, Any], classes: ToolClasses | None = None) -> list[str]:
    """A context manifest's ``tools`` (MCP servers) must be grantable catalog servers; and a
    manifest with any ``source: input`` section feeds untrusted content to its agent, so its
    tools obey the reader rule too."""
    sections = doc.get("sections") or []
    who = f"manifest {doc.get('id', '?')}"
    problems = grant_problems({"mcp": doc.get("tools") or []}, classes, who)
    if not any(isinstance(s, Mapping) and s.get("source") == "input" for s in sections):
        return problems
    return problems + reader_problems({"mcp": doc.get("tools") or []}, classes, who)


def doc_notes(doc: Mapping[str, Any], classes: ToolClasses | None = None) -> list[str]:
    """:func:`grant_notes` for a profile (any shape) or a context manifest (its ``tools``)."""
    if _kind(doc) == "manifest":
        return grant_notes({"mcp": doc.get("tools") or []}, classes, f"manifest {doc.get('id')}")
    grants = doc.get("grants") if isinstance(doc.get("grants"), Mapping) else doc
    return grant_notes(grants, classes, str(doc.get("id", "profile")))


def _names(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str) or not isinstance(raw, Iterable):
        return [str(raw)]
    return sorted({str(x) for x in raw})


# ---------------------------------------------------------------- repository lint
_SKIP_PARTS = {"negative", "_frozen", ".git", "node_modules", "__pycache__", ".venv", "venv"}
_SUFFIXES = {".json", ".yml", ".yaml"}


def _candidates(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    import subprocess

    try:
        out = subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            capture_output=True,
            check=False,
        )
        names = out.stdout.decode().split("\0") if out.returncode == 0 else None
    except OSError:
        names = None
    files = [path / n for n in names if n] if names is not None else list(path.rglob("*"))
    return sorted(
        f
        for f in files
        if f.suffix in _SUFFIXES
        and f.is_file()
        and not _SKIP_PARTS & set(f.relative_to(path).parts)
    )


def _kind(doc: Any) -> str | None:
    if not isinstance(doc, Mapping):
        return None
    pid = doc.get("id")
    granted = any(k in doc for k in ("grants", "mcp", "capabilities", "tier"))
    if isinstance(pid, str) and pid.startswith("profile:") and granted:
        return "profile"
    if isinstance(doc.get("sections"), list) and "tools" in doc and "persona" in doc:
        return "manifest"
    return None


def lint_paths(
    paths: Iterable[str | Path],
    classes: ToolClasses | None = None,
    notes: list[tuple[str, str]] | None = None,
) -> tuple[list[tuple[str, str]], dict[str, int]]:
    """Apply the reader rule to every agent profile (spec, compiled or lean runtime view) and
    every context manifest found under ``paths`` (files, or directories searched through git).

    Returns ``([(file, problem)], {"profile": n, "manifest": m})``; ``notes``, when given, receives
    ``(file, warning)`` for every deprecated grant (:func:`grant_notes`).  Schema negatives and frozen
    baselines are skipped; a named file that cannot be parsed is a problem, a discovered one is
    not (it is not an agent document).
    """
    import json

    import yaml

    problems: list[tuple[str, str]] = []
    counts = {"profile": 0, "manifest": 0}
    for raw in paths:
        root = Path(raw)
        if not root.exists():
            problems.append((str(root), "no such file or directory"))
            continue
        for f in _candidates(root):
            try:
                text = f.read_text(encoding="utf-8")
                docs = [json.loads(text)] if f.suffix == ".json" else list(yaml.safe_load_all(text))
            except (OSError, ValueError, yaml.YAMLError) as exc:
                if root.is_file():
                    problems.append((str(f), f"cannot parse: {exc}"))
                continue
            for doc in docs:
                kind = _kind(doc)
                if kind is None:
                    continue
                counts[kind] += 1
                check = profile_problems if kind == "profile" else manifest_problems
                problems += [(str(f), p) for p in check(doc, classes)]
                if notes is not None:
                    notes += [(str(f), n) for n in doc_notes(doc, classes)]
    return problems, counts
