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

Actors act only through the broker (checklist G-13, ADR-0030), and this applies to **every**
profile, reader or not: :func:`broker_problems` refuses a granted MCP server with a tool in a
``broker_only`` class (exec, file-write, credential) unless its catalog record says ``acts_via:
broker`` (its acting tools are broker calls: the broker gates, approves and audits each one), or
says ``acts_via: direct`` with a ``direct_reason``, carries a current human approve review and is
listed for the profile in the ceiling policy's ``direct_mcp`` (an exception the policy owner
makes per profile and server); a ``broker_only`` capability other than ``cap:broker``; and a tier
whose classes are ``broker_only`` (execute, privileged) without ``cap:broker``.
"""

from __future__ import annotations

import re
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
#: how a catalog server's acting tools reach the world (``acts_via``, mcp_server 1.1): through the
#: broker, or directly (an exception: a reason, a human approve review and a policy listing)
ACTS_VIA = ("broker", "direct")
#: the one acting grant a profile may hold: the broker's own capability (its tier needs it too)
BROKER_CAPABILITY = "cap:broker"
#: an id a message may quote: a profile or manifest id (``profile:<slug>``) as the schemas spell
#: it.  Messages reach stdout, stderr and CI logs, and a document under ``--grants`` is not
#: schema-checked first, so any other value (a token pasted into a grant list) is never quoted.
_ID = re.compile(r"(?:[a-z]+:)?[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
#: the rules a lint applies (``hnx agent lint --rule``): readers-cannot-act (G-03, with the
#: catalog's grant rules) and actors-act-via-broker (G-13)
READERS = "readers-cannot-act"
BROKER = "actors-act-via-broker"
RULES = (READERS, BROKER)


class ToolClasses:
    """The classification table: ``{mcp, capabilities, tiers}`` -> classes, plus the reader ban."""

    def __init__(
        self,
        doc: Mapping[str, Any],
        source: str = "tool classes",
        catalog: Mapping[str, Mapping[str, Any]] | None = None,
        catalog_source: str | None = None,
    ) -> None:
        #: per MCP server of the catalog the table was derived from: status, reason, data_tier,
        #: replaced_by and whether it reaches the internet (:func:`reaches_internet`)
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
        #: classes no profile may hold except through the broker (G-13)
        self.broker_only = frozenset(doc.get("broker_only") or ())
        self.table: dict[str, dict[str, tuple[str, ...]]] = {}
        unknown: set[str] = (set(self.reader_forbidden) | self.broker_only) - set(self.classes)
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
        if not self.broker_only:
            raise SpecError(
                f"{source}: 'broker_only' is empty (that would let any profile act directly)"
            )

    @classmethod
    def load(cls, path: str | Path | None = None, catalog: str | Path | None = None) -> ToolClasses:
        """The table at ``path`` (default: the packaged ``tool_classes.yml``), its ``mcp`` section
        always derived from the MCP catalog at ``catalog`` (default:
        :func:`homelabnext.mcp.servers.default_dir`, so a private overlay's catalog is used where
        its examples directory is).  A table with an ``mcp`` section of its own is refused: it
        would class servers, and skip the catalog's status and data-tier rules, by hand; so is
        one whose ``reader_forbidden`` or ``broker_only`` leaves out a class the packaged table
        lists."""
        import yaml

        p = Path(path) if path else DEFAULT_CLASSES
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(doc, Mapping):
            return cls(doc, source=str(p))
        if "mcp" in doc:
            raise SpecError(
                f"{p}: has an mcp section; MCP servers are classed only by the MCP catalog "
                "(its records' tools), so remove it (hnx mcp catalog classes shows the derived one)"
            )
        if p.resolve() != DEFAULT_CLASSES.resolve():
            packaged = yaml.safe_load(DEFAULT_CLASSES.read_text(encoding="utf-8")) or {}
            lost = sorted(
                set(packaged.get("reader_forbidden") or ()) - set(doc.get("reader_forbidden") or ())
            )
            if lost:
                raise SpecError(
                    f"{p}: reader_forbidden leaves out {lost}, which the packaged table forbids a "
                    "reader (a table may forbid more, never less)"
                )
            lost = sorted(
                set(packaged.get("broker_only") or ()) - set(doc.get("broker_only") or ())
            )
            if lost:
                raise SpecError(
                    f"{p}: broker_only leaves out {lost}, which the packaged table lets a profile "
                    "hold only through the broker (a table may forbid more, never less)"
                )
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
        review_policy = _review_policy(cat)
        meta = {
            sid: {
                "status": rec.get("status"),
                "reason": rec.get("reason"),
                "data_tier": rec.get("data_tier"),
                "replaced_by": rec.get("replaced_by"),
                "internet": reaches_internet(rec),
                "acts_via": rec.get("acts_via"),
                "direct_reason": bool(rec.get("direct_reason")),
                # only a direct server's exception needs it, so only those are evaluated
                "human_approved": rec.get("acts_via") == "direct"
                and human_approved(rec, review_policy),
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


def _review_policy(cat: Any) -> Any:
    """The review policy beside the catalog (``review-policy.yml``), or None; an unreadable one is
    None too, so a human review counts only as ``kind: human`` from a non-``agent:`` identity
    (``hnx mcp catalog check`` reports the policy itself)."""
    from homelabnext.mcp import servers
    from homelabnext.reviews import ReviewError

    try:
        return servers.default_policy(cat)
    except (ReviewError, OSError):
        return None


def human_approved(rec: Mapping[str, Any], review_policy: Any = None) -> bool:
    """The record carries a passing ``kind: human``, ``role: approve`` review of its current
    content (a review of an earlier content does not count), from a human reviewer of
    ``review_policy`` when one is given."""
    from homelabnext.mcp import servers
    from homelabnext.reviews import evaluate

    ev = evaluate(
        rec.get("reviews"),
        author=rec.get("author"),
        digest=servers.record_digest(rec),
        artefact=servers.ARTEFACT,
        state=str(rec.get("status")),
        policy=review_policy,
    )
    return any(r.get("role") == "approve" and r.get("kind") == "human" for r in ev.current)


def reaches_internet(rec: Mapping[str, Any]) -> bool:
    """A catalog record sends what it is given out of the lab: a hosted server (the vendor's), or
    one whose ``egress`` names ``internet``."""
    egress = rec.get("egress")
    return rec.get("runtime") == "hosted" or (isinstance(egress, list) and "internet" in egress)


@cache
def default_classes() -> ToolClasses:
    return ToolClasses.load()


def table_vocabulary(path: str | Path | None = None) -> list[str]:
    """The capability classes ``tool_classes.yml`` declares (without reading the catalog)."""
    import yaml

    doc = yaml.safe_load(Path(path or DEFAULT_CLASSES).read_text(encoding="utf-8")) or {}
    return sorted((doc.get("classes") or {}) if isinstance(doc, Mapping) else ())


def table_broker_only(path: str | Path | None = None) -> list[str]:
    """The classes ``tool_classes.yml`` lets a profile hold only through the broker."""
    import yaml

    doc = yaml.safe_load(Path(path or DEFAULT_CLASSES).read_text(encoding="utf-8")) or {}
    return sorted((doc.get("broker_only") or ()) if isinstance(doc, Mapping) else ())


def table_capabilities(path: str | Path | None = None) -> list[str]:
    """The ``cap:`` ids ``tool_classes.yml`` classifies."""
    import yaml

    doc = yaml.safe_load(Path(path or DEFAULT_CLASSES).read_text(encoding="utf-8")) or {}
    caps = doc.get("capabilities") if isinstance(doc, Mapping) else None
    return sorted(caps or ())


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
    who = _shown(who)
    problems: list[str] = []
    for at, name in _entries(grants.get("mcp")):
        if classes.catalog is None:
            if classes.classify("mcp", name) is None:
                problems.append(
                    f"{who} names an unknown MCP server (mcp entry {at}), which is not in "
                    f"{classes.source} (grant a catalog id)"
                )
            continue
        meta = classes.catalog.get(name)
        if meta is None:
            problems.append(
                f"{who} names an unknown MCP server (mcp entry {at}), which is not in "
                f"{classes.catalog_source} (add a record, or grant a catalog id)"
            )
            continue
        status = meta.get("status")
        if status == "retired":
            problems.append(
                f"{who} is granted MCP server {name!r}, which is retired (its record's reason "
                "says why)"
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
                f"{who} may send its context to the cloud (its data_tier is not local-only) "
                f"but is granted MCP server {name!r}, whose data is local-only"
            )
    return problems


def grant_notes(
    grants: Mapping[str, Any], classes: ToolClasses | None = None, who: str = "profile"
) -> list[str]:
    """Warnings, not refusals: every granted MCP server that is ``deprecated``, and the server to
    grant instead (``replaced_by``).  The record's free-text ``reason`` is not repeated: it is
    a value, and a message reaches logs."""
    classes = classes or default_classes()
    who = _shown(who)
    out: list[str] = []
    for name in _names(grants.get("mcp")):
        meta = (classes.catalog or {}).get(name) or {}
        if meta.get("status") == "deprecated":
            instead = meta.get("replaced_by")
            out.append(
                f"{who} is granted MCP server {name!r}, which is deprecated (its record's reason "
                "says why)" + (f"; grant {instead!r} instead" if instead else "")
            )
    return out


def reader_problems(
    grants: Mapping[str, Any], classes: ToolClasses | None = None, who: str = "profile"
) -> list[str]:
    """Every grant a reader may not hold (empty list = an acceptable reader).

    ``grants`` has ``mcp``, ``capabilities`` and optionally ``tier``.
    """
    classes = classes or default_classes()
    who = _shown(who)
    problems: list[str] = []
    wanted: list[tuple[str, str, str, str]] = [
        *(("mcp", "mcp server", n, f"mcp entry {at}") for at, n in _entries(grants.get("mcp"))),
        *(("capabilities", "capability", n, f"capabilities entry {at}")
          for at, n in _entries(grants.get("capabilities"))),
    ]  # fmt: skip
    if grants.get("tier") is not None:
        wanted.append(("tiers", "tier", str(grants["tier"]), "its tier"))
    for kind, label, name, at in wanted:
        got = classes.classify(kind, name)
        if got is None:
            problems.append(
                f"{who} reads untrusted content but holds an unknown {label} ({at}), which is "
                f"not classified in {classes.source} (unknown is refused for a reader)"
            )
            continue
        bad = sorted(set(got) & classes.reader_forbidden)
        if bad:
            problems.append(
                f"{who} reads untrusted content but holds {label} {name!r} ({', '.join(bad)}): "
                "readers cannot act; split it into a reader and an actor"
            )
    return problems


def broker_problems(
    grants: Mapping[str, Any],
    classes: ToolClasses | None = None,
    who: str = "profile",
    direct: Iterable[str] | None = None,
) -> list[str]:
    """Rule ``actors-act-via-broker`` (checklist G-13, ADR-0030), for ANY profile: every grant
    that would let it act (a ``broker_only`` class) other than through the broker.

    ``grants`` has ``mcp``, ``capabilities`` and optionally ``tier``.  ``direct`` is the ceiling
    policy's ``direct_mcp`` for this profile (:meth:`CeilingPolicy.direct_mcp`); ``None`` (no
    policy at hand) allows no ``acts_via: direct`` server.  An MCP server the catalog does not
    hold is left to :func:`grant_problems`, which refuses it for every profile.
    """
    classes = classes or default_classes()
    who = _shown(who)
    only = classes.broker_only
    problems: list[str] = []
    for _, name in _entries(grants.get("mcp")):
        got = classes.classify("mcp", name)
        acting = sorted(set(got or ()) & only)
        if not acting:
            continue
        meta = (classes.catalog or {}).get(name)
        if meta is None:
            problems.append(
                f"{who} is granted MCP server {name!r} ({', '.join(acting)}), and no catalog "
                "record says how it acts (acts_via): agents act only through the broker"
            )
            continue
        via = meta.get("acts_via")
        if via == "broker":
            continue
        if via != "direct":
            problems.append(
                f"{who} is granted MCP server {name!r} ({', '.join(acting)}), whose record "
                "does not say acts_via: broker: agents act only through the broker"
            )
            continue
        missing = []
        if not meta.get("direct_reason"):
            missing.append("a direct_reason on its record")
        if not meta.get("human_approved"):
            missing.append("a current human approve review on its record")
        if direct is None:
            missing.append(
                "a ceiling policy listing it in direct_mcp for this profile (none given)"
            )
        elif name not in set(direct):
            missing.append("the ceiling policy's direct_mcp entry for this profile")
        if missing:
            problems.append(
                f"{who} is granted MCP server {name!r} ({', '.join(acting)}), which acts "
                f"directly (acts_via: direct) without {' and '.join(missing)}: agents act only "
                "through the broker"
            )
    caps = set(_names(grants.get("capabilities")))
    for at, name in _entries(grants.get("capabilities")):
        if name == BROKER_CAPABILITY:
            continue
        got = classes.classify("capabilities", name)
        if got is None:  # unknown is never assumed not to act (the tier rule's own wording)
            problems.append(
                f"{who} holds an unknown capability (capabilities entry {at}), which is not "
                f"classified in {classes.source} (unknown is never assumed not to act)"
            )
            continue
        acting = sorted(set(got) & only)
        if acting:
            problems.append(
                f"{who} holds capability {name!r} ({', '.join(acting)}): agents act only "
                f"through the broker; {BROKER_CAPABILITY} is the one acting capability (ask it "
                "for a named action)"
            )
    if grants.get("tier") is not None:
        tier = str(grants["tier"])
        got = classes.classify("tiers", tier)
        if got is None:
            problems.append(
                f"{who} holds an unknown tier (its tier), which is not classified in "
                f"{classes.source} (unknown is never assumed not to act)"
            )
        elif set(got) & only and BROKER_CAPABILITY not in caps:
            problems.append(
                f"{who} holds tier {tier!r} ({', '.join(sorted(set(got) & only))}) without "
                f"{BROKER_CAPABILITY}: an acting tier acts only through the broker"
            )
    return problems


def is_reader(doc: Mapping[str, Any]) -> bool:
    """A profile or spec reads untrusted content unless it says ``reads_untrusted: false``."""
    return doc.get("reads_untrusted", True) is not False


def profile_problems(
    doc: Mapping[str, Any],
    classes: ToolClasses | None = None,
    policy: Any = None,
    rules: Iterable[str] = RULES,
) -> list[str]:
    """Catalog problems (:func:`grant_problems`, every profile), reader problems (readers) and
    broker problems (:func:`broker_problems`, every profile) for any agent-profile shape: a spec,
    a compiled ``agent/profile`` (grants under ``grants``) or the lean ``platform/agent_profile``
    (``mcp``/``capabilities`` at the top).  ``policy`` (a :class:`CeilingPolicy`) supplies the
    profile's ``direct_mcp``; without one no ``acts_via: direct`` server is allowed.  ``rules``
    picks :data:`READERS` (catalog and reader rules) and/or :data:`BROKER`.
    """
    if "reads_untrusted" in doc and not isinstance(doc["reads_untrusted"], bool):
        return ["reads_untrusted must be true or false"]
    grants = doc.get("grants") if isinstance(doc.get("grants"), Mapping) else doc
    who = str(doc.get("id", "profile"))
    tier = doc.get("data_tier") if isinstance(doc.get("data_tier"), str) else None
    problems: list[str] = []
    if READERS in rules:
        problems += grant_problems(grants, classes, who, tier)
        if is_reader(doc):
            problems += reader_problems(grants, classes, who)
    if BROKER in rules:
        direct = policy.direct_mcp(who) if policy is not None else None
        problems += broker_problems(grants, classes, who, direct)
    return problems


def manifest_problems(
    doc: Mapping[str, Any],
    classes: ToolClasses | None = None,
    policy: Any = None,
    rules: Iterable[str] = RULES,
) -> list[str]:
    """A context manifest's ``tools`` (MCP servers) must be grantable catalog servers that act,
    if at all, through the broker (a manifest is bound to a persona, not to a profile, so no
    policy names a direct exception for it); and a manifest with any ``source: input`` section
    feeds untrusted content to its agent, so its tools obey the reader rule too."""
    sections = doc.get("sections") or []
    who = f"manifest {doc.get('id', '?')}"
    tools = {"mcp": doc.get("tools") or []}
    problems: list[str] = []
    if READERS in rules:
        problems += grant_problems(tools, classes, who)
        if any(isinstance(s, Mapping) and s.get("source") == "input" for s in sections):
            problems += reader_problems(tools, classes, who)
    if BROKER in rules:
        problems += broker_problems(tools, classes, who)
    return problems


def doc_notes(doc: Mapping[str, Any], classes: ToolClasses | None = None) -> list[str]:
    """:func:`grant_notes` for a profile (any shape) or a context manifest (its ``tools``)."""
    if _kind(doc) == "manifest":
        return grant_notes({"mcp": doc.get("tools") or []}, classes, f"manifest {doc.get('id')}")
    grants = doc.get("grants") if isinstance(doc.get("grants"), Mapping) else doc
    return grant_notes(grants, classes, str(doc.get("id", "profile")))


def _names(raw: Any) -> list[str]:
    return [n for _, n in _entries(raw)]


def _entries(raw: Any) -> list[tuple[int, str]]:
    """``(position, name)`` of each distinct name of a grant list, by name; the position (from
    1, the first occurrence) is how a message points at a name it may not quote."""
    if raw is None:
        return []
    if isinstance(raw, str) or not isinstance(raw, Iterable):
        return [(1, str(raw))]
    first: dict[str, int] = {}
    for i, x in enumerate(raw, 1):
        first.setdefault(str(x), i)
    return sorted(((i, n) for n, i in first.items()), key=lambda e: e[1])


def _shown(who: str) -> str:
    """A profile or manifest label as a message may print it: ``profile``/``manifest`` with an id
    that is an id (:data:`_ID`), else the kind alone (the id is not a name, so not quoted)."""
    from homelabnext.mcp.credentials import looks_secret

    kind, _, ident = who.rpartition(" ")
    if _ID.fullmatch(ident) and len(ident) <= 80 and not looks_secret(ident.split(":")[-1]):
        return who
    return f"{kind or 'a profile'} whose id is not an id"


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
    *,
    policy: Any = None,
    rules: Iterable[str] = RULES,
) -> tuple[list[tuple[str, str]], dict[str, int]]:
    """Apply the reader rule and the broker rule (``rules``: :data:`RULES`) to every agent
    profile (spec, compiled or lean runtime view) and every context manifest found under
    ``paths`` (files, or directories searched through git); ``policy`` supplies each profile's
    ``direct_mcp`` (without one no ``acts_via: direct`` server is allowed).

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
                    from homelabnext.mcp.credentials import reason

                    problems.append((str(f), f"cannot parse: {reason(exc)}"))
                continue
            for doc in docs:
                kind = _kind(doc)
                if kind is None:
                    continue
                counts[kind] += 1
                check = profile_problems if kind == "profile" else manifest_problems
                problems += [(str(f), p) for p in check(doc, classes, policy, rules)]
                if notes is not None:
                    notes += [(str(f), n) for n in doc_notes(doc, classes)]
    return problems, counts
