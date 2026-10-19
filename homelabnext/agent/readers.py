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

The classification is data, not code: ``tool_classes.yml`` next to this module maps every MCP
server, capability and broker tier to capability classes and lists the classes a reader may not
hold.  A grant missing from that table is refused for a reader (unknown is never assumed safe).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from functools import cache
from pathlib import Path
from typing import Any

from .errors import SpecError

DEFAULT_CLASSES = Path(__file__).with_name("tool_classes.yml")
KINDS = ("mcp", "capabilities", "tiers")


class ToolClasses:
    """The classification table: ``{mcp, capabilities, tiers}`` -> classes, plus the reader ban."""

    def __init__(self, doc: Mapping[str, Any], source: str = "tool classes") -> None:
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
    def load(cls, path: str | Path | None = None) -> ToolClasses:
        import yaml

        p = Path(path) if path else DEFAULT_CLASSES
        return cls(yaml.safe_load(p.read_text(encoding="utf-8")) or {}, source=str(p))

    def classify(self, kind: str, name: str) -> tuple[str, ...] | None:
        """Classes of one grant, or ``None`` if the table does not know it."""
        return self.table[kind].get(name)


@cache
def default_classes() -> ToolClasses:
    return ToolClasses.load()


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
    """Reader problems for any agent-profile shape: a spec, a compiled ``agent/profile`` (grants
    under ``grants``) or the lean ``platform/agent_profile`` (``mcp``/``capabilities`` at the top).
    """
    if "reads_untrusted" in doc and not isinstance(doc["reads_untrusted"], bool):
        return ["reads_untrusted must be true or false"]
    if not is_reader(doc):
        return []
    grants = doc.get("grants") if isinstance(doc.get("grants"), Mapping) else doc
    return reader_problems(grants, classes, str(doc.get("id", "profile")))


def manifest_problems(doc: Mapping[str, Any], classes: ToolClasses | None = None) -> list[str]:
    """A context manifest with any ``source: input`` section feeds untrusted content to its
    agent, so its ``tools`` (MCP servers) obey the reader rule."""
    sections = doc.get("sections") or []
    if not any(isinstance(s, Mapping) and s.get("source") == "input" for s in sections):
        return []
    return reader_problems(
        {"mcp": doc.get("tools") or []}, classes, f"manifest {doc.get('id', '?')}"
    )


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
    paths: Iterable[str | Path], classes: ToolClasses | None = None
) -> tuple[list[tuple[str, str]], dict[str, int]]:
    """Apply the reader rule to every agent profile (spec, compiled or lean runtime view) and
    every context manifest found under ``paths`` (files, or directories searched through git).

    Returns ``([(file, problem)], {"profile": n, "manifest": m})``.  Schema negatives and frozen
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
    return problems, counts
