# SPDX-License-Identifier: Apache-2.0
"""Workflow packs on disk: loading, schema validation, the pack digest, discovery in git.

A *workflow pack* is a YAML or JSON file whose top level has ``pack``, ``trigger`` and ``steps``
(``schemas/workflows/pack.schema.json``).  Files under a ``negative/`` or ``_frozen/`` directory,
and everything under ``schemas/`` (contract instances, checked by ``tools/schema_check.py``), are
not packs.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable
from functools import cache
from pathlib import Path
from typing import Any

from homelabnext import paths
from homelabnext.agent.digest import digest_of

PACK_SUFFIXES = (".yml", ".yaml", ".json")
SKIP_PARTS = ("negative", "_frozen")
SKIP_TOP = ("schemas",)
_SCHEMA_DIRS = ("ids", "broker", "workflows")


class WorkflowError(Exception):
    """The validator could not run: bad input (exit 2) or no git to enumerate packs (exit 100)."""

    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- documents
def _yaml_loader():
    import yaml

    class _StrLoader(yaml.SafeLoader):
        """Timestamps stay strings: a pack is JSON data, and its digest must not depend on YAML."""

    _StrLoader.yaml_implicit_resolvers = {
        k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
        for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    return _StrLoader


def load_doc(path: Path) -> Any:
    """Parse a pack, deploy manifest or broker manifest (YAML timestamps kept as strings)."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise WorkflowError(f"{path}: unreadable: {exc}") from exc
    try:
        if path.suffix == ".json":
            return json.loads(text)
        import yaml

        return yaml.load(text, Loader=_yaml_loader())  # a SafeLoader subclass
    except Exception as exc:
        raise WorkflowError(f"{path}: does not parse: {exc}") from exc


def is_pack(doc: Any) -> bool:
    return isinstance(doc, dict) and all(k in doc for k in ("pack", "trigger", "steps"))


def pack_digest(doc: Any) -> str:
    """``sha256:<hex>`` of the canonical JSON of the whole pack, fixtures included.

    The deploy manifest pins this value, so a deployed pack is byte-for-byte (canonically) the
    pack that was validated; comments and key order do not change it, any value does.
    """
    return digest_of(doc)


@cache
def _registry():
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    reg = Registry()
    base = paths.schemas_dir()
    for d in _SCHEMA_DIRS:
        for f in sorted((base / d).glob("*.json")):
            doc = json.loads(f.read_text(encoding="utf-8"))
            reg = reg.with_resource(
                doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
            )
    return reg


@cache
def _validator(directory: str, name: str):
    from jsonschema import Draft202012Validator

    f = paths.schema_file(directory, f"{name}.schema.json")
    return Draft202012Validator(json.loads(f.read_text("utf-8")), registry=_registry())


def schema_errors(directory: str, name: str, doc: Any) -> list[str]:
    """Errors of ``doc`` against ``schemas/<directory>/<name>.schema.json`` (empty = valid)."""
    try:
        v = _validator(directory, name)
    except ImportError as exc:  # pragma: no cover - only without the core extra
        raise WorkflowError(
            "hnx workflows needs jsonschema: pip install 'homelabnext[core]'"
        ) from exc
    return [
        f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:300]}"
        for e in sorted(v.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    ]


# ---------------------------------------------------------------- discovery
def git_files(root: Path, *args: str) -> list[str]:
    try:
        res = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise WorkflowError(f"cannot list workflow packs: {exc}", 100) from exc
    if res.returncode != 0:
        raise WorkflowError(f"cannot list workflow packs: {res.stderr.strip()}", 100)
    return [p for p in res.stdout.split("\0") if p]


def _candidate(rel: str) -> bool:
    parts = Path(rel).parts
    return (
        rel.endswith(PACK_SUFFIXES)
        and not any(p in SKIP_PARTS for p in parts)
        and parts[0] not in SKIP_TOP
    )


def _pack_or_none(path: Path) -> Any:
    """The document when ``path`` is a pack.  Files that never mention the three keys are not
    parsed, so the scan stays cheap and unrelated broken files remain other gates' concern."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if not all(k in text for k in ("pack", "trigger", "steps")):
        return None
    doc = load_doc(path)
    return doc if is_pack(doc) else None


def discover(root: Path) -> tuple[list[Path], list[Path]]:
    """``(tracked, untracked)`` packs under ``root`` (untracked = not ignored, not yet added)."""
    tracked = [root / p for p in git_files(root, "--cached") if _candidate(p)]
    others = [root / p for p in git_files(root, "--others", "--exclude-standard") if _candidate(p)]
    return (
        [p for p in tracked if p.is_file() and _pack_or_none(p) is not None],
        [p for p in others if p.is_file() and _pack_or_none(p) is not None],
    )


def expand(paths_: Iterable[Path]) -> list[Path]:
    """Explicit files as given; a directory contributes the packs inside it."""
    out: list[Path] = []
    for p in paths_:
        if p.is_dir():
            found = sorted(f for f in p.rglob("*") if f.suffix in PACK_SUFFIXES and f.is_file())
            out += [f for f in found if _pack_or_none(f) is not None]
        elif p.is_file():
            out.append(p)
        else:
            raise WorkflowError(f"{p}: no such file or directory")
    return out
