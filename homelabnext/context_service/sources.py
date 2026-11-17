# SPDX-License-Identifier: Apache-2.0
"""Configured git sources: fetched read-only at their ref, then turned into labelled documents.

**Fetch.**  Each source is fetched into a fresh sibling directory (``<sources>/.<name>.new``):
``git init``, ``git fetch --depth 1 <url> <ref>`` (a branch or tag is tracked, a 40-hex commit is
pinned; git's protocol v2 fetches either), ``git checkout --detach FETCH_HEAD`` with symlinks
written as plain files.  Only when that succeeded is it renamed into place, the old checkout moved
aside first and removed after: a failed fetch leaves the last good checkout untouched.  Nothing in
a checkout is ever executed (no hook runs on fetch or a detached checkout).  A credential travels
in an ``http.extraHeader`` set through git's environment, never in an argument or the URL.

**Documents.**  ``files``: one document per file the source's globs match, id
``<kind>:<source>/<path>``.  ``yaml-records``: one per record of a YAML list (a register such as a
lessons file), id ``<kind>:<source>/<record id>``, content the record's fields as ``key: value``
lines.  **TLP** (ADR-0033): every item takes the source's declared label, raised to the strictest
marker or ``tlp`` field it carries; a looser one is kept only with ``honour_item_labels``
(:func:`homelabnext.tlp.item_label`).

**Removal is guarded** (:func:`safe_remove`): a path is removed only when it resolves, without a
symlink, strictly inside the sources directory at least three components deep.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from homelabnext import _yaml
from homelabnext import tlp as _tlp
from homelabnext.context.model import MAX_CONTENT_CHARS, Document

from .config import Source

__all__ = ["Collected", "SourceError", "collect", "safe_remove", "sync"]

_ID_PART = re.compile(r"[^\s*]{1,400}\Z")
_HEADING = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


class SourceError(Exception):
    """A source could not be fetched or read; the message names the source, never a credential."""


@dataclass(frozen=True)
class Collected:
    documents: tuple[tuple[Document, _tlp.Label], ...]
    skipped: int  # files or records that cannot be a document (a name with a space, too large)


def safe_remove(path: Path, root: Path) -> None:
    """Remove ``path`` (a tree) only when it is safely inside ``root``; else ``SourceError``."""
    root_r = root.resolve()
    if path.is_symlink():
        raise SourceError("refusing to remove a symlink")
    target = path.resolve()
    if target == Path(target.anchor) or len(target.parts) < 4 or len(root_r.parts) < 3:
        raise SourceError("refusing to remove a shallow path")
    if ".." in path.parts:
        raise SourceError("refusing a path with ..")
    if target == root_r or not target.is_relative_to(root_r):
        raise SourceError("refusing to remove a path outside the sources directory")
    if target.exists():
        shutil.rmtree(target)


def _git_env(source: Source, env: Mapping[str, str], home: Path) -> dict[str, str]:
    out = {
        "PATH": env.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(home),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ASKPASS": "/bin/false",
        "LC_ALL": "C",
    }
    pairs = [("core.symlinks", "false"), ("core.hooksPath", os.devnull)]
    if source.credential_env:
        value = env.get(source.credential_env, "")
        if not value or any(c.isspace() for c in value):
            raise SourceError(f"source {source.name}: its credential is not set")
        if source.credential_scheme == "basic":
            value = "Basic " + base64.b64encode(value.encode()).decode()
        else:
            value = "Bearer " + value
        pairs.append(("http.extraHeader", f"Authorization: {value}"))
    out["GIT_CONFIG_COUNT"] = str(len(pairs))
    for i, (k, v) in enumerate(pairs):
        out[f"GIT_CONFIG_KEY_{i}"] = k
        out[f"GIT_CONFIG_VALUE_{i}"] = v
    return out


Runner = Callable[..., subprocess.CompletedProcess]


def sync(
    source: Source,
    root: Path,
    *,
    env: Mapping[str, str],
    git: str = "git",
    timeout: float = 600.0,
    runner: Runner = subprocess.run,
) -> tuple[Path, str]:
    """Fetch ``source`` into ``root/<name>``; returns the checkout and its commit."""
    root.mkdir(parents=True, exist_ok=True)
    staging, aside, final = (
        root / f".{source.name}.new",
        root / f".{source.name}.old",
        root / source.name,
    )
    for p in (staging, aside):
        if p.exists() or p.is_symlink():
            safe_remove(p, root)
    staging.mkdir()
    genv = _git_env(source, env, staging)
    url = source.url
    if url.startswith("/"):
        url = "file://" + url
    extra: list[str] = []
    if url.startswith("file://"):
        # a local mirror (allow_file_sources): another user's repository is "dubious" to git,
        # and safe.directory is read only from a protected (here: the run's own global) file
        extra = ["-c", "protocol.file.allow=always"]
        trust = root / ".gitconfig-local"
        trust.write_text("[safe]\n\tdirectory = *\n", encoding="utf-8")
        genv["GIT_CONFIG_GLOBAL"] = str(trust)

    def run(*args: str) -> str:
        try:
            r = runner(
                [git, *extra, "-C", str(staging), *args],
                env=genv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SourceError(
                f"source {source.name}: git {args[0]} failed ({type(exc).__name__})"
            ) from exc
        if r.returncode != 0:
            why = (r.stderr or "").strip().splitlines()
            tail = why[-1][:200] if why else ""
            raise SourceError(f"source {source.name}: git {args[0]} exited {r.returncode} {tail}")
        return r.stdout

    try:
        run("init", "--quiet")
        run("fetch", "--quiet", "--depth", "1", "--no-tags", url, source.ref)
        run("checkout", "--quiet", "--detach", "FETCH_HEAD")
        commit = run("rev-parse", "HEAD").strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
            raise SourceError(f"source {source.name}: no commit after the fetch")
        if re.fullmatch(r"[0-9a-f]{40}", source.ref) and commit != source.ref:
            raise SourceError(f"source {source.name}: the pinned commit was not what was fetched")
    except BaseException:
        safe_remove(staging, root)
        raise
    if final.exists() or final.is_symlink():
        final.rename(aside)  # a symlink is moved aside, never followed
    staging.rename(final)
    if aside.exists() or aside.is_symlink():
        if aside.is_symlink():
            aside.unlink()
        else:
            safe_remove(aside, root)
    return final, commit


def _carried(text: str) -> list[_tlp.Label]:
    return _tlp.markers([text])


def _label(source: Source, carried: list[_tlp.Label], *field: Any) -> _tlp.Label:
    """``field``: the item's own ``tlp`` value when it has one (``null`` there is ``red``)."""
    if field:
        return _tlp.item_label(source.label, field[0], honour_item_labels=source.honour_item_labels)
    if carried:
        return _tlp.item_label(
            source.label, _tlp.strictest(carried), honour_item_labels=source.honour_item_labels
        )
    return source.label


def _flat(value: Any) -> str:
    if isinstance(value, list):
        return "\n".join(f"- {_flat(v)}" for v in value)
    if isinstance(value, dict):
        return "\n".join(f"{k}: {_flat(v)}" for k, v in value.items())
    return "" if value is None else str(value)


def _files(checkout: Path, source: Source) -> list[Path]:
    base = checkout.resolve()
    seen: dict[str, Path] = {}
    for g in source.paths:
        for p in sorted(checkout.glob(g)):
            if ".git" in p.relative_to(checkout).parts:
                continue
            if p.is_symlink() or not p.is_file():
                continue
            if not p.resolve().is_relative_to(base):
                continue
            seen.setdefault(p.relative_to(checkout).as_posix(), p)
    return [seen[k] for k in sorted(seen)]


def collect(checkout: Path, source: Source) -> Collected:
    """The source's documents with their labels; ``SourceError`` when it yields none."""
    out: list[tuple[Document, _tlp.Label]] = []
    skipped = 0
    for f in _files(checkout, source):
        rel = f.relative_to(checkout).as_posix()
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        if source.format == "files":
            if not _ID_PART.match(rel) or len(text) > MAX_CONTENT_CHARS or not text.strip():
                skipped += 1
                continue
            m = _HEADING.search(text)
            title = m[1] if m else rel.rsplit("/", 1)[-1]
            doc = Document(f"{source.kind}:{source.name}/{rel}", source.kind, text, title, rel)
            out.append((doc, _label(source, _carried(text))))
            continue
        try:
            loaded = _yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SourceError(f"source {source.name}: {rel} is not YAML") from exc
        records = loaded.get(source.records_key) if isinstance(loaded, dict) else loaded
        if source.records_key and not isinstance(loaded, dict):
            records = None
        if not isinstance(records, list):
            raise SourceError(
                f"source {source.name}: {rel} holds no list"
                + (f" under {source.records_key}" if source.records_key else "")
            )
        for rec in records:
            rid = rec.get(source.id_field) if isinstance(rec, dict) else None
            if rid is None or not _ID_PART.match(str(rid)):
                skipped += 1
                continue
            title = str(rec.get(source.title_field) or rid)
            body = "\n".join(
                f"{k}: {_flat(v)}" for k, v in rec.items() if k not in (source.title_field,)
            )
            content = f"{title}\n\n{body}\n"
            if len(content) > MAX_CONTENT_CHARS:
                skipped += 1
                continue
            status = rec.get("status")
            doc = Document(
                f"{source.kind}:{source.name}/{rid}",
                source.kind,
                content,
                title,
                rel,
                status if isinstance(status, str) else "",
            )
            own = (rec["tlp"],) if "tlp" in rec else ()
            out.append((doc, _label(source, _carried(content), *own)))
    if not out:
        raise SourceError(f"source {source.name}: its paths matched no document")
    if len(out) > source.max_documents:
        raise SourceError(f"source {source.name}: more than {source.max_documents} documents")
    ids = [d.id for d, _ in out]
    if len(set(ids)) != len(ids):
        raise SourceError(f"source {source.name}: two items share an id")
    return Collected(tuple(out), skipped)
