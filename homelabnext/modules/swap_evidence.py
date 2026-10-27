# SPDX-License-Identifier: Apache-2.0
"""The model evidence of a swap, read from the repository rather than assembled by a caller
(docs/modules.md, "Swap record 1.2"; ``hnx modules swap-check``).

:func:`from_git` builds the :class:`~homelabnext.modules.swap.ModelEvidence` a swap's
``model_roles`` legs are checked against:

- the role table **before** is the one at the base commit (``git``), never a file the caller
  names: a table absent at the base, a symbolic link there, or a blob over
  :data:`~homelabnext.modules.loader.MAX_BYTES` is refused;
- the role table **after** is the one in the working tree at the same path, read like every
  loader input (no symbolic link on its path, a regular file, capped, opened without blocking);
- the model store and the evaluation reports are read from where the repository keeps them
  (:data:`STORE`, :data:`REPORTS`), the same way, plus any report the caller adds; a report is
  only a candidate: a leg pins the one it means by digest;
- ``require_live`` is policy, on unless the caller says otherwise, and never the record's.

Whatever cannot be read is :class:`EvidenceError`, never a missing table read as "no change".
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from homelabnext.models.store import Store, StoreError
from homelabnext.modules import loader as ld
from homelabnext.modules.review_tier import _linked
from homelabnext.modules.swap import ModelEvidence
from homelabnext.registry.models import RoleTable, RoleTableError

__all__ = ["REPORTS", "ROLES", "STORE", "EvidenceError", "from_git", "read_base", "read_head"]

#: the role table, relative to the repository root
ROLES = "examples/model_roles.json"
#: the model store the serving roles read, relative to the repository root
STORE = "examples/model-serving/model_store.json"
#: the evaluation reports a leg may pin: the committed fake's (make models-report) and the live
#: one kept with a model change (make models-eval); those absent are skipped
REPORTS = ("examples/model_roles.eval.json", "build/models/eval.json")
_TIMEOUT = 60
_LS_TREE = re.compile(r"^(\d{6}) (\w+) ([0-9a-f]{40,64}) +(-|\d+)\t")


class EvidenceError(ld.LoaderError):
    """An evidence input that cannot be read (the CLI's exit 2)."""


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, check=False, timeout=_TIMEOUT
    )


def _rel(rel: str) -> str:
    if not rel or rel.startswith("/") or ".." in Path(rel).parts:
        raise EvidenceError(f"{rel!r}: not a path inside the repository")
    return Path(rel).as_posix()


def read_base(root: Path, base: str, rel: str) -> bytes:
    """The bytes of ``rel`` at commit ``base``: a regular blob of at most ``MAX_BYTES``."""
    rel = _rel(rel)
    if not base or _git(root, "rev-parse", "--verify", "--quiet", f"{base}^{{tree}}").returncode:
        raise EvidenceError(f"--base {base!r}: not a commit here")
    r = _git(root, "ls-tree", "-l", "-z", base, "--", rel)
    if r.returncode:
        raise EvidenceError(f"git ls-tree {base} failed")
    rows = [x for x in r.stdout.decode("utf-8", "replace").split("\0") if x]
    m = _LS_TREE.match(rows[0]) if len(rows) == 1 else None
    if m is None or not rows[0].endswith("\t" + rel):
        raise EvidenceError(f"{rel} is not in {base}: the table before the swap is its base's")
    mode, kind, oid, size = m.groups()
    if mode == "120000":
        raise EvidenceError(f"{rel} at {base}: a symbolic link")
    if kind != "blob" or mode not in ("100644", "100755"):
        raise EvidenceError(f"{rel} at {base}: not a regular file")
    if int(size) > ld.MAX_BYTES:
        raise EvidenceError(f"{rel} at {base}: over {ld.MAX_BYTES} bytes")
    blob = _git(root, "cat-file", "blob", oid)
    if blob.returncode or len(blob.stdout) > ld.MAX_BYTES:
        raise EvidenceError(f"{rel} at {base}: cannot be read")
    return blob.stdout


def read_head(root: Path, rel: str) -> bytes | None:
    """The working-tree bytes of ``rel``, or None when it is absent; a symbolic link anywhere on
    its path, or a file the loader would refuse, is :class:`EvidenceError`."""
    rel = _rel(rel)
    if _linked(root, rel):
        raise EvidenceError(f"{rel}: a symbolic link on its path")
    p = root / rel
    if not p.exists():
        return None
    try:
        return ld.read_bytes(p, follow=False)
    except ld.Unreadable as exc:
        raise EvidenceError(f"{rel}: {exc}") from None


def _json(data: bytes, where: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EvidenceError(f"{where}: not valid JSON ({exc.__class__.__name__})") from None


def _table(data: bytes, where: str) -> RoleTable:
    try:
        return RoleTable.from_dict(_json(data, where))
    except RoleTableError as exc:
        raise EvidenceError(f"{where}: {exc}") from None


def from_git(
    root: Path,
    base: str,
    *,
    roles: str = ROLES,
    store: str | None = STORE,
    reports: Sequence[str] = REPORTS,
    extra_reports: Sequence[Path] = (),
    require_live: bool = True,
) -> ModelEvidence:
    """The evidence for a swap from ``base`` to the working tree of ``root`` (see the module
    docstring).  ``store=None`` gives no store, which live evidence then refuses."""
    before = _table(read_base(root, base, roles), f"{roles} at {base}")
    head = read_head(root, roles)
    if head is None:
        raise EvidenceError(f"{roles}: not in the working tree")
    after = _table(head, roles)
    model_store = None
    if store is not None:
        data = read_head(root, store)
        if data is None:
            raise EvidenceError(f"{store}: not in the working tree")
        try:
            model_store = Store.from_dict(_json(data, store))
        except StoreError as exc:
            raise EvidenceError(f"{store}: {exc}") from None
    found = []
    for rel in reports:
        data = read_head(root, rel)
        if data is not None:
            found.append(_json(data, rel))
    for path in extra_reports:
        if path.is_symlink():
            raise EvidenceError(f"{path}: a symbolic link")
        try:
            found.append(_json(ld.read_bytes(path, follow=False), str(path)))
        except ld.Unreadable as exc:
            raise EvidenceError(f"{path}: {exc}") from None
    return ModelEvidence(
        before=before, after=after, reports=found, store=model_store, require_live=require_live
    )
