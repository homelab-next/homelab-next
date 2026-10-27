# SPDX-License-Identifier: Apache-2.0
"""The model evidence of a swap, read from the repository rather than assembled by a caller
(docs/modules.md, "Swap record 1.2"; ``hnx modules swap-check`` and ``swap-gate``).

:func:`from_git` builds the :class:`~homelabnext.modules.swap.ModelEvidence` a swap's
``model_roles`` legs are checked against.  **Everything that vouches for the new model is read
from the base commit, never from the change being checked**:

- the role table **before** (:data:`ROLES` at the base);
- the model store (:data:`STORE`), so the new binding's entry must already be on the base;
- the evaluation reports (:data:`REPORTS` and every ``*.json`` directly in :data:`EVALS`), so the
  report for the table after the rebind, its canary entries live, must already be on the base;
- the golden suites the report is checked with (:data:`SUITES`).

Only the role table **after** comes from the working tree, read like every loader input (no
symbolic link on its path, a regular file, capped, opened without blocking): it is what the
change proposes.  So a model is vetted in one change (the store entry and the live report, both
human-approve in ``hnx modules review-tier``) and rebound in a later one; a change cannot vouch
for itself.  What this does not prove: a report's ``live`` is the claim of whoever ran it, now a
claim a code owner reviewed; and the checking code is whatever is installed (CI runs it from a
checkout of the base, job ``trusted-gates``).

A base is resolved once to a commit (``rev-parse --verify --end-of-options REV^{commit}``) and
only that sha is used: an option-like value or a tree is refused.  ``require_live`` is policy, on
unless the caller says otherwise, and never the record's.  ``--report`` files (``extra_reports``)
are a local convenience; CI never passes one.

:func:`gate` is the CI check: when the role table differs from the base's, a swap record added or
changed under :data:`SWAPS` must cover it, its legs holding against that evidence.

Whatever cannot be read is :class:`EvidenceError`, never a missing table read as "no change".
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import weakref
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from homelabnext.models.store import Store, StoreError
from homelabnext.modules import loader as ld
from homelabnext.modules.swap import ModelEvidence
from homelabnext.registry.models import RoleTable, RoleTableError

__all__ = [
    "EVALS",
    "MAX_EVALS",
    "REPORTS",
    "ROLES",
    "STORE",
    "SUITES",
    "SWAPS",
    "EvidenceError",
    "changed_records",
    "from_git",
    "gate",
    "read_base",
    "read_head",
    "resolve_base",
]

#: the role table, relative to the repository root
ROLES = "examples/model_roles.json"
#: the model store the serving roles read, relative to the repository root
STORE = "examples/model-serving/model_store.json"
#: the committed evaluation report of the role table (make models-report)
REPORTS = ("examples/model_roles.eval.json",)
#: where a vetting change commits the live report for a proposed table (make models-eval)
EVALS = "examples/model-evals"
#: the most reports read from EVALS: more is refused, never truncated
MAX_EVALS = 64
#: the golden suites a report is checked with (homelabnext.golden.pins.DEFAULT_SUITES)
SUITES = ("homelabnext/golden/examples/classifier_smoke.yml",)
#: where a change keeps the swap record that covers its role-table change (swap-gate)
SWAPS = "examples/swaps"
_RECORD_SUFFIXES = (".json", ".yml", ".yaml")
_TIMEOUT = 60
_LS_TREE = re.compile(r"^(\d{6}) (\w+) ([0-9a-f]{40,64}) +(-|\d+)\t(.*)$", re.S)


class EvidenceError(ld.LoaderError):
    """An evidence input that cannot be read (the CLI's exit 2)."""


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), *args],
        capture_output=True,
        check=False,
        timeout=_TIMEOUT,
    )


def _rel(rel: str) -> str:
    if not rel or rel.startswith("/") or ".." in PurePosixPath(rel).parts:
        raise EvidenceError(f"{rel!r}: not a path inside the repository")
    return PurePosixPath(rel).as_posix()


def resolve_base(root: Path, base: str) -> str:
    """``base`` as the sha of a commit; anything else (empty, an option, a tree, unknown) is
    :class:`EvidenceError`."""
    if not base or not base.strip():
        raise EvidenceError("--base needs a commit (an empty value would skip the check)")
    r = _git(root, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{base}^{{commit}}")
    sha = r.stdout.decode("ascii", "replace").strip()
    if r.returncode or not re.fullmatch(r"[0-9a-f]{40,64}", sha):
        raise EvidenceError(f"--base {base!r}: not a commit here")
    return sha


def _ls(root: Path, sha: str, rel: str) -> list[tuple[str, str, str, str, str]]:
    r = _git(root, "ls-tree", "-l", "-z", sha, "--", rel)
    if r.returncode:
        raise EvidenceError(f"git ls-tree {sha[:12]} failed")
    rows = []
    for row in r.stdout.decode("utf-8", "replace").split("\0"):
        if row:
            m = _LS_TREE.match(row)
            if m is None:
                raise EvidenceError(f"git ls-tree {sha[:12]}: an unexpected row")
            rows.append(m.groups())
    return rows


def _blob(root: Path, sha: str, rel: str, row: tuple[str, str, str, str, str]) -> bytes:
    mode, kind, oid, size, _ = row
    where = f"{rel} at {sha[:12]}"
    if mode == "120000":
        raise EvidenceError(f"{where}: a symbolic link")
    if kind != "blob" or mode not in ("100644", "100755"):
        raise EvidenceError(f"{where}: not a regular file")
    if int(size) > ld.MAX_BYTES:
        raise EvidenceError(f"{where}: over {ld.MAX_BYTES} bytes")
    blob = _git(root, "cat-file", "blob", oid)
    if blob.returncode or len(blob.stdout) > ld.MAX_BYTES:
        raise EvidenceError(f"{where}: cannot be read")
    return blob.stdout


def read_base(root: Path, base: str, rel: str, *, missing_ok: bool = False) -> bytes | None:
    """The bytes of ``rel`` at commit ``base``: a regular blob of at most ``MAX_BYTES``.  Absent
    there is :class:`EvidenceError`, or None with ``missing_ok``."""
    rel = _rel(rel)
    sha = resolve_base(root, base)
    rows = _ls(root, sha, rel)
    if len(rows) != 1 or rows[0][4] != rel:
        if missing_ok and not rows:
            return None
        raise EvidenceError(f"{rel} is not in {sha[:12]}: the evidence is the base's")
    return _blob(root, sha, rel, rows[0])


def _base_dir(root: Path, sha: str, rel: str) -> list[tuple[str, bytes]]:
    """Every ``*.json`` directly in directory ``rel`` at ``sha`` (none when it is absent)."""
    rel = _rel(rel)
    rows = [r for r in _ls(root, sha, rel + "/") if r[4].endswith(".json")]
    if len(rows) > MAX_EVALS:
        raise EvidenceError(f"{rel} at {sha[:12]}: over {MAX_EVALS} reports")
    return [(r[4], _blob(root, sha, r[4], r)) for r in rows]


def read_head(root: Path, rel: str) -> bytes | None:
    """The working-tree bytes of ``rel``, or None when it is absent; a symbolic link anywhere on
    its path (the root included), or a file the loader would refuse, is :class:`EvidenceError`."""
    rel = _rel(rel)
    data = ld.read_tree_file(root, rel)
    if isinstance(data, str):
        raise EvidenceError(f"{rel}: {data}")
    return data


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
    evals: str | None = EVALS,
    suites: Sequence[str] = SUITES,
    extra_reports: Sequence[Path] = (),
    require_live: bool = True,
    workdir: Path | None = None,
) -> ModelEvidence:
    """The evidence for a swap from ``base`` to the working tree of ``root`` (see the module
    docstring).  ``store=None`` gives no store, which live evidence then refuses.  The base's
    suites are written under ``workdir`` (a private temporary directory, removed with the
    evidence, when None), since the report check reads them by path."""
    sha = resolve_base(root, base)
    before = _table(read_base(root, sha, roles), f"{roles} at {sha[:12]}")
    head = read_head(root, roles)
    if head is None:
        raise EvidenceError(f"{roles}: not in the working tree")
    after = _table(head, roles)
    model_store = None
    if store is not None:
        try:
            model_store = Store.from_dict(_json(read_base(root, sha, store), f"{store} at base"))
        except StoreError as exc:
            raise EvidenceError(f"{store} at {sha[:12]}: {exc}") from None
    found = []
    for rel in reports:
        data = read_base(root, sha, rel, missing_ok=True)
        if data is not None:
            found.append(_json(data, f"{rel} at {sha[:12]}"))
    if evals is not None:
        found += [_json(data, f"{rel} at {sha[:12]}") for rel, data in _base_dir(root, sha, evals)]
    for path in extra_reports:
        if path.is_symlink():
            raise EvidenceError(f"{path}: a symbolic link")
        try:
            found.append(_json(ld.read_bytes(path, follow=False), str(path)))
        except ld.Unreadable as exc:
            raise EvidenceError(f"{path}: {exc}") from None
    suite_bytes = [(rel, read_base(root, sha, rel)) for rel in suites]
    owned = workdir is None
    out = Path(tempfile.mkdtemp(prefix="hnx-swap-suites-")) if owned else workdir
    suite_paths = []
    for i, (rel, data) in enumerate(suite_bytes):
        d = out / str(i)  # the base's file under its own name: the report digests both
        d.mkdir(parents=True, exist_ok=True)
        p = d / PurePosixPath(rel).name
        p.write_bytes(data)
        suite_paths.append(p)
    ev = ModelEvidence(
        before=before,
        after=after,
        reports=found,
        suites=tuple(suite_paths),
        store=model_store,
        require_live=require_live,
    )
    if owned:
        weakref.finalize(ev, shutil.rmtree, out, True)
    return ev


def changed_records(root: Path, base: str) -> list[str]:
    """The swap records (``*.json``, ``*.yml``, ``*.yaml`` under :data:`SWAPS`) the working tree
    adds or changes against ``base``, untracked ones included; a removed record covers nothing."""
    sha = resolve_base(root, base)
    rels: set[str] = set()
    for args in (
        ("diff", "--no-renames", "--name-only", "-z", sha, "--", SWAPS),
        ("ls-files", "--others", "--exclude-standard", "-z", "--", SWAPS),
    ):
        r = _git(root, *args)
        if r.returncode:
            raise EvidenceError(f"git {args[0]} against {sha[:12]} failed")
        rels |= {x for x in r.stdout.decode("utf-8", "replace").split("\0") if x}
    return sorted(r for r in rels if r.endswith(_RECORD_SUFFIXES) and (root / r).exists())


def _roles_changed(before: RoleTable, after: RoleTable) -> list[str]:
    b, a = before.pins(), after.pins()
    return sorted(r for r in set(b) | set(a) if b.get(r) != a.get(r))


def gate(root: Path, base: str, *, roles: str = ROLES) -> tuple[list[str], str]:
    """(the problems, what was decided).  A role table that is the base's passes; a changed one
    needs at least one swap record added or changed under :data:`SWAPS`, and every such record
    must pass the schema and :func:`~homelabnext.modules.swap.model_role_problems` against the
    base's evidence (live required).  Module, site and migration checks are ``swap-check``'s."""
    from homelabnext.modules import swap as ms

    sha = resolve_base(root, base)
    head = read_head(root, roles)
    old = read_base(root, sha, roles, missing_ok=True)
    if head is None and old is None:
        return [], f"no {roles} at either end"
    if head is not None and old is not None and _json(head, roles) == _json(old, roles):
        return [], f"{roles} is unchanged since {sha[:12]}"
    with tempfile.TemporaryDirectory(prefix="hnx-swap-gate-") as tmp:
        ev = from_git(root, sha, roles=roles, workdir=Path(tmp))
        changed = _roles_changed(ev.before, ev.after)
        records = changed_records(root, sha)
        if not records:
            return [
                f"{roles} changes since {sha[:12]} (roles: {', '.join(changed) or 'none rebound'})"
                f" and no swap record under {SWAPS}/ in this change covers it: commit the record"
                " whose model_roles legs rebind them, after the store entry and the live report"
                f" are on the base ({STORE}, {EVALS}/)"
            ], "uncovered"
        schema = ld._schema("platform", "module_swap.schema.json")
        budget = ld.Budget()
        problems: list[str] = []
        for rel in records:
            if ld.path_has_symlink(root, rel):
                problems.append(f"{rel}: a symbolic link on its path")
                continue
            try:
                record = ld.load_input(root / rel, budget)
            except ld.Unreadable as exc:
                raise EvidenceError(f"{rel}: {exc}") from None
            errs = ld._errors(schema, record)
            if errs:
                problems += [f"{rel}: record: {e}" for e in errs]
                continue
            problems += [f"{rel}: {p}" for p in ms.model_role_problems(record, ev)]
        return problems, f"{len(records)} record(s) for roles {', '.join(changed) or 'none'}"
