# SPDX-License-Identifier: Apache-2.0
"""Open-format, leave-the-product exports for core capability fakes (ADR-0040 decision 6,
ADR-0008 decision 1).

An open-format export is the *leave the product* hook: a tree in a format the next product can
read, beside the database dump that restores the same product (ADR-0042 decision 2).  Each
adapter here wraps a slot's in-tree fake and exposes the
:class:`~conformance.protocols.migration.Migratable` shape, so the ``migration`` suite's
round-trip MUST (export, import into an empty fake, export again: equal manifest files) runs
against that adapter as evidence for that slot (``MIGRATION_PROOF`` in
``tests/modules/test_import_validation.py``).

The dump is always a tree under an empty directory plus the draft ``platform/export_manifest``
1.0 the ``homelabnext.modules.importcheck`` library writes; a reader is held to that manifest
exactly, so an exporter never writes what its peer must refuse (hard links, special files,
traversal paths).  ``import_`` delegates to the library, then atomically replaces the fake's
state when every file verified, so a refused import never leaves half the data behind.

The adapters are the leave-the-product analogue of IRIS/OpenProject JSON (cases, projects) and
of the records lane layout (records).  MISP/Synapse STIX (threat-intel, cti-graph,
ioc-enrichment) adds the ``stix`` format with ADR-0049, which is the ADR that registers those
slots; it is out of scope here.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any

from conformance.fakes.case_store import FakeCaseStore
from conformance.fakes.project_store import FakeProjectStore
from conformance.fakes.records_target import FakeRecordsTarget
from conformance.protocols.cases import Alert, Case
from conformance.protocols.migration import ImportRefused, Limits
from homelabnext.modules.importcheck import (
    build_manifest,
    check_manifest,
    copy_tree,
    read_tree,
)

__all__ = [
    "PortableCaseStore",
    "PortableProjectStore",
    "PortableRecordsTarget",
]


def _canonical_json(value: Any) -> bytes:
    """Canonical JSON for a round-trip-stable export: sorted keys, no spaces, trailing newline."""
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _empty(dest: Path) -> Path:
    """The library's ``export`` contract: ``dest`` exists and is empty."""
    dest = Path(dest)
    if not dest.is_dir():
        raise ValueError(f"export: destination {dest} is not a directory")
    if any(dest.iterdir()):
        raise ValueError("export: destination is not empty")
    return dest


def _refuse_bad_manifest(manifest: Mapping[str, Any], slot: str, fmt: str) -> None:
    """The library's checks that run before the tree is touched (declared format, totals, paths)
    so a refused import never changes anything, as the Migratable MUST requires."""
    problems = check_manifest(manifest, slot=slot, formats=(fmt,))
    if problems:
        raise ImportRefused(problems)


def _effective_limits(self_limits: Limits, caller: Limits | None) -> Limits:
    """``Migratable.import_`` MUST combine the caller's limits with the adapter's own."""
    return self_limits.tighten(caller) if caller is not None else self_limits


def _copy_regular_files(root: Path, dest: Path) -> None:
    """Byte-for-byte copy of every regular file under ``root`` into ``dest``.  Link and
    special-file entries are skipped (``build_manifest`` is then held to its own refusal rule
    over ``dest``, so an exporter never writes what its peer must refuse)."""
    root = Path(root).resolve()
    for top, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        rel_dir = os.path.relpath(top, root)
        for name in sorted(names):
            src = os.path.join(top, name)
            st = os.lstat(src)
            if st.st_mode & 0o170000 != 0o100000:  # regular file only
                continue
            if st.st_nlink != 1:
                continue
            target_dir = dest if rel_dir == "." else dest / rel_dir
            target_dir.mkdir(parents=True, exist_ok=True)
            with open(src, "rb") as sh, open(target_dir / name, "wb") as dh:
                dh.write(sh.read())


class PortableCaseStore(FakeCaseStore):
    """Cases fake with IRIS-aligned JSONL export/import (``jsonl`` format), beside a
    product-level database dump.

    The leave-the-product shape: ``alerts.jsonl`` + ``cases.jsonl`` + ``meta.json`` (the id
    counter, so a fresh ``create_alert`` after an import does not collide with a restored id).
    The lane for next-product onboarding (IRIS cases, DFIR-IRIS templates) is JSON lines; a
    reader streams them in and recreates the records.  A ``markdown-tree`` export is left for a
    follow-up (`ADR-0040 decision 6`).

    Loss documented (ADR-0008 decision 4): dedup keys live only inside the running process; the
    export is of the final alert states, so a de-duplicated alert history (every raw submission)
    is not recoverable from the dump.
    """

    slot = "cases"
    export_formats = ("jsonl",)

    def __init__(self) -> None:
        super().__init__()
        self._limits = Limits(max_files=10_000, max_bytes=1 << 24, max_file_bytes=1 << 20)

    # -- export ----------------------------------------------------------------------------

    def export(self, dest: Path, fmt: str) -> dict[str, Any]:
        if fmt not in self.export_formats:
            raise ValueError(f"{self.slot} does not export {fmt!r}")
        dest = _empty(Path(dest))
        alerts = b"".join(
            _canonical_json(asdict(a)) for a in sorted(self._alerts.values(), key=lambda x: x.id)
        )
        cases = b"".join(
            _canonical_json(asdict(c)) for c in sorted(self._cases.values(), key=lambda x: x.id)
        )
        meta = _canonical_json({"id_counter": self._n, "dedup": dict(sorted(self._dedup.items()))})
        (dest / "alerts.jsonl").write_bytes(alerts)
        (dest / "cases.jsonl").write_bytes(cases)
        (dest / "meta.json").write_bytes(meta)
        return build_manifest(dest, self.slot, fmt, self._limits)

    # -- import ----------------------------------------------------------------------------

    def import_(self, src: Path, manifest: Mapping[str, Any], limits: Limits | None = None) -> int:
        _refuse_bad_manifest(manifest, self.slot, self.export_formats[0])
        # read_tree stages every file in memory; a refusal leaves self untouched.
        staged = read_tree(
            Path(src),
            manifest,
            _effective_limits(self._limits, limits),
            slot=self.slot,
            formats=self.export_formats,
        )
        alerts = _parse_jsonl(staged.get("alerts.jsonl", b""))
        cases = _parse_jsonl(staged.get("cases.jsonl", b""))
        meta = json.loads(staged.get("meta.json", b"{}").decode("utf-8"))
        # swap state after everything parses
        self._alerts = {a["id"]: _mkalert(a) for a in alerts}
        self._cases = {c["id"]: _mkcase(c) for c in cases}
        self._dedup = dict(meta.get("dedup", {}))
        self._n = int(meta.get("id_counter", 0))
        return len(manifest["files"])


def _parse_jsonl(body: bytes) -> list[dict]:
    if not body:
        return []
    return [json.loads(line) for line in body.decode("utf-8").splitlines() if line.strip()]


def _mkalert(d: dict) -> Alert:
    return Alert(
        id=d["id"],
        source=d["source"],
        title=d["title"],
        severity=d["severity"],
        status=d["status"],
        count=d.get("count", 1),
        case_id=d.get("case_id"),
        reason=d.get("reason"),
    )


def _mkcase(d: dict) -> Case:
    return Case(
        id=d["id"],
        title=d["title"],
        status=d["status"],
        alert_ids=tuple(d.get("alert_ids", ())),
        notes=tuple(tuple(n) for n in d.get("notes", ())),
        resolution=d.get("resolution"),
        extra=dict(d.get("extra", {})),
    )


class PortableProjectStore(FakeProjectStore):
    """Projects fake with ``object-tree`` export/import.

    Leave-the-product shape: ``items/<uid>.json`` (one file per work item) + ``meta.json``.
    The library's ``MemoryBackend`` holds the canonical dict representation
    (``homelabnext.projects.store.doc_of``), and ``_backend._docs`` is reassigned atomically
    after every file parsed.

    Loss documented: the change feed's cursor (``changes_since``) is in-process and does not
    survive the export; a consumer must re-snapshot after a restore.
    """

    slot = "projects"
    export_formats = ("object-tree",)

    def __init__(self) -> None:
        super().__init__()
        self._limits = Limits(max_files=10_000, max_bytes=1 << 26, max_file_bytes=1 << 22)

    def export(self, dest: Path, fmt: str) -> dict[str, Any]:
        if fmt not in self.export_formats:
            raise ValueError(f"{self.slot} does not export {fmt!r}")
        dest = _empty(Path(dest))
        items_dir = dest / "items"
        items_dir.mkdir()
        for uid, doc in sorted(self.backend._docs.items()):
            (items_dir / f"{uid}.json").write_bytes(_canonical_json(doc))
        meta = {"schema": "homelabnext.projects/1", "uid_count": len(self.backend._docs)}
        (dest / "meta.json").write_bytes(_canonical_json(meta))
        return build_manifest(dest, self.slot, fmt, self._limits)

    def import_(self, src: Path, manifest: Mapping[str, Any], limits: Limits | None = None) -> int:
        _refuse_bad_manifest(manifest, self.slot, self.export_formats[0])
        staged = read_tree(
            Path(src),
            manifest,
            _effective_limits(self._limits, limits),
            slot=self.slot,
            formats=self.export_formats,
        )
        docs: dict[str, dict] = {}
        for path, body in staged.items():
            if not path.startswith("items/") or not path.endswith(".json"):
                continue
            doc = json.loads(body.decode("utf-8"))
            uid = doc.get("uid") or Path(path).stem
            docs[uid] = doc
        # atomic swap
        self.backend._docs = docs
        return len(manifest["files"])


class PortableRecordsTarget(FakeRecordsTarget):
    """Records fake with ``markdown-tree`` export/import: a byte-for-byte copy of the lane
    layout (``inbox/``, ``decided/approved/``, ``decided/denied/``, ``decided/completed/``) plus
    the manifest.

    Leave-the-product shape: the lane tree is the natural interchange; a successor records
    product onboards by walking the same directory.  A round-trip wipes and copies back under
    ``homelabnext.modules.importcheck.copy_tree``, so a refused import never leaves the live
    tree half-rewritten.
    """

    slot = "records"
    export_formats = ("markdown-tree",)

    def __init__(self) -> None:
        super().__init__()
        self._limits = Limits(max_files=10_000, max_bytes=1 << 26, max_file_bytes=1 << 22)

    def export(self, dest: Path, fmt: str) -> dict[str, Any]:
        if fmt not in self.export_formats:
            raise ValueError(f"{self.slot} does not export {fmt!r}")
        dest = _empty(Path(dest))
        # Walk the live records tree; ``build_manifest`` below refuses any symbolic link or
        # special file it finds, so an exporter never writes what its peer must refuse.
        _copy_regular_files(self._dir, dest)
        return build_manifest(dest, self.slot, fmt, self._limits)

    def import_(self, src: Path, manifest: Mapping[str, Any], limits: Limits | None = None) -> int:
        _refuse_bad_manifest(manifest, self.slot, self.export_formats[0])
        # Stage into a verified copy beside the live tree; swap only when every file verified.
        staging = self._dir.parent / f".{self._dir.name}.staging"
        if staging.exists():
            shutil.rmtree(staging)
        n = copy_tree(
            Path(src),
            manifest,
            staging,
            _effective_limits(self._limits, limits),
            slot=self.slot,
            formats=self.export_formats,
        )
        # Replace the live tree. The library's own atomic-copy guarantees nothing was partial.
        old = self._dir.parent / f".{self._dir.name}.old"
        if old.exists():
            shutil.rmtree(old)
        self._dir.rename(old)
        try:
            staging.rename(self._dir)
        except Exception:
            # best-effort rollback
            old.rename(self._dir)
            raise
        shutil.rmtree(old, ignore_errors=True)
        # Re-init the agent/reader/decider over the new tree (they hold only self._dir, so new
        # instances are enough).
        from datetime import UTC, datetime

        from homelabnext.records.agent import Records, RecordsReader
        from homelabnext.records.decider import Decider, init_tree

        init_tree(self._dir)
        clock = lambda: datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)  # noqa: E731
        self._agent = Records(self._dir, clock)
        self._reader = RecordsReader(self._dir)
        self._decider = Decider(self._dir, decided_by="operator", clock=clock)
        return n


# Deterministic seed data for round-trip tests (and the migration suite's own factory): a fresh
# instance exports the same tree every time, so an export/import/export round-trip has a
# fixed point.


def _seed_cases(store: PortableCaseStore) -> PortableCaseStore:
    a1 = store.create_alert("brute-force", "ssh login flood", "high", dedup_key="src=host-a")
    a2 = store.create_alert("exposure", "unencrypted bucket", "medium")
    c = store.promote(a1.id, title="investigate brute force")
    store.add_note(c.id, "analyst", "triage started")
    store.dismiss(a2.id, "known scanner")
    return store


def _seed_projects(store: PortableProjectStore) -> PortableProjectStore:
    p = store.create("project", "ship open-format exports", external_key="PRJ-EXPORTS")
    s1 = store.create("step", "write adapters", project=p.uid)
    store.create("step", "round-trip test", project=p.uid)
    store.close(s1.uid, result="adapters landed")
    return store


def _seed_records(store: PortableRecordsTarget) -> PortableRecordsTarget:
    base = {
        "type": "proposal",
        "requesting_agent": "profile:triage",
        "risk": "low",
        "rollback": "Revert the setting",
    }
    name = store.propose({**base, "title": "wire portable exports"}, body="scope this M\n")
    store.approve(name)
    name2 = store.propose({**base, "title": "wire portable cases"}, body="json lanes\n")
    store.deny(name2, reason="duplicate")
    return store


#: factories named by slot — the round-trip test parameterises over this map.
PORTABLE_FACTORIES = {
    "cases": lambda: _seed_cases(PortableCaseStore()),
    "projects": lambda: _seed_projects(PortableProjectStore()),
    "records": lambda: _seed_records(PortableRecordsTarget()),
}
