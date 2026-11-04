# SPDX-License-Identifier: Apache-2.0
"""Exceptions of the lake library. Every one is a :class:`LakeError`."""

from __future__ import annotations


class LakeError(Exception):
    """Base class."""


class MissingExtra(LakeError, ImportError):
    """An optional dependency is not installed. The message names the extra to install."""

    def __init__(self, module: str, extra: str = "lake"):
        self.module = module
        self.extra = extra
        super().__init__(
            f"the {module!r} package is required for this lake adapter; "
            f"install it with: pip install 'homelabnext[{extra}]'"
        )


class SchemaMismatch(LakeError):
    """An existing table does not match the schema generated from the OCSF subset."""

    def __init__(self, table: str, diffs: list[str]):
        self.table = table
        self.diffs = list(diffs)
        super().__init__(
            f"table {table!r} does not match its pinned schema; refusing to touch it:\n  "
            + "\n  ".join(self.diffs)
        )


class RowRejected(LakeError):
    """A row (or a whole batch) failed validation; nothing from the batch was written."""

    def __init__(self, table: str, problems: list[str]):
        self.table = table
        self.problems = list(problems)
        shown = problems[:20]
        more = f"\n  ... and {len(problems) - 20} more" if len(problems) > 20 else ""
        super().__init__(
            f"batch for {table!r} rejected, nothing written:\n  " + "\n  ".join(shown) + more
        )


class UnknownTable(LakeError, KeyError):
    pass


class CassetteMiss(LakeError):
    """A cassette has no recording for the query that was asked."""


class WriteNotSupported(LakeError):
    """The adapter is read-only (writes go through the catalog adapter)."""


class CheckpointError(LakeError):
    pass


class EndpointNotConfigured(LakeError, LookupError):
    """No endpoint is configured for a capability. There is deliberately no default to fall back to."""


class BatchSourceMismatch(LakeError):
    """A batch id already committed by another source: replaying it would report that source's
    commit as this one's and write nothing, so the write is refused instead."""


def check_replay_source(table: str, batch_id: str, stored: str | None, source: str | None) -> None:
    """Refuse a replay of ``batch_id`` whose recorded source (``stored``) is not ``source``.  A
    ledger entry that recorded no source (older entries) is not judged."""
    if stored is not None and stored != source:
        raise BatchSourceMismatch(
            f"{table}: batch {batch_id!r} was committed by source {stored!r}, not {source!r}"
        )
