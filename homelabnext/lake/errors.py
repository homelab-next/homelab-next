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
    """Judge a replay of ``batch_id`` committed by ``stored`` (``None``: no source recorded,
    a legacy ledger entry included) for a write that claims ``source`` (its ``expect_source``
    when it gave one, else its ``source``).

    A write that claims a source must find exactly that source recorded; anything else, a
    recorded ``None`` included, raises :class:`BatchSourceMismatch` (fail closed), so no writer
    can make a sourced writer's batch replay by committing its id first, with or without a
    source.  A writer re-sending a batch without its mark (the dual-write queue, so the mark
    never moves back) passes ``expect_source`` and is judged the same way.  A write that claims
    no source at all is not judged and replays as before: such a writer can only drop its own
    rows."""
    if source is not None and stored != source:
        raise BatchSourceMismatch(
            f"{table}: batch {batch_id!r} was committed by source {stored!r}, not {source!r}"
        )


def claimed_source(source: str | None, expect_source: str | None) -> str | None:
    """The source a write claims, for :func:`check_replay_source`: ``expect_source`` when given,
    else ``source``.  A write that names both, differently, is refused: it would mark one source
    and be judged as another."""
    if source is not None and expect_source is not None and source != expect_source:
        raise LakeError(f"a write naming source {source!r} cannot expect source {expect_source!r}")
    return source if expect_source is None else expect_source
