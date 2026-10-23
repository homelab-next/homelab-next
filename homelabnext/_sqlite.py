# SPDX-License-Identifier: Apache-2.0
"""One SQLite connection per operation, the way the hub's stores use it (the agent activity store,
the orchestration telemetry store): one transaction, always closed.

A writer sets the journal mode on every open: ``WAL`` (the default, the agent activity store, which
the hub writes itself) or ``DELETE`` (a rollback journal: the orchestration telemetry store, which
one-shot passes write and another user may read).  A ``read_only`` open needs no write access to
the file or its directory only when the database is NOT in WAL mode: a WAL reader must map the
``-shm`` index, so it creates ``-wal`` and ``-shm`` when they are missing (owned by the reader, so
a writer running as another user can never open the database again) and fails when it cannot
create them.  A read-only open of a WAL database is therefore refused before SQLite sees it."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

#: the journal modes a writer may set
JOURNAL_MODES = ("WAL", "DELETE")
_HEADER = b"SQLite format 3\x00"


def is_wal(path: str | Path) -> bool:
    """True when the database file's header says WAL (file format read/write version 2)."""
    with open(path, "rb") as f:
        head = f.read(20)
    return len(head) == 20 and head.startswith(_HEADER) and 2 in (head[18], head[19])


@contextmanager
def transaction(
    path: str | Path,
    *,
    secure_delete: bool = False,
    read_only: bool = False,
    journal_mode: str = "WAL",
) -> Iterator[sqlite3.Connection]:
    """A connection to ``path`` inside one transaction (committed on exit, rolled back on an
    exception).  ``secure_delete``: deleted rows are overwritten, not left in a free page.
    ``journal_mode``: what a writer sets (:data:`JOURNAL_MODES`).  ``read_only``: opened with
    ``mode=ro`` (a missing file is an error, never created, and every write is refused by SQLite),
    the journal mode is left as the writer set it, and a database in WAL mode is refused
    (:class:`sqlite3.OperationalError`) since reading it would create files (module docstring).
    A reader that meets a writer's lock waits for it (``timeout``) instead of failing."""
    if journal_mode not in JOURNAL_MODES:
        raise ValueError(f"journal_mode is one of {JOURNAL_MODES}, not {journal_mode!r}")
    if read_only:
        if is_wal(path):
            raise sqlite3.OperationalError(
                f"{path} is in WAL mode: a read-only open would create its -wal and -shm files; "
                "a writer pass of its owner converts it"
            )
        db = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, timeout=10)
    else:
        db = sqlite3.connect(path, timeout=10)
    try:
        if not read_only:
            got = db.execute(f"PRAGMA journal_mode={journal_mode}").fetchone()[0]
            if got.upper() != journal_mode:
                raise sqlite3.OperationalError(f"{path}: journal mode is {got}, not {journal_mode}")
        if secure_delete:
            db.execute("PRAGMA secure_delete=ON")
        with db:
            yield db
    finally:
        db.close()
