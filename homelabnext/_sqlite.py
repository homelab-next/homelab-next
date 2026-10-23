# SPDX-License-Identifier: Apache-2.0
"""One SQLite connection per operation, the way the hub's stores use it (the agent activity store,
the orchestration telemetry store): WAL journal, one transaction, always closed."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def transaction(
    path: str | Path, *, secure_delete: bool = False, read_only: bool = False
) -> Iterator[sqlite3.Connection]:
    """A connection to ``path`` inside one transaction (committed on exit, rolled back on an
    exception).  ``secure_delete``: deleted rows are overwritten, not left in a free page.
    ``read_only``: opened with ``mode=ro`` (a missing file is an error, never created, and every
    write is refused by SQLite), and the journal mode is left as the writer set it."""
    if read_only:
        db = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, timeout=10)
    else:
        db = sqlite3.connect(path, timeout=10)
    try:
        if not read_only:
            db.execute("PRAGMA journal_mode=WAL")
        if secure_delete:
            db.execute("PRAGMA secure_delete=ON")
        with db:
            yield db
    finally:
        db.close()
