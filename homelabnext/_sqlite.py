# SPDX-License-Identifier: Apache-2.0
"""One SQLite connection per operation, the way the hub's stores use it (the agent activity store,
the orchestration telemetry store): WAL journal, one transaction, always closed."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def transaction(path: str | Path, *, secure_delete: bool = False) -> Iterator[sqlite3.Connection]:
    """A connection to ``path`` inside one transaction (committed on exit, rolled back on an
    exception).  ``secure_delete``: deleted rows are overwritten, not left in a free page."""
    db = sqlite3.connect(path, timeout=10)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        if secure_delete:
            db.execute("PRAGMA secure_delete=ON")
        with db:
            yield db
    finally:
        db.close()
