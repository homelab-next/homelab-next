# SPDX-License-Identifier: Apache-2.0
"""Records lifecycle: lanes, the single agent write path, and a reader.

``inbox/`` is the only agent-writable lane; ``decided/{approved,denied,completed}/`` belong to the
decision maker.  The operator-side movers are in ``homelabnext.records.decider`` and are
intentionally NOT re-exported here.
"""

from .agent import LaneViolation, Records, RecordsReader
from .notes import (
    AGENT_LANE,
    ALL_LANES,
    DECIDED_LANES,
    Note,
    NoteError,
    check_filename,
    parse_note,
    render_note,
    slugify,
    validate_note,
)

__all__ = [
    "AGENT_LANE",
    "ALL_LANES",
    "DECIDED_LANES",
    "LaneViolation",
    "Note",
    "NoteError",
    "Records",
    "RecordsReader",
    "check_filename",
    "parse_note",
    "render_note",
    "slugify",
    "validate_note",
]
