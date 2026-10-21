# SPDX-License-Identifier: Apache-2.0
"""Shared helpers of the register tests: the example records by the code readers know them by.

The example records are identified by uids (ADR-0019); ``examples/registers/aliases.yml`` maps
the codes they carried before the migration to those uids, so a test can still say "LL-001"
and mean the expired-certificate lesson, without a number appearing in any record.
"""

import pathlib

from homelabnext.identity.aliases import load_aliases

REPO = pathlib.Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "examples" / "registers"
U = load_aliases(EXAMPLES).codes  # legacy code -> uid of the example records


def f(code: str) -> str:
    """``LL-001`` -> ``<uid>.md``, the example record's file name."""
    return f"{U[code]}.md"


def evd(code: str) -> str:
    """``LL-001`` -> ``<uid>.events``, the example record's sidecar directory."""
    return f"{U[code]}.events"


def edit(path: pathlib.Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text, old
    path.write_text(text.replace(old, new))
