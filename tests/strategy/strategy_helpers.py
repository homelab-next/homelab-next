# SPDX-License-Identifier: Apache-2.0
"""Shared constants and helpers of the strategy tests (an injected clock, a text edit)."""

import datetime as dt
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]
EXAMPLE = REPO / "examples" / "strategy"
NOW = dt.datetime(2026, 10, 20, 13, 10, tzinfo=dt.UTC)


def edit(root: pathlib.Path, path: str, old: str, new: str) -> None:
    """Replace ``old`` by ``new`` once in a record of the tree.  ``path`` may name the record by
    its legacy code (``requirements/PIR-001.md`` or ``PIR-001``), and every example code in
    ``old`` and ``new`` is written as its uid (``supports: [SO-002]``)."""
    import re

    m = re.fullmatch(r"(?:[a-z]+/)?([A-Z]+-\d{3})(?:\.md)?", path)
    path = rel(m[1]) if m else path
    old, new = uids(old), uids(new)
    p = root / path
    text = p.read_text()
    assert old in text, f"{old!r} not in {path}"
    p.write_text(text.replace(old, new, 1))


def clock(at: dt.datetime = NOW):
    return lambda: at


# The example records are identified by uids (ADR-0019); aliases.yml maps the codes they carried
# before the migration to them, so a test still says "PIR-001" for the probing requirement.
def _aliases():
    from homelabnext.identity.aliases import load_aliases

    return load_aliases(EXAMPLE).codes


U = _aliases()
_DIR = {"SO": "objectives", "OO": "objectives", "TO": "objectives", "TT": "objectives"}
_DIR |= {"MOE": "measures", "MOP": "measures", "RFI": "rfis"}
_DIR |= {"CCIR": "requirements", "FFIR": "requirements", "PIR": "requirements"}


def rel(code: str) -> str:
    """``PIR-001`` -> ``requirements/<uid>.md``, the example record's path in the tree."""
    return f"{_DIR[code.rsplit('-', 1)[0]]}/{U[code]}.md"


def uids(text: str) -> str:
    """``text`` with every example code (``SO-001``) written as its uid."""
    import re

    return re.sub(
        r"\b(?:SO|OO|TO|TT|MOE|MOP|CCIR|FFIR|PIR|RFI)-\d{3}\b", lambda m: U.get(m[0], m[0]), text
    )
