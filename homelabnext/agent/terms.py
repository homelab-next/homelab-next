# SPDX-License-Identifier: Apache-2.0
"""Terms and scope: the vocabulary every agent session starts with.

One source, ``homelabnext/agent/terms.md`` (shipped in the package), feeds three readers so they
cannot disagree:

* every session's context pack (:func:`homelabnext.agent.start_session`), as the reserved
  stable section ``terms``, beside the ``access`` block: a manifest that defines its own
  ``terms`` section is refused, so neither a profile's manifest nor untrusted input can remove or
  replace it, and it is part of the pack digest like every section;
* ``docs/terms.md``, generated from it (:func:`render_doc`; ``hnx agent terms --check`` in
  ``make check`` fails when the committed page has drifted, ``--write`` regenerates it);
* the MCP server's read-only ``terms`` tool.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

from homelabnext.context.levels import generated_summary_lines

TERMS_SECTION = "terms"
SOURCE = Path(__file__).with_name("terms.md")
DOC = Path("docs") / "terms.md"
#: written here, not in docs/terms.md: text in that page becomes the context pack's `terms`
#: section, and this line is only the page's L0 summary (marked generated, since this module
#: writes the page)
SUMMARY = (
    "What the project's words mean and its scope: our activity and how we use threat "
    "vocabulary, shared by every agent and reader."
)
_SPDX = "<!-- SPDX-License-Identifier: Apache-2.0 -->\n"
_GENERATED = (
    "<!-- generated from homelabnext/agent/terms.md by `hnx agent terms --write`; "
    "edit that file, not this page -->\n"
)


@cache
def terms_text() -> str:
    """The terms, without the source file's licence comment."""
    text = SOURCE.read_text(encoding="utf-8")
    text = text.removeprefix(_SPDX)
    return text.strip() + "\n"


def terms_section() -> dict:
    """The reserved stable ``terms`` section of a session's context pack."""
    text = terms_text()
    return {
        "name": TERMS_SECTION,
        "tier": "stable",
        "source": "static",
        "required": True,
        "max_chars": len(text),
        "text": text,
    }


def render_doc() -> str:
    """``docs/terms.md``: the source with a generated-file note."""
    return (
        "---\n"
        + generated_summary_lines(SUMMARY)
        + "\n---\n"
        + _SPDX
        + _GENERATED
        + "\n"
        + terms_text()
    )


def check_doc(path: Path | str = DOC) -> list[str]:
    """Problems with the committed page (empty list = current)."""
    p = Path(path)
    try:
        got = p.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{p}: cannot read ({exc.strerror or exc})"]
    if got != render_doc():
        return [f"{p}: differs from homelabnext/agent/terms.md (run: hnx agent terms --write)"]
    return []
