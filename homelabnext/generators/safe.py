# SPDX-License-Identifier: Apache-2.0
"""One guard for every value a generator interpolates into text.

The schemas already constrain registry fields to single-line slugs; this is the second layer.  A
generator that writes a value into a line-oriented format calls :func:`checked` (or
:func:`check_fields`) first, and a value carrying a line break, any other control character or a
metacharacter of the target format is refused with :class:`UnsafeValueError` instead of being
rendered.  A refused value means the input bypassed validation (a hand-built model, a schema that
was loosened), so failing loudly is the only safe answer: there is no escaping that is correct for
every consumer of the generated file.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

#: C0 controls (which include ``\n`` and ``\r``), DEL and the Unicode line/paragraph separators.
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]")

#: Characters that change the meaning of a line in each target format.
FORMAT_METACHARS: dict[str, str] = {
    # Caddyfile: blocks, comments, quoting, placeholders, token separators in a comment-free line
    "caddy": '{}#"`\\',
    # Markdown tables and inline HTML
    "markdown": "|<>`\\",
    # systemd unit files: specifiers and quoting (a value is always a whole directive value)
    "systemd": '%"\\',
    # dotenv / Environment= files
    "env": "\"'`$\\ ",
    # RFC 1035 zone files: comments, quoting, grouping
    "zone": ';"()\\ ',
    # hosts(5) and other whitespace-separated tables
    "table": "# ,",
    # a shell word that is always double-quoted by the generator
    "shell": '"`$\\',
    # Proxmox .fw rule lines
    "pvefw": "#",
}


class UnsafeValueError(ValueError):
    """A value would change the structure of the generated file."""


def checked(value: Any, field: str, fmt: str | None = None) -> str:
    """Return ``str(value)`` or raise :class:`UnsafeValueError`.

    ``field`` names the input (for the message); ``fmt`` is a key of :data:`FORMAT_METACHARS`
    whose characters are refused in addition to control characters.
    """
    text = str(value)
    m = CONTROL_RE.search(text)
    if m:
        raise UnsafeValueError(
            f"{field}: control character {m.group()!r} in {text!r}; values must be a single line"
        )
    if fmt is not None:
        bad = sorted({c for c in text if c in FORMAT_METACHARS[fmt]})
        if bad:
            raise UnsafeValueError(
                f"{field}: {fmt} metacharacter(s) {''.join(bad)!r} in {text!r} are refused"
            )
    return text


def check_fields(fmt: str | None, fields: Mapping[str, Any]) -> None:
    """:func:`checked` every value of ``fields`` (``None`` values are skipped)."""
    for name, value in fields.items():
        if value is not None:
            checked(value, name, fmt)


def control_char_paths(node: Any, path: str = "") -> Iterable[str]:
    """Yield ``path: message`` for every string (key or value) holding a control character.

    Used by the document loaders as a schema-independent backstop: Python's ``re`` lets ``$`` match
    before a trailing newline, so a pattern alone does not keep ``"name\\n"`` out.
    """
    if isinstance(node, str):
        m = CONTROL_RE.search(node)
        if m:
            yield f"{path or '<root>'}: control character {m.group()!r} in {node!r}"
    elif isinstance(node, Mapping):
        for k, v in node.items():
            sub = f"{path}/{k}" if path else str(k)
            if isinstance(k, str) and CONTROL_RE.search(k):
                yield f"{sub}: control character in key {k!r}"
            yield from control_char_paths(v, sub)
    elif isinstance(node, list | tuple):
        for i, v in enumerate(node):
            yield from control_char_paths(v, f"{path}/{i}" if path else str(i))
