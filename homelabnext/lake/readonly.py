# SPDX-License-Identifier: Apache-2.0
"""A client-side read-only gate for SQL a reader (an agent, a person) hands to the lake.

:func:`select_only` accepts one ``SELECT`` (or ``WITH ... SELECT``) statement and refuses
everything else before a byte reaches the engine:

* the first keyword, after any opening parentheses, is ``SELECT`` or ``WITH``;
* there is one statement: a ``;`` outside a literal, a quoted identifier or a comment is refused
  (one trailing ``;`` is dropped);
* no bare word of :data:`WRITE_WORDS` appears outside literals, quoted identifiers and comments
  (``INSERT``, ``CREATE``, ``CALL``, ``ALTER``, ``EXECUTE`` and the rest), so neither a data-changing
  clause nor a table procedure (``ALTER TABLE ... EXECUTE``) can ride inside a ``WITH``; a column
  of such a name is written as a quoted identifier (``"update"``);
* the text is at most :data:`MAX_SQL` characters.

It is a gate in front of the real control, never the control itself: the reader signs in to the
engine as its own account, which the engine's access rules let read and nothing else (for a lake,
a catalog the engine itself holds read-only, which refuses every write and every table procedure
whoever asks). A statement this gate passes can still be refused there, and must be.

The scanner skips the same things :mod:`.sqlparams` does (``'...'`` literals with ``''`` escapes,
``"..."`` identifiers, ``--`` and ``/* */`` comments), so ``:name`` placeholders are found the same
way by both.
"""

from __future__ import annotations

import re

from .errors import LakeError

__all__ = ["MAX_SQL", "WRITE_WORDS", "QueryRefused", "select_only"]

#: the longest statement accepted (characters)
MAX_SQL = 20_000
#: the statement verbs that change something, run something or manage the session; refused as a
#: bare word anywhere in the statement
WRITE_WORDS = frozenset(
    {
        "ALTER", "ANALYZE", "CALL", "COMMIT", "CREATE", "DEALLOCATE", "DELETE", "DENY", "DROP",
        "EXECUTE", "GRANT", "INSERT", "MERGE", "PREPARE", "REFRESH", "RESET", "REVOKE",
        "ROLLBACK", "TRUNCATE", "UPDATE", "VACUUM",
    }
)  # fmt: skip
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_LEAD = re.compile(r"[\s(]*(SELECT|WITH)\b", re.I)


class QueryRefused(LakeError):
    """The statement is not one read-only query; nothing was sent."""


def _skeleton(sql: str) -> str:
    """``sql`` with every literal, quoted identifier and comment blanked out, character for
    character (so an index into the skeleton is an index into ``sql``)."""
    out: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in ("'", '"'):
            j = i + 1
            while True:
                if j >= n:
                    raise QueryRefused("an unterminated quoted literal or identifier")
                if sql[j] == ch:
                    if j + 1 < n and sql[j + 1] == ch:
                        j += 2
                        continue
                    break
                j += 1
            out.append(" " * (j + 1 - i))
            i = j + 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            end = n if j < 0 else j
            out.append(" " * (end - i))
            i = end
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            if j < 0:
                raise QueryRefused("an unterminated comment")
            out.append(" " * (j + 2 - i))
            i = j + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def select_only(sql: str) -> str:
    """``sql`` (one trailing ``;`` and surrounding white space removed) when it is one read-only
    query, else :class:`QueryRefused` naming why (never echoing the statement)."""
    if not isinstance(sql, str) or not sql.strip():
        raise QueryRefused("an empty statement")
    if len(sql) > MAX_SQL:
        raise QueryRefused(f"the statement is longer than {MAX_SQL} characters")
    if "\x00" in sql:
        raise QueryRefused("the statement holds a NUL character")
    text = sql.strip()
    skeleton = _skeleton(text).rstrip()
    if skeleton.endswith(";"):
        skeleton = skeleton[:-1]
        text = text[: len(skeleton)].rstrip()
    if ";" in skeleton:
        raise QueryRefused("more than one statement (a ';' outside a literal)")
    if not _LEAD.match(skeleton):
        raise QueryRefused("only a SELECT (or WITH ... SELECT) query is accepted")
    words = {w.upper() for w in _WORD.findall(skeleton)}
    bad = sorted(words & WRITE_WORDS)
    if bad:
        raise QueryRefused(
            f"refused word(s) {', '.join(bad)}: only reads are accepted (quote a column of "
            'that name, e.g. "update")'
        )
    return text
