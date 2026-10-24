# SPDX-License-Identifier: Apache-2.0
"""Credential and identifier *shapes* shared by two consumers with opposite policies.

* ``tools/leak_scan.py`` is the publishing gate: it decides whether a value may ship in this
  repository, so it exempts documentation values and obvious placeholders.
* :mod:`homelabnext.agent.screen` redacts untrusted content before it reaches a model prompt, so
  it exempts nothing: a placeholder in somebody else's data is still that data.

Only the regular expressions (and the deny-list file format) are shared; each consumer keeps its
own accept rules.  Standard library only, so the leak scanner can import this module from a bare
checkout with no dependencies installed.

The expressions are written so that this file does not match itself (character classes break up
the literal tokens): the leak scanner scans it like any other file.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Vendor credential prefixes whose shape alone identifies them.
AWS_ACCESS_KEY = r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
GITHUB_TOKEN = r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"
SLACK_TOKEN = r"\bxox[abposr]-[A-Za-z0-9-]{10,}"
GOOGLE_KEY = r"\bAIza[0-9A-Za-z_-]{35}\b"
JWT = r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
PRIVATE_KEY_HEADER = r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"
# ``domain`` is a named group so a consumer can apply its own domain policy.
EMAIL = r"[\w.+-]+@(?P<domain>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b"

# Text right before a dotted quad that makes it a version or an OID, not an address.
VERSION_CONTEXT_RE = re.compile(
    r"(?i)(?:\bv|version\W{0,3}|ver\W{0,2}|[=<>~^!]=?\s*|@|oid\W{0,3})$"
)


#: the separators inside a name: a plain deny-list term matches across any run of them, or none
_NAME_SEPARATORS = re.compile(r"[-_.]+")


def _words(part: str) -> str:
    words = [re.escape(w) for w in _NAME_SEPARATORS.split(part) if w]
    return r"[-_.]*".join(words)


def _term(raw: str) -> str:
    """The regex of a plain deny-list term (see :func:`compile_denylist`)."""
    parts = [_words(p) for p in raw.split() if _words(p)]
    if not parts:
        raise re.error(f"{raw!r} has no letters or digits")
    # not after a letter or digit; not before a letter, and when the term itself ends in a digit
    # (an address, a number) not before another digit either: name2 is a variant of name, but
    # a longer number is not a variant of a number.  Whitespace matches only where the term
    # itself has it.
    end = r"(?![^\W_])" if raw.rstrip()[-1:].isdigit() else r"(?![^\W\d_])"
    return r"(?<![^\W_])" + r"\s+".join(parts) + end


def compile_denylist(lines: Iterable[str]) -> list[tuple[int, re.Pattern[str]]]:
    """Parse deny-list lines into ``[(line number, regex)]``.

    One term per line; blank lines and ``#`` comments are skipped.  A plain term matches
    case-insensitively wherever it is not part of a longer run of letters and digits: ``-``,
    ``_`` and ``.`` are separators, not part of a word, so ``name`` also matches ``name-core``,
    ``name_core``, ``name.example`` and ``name2`` (a term ending in a digit is not extended by
    more digits).  The ``-``, ``_`` and ``.`` inside a term match any run of those separators, or
    none, so ``some-name`` also matches ``some_name`` and ``somename``; whitespace matches only
    where the term itself has whitespace, so ``some-name`` does not match the phrase
    ``some name``.  ``re:<regex>`` is a raw case-insensitive
    regex.  Raises ``ValueError`` naming the line of a bad regex.  An empty result is returned
    as is: whether an empty list is acceptable is the caller's decision.
    """
    terms: list[tuple[int, re.Pattern[str]]] = []
    for lineno, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            rx = re.compile(raw[3:] if raw.startswith("re:") else _term(raw), re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"deny-list line {lineno}: bad regex ({exc})") from exc
        terms.append((lineno, rx))
    return terms
