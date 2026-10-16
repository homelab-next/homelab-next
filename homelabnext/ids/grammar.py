# SPDX-License-Identifier: Apache-2.0
"""Logical-id grammar.

A logical id names a thing independently of the product that implements it
(``cap:lake-query``, ``det:auth-failure-burst``).  Product locators (URIs, IP
literals, engine rule numbers) never appear in an id; they live in adapter
maps behind a resolver (see :mod:`homelabnext.ids.resolver`).

Grammar (ASCII, lowercase)::

    id        = kind ":" body                    (max 128 chars)
    kind      = cap | svc | det | profile | persona | skill | mdl | memory | table
    body      = slug                              for cap svc det profile persona skill mdl
              | slug "/" slug                     for memory   (scope/id)
              | ident "." ident                   for table    (schema.name)
    slug      = [a-z][a-z0-9]*(-[a-z0-9]+)*       (max 64)
    ident     = [a-z][a-z0-9]*(_[a-z0-9]+)*       (max 64)

Additional rule, enforced by grammar *and* by the JSON schema: no run of four
or more digits and no ``rule``/``sid`` immediately followed by a digit.  That
keeps vendor rule numbers and addresses out of ids.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_ID_LEN = 128

SLUG = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
IDENT = r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*"

#: kind -> regex for the part after "<kind>:"
BODY_PATTERNS: dict[str, str] = {
    "cap": SLUG,
    "svc": SLUG,
    "det": SLUG,
    "profile": SLUG,
    "persona": SLUG,
    "skill": SLUG,
    "mdl": SLUG,
    "memory": SLUG + "/" + SLUG,
    "table": IDENT + r"\." + IDENT,
}
KINDS: tuple[str, ...] = tuple(BODY_PATTERNS)

#: shapes that must never appear inside an id (see module docstring)
FORBIDDEN_RE = re.compile(r"[0-9]{4,}|(?:rule|sid)[-_]?[0-9]")

_COMPILED = {k: re.compile(v) for k, v in BODY_PATTERNS.items()}


class IdError(ValueError):
    """Raised when a string is not a valid logical id."""

    def __init__(self, message: str, code: str = "GRAMMAR") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LogicalId:
    kind: str
    body: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.body}"

    @property
    def parts(self) -> tuple[str, ...]:
        sep = {"memory": "/", "table": "."}.get(self.kind)
        return tuple(self.body.split(sep)) if sep else (self.body,)


def schema_pattern(kind: str) -> str:
    """Anchored pattern (JSON-Schema / ECMA compatible) for one kind."""
    return f"^{kind}:{BODY_PATTERNS[kind]}$"


def union_pattern() -> str:
    alts = "|".join(f"{k}:{BODY_PATTERNS[k]}" for k in KINDS)
    return f"^(?:{alts})$"


def parse(text: str) -> LogicalId:
    if not isinstance(text, str):
        raise IdError("logical id must be a string")
    if len(text) > MAX_ID_LEN:
        raise IdError(f"logical id longer than {MAX_ID_LEN} characters")
    kind, sep, body = text.partition(":")
    if not sep or kind not in BODY_PATTERNS:
        raise IdError(f"unknown or missing kind in {text!r}; expected one of {', '.join(KINDS)}")
    if not _COMPILED[kind].fullmatch(body) or any(
        len(seg) > 64 for seg in body.replace("/", ".").split(".")
    ):
        raise IdError(f"body {body!r} does not match the {kind}: grammar")
    if FORBIDDEN_RE.search(text):
        raise IdError("id contains a rule-number or address-like digit run", code="RULE_NUMBER")
    return LogicalId(kind, body)


def is_valid(text: object) -> bool:
    try:
        parse(text)  # type: ignore[arg-type]
    except IdError:
        return False
    return True


def format_id(kind: str, *parts: str) -> str:
    """Build and validate an id from its parts (round-trips with :func:`parse`)."""
    sep = {"memory": "/", "table": "."}.get(kind, "")
    if kind not in BODY_PATTERNS:
        raise IdError(f"unknown kind {kind!r}")
    if sep:
        body = sep.join(parts)
    elif len(parts) == 1:
        body = parts[0]
    else:
        raise IdError(f"{kind}: takes exactly one part")
    text = f"{kind}:{body}"
    parse(text)
    return text
