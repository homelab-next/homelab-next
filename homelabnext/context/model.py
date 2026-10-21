# SPDX-License-Identifier: Apache-2.0
"""The ``context`` capability's data shapes, errors and the rules every implementation shares.

The rules here are part of the contract, not one implementation's choices: what a scope entry
means (:func:`in_scope`), what makes a query or a document invalid (:func:`check_query`,
:func:`check_documents`), which records are inactive (:data:`INACTIVE_STATUSES`, the graph's
own set) and how a content digest is computed (:func:`digest`).  An adapter for a real product
may call these helpers; the conformance suite proves the behaviour either way.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from homelabnext.graph.query import INACTIVE_STATUSES

__all__ = [
    "INACTIVE_STATUSES",
    "MAX_BUDGET",
    "MAX_CONTENT_CHARS",
    "MAX_QUERY_CHARS",
    "SNIPPET_CHARS",
    "ContextError",
    "Document",
    "Hit",
    "IndexReport",
    "InvalidDocument",
    "InvalidQuery",
    "NotFound",
    "Query",
    "check_documents",
    "check_query",
    "digest",
    "in_scope",
    "is_active",
    "snippet",
    "terms",
]

#: the most hits one query may ask for
MAX_BUDGET = 200
#: query text longer than this is an ``InvalidQuery`` (never silently truncated)
MAX_QUERY_CHARS = 16_384
#: a document whose content is longer than this is an ``InvalidDocument``
MAX_CONTENT_CHARS = 4_000_000
#: the longest snippet a hit carries
SNIPPET_CHARS = 240

_ID = re.compile(r"[^\s:*][^\s*]{0,510}")  # no whitespace, no wildcard, at most 511 characters
_TERM = re.compile(r"\w+")


class ContextError(Exception):
    """Base of the contract's errors.  A message never contains document content."""


class NotFound(ContextError):
    """No such document, or one outside the caller's scope: the two are indistinguishable."""


class InvalidQuery(ContextError, ValueError):
    """The query is malformed (scope, budget, kinds, seeds or oversized text).  The message
    never echoes the query text."""


class InvalidDocument(ContextError, ValueError):
    """A document in an ``index`` batch is malformed; nothing in that batch was indexed."""


@dataclass(frozen=True)
class Document:
    """One unit of context, as the indexer hands it over."""

    id: str  # namespaced, ``<kind>:<name>`` (``doc:docs/graph.md``, ``lesson:<uid>``)
    kind: str  # node kind (``doc``, ``lesson``, ``runbook``, ``cap``, ...)
    content: str  # returned byte-for-byte; its sha256 is the hit's digest
    title: str = ""
    path: str = ""  # repo-relative source file ("" when none)
    status: str = ""  # lifecycle status; retired, superseded or incorporated is inactive
    links: tuple[str, ...] = ()  # ids this document relates to (followed in both directions)


@dataclass(frozen=True)
class Query:
    """What a caller asks.  ``allowed`` has no default: a caller always states what it may see.

    ``allowed`` entries are exact ids (``lesson:<uid>``) or namespaces: an entry ending in
    ``:`` or ``/`` matches every id that starts with it (``lesson:``, ``doc:docs/capabilities/``).
    Nothing else is a pattern: ``doc:docs/a`` does not admit ``doc:docs/ab``, an entry
    without ``:`` can name no id and is invalid, and so is any ``*``.
    """

    allowed: frozenset[str]  # the ids and namespaces the caller may see; empty sees nothing
    text: str = ""  # keywords; at most MAX_QUERY_CHARS characters
    seeds: tuple[str, ...] = ()  # ids the task starts from; related documents rank first
    kinds: frozenset[str] | None = None  # only these kinds (None: every kind)
    budget: int = 10  # at most this many hits, 0..MAX_BUDGET
    include_inactive: bool = False  # also return (and relate through) inactive records


@dataclass(frozen=True)
class Hit:
    """One result.  ``content`` is exactly what was indexed; ``snippet`` is a substring of it."""

    id: str
    kind: str
    title: str
    path: str
    score: float  # higher ranks first; equal scores are ordered by id
    snippet: str  # at most SNIPPET_CHARS characters, always a substring of content
    content: str
    digest: str  # sha256 hex of the UTF-8 content


@dataclass(frozen=True)
class IndexReport:
    """What one ``index`` call changed, each tuple sorted by id."""

    added: tuple[str, ...] = ()
    replaced: tuple[str, ...] = ()  # same id, different content, links, title or status
    unchanged: tuple[str, ...] = ()


def digest(content: str) -> str:
    """sha256 hex of the content's UTF-8 bytes (lone surrogates kept, never replaced)."""
    return hashlib.sha256(content.encode("utf-8", "surrogatepass")).hexdigest()


def is_active(status: str) -> bool:
    return status not in INACTIVE_STATUSES


def in_scope(doc_id: str, allowed: Iterable[str]) -> bool:
    """True when ``doc_id`` is an allowed id or lies in an allowed namespace."""
    for entry in allowed:
        if entry.endswith((":", "/")):
            if doc_id.startswith(entry):
                return True
        elif doc_id == entry:
            return True
    return False


def terms(text: str) -> list[str]:
    """Lower-case word tokens, in order of first appearance, without repeats."""
    return list(dict.fromkeys(t.lower() for t in _TERM.findall(text)))


def snippet(content: str, words: Sequence[str]) -> str:
    """A window of ``content`` around the first matching word (else its start)."""
    low = content.lower()
    at = min((i for w in words if (i := low.find(w)) >= 0), default=0)
    start = max(0, at - SNIPPET_CHARS // 4)
    return content[start : start + SNIPPET_CHARS]


def _str_set(value: object, what: str) -> frozenset[str]:
    if isinstance(value, str | bytes) or not isinstance(value, Iterable):
        raise InvalidQuery(f"{what} must be a set of strings, not {type(value).__name__}")
    items = list(value)
    if not all(isinstance(i, str) for i in items):
        raise InvalidQuery(f"{what} must contain only strings")
    return frozenset(items)


def _scope_entry_ok(entry: str) -> bool:
    if not entry or "*" in entry or any(c.isspace() or not c.isprintable() for c in entry):
        return False
    kind, sep, _ = entry.partition(":")
    return bool(kind) and bool(sep)


def check_query(q: Query) -> Query:
    """The query with its collections normalised, or ``InvalidQuery``."""
    if not isinstance(q, Query):
        raise InvalidQuery(f"expected a Query, got {type(q).__name__}")
    allowed = _str_set(q.allowed, "allowed")
    bad = sum(1 for e in allowed if not _scope_entry_ok(e))
    if bad:
        raise InvalidQuery(
            f"{bad} scope entr{'y is' if bad == 1 else 'ies are'} invalid: an entry is an exact "
            "id or a namespace ending in ':' or '/', never empty and never a wildcard"
        )
    if not isinstance(q.text, str):
        raise InvalidQuery(f"text must be a string, not {type(q.text).__name__}")
    if len(q.text) > MAX_QUERY_CHARS:
        raise InvalidQuery(f"text is longer than {MAX_QUERY_CHARS} characters")
    if isinstance(q.seeds, str | bytes) or not isinstance(q.seeds, Iterable):
        raise InvalidQuery("seeds must be a sequence of ids")
    seeds = tuple(q.seeds)
    if not all(isinstance(s, str) for s in seeds):
        raise InvalidQuery("seeds must contain only strings")
    kinds = None if q.kinds is None else _str_set(q.kinds, "kinds")
    if isinstance(q.budget, bool) or not isinstance(q.budget, int):
        raise InvalidQuery(f"budget must be an integer, not {type(q.budget).__name__}")
    if not 0 <= q.budget <= MAX_BUDGET:
        raise InvalidQuery(f"budget must be between 0 and {MAX_BUDGET}")
    if not isinstance(q.include_inactive, bool):
        raise InvalidQuery("include_inactive must be a boolean")
    return Query(allowed, q.text, seeds, kinds, q.budget, q.include_inactive)


def check_documents(docs: Sequence[Document]) -> list[Document]:
    """The batch as a list, or ``InvalidDocument`` naming the first bad position (not its
    content).  Ids must be unique within a batch."""
    if isinstance(docs, str | bytes | Document) or not isinstance(docs, Iterable):
        raise InvalidDocument("index takes a sequence of Document")
    out = list(docs)
    seen: set[str] = set()
    for n, d in enumerate(out):
        if not isinstance(d, Document):
            raise InvalidDocument(f"item {n} is not a Document")
        if not isinstance(d.id, str) or not _ID.fullmatch(d.id) or ":" not in d.id:
            raise InvalidDocument(f"item {n}: id must be '<kind>:<name>' without spaces or '*'")
        if d.id in seen:
            raise InvalidDocument(f"item {n}: duplicate id {d.id!r} in one batch")
        seen.add(d.id)
        if not isinstance(d.kind, str) or not d.kind:
            raise InvalidDocument(f"item {n}: kind must be a non-empty string")
        if not isinstance(d.content, str):
            raise InvalidDocument(f"item {n}: content must be a string")
        if len(d.content) > MAX_CONTENT_CHARS:
            raise InvalidDocument(f"item {n}: content longer than {MAX_CONTENT_CHARS} characters")
        for f in ("title", "path", "status"):
            if not isinstance(getattr(d, f), str):
                raise InvalidDocument(f"item {n}: {f} must be a string")
        if isinstance(d.links, str) or not all(isinstance(x, str) for x in d.links):
            raise InvalidDocument(f"item {n}: links must be a tuple of ids")
    return out
