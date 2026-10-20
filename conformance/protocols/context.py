# SPDX-License-Identifier: Apache-2.0
"""Contract for ``context``: the store an agent queries for context, scoped to what it may see.

An indexer hands the store :class:`Document` objects (``index``) and removes them (``delete``);
a reader asks with a :class:`Query` and gets ranked :class:`Hit` objects (``query``) or one
document by id (``get``).  The knowledge graph and the profile packs stay in homelabnext; this
seam is only retrieval, so a context or memory product can sit behind it, or none at all (the
reference store, ``homelabnext.context.ContextStore``, serves the repository's own graph).

What every implementation guarantees, whatever its ranking:

* **Scope is mandatory and exact.**  ``Query.allowed`` (and ``get``'s ``allowed``) has no
  default and no wildcard.  An entry is an exact id or a namespace ending in ``:`` or ``/``.
  Nothing outside it is returned: not as a hit, not in a snippet, not in an error message, and
  not *through* it -- relations are followed only between documents the caller may see.  A
  document outside the scope is reported exactly like one that does not exist (``NotFound``).
* **Inactive records stay out.**  A document whose ``status`` is ``retired``, ``superseded`` or
  ``incorporated`` is neither returned nor related through unless ``include_inactive=True``.
* **Relations outrank keywords.**  A document linked to a seed (either direction) ranks above
  one that only matches the text; nearer ranks above farther.  With no text and no seeds the
  result is empty.
* **Determinism.**  The same documents and the same query give the same hits in the same order
  with the same scores, whatever order the documents were indexed in; equal scores are ordered
  by id.  ``budget`` caps the hits and a smaller budget returns a prefix of a larger one.
* **Fidelity.**  ``content`` is exactly the indexed string, ``digest`` its sha256, ``snippet`` a
  substring of it.  Re-indexing an id replaces it (no stale copy is ever returned); ``delete``
  removes it.
* **Hostile input.**  Control characters, injection-looking strings and oversized text are
  data: the result is a list within scope or ``InvalidQuery``, whose message never echoes the
  text.  Errors are the contract's own types.

Adding a product (an existing context or memory store, for example OpenViking): write an adapter
module, say ``my_adapters/openviking.py``, whose factory returns an object with these four
methods.  ``index`` maps each document to one product resource (the document id is the
resource's logical name; keep the product's own locator out of ids and hits), ``query`` asks the
product for candidates and then enforces ``allowed`` and the inactive rule itself
(``homelabnext.context.in_scope`` and ``check_query`` are the reference rules), re-ranks with
relation first and orders ties by id.  Translate the product's errors into ``NotFound`` /
``InvalidQuery`` / ``InvalidDocument``.  Name the factory in a target file
(``capabilities: {context: {adapter: my_adapters.openviking:make, features: [semantic]}}``) and
run ``hnx conform run context --target that-file.yml``.  Declare ``semantic`` only if the product
really matches by meaning.

Subject attributes: the four methods below, and ``features`` (optional: ``semantic``).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from homelabnext.context import (
    MAX_BUDGET,
    MAX_QUERY_CHARS,
    SNIPPET_CHARS,
    ContextError,
    Document,
    Hit,
    IndexReport,
    InvalidDocument,
    InvalidQuery,
    NotFound,
    Query,
)

__all__ = [
    "MAX_BUDGET",
    "MAX_QUERY_CHARS",
    "SNIPPET_CHARS",
    "ContextError",
    "ContextStore",
    "Document",
    "Hit",
    "IndexReport",
    "InvalidDocument",
    "InvalidQuery",
    "NotFound",
    "Query",
]


@runtime_checkable
class ContextStore(Protocol):
    def index(self, docs: Sequence[Document]) -> IndexReport:
        """Add or replace documents by id.  An id indexed again with any field changed replaces
        the old version everywhere; an identical one is ``unchanged``.  Raises InvalidDocument
        (and indexes nothing from the batch) for a malformed document or a repeated id."""

    def query(self, q: Query) -> list[Hit]:
        """Hits within ``q.allowed``, best first: seeds and documents related to them, then
        keyword matches; at most ``q.budget``.  Raises InvalidQuery for a malformed query
        (scope missing, empty-string or wildcard entry, bad budget, oversized text)."""

    def get(self, doc_id: str, allowed: frozenset[str]) -> Hit:
        """One document by id (any status) with ``score`` 0.  Raises NotFound when the id is
        unknown or outside ``allowed``, identically; InvalidQuery for a malformed scope."""

    def delete(self, doc_id: str) -> None:
        """Remove a document; it is never returned or related through again.  Raises NotFound
        for an unknown id."""
