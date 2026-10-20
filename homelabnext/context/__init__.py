# SPDX-License-Identifier: Apache-2.0
"""Retrieval for agents: the ``context`` capability's data shapes and its reference store.

A caller asks for context with a :class:`Query` (keywords, seed ids, a kinds filter, a budget
and a mandatory scope) and gets ranked :class:`Hit` objects: documents related to the seeds
first, then keyword matches, never anything outside the scope and never an inactive (retired,
superseded, incorporated) record unless asked.  :class:`ContextStore` is the reference
implementation and :func:`repo_store` fills one from the repository's knowledge graph
(``homelabnext.graph``); it is what a read-only MCP server calls.  The contract and its
conformance suite are ``conformance/protocols/context.py`` and ``conformance/suites/context.py``
(``docs/capabilities/context.md``).
"""

from .model import (
    INACTIVE_STATUSES,
    MAX_BUDGET,
    MAX_CONTENT_CHARS,
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
    check_documents,
    check_query,
    digest,
    in_scope,
)
from .repo import documents_from_graph, repo_store
from .store import ContextStore

__all__ = [
    "INACTIVE_STATUSES",
    "MAX_BUDGET",
    "MAX_CONTENT_CHARS",
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
    "check_documents",
    "check_query",
    "digest",
    "documents_from_graph",
    "in_scope",
    "repo_store",
]
