# SPDX-License-Identifier: Apache-2.0
"""A read-only MCP server over the repository: ``hnx mcp serve`` (stdio only; guide:
``docs/mcp.md``).

Agents get structured answers from the source of truth instead of reading prose: the
capability contracts (:func:`homelabnext.sop.capabilities.contract_data`, the model the
capability pages are rendered from), the JSON Schemas, the service registry, the knowledge
graph, the ``context`` reference store, the lesson review and the invariants results.

* :mod:`.catalog` -- the tools as plain functions (:class:`Catalog`, :data:`TOOLS`), no SDK;
* :mod:`.scope` -- the scope a compiled agent profile implies, and the intersection that keeps
  a call from widening it;
* :mod:`.server` -- the binding to the official ``mcp`` SDK (``homelabnext[mcp]``), the only
  module that imports it.
"""

from .catalog import MAX_RESULT_CHARS, TOOLS, Catalog, CatalogError
from .scope import SERVER_NAME, ScopeError, intersect, load_profile_scope, profile_scope

__all__ = [
    "MAX_RESULT_CHARS",
    "SERVER_NAME",
    "TOOLS",
    "Catalog",
    "CatalogError",
    "ScopeError",
    "intersect",
    "load_profile_scope",
    "profile_scope",
]
