# SPDX-License-Identifier: Apache-2.0
"""YAML loaders shared by the document readers: a duplicate mapping key is an error.

PyYAML's ``SafeLoader`` keeps the last of two equal keys, so a document that sets a field twice
silently loses the first value. The registry, site, guest and customization readers all refuse
that; they used to carry four private copies of the same constructor.

* :class:`UniqueKeyLoader` is ``SafeLoader`` refusing duplicate keys.
* :class:`UniqueKeyStrDateLoader` also leaves ISO dates and timestamps as strings (the schemas
  type them as strings).
* :func:`expanded_size` counts the nodes a composed document constructs into, aliases and merge
  keys expanded, without constructing it: a reader refuses a document above its budget first
  (a few hundred bytes of nested aliases or merges construct into billions of nodes).
* :func:`load_unique` reads a file with :class:`UniqueKeyLoader`, turning an unreadable file or a
  YAML error into the caller's own error type.

Importing this module imports PyYAML; a reader that keeps PyYAML optional imports it lazily.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "MAX_EXPANDED_BYTES",
    "MAX_EXPANDED_NODES",
    "AliasRefused",
    "BudgetedLoader",
    "ExpansionRefused",
    "RecursiveAlias",
    "UniqueKeyLoader",
    "UniqueKeyStrDateLoader",
    "expanded_cost",
    "expanded_size",
    "load_unique",
]


_MERGE = "tag:yaml.org,2002:merge"


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False):
    """A mapping whose explicit keys are unique; a merge key (``<<: *anchor``) is not one of them
    (its keys may be overridden, as YAML intends) and is left to ``SafeLoader`` to expand.  Two
    merge keys in one mapping are refused like any duplicate: PyYAML keeps the last one, yaml.v3
    rejects the document (one ``<<`` takes a list of anchors)."""
    seen: set[Any] = set()
    merges = 0
    for key_node, _ in node.value:
        if key_node.tag == _MERGE:
            merges += 1
            if merges > 1:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "duplicate key '<<' (merge several anchors as <<: [*a, *b])",
                    key_node.start_mark,
                )
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            dup = key in seen
        except TypeError:  # a list or mapping as a key: what SafeLoader reports, as a YAMLError
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found unhashable key",
                key_node.start_mark,
            ) from None
        if dup:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


class ExpansionRefused(yaml.MarkedYAMLError):
    """A document refused before it is constructed: its aliases and merge keys expand past the
    loader's node or byte budget, or it is nested too deeply to compose.  A ``yaml.YAMLError``,
    so every reader's existing handler reports it as a document it cannot read."""


class RecursiveAlias(ExpansionRefused):
    """A node that contains itself through an alias (``a: &a [*a]``): it would construct into a
    self-referencing value, so a budgeted reader refuses it."""


class AliasRefused(ExpansionRefused):
    """An alias in a document whose loader takes none (``allow_aliases = False``)."""


#: what a document may construct into, aliases and merge keys expanded: far above any real
#: document of the platform (the example registry is a few thousand nodes and a few hundred KB),
#: far below what nested aliases or merges reach in a few hundred bytes
MAX_EXPANDED_NODES = 200_000
MAX_EXPANDED_BYTES = 16 * 1024 * 1024


def expanded_cost(
    node: yaml.Node | None,
    max_nodes: int = MAX_EXPANDED_NODES,
    max_bytes: int = MAX_EXPANDED_BYTES,
    *,
    allow_aliases: bool = True,
) -> tuple[int, int]:
    """``(nodes, scalar bytes)`` that ``node`` (from composing) constructs into with every alias
    and merge expanded; raises :class:`ExpansionRefused` past either budget, :class:`RecursiveAlias`
    for a node that contains itself (PyYAML registers an anchor before composing its children)
    and, with ``allow_aliases=False``, :class:`AliasRefused` for any node reached twice.  Linear
    in the composed graph: each node's cost is computed once and reused wherever an alias names
    it."""
    if node is None:
        return 0, 0
    cost: dict[int, tuple[int, int]] = {}
    open_: set[int] = set()  # started, children not yet all counted: the current path
    stack: list[tuple[yaml.Node, bool]] = [(node, False)]
    while stack:
        cur, done = stack.pop()
        if not done and id(cur) in cost:
            if not allow_aliases:
                raise AliasRefused(
                    None,
                    None,
                    "an alias (or anchor reused); this document takes none",
                    cur.start_mark,
                )
            continue
        if isinstance(cur, yaml.ScalarNode):
            cost[id(cur)] = (1, len(cur.value))
            continue
        if not done and id(cur) in open_:
            raise RecursiveAlias(
                None, None, "a recursive alias: the node contains itself", cur.start_mark
            )
        children: list[yaml.Node] = (
            [n for pair in cur.value for n in pair]
            if isinstance(cur, yaml.MappingNode)
            else list(cur.value)
        )
        if not done:
            open_.add(id(cur))
            stack.append((cur, True))
            stack.extend((c, False) for c in reversed(children))
            continue
        open_.discard(id(cur))
        nodes, size = 1, 0
        for c in children:
            n, b = cost[id(c)]
            nodes, size = nodes + n, size + b
            if nodes > max_nodes or size > max_bytes:
                raise ExpansionRefused(
                    None,
                    None,
                    f"expands past {max_nodes} YAML nodes or {max_bytes} bytes (aliases and "
                    "merge keys included); refused before it is constructed",
                    cur.start_mark,
                )
        cost[id(cur)] = (nodes, size)
    return cost[id(node)]


def expanded_size(node: yaml.Node | None, limit: int) -> int:
    """The node count of :func:`expanded_cost`, ``limit + 1`` past ``limit``."""
    try:
        return expanded_cost(node, limit, 1 << 62)[0]
    except RecursiveAlias:
        raise
    except ExpansionRefused:
        return limit + 1


class BudgetedLoader(yaml.SafeLoader):
    """SafeLoader that holds every document to an expansion budget before constructing it
    (:func:`expanded_cost`: ``max_nodes`` nodes and ``max_bytes`` scalar bytes with aliases and
    merges expanded, no node that contains itself), so every reader built on it is safe from
    alias and merge bombs.  A subclass may lower the budget or set ``allow_aliases = False``.
    Nesting too deep to compose or construct is :class:`ExpansionRefused` too, never a
    ``RecursionError``."""

    max_nodes = MAX_EXPANDED_NODES
    max_bytes = MAX_EXPANDED_BYTES
    allow_aliases = True

    def get_single_node(self):  # type: ignore[override]
        try:
            node = super().get_single_node()
        except RecursionError:
            raise ExpansionRefused(None, None, "nested too deeply to read", None) from None
        expanded_cost(node, self.max_nodes, self.max_bytes, allow_aliases=self.allow_aliases)
        return node

    def get_node(self):  # type: ignore[override]
        try:
            node = super().get_node()
        except RecursionError:
            raise ExpansionRefused(None, None, "nested too deeply to read", None) from None
        expanded_cost(node, self.max_nodes, self.max_bytes, allow_aliases=self.allow_aliases)
        return node

    def construct_document(self, node):  # type: ignore[override]
        try:
            return super().construct_document(node)
        except RecursionError:
            raise ExpansionRefused(None, None, "nested too deeply to construct", None) from None


class UniqueKeyLoader(BudgetedLoader):
    """:class:`BudgetedLoader` that refuses duplicate mapping keys (a silent override is a bug)."""


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


class UniqueKeyStrDateLoader(UniqueKeyLoader):
    """:class:`UniqueKeyLoader` that leaves ISO dates and timestamps as strings."""


UniqueKeyStrDateLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def load_unique(path: Path, error: type[Exception]) -> Any:
    """``path`` parsed with :class:`UniqueKeyLoader`; a read or parse failure raises
    ``error("cannot read <path>: <reason>")``, chained to the original exception."""
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise error(f"cannot read {path}: {exc}") from exc
