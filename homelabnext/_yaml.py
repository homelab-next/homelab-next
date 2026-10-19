# SPDX-License-Identifier: Apache-2.0
"""YAML loaders shared by the document readers: a duplicate mapping key is an error.

PyYAML's ``SafeLoader`` keeps the last of two equal keys, so a document that sets a field twice
silently loses the first value. The registry, site, guest and customization readers all refuse
that; they used to carry four private copies of the same constructor.

* :class:`UniqueKeyLoader` is ``SafeLoader`` refusing duplicate keys.
* :class:`UniqueKeyStrDateLoader` also leaves ISO dates and timestamps as strings (the schemas
  type them as strings).

Importing this module imports PyYAML; a reader that keeps PyYAML optional imports it lazily.
"""

from __future__ import annotations

from typing import Any

import yaml

__all__ = ["UniqueKeyLoader", "UniqueKeyStrDateLoader"]


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False):
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


class UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate mapping keys (a silent override is a bug)."""


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


class UniqueKeyStrDateLoader(UniqueKeyLoader):
    """:class:`UniqueKeyLoader` that leaves ISO dates and timestamps as strings."""


UniqueKeyStrDateLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
