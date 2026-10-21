# SPDX-License-Identifier: Apache-2.0
"""Record identity: every record is a UUIDv7; its number is computed, never stored (ADR-0019).

* :mod:`.uid` -- :func:`uuid7` (monotonic, standard library only) and :func:`is_uid`;
* :mod:`.types` -- the record types, their directories and display prefixes;
* :mod:`.numbers` -- display numbers (``PIR 2.1``) from type, parent and sibling order;
* :mod:`.aliases` -- the legacy code -> uid map, read with a deprecation warning;
* :mod:`.migrate` -- ``hnx records assign-uids``, the one-time, idempotent migration.

This package imports nothing outside the standard library at import time (the registers' git
hooks use :mod:`.uid`); :mod:`.aliases` and :mod:`.migrate` read YAML when called.
"""

from .numbers import Node, label_map, node_of, number_map, order_problems
from .types import (
    LEGACY_CODE_RE,
    REGISTER_TYPES,
    STRATEGY_TYPES,
    TYPE_DIR,
    TYPE_ORDER,
    label_prefix,
)
from .uid import UID_PATTERN, UID_RE, UidGenerator, is_uid, uid_time, uuid7

__all__ = [
    "LEGACY_CODE_RE",
    "REGISTER_TYPES",
    "STRATEGY_TYPES",
    "TYPE_DIR",
    "TYPE_ORDER",
    "UID_PATTERN",
    "UID_RE",
    "Node",
    "UidGenerator",
    "is_uid",
    "label_map",
    "label_prefix",
    "node_of",
    "number_map",
    "order_problems",
    "uid_time",
    "uuid7",
]
