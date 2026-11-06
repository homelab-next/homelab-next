# SPDX-License-Identifier: Apache-2.0
"""Crash-safe state files and the keyed state-store API used by checks."""

from .keyed import KeyedState
from .store import (
    SCHEMA_VERSION,
    StateCorruptError,
    StateError,
    StateStore,
    StateVersionError,
    atomic_write_text,
    file_lock,
    quarantined_files,
)

__all__ = [
    "SCHEMA_VERSION",
    "KeyedState",
    "StateCorruptError",
    "StateError",
    "StateStore",
    "StateVersionError",
    "atomic_write_text",
    "file_lock",
    "quarantined_files",
]
