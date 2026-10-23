# SPDX-License-Identifier: Apache-2.0
"""Contract for ``secrets``: a versioned key-value store with leases.

The single most important property is negative: **no value ever appears in an error message,
``repr`` or ``str`` of anything the store returns or raises**.  A secret handed back is a
``Secret`` whose ``repr`` is redacted; callers read ``.data`` deliberately.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = [
    "InvalidPath",
    "Lease",
    "LeaseError",
    "Secret",
    "SecretNotFound",
    "SecretStore",
    "SecretsError",
]


class SecretsError(Exception):
    pass


class SecretNotFound(SecretsError):
    pass


class InvalidPath(SecretsError):
    pass


class LeaseError(SecretsError):
    pass


@dataclass(frozen=True)
class Secret:
    path: str
    version: int
    data: Mapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return f"Secret(path={self.path!r}, version={self.version}, data=<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True)
class Lease:
    id: str
    path: str
    expires_at: float
    data: Mapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return f"Lease(id={self.id!r}, path={self.path!r}, data=<redacted>)"

    __str__ = __repr__


@runtime_checkable
class SecretStore(Protocol):
    def put(self, path: str, data: Mapping[str, str]) -> int:
        """Write a new version (1, 2, ...).  Paths are ``a/b/c``: no empty segment, no ``..``.
        The store keeps its own copy: changing ``data`` afterwards changes nothing stored."""

    def get(self, path: str, version: int | None = None) -> Secret:
        """Latest (or given) version.  Raises SecretNotFound, also for a version that was never
        written: ``0`` and negative versions are absent, never "latest" or "counted from the
        end".  A version is an ``int``: anything else (``True``, ``1.0``, ``"2"``, ``nan``,
        ``inf``) names no version and raises SecretNotFound too - it is never coerced."""

    def delete(self, path: str) -> None:
        """Remove every version, for good: a later ``put`` starts a fresh history at version 1,
        and no deleted version is readable again.  Raises SecretNotFound if absent."""

    def list(self, prefix: str = "") -> Sequence[str]:
        """Paths only, sorted, never values; a deleted path is not listed under any prefix."""

    def lease(self, path: str, ttl: float) -> Lease:
        """A time-limited read; ``data`` is the holder's own copy, like ``get``'s (of any
        version): changing it reaches neither the store nor another lease.  Raises SecretNotFound, or
        LeaseError for a ttl that is not a positive, finite number of seconds (``nan`` and
        ``inf`` included: either would be a read that never expires), before anything is
        granted."""

    def lease_valid(self, lease_id: str) -> bool: ...

    def revoke(self, lease_id: str) -> None:
        """Idempotent."""
