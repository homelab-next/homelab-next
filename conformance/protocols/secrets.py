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
        """Write a new version (1, 2, ...).  Paths are ``a/b/c``: no empty segment, no ``..``."""

    def get(self, path: str, version: int | None = None) -> Secret:
        """Latest (or given) version.  Raises SecretNotFound."""

    def delete(self, path: str) -> None:
        """Remove every version.  Raises SecretNotFound if absent."""

    def list(self, prefix: str = "") -> Sequence[str]:
        """Paths only, sorted, never values."""

    def lease(self, path: str, ttl: float) -> Lease:
        """A time-limited read.  Raises SecretNotFound, or LeaseError for ttl <= 0."""

    def lease_valid(self, lease_id: str) -> bool: ...

    def revoke(self, lease_id: str) -> None:
        """Idempotent."""
