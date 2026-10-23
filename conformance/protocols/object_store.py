# SPDX-License-Identifier: Apache-2.0
"""Contract for ``object-store``: S3-like blobs in buckets.

Deliberately the common subset of S3, MinIO, Ceph and a directory on disk.  Keys are opaque text
(``/`` is just a character), values are bytes.  Keys are never resolved as paths: ``../x`` and
``a/../../b`` are either stored under exactly that key or refused (``ValueError`` /
``ObjectStoreError``), and ``a//b``, ``a/./b`` and ``./x`` are keys of their own, never another
name for ``a/b`` or ``x``.  A bucket is its own namespace, not a prefix of one flat key space: no
key reaches an object of another bucket, even when one bucket's name extends the other's
(``b`` + ``1k`` is not ``b1`` + ``k``).  ``list`` is by prefix, ordered by key (code-point order of
the UTF-8 bytes), paginated with an opaque ``next`` token, and names existing objects only: a
deleted key is not listed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = [
    "ListPage",
    "NoSuchBucket",
    "NoSuchKey",
    "ObjectInfo",
    "ObjectStore",
    "ObjectStoreError",
]


class ObjectStoreError(Exception):
    pass


class NoSuchBucket(ObjectStoreError):
    pass


class NoSuchKey(ObjectStoreError):
    pass


@dataclass(frozen=True)
class ObjectInfo:
    key: str
    size: int
    etag: str  # changes if and only if the content changes
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ListPage:
    keys: tuple[str, ...]
    next: str | None  # None when this is the last page


@runtime_checkable
class ObjectStore(Protocol):
    def create_bucket(self, bucket: str) -> None:
        """Idempotent: creating an existing bucket is not an error."""

    def put(
        self, bucket: str, key: str, data: bytes, *, metadata: Mapping[str, str] | None = None
    ) -> ObjectInfo:
        """Create or overwrite (last writer wins).  Raises NoSuchBucket."""

    def get(self, bucket: str, key: str) -> bytes:
        """Raises NoSuchBucket / NoSuchKey."""

    def head(self, bucket: str, key: str) -> ObjectInfo:
        """Raises NoSuchBucket / NoSuchKey."""

    def delete(self, bucket: str, key: str) -> None:
        """Idempotent: deleting a missing key is not an error.  Raises NoSuchBucket."""

    def list(
        self, bucket: str, prefix: str = "", *, limit: int = 1000, after: str | None = None
    ) -> ListPage:
        """Keys with ``prefix`` in order; at most ``limit`` per page; ``after`` is a ``next``."""
