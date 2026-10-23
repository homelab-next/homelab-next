# SPDX-License-Identifier: Apache-2.0
"""In-memory S3-like object store (the ``object-store`` fake) and its defective twin."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from conformance.protocols.object_store import ListPage, NoSuchBucket, NoSuchKey, ObjectInfo


class FakeObjectStore:
    features = frozenset({"metadata"})

    def __init__(self) -> None:
        self._b: dict[str, dict[str, tuple[bytes, dict[str, str]]]] = {}

    def create_bucket(self, bucket: str) -> None:
        self._b.setdefault(bucket, {})

    def _bucket(self, bucket: str) -> dict[str, tuple[bytes, dict[str, str]]]:
        try:
            return self._b[bucket]
        except KeyError:
            raise NoSuchBucket(bucket) from None

    @staticmethod
    def _etag(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()[:32]

    def put(
        self, bucket: str, key: str, data: bytes, *, metadata: Mapping[str, str] | None = None
    ) -> ObjectInfo:
        if not isinstance(data, bytes | bytearray):
            raise TypeError("data must be bytes")
        meta = dict(metadata or {})
        self._bucket(bucket)[key] = (bytes(data), meta)
        return ObjectInfo(key, len(data), self._etag(bytes(data)), meta)

    def get(self, bucket: str, key: str) -> bytes:
        try:
            return self._bucket(bucket)[key][0]
        except KeyError:
            raise NoSuchKey(key) from None

    def head(self, bucket: str, key: str) -> ObjectInfo:
        data, meta = self._bucket(bucket).get(key, (None, None))  # type: ignore[assignment]
        if data is None:
            raise NoSuchKey(key)
        return ObjectInfo(key, len(data), self._etag(data), dict(meta))

    def delete(self, bucket: str, key: str) -> None:
        self._bucket(bucket).pop(key, None)

    def list(
        self, bucket: str, prefix: str = "", *, limit: int = 1000, after: str | None = None
    ) -> ListPage:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        keys = sorted(
            (k for k in self._bucket(bucket) if k.startswith(prefix)),
            key=lambda k: k.encode("utf-8"),
        )
        if after is not None:
            keys = [k for k in keys if k.encode("utf-8") > after.encode("utf-8")]
        page = keys[:limit]
        more = len(keys) > limit
        return ListPage(tuple(page), page[-1] if more else None)


class BrokenListObjectStore(FakeObjectStore):
    """Pagination bug: the last key of every truncated page is dropped but the cursor moves on."""

    def list(self, bucket, prefix="", *, limit=1000, after=None):
        page = super().list(bucket, prefix, limit=limit, after=after)
        if page.next is None:
            return page
        return ListPage(page.keys[:-1], page.next)


class BrokenEtagObjectStore(FakeObjectStore):
    """The etag is derived from the size only, so different content can share an etag."""

    @staticmethod
    def _etag(data: bytes) -> str:
        return f"len-{len(data)}"


class PathResolvingObjectStore(FakeObjectStore):
    """A directory-on-disk store that resolves ``bucket/key`` as a path, so ``..`` escapes."""

    def _where(self, bucket: str, key: str) -> tuple[str, str]:
        import posixpath

        self._bucket(bucket)
        full = posixpath.normpath(posixpath.join("/", bucket, key)).lstrip("/")
        b, _, k = full.partition("/")
        return (b, k) if b in self._b else (bucket, k or key)

    def put(self, bucket, key, data, *, metadata=None):
        return super().put(*self._where(bucket, key), data, metadata=metadata)

    def get(self, bucket, key):
        return super().get(*self._where(bucket, key))


class DeleteEveryBucketObjectStore(FakeObjectStore):
    """Defect: ``delete(bucket, key)`` removes ``key`` from every bucket, not just ``bucket``."""

    def delete(self, bucket: str, key: str) -> None:
        self._bucket(bucket)
        for objects in self._b.values():
            objects.pop(key, None)


class HeadMissingIsEmptyObjectStore(FakeObjectStore):
    """Defect: ``head`` of a missing key returns a zero-size object instead of NoSuchKey."""

    def head(self, bucket: str, key: str) -> ObjectInfo:
        try:
            return super().head(bucket, key)
        except NoSuchKey:
            return ObjectInfo(key, 0, "", {})


class DeleteMissingBucketObjectStore(FakeObjectStore):
    """Defect: ``delete`` on a bucket that does not exist succeeds instead of NoSuchBucket."""

    def delete(self, bucket: str, key: str) -> None:
        self._b.get(bucket, {}).pop(key, None)
