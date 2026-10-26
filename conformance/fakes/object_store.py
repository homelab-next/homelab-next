# SPDX-License-Identifier: Apache-2.0
"""In-memory S3-like object store (the ``object-store`` fake) and its defective twin."""

from __future__ import annotations

import hashlib
import urllib.parse
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


class FlatKeyspaceObjectStore(FakeObjectStore):
    """Defect: one flat namespace keyed ``bucket + key`` with no separator (a KV-backed store):
    bucket ``b`` key ``1k`` is bucket ``b1`` key ``k``, and listing ``b`` shows ``b1``'s keys."""

    _sep = ""

    def __init__(self) -> None:
        super().__init__()
        self._flat: dict[str, tuple[bytes, dict[str, str]]] = {}

    def put(self, bucket, key, data, *, metadata=None):
        info = super().put(bucket, key, data, metadata=metadata)
        self._flat[bucket + self._sep + key] = self._b[bucket][key]
        return info

    def get(self, bucket, key):
        self._bucket(bucket)
        try:
            return self._flat[bucket + self._sep + key][0]
        except KeyError:
            raise NoSuchKey(key) from None

    def delete(self, bucket, key):
        self._bucket(bucket)
        self._flat.pop(bucket + self._sep + key, None)
        self._b[bucket].pop(key, None)

    def list(self, bucket, prefix="", *, limit=1000, after=None):
        self._bucket(bucket)
        keys = sorted(
            (
                k[len(bucket + self._sep) :]
                for k in self._flat
                if k.startswith(bucket + self._sep + prefix)
            ),
            key=lambda k: k.encode("utf-8"),
        )
        if after is not None:
            keys = [k for k in keys if k.encode("utf-8") > after.encode("utf-8")]
        page = keys[:limit]
        return ListPage(tuple(page), page[-1] if len(keys) > limit else None)


class PathCollapsingObjectStore(FakeObjectStore):
    """Defect: a directory-backed store that builds paths from keys: ``a//b``, ``a/./b`` and
    ``./x`` collapse to ``a/b`` and ``x`` (``..`` is kept, so nothing escapes), and distinct keys
    alias one object."""

    @staticmethod
    def _norm(key: str) -> str:
        parts = [p for p in key.split("/") if p not in ("", ".")]
        return "/".join(parts) if parts else key

    def put(self, bucket, key, data, *, metadata=None):
        return super().put(bucket, self._norm(key), data, metadata=metadata)

    def get(self, bucket, key):
        return super().get(bucket, self._norm(key))

    def head(self, bucket, key):
        return super().head(bucket, self._norm(key))

    def delete(self, bucket, key):
        return super().delete(bucket, self._norm(key))


class ListsDeletedObjectStore(FakeObjectStore):
    """Defect: ``delete`` removes the object but leaves its entry in the listing index."""

    def __init__(self) -> None:
        super().__init__()
        self._ghosts: dict[str, set[str]] = {}

    def delete(self, bucket, key):
        super().delete(bucket, key)
        self._ghosts.setdefault(bucket, set()).add(key)

    def put(self, bucket, key, data, *, metadata=None):
        self._ghosts.get(bucket, set()).discard(key)
        return super().put(bucket, key, data, metadata=metadata)

    def list(self, bucket, prefix="", *, limit=1000, after=None):
        known = {*self._bucket(bucket), *self._ghosts.get(bucket, ())}
        keys = sorted((k for k in known if k.startswith(prefix)), key=lambda k: k.encode("utf-8"))
        if after is not None:
            keys = [k for k in keys if k.encode("utf-8") > after.encode("utf-8")]
        page = keys[:limit]
        return ListPage(tuple(page), page[-1] if len(keys) > limit else None)


class _KeyMappingObjectStore(FakeObjectStore):
    """Base of the defects that map a key to a stored name before every operation."""

    def _k(self, bucket: str, key: str) -> str:
        raise NotImplementedError

    def put(self, bucket, key, data, *, metadata=None):
        info = super().put(bucket, self._k(bucket, key), data, metadata=metadata)
        return ObjectInfo(key, info.size, info.etag, info.metadata)

    def get(self, bucket, key):
        return super().get(bucket, self._k(bucket, key))

    def head(self, bucket, key):
        return super().head(bucket, self._k(bucket, key))

    def delete(self, bucket, key):
        return super().delete(bucket, self._k(bucket, key))


class FormDecodingObjectStore(_KeyMappingObjectStore):
    """Defect: an HTTP-fronted store that form-decodes keys (``unquote_plus``), the classic S3
    ``+``/space and ``%2F`` bug: ``a+b`` is ``a b`` and ``a%2Fb`` is ``a/b``."""

    def _k(self, bucket, key):
        return urllib.parse.unquote_plus(key)


class CaseFoldingObjectStore(_KeyMappingObjectStore):
    """Defect: a directory-backed store on a case-insensitive filesystem (the macOS and Windows
    default): ``Report`` and ``report`` are one object."""

    def _k(self, bucket, key):
        for k in self._bucket(bucket):
            if k.casefold() == key.casefold():
                return k
        return key


class DottedFlatKeyspaceObjectStore(FlatKeyspaceObjectStore):
    """Defect: one flat ``bucket.key`` space (NATS KV and Redis style): with an S3-legal dotted
    bucket name, bucket ``x`` key ``y.k`` is bucket ``x.y`` key ``k``."""

    _sep = "."
