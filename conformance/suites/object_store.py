# SPDX-License-Identifier: Apache-2.0
"""``object-store``: S3-like blobs - round trips, listing, pagination, error types."""

from __future__ import annotations

from conformance.fakes.object_store import (
    BrokenEtagObjectStore,
    BrokenListObjectStore,
    FakeObjectStore,
    PathResolvingObjectStore,
)
from conformance.protocols.object_store import NoSuchBucket, NoSuchKey, ObjectStoreError
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

SUITE = Suite(
    "object-store",
    "buckets of byte objects: put/get/head/delete and ordered, paginated listing",
    "conformance.protocols.object_store:ObjectStore",
)


def _bucket(store):
    b = uniq("bkt")
    store.create_bucket(b)
    return b


@SUITE.check("put-get-roundtrip", "bytes written are the bytes read back")
def _(store):
    b = _bucket(store)
    store.put(b, "a/b.txt", b"hello")
    assert store.get(b, "a/b.txt") == b"hello"


@SUITE.check("binary-safe", "all 256 byte values survive, including NUL and empty objects")
def _(store):
    b = _bucket(store)
    blob = bytes(range(256)) * 4
    store.put(b, "bin", blob)
    store.put(b, "empty", b"")
    assert store.get(b, "bin") == blob, "binary content altered"
    assert store.get(b, "empty") == b"", "empty object not preserved"


@SUITE.check("get-missing-key-raises", "a missing key raises NoSuchKey, not None or empty bytes")
def _(store):
    b = _bucket(store)
    exc = raises(lambda: store.get(b, "nope"), "missing key", NoSuchKey)
    assert isinstance(exc, NoSuchKey), f"wrong error type {type(exc).__name__}"


@SUITE.check("missing-bucket-raises", "operations on a missing bucket raise NoSuchBucket")
def _(store):
    ghost = uniq("ghost")
    for name, fn in (
        ("put", lambda: store.put(ghost, "k", b"x")),
        ("get", lambda: store.get(ghost, "k")),
        ("list", lambda: store.list(ghost)),
    ):
        exc = raises(fn, f"{name} on missing bucket", NoSuchBucket, NoSuchKey)
        assert isinstance(exc, NoSuchBucket), f"{name}: raised {type(exc).__name__}"


@SUITE.check("overwrite-last-writer-wins", "a second put replaces the object")
def _(store):
    b = _bucket(store)
    store.put(b, "k", b"one")
    store.put(b, "k", b"two-longer")
    assert store.get(b, "k") == b"two-longer"
    assert store.head(b, "k").size == len(b"two-longer")


@SUITE.check("etag-tracks-content", "equal content has an equal etag; different content differs")
def _(store):
    b = _bucket(store)
    e1 = store.put(b, "x", b"aaaa").etag
    e2 = store.put(b, "y", b"aaaa").etag
    e3 = store.put(b, "z", b"bbbb").etag
    assert e1 == e2, "same content produced different etags"
    assert e1 != e3, "different content (same size) produced the same etag"
    assert store.head(b, "x").etag == e1, "head etag differs from put etag"


@SUITE.check("delete-is-idempotent", "deleting a missing key is not an error; the key is gone")
def _(store):
    b = _bucket(store)
    store.put(b, "k", b"v")
    store.delete(b, "k")
    store.delete(b, "k")
    raises(lambda: store.get(b, "k"), "get after delete", NoSuchKey)


@SUITE.check("list-prefix-and-order", "listing filters by prefix and is ordered by key")
def _(store):
    b = _bucket(store)
    for k in ("logs/b", "logs/a", "data/z", "logs/c", "logsx"):
        store.put(b, k, b"1")
    page = store.list(b, "logs/")
    assert list(page.keys) == ["logs/a", "logs/b", "logs/c"], f"got {list(page.keys)}"
    assert page.next is None, "a complete listing must not return a continuation token"


@SUITE.check("list-pagination-complete", "paging visits every key exactly once, in order")
def _(store):
    b = _bucket(store)
    keys = [f"p/{i:03d}" for i in range(11)]
    for k in keys:
        store.put(b, k, b"1")
    seen: list[str] = []
    after = None
    for _ in range(50):
        page = store.list(b, "p/", limit=4, after=after)
        assert len(page.keys) <= 4, f"page larger than limit: {len(page.keys)}"
        seen += page.keys
        if page.next is None:
            break
        after = page.next
    else:
        raise AssertionError("pagination did not terminate")
    assert seen == keys, f"expected {keys}, got {seen}"


@SUITE.check("unicode-and-slash-keys", "keys are opaque text: unicode and '/' work")
def _(store):
    b = _bucket(store)
    keys = ["dir/sub/obj", "résumé.txt", "日本/語"]
    for k in keys:
        store.put(b, k, k.encode("utf-8"))
    for k in keys:
        assert store.get(b, k) == k.encode("utf-8"), f"key {k!r} lost"


@SUITE.check(
    "keys-never-escape-the-bucket",
    "'..' keys are stored verbatim or refused; buckets never see each other's objects",
)
def _(store):
    a, b = _bucket(store), _bucket(store)
    store.put(a, "secret", b"bucket-a")
    store.put(a, "x", b"a-x")
    raises(lambda: store.get(b, "secret"), "another bucket's key", NoSuchKey)
    assert "secret" not in store.list(b).keys, "a bucket lists another bucket's key"
    for key in ("../x", "a/../../b", f"../{a}/secret", f"x/../../{a}/secret", "./x"):
        try:
            store.put(b, key, b"evil")
        except (ValueError, ObjectStoreError):
            raises(lambda k=key: store.get(b, k), f"refused key {key!r}", NoSuchKey, ValueError)
            continue
        assert store.get(b, key) == b"evil", f"key {key!r} not stored under itself"
    assert store.get(a, "secret") == b"bucket-a", "a '..' key overwrote another bucket's object"
    assert store.get(a, "x") == b"a-x", "a '..' key overwrote another key"
    for key in (f"../{a}/secret", f"x/../../{a}/secret"):
        try:
            got = store.get(b, key)
        except (NoSuchKey, ValueError, ObjectStoreError):
            continue
        assert got != b"bucket-a", f"key {key!r} read another bucket's object"


@SUITE.check(
    "user-metadata-preserved",
    "metadata supplied on put comes back from head",
    severity="should",
    requires=["metadata"],
)
def _(store):
    b = _bucket(store)
    store.put(b, "m", b"x", metadata={"owner": "team-a"})
    assert dict(store.head(b, "m").metadata).get("owner") == "team-a"


def make_fake():
    return FakeObjectStore()


MUTANTS = {
    "pagination-drops-boundary-key": Mutant(
        BrokenListObjectStore,
        "list-pagination-complete",
        "the last key of each truncated page is lost",
    ),
    "weak-etag": Mutant(
        BrokenEtagObjectStore, "etag-tracks-content", "etag depends on the size only"
    ),
    "keys-resolved-as-paths": Mutant(
        PathResolvingObjectStore,
        "keys-never-escape-the-bucket",
        "bucket/key is normalised as a path, so '..' reaches other keys and buckets",
    ),
}
