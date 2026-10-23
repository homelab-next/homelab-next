# SPDX-License-Identifier: Apache-2.0
"""``secrets``: versioned secrets with leases - and no value ever in an error or a repr."""

from __future__ import annotations

import contextlib

from conformance.fakes.secret_store import (
    AliasingSecretStore,
    ChainedLeakSecretStore,
    CoercingVersionSecretStore,
    DeletesLatestOnlySecretStore,
    FakeSecretStore,
    LeakyErrorSecretStore,
    LeaseAliasingSecretStore,
    ListsDeletedSecretStore,
    NegativeTtlSecretStore,
    NegativeVersionSecretStore,
    NeverExpiringSecretStore,
    NonFiniteLeaseSecretStore,
    TombstoneSecretStore,
    UnknownLeaseValidSecretStore,
    VersionErrorLeaksSecretStore,
    VersionZeroIsLatestSecretStore,
)
from conformance.protocols.secrets import (
    InvalidPath,
    LeaseError,
    SecretNotFound,
)
from homelabnext.conform.core import Mutant, Suite

from ._util import exc_text, expires, raises, uniq

SUITE = Suite(
    "secrets",
    "versioned key-value secrets with leases and redacted errors",
    "conformance.protocols.secrets:SecretStore",
)

VALUE = "s3cr3t-value-DO-NOT-LEAK"


def _path(s):
    return f"conf/{uniq('p')}"


@SUITE.check("put-get-roundtrip", "the stored mapping is read back unchanged")
def _(s):
    p = _path(s)
    s.put(p, {"user": "svc", "password": VALUE})
    assert dict(s.get(p).data) == {"user": "svc", "password": VALUE}


@SUITE.check("versions-increase-and-stay-readable", "every put is a new version; old ones remain")
def _(s):
    p = _path(s)
    v1 = s.put(p, {"k": "one"})
    v2 = s.put(p, {"k": "two"})
    assert (v1, v2) == (1, 2), f"versions {v1}, {v2}"
    assert dict(s.get(p).data) == {"k": "two"}, "latest is not the newest version"
    assert dict(s.get(p, version=1).data) == {"k": "one"}, "old version unreadable"


@SUITE.check(
    "missing-secret-raises",
    "an absent path or version raises SecretNotFound; versions are ints from 1 (0, -1, True, 1.0 "
    "and '2' name none)",
)
def _(s):
    p = _path(s)
    raises(lambda: s.get(p), "absent path", SecretNotFound)
    s.put(p, {"k": "one"})
    s.put(p, {"k": "two"})
    for v in (3, 9, 0, -1, -2):
        raises(lambda v=v: s.get(p, version=v), f"absent version {v}", SecretNotFound)
    # not an int: never coerced into one (True is 1, 1.9 truncates to 1, "2" parses to 2)
    for v in (True, False, 1.0, 1.9, "2", float("nan"), float("inf")):
        raises(lambda v=v: s.get(p, version=v), f"version {v!r}", SecretNotFound)


@SUITE.check(
    "delete-removes-all-versions",
    "after delete no version is readable, the path is not listed, deleting again raises, and a "
    "new put starts a fresh history",
)
def _(s):
    p = _path(s)
    s.put(p, {"k": "one"})
    s.put(p, {"k": "two"})
    s.delete(p)
    raises(lambda: s.get(p), "get after delete", SecretNotFound)
    for v in (1, 2):
        raises(lambda v=v: s.get(p, version=v), f"version {v} after delete", SecretNotFound)
    parent = p.rsplit("/", 1)[0] + "/"
    for prefix in (p, parent, ""):
        assert p not in list(s.list(prefix)), f"a deleted path is still listed under {prefix!r}"
    raises(lambda: s.delete(p), "second delete", SecretNotFound)
    # deleted for good: writing the path again starts over, it does not revive the old history
    assert s.put(p, {"k": "three"}) == 1, "a put after delete continued the deleted numbering"
    assert dict(s.get(p, version=1).data) == {"k": "three"}, "version 1 is the deleted secret"
    raises(lambda: s.get(p, version=2), "version 2 of the new history", SecretNotFound)


@SUITE.check(
    "stored-data-is-a-copy",
    "changing the mapping given to put, or the one get returned, does not change the secret",
)
def _(s):
    p = _path(s)
    given = {"password": VALUE}
    s.put(p, given)
    given["password"] = "rewritten-by-caller"
    given["extra"] = "added-by-caller"
    got = s.get(p)
    assert dict(got.data) == {"password": VALUE}, "the caller's later change reached the store"
    with contextlib.suppress(TypeError):  # a read-only mapping is fine too
        got.data["password"] = "rewritten-through-get"  # type: ignore[index]
    assert dict(s.get(p).data) == {"password": VALUE}, "a returned mapping is the stored one"
    leased = s.lease(p, 300)
    with contextlib.suppress(TypeError):
        leased.data["password"] = "rewritten-through-lease"  # type: ignore[index]
    assert dict(s.get(p).data) == {"password": VALUE}, "a lease's mapping is the stored one"


@SUITE.check("invalid-paths-rejected", "empty segments and '..' are refused")
def _(s):
    for bad in ("", "a//b", "../x", "a/../b", "/lead"):
        raises(lambda b=bad: s.put(b, {"k": "v"}), f"path {bad!r}", InvalidPath, ValueError)


@SUITE.check(
    "errors-never-contain-values",
    "no error - message, repr, attributes, cause chain or traceback - includes a secret value",
)
def _(s):
    text = []
    held = _path(s)  # a path that holds the value: its "no such version" errors must not echo it
    s.put(held, {"password": VALUE})
    for fn in (
        lambda: s.get(held, version=99),
        lambda: s.get(held, version=0),
        lambda: s.get(held, version=-1),
        lambda: s.put("../bad", {"password": VALUE}),
        lambda: s.put("", {"password": VALUE}),
        lambda: s.put("a//b", {"password": VALUE}),
        lambda: s.get(_path(s)),
        lambda: s.get("../" + _path(s)),
        lambda: s.lease(_path(s), 30),
    ):
        try:
            fn()
        except Exception as exc:
            text.append(exc_text(exc))
    assert text, "no error was raised at all"
    leaked = [t for t in text if VALUE in t]
    assert not leaked, "secret value appeared in an error (message, chain, attributes or traceback)"


@SUITE.check("repr-is-redacted", "repr/str of a returned secret hides the value")
def _(s):
    p = _path(s)
    s.put(p, {"password": VALUE})
    sec = s.get(p)
    assert VALUE not in repr(sec) and VALUE not in str(sec), f"value shown in {sec!r}"


@SUITE.check("list-returns-paths-only", "listing shows sorted paths and never values")
def _(s):
    base = f"conf/{uniq('l')}"
    for leaf in ("b", "a"):
        s.put(f"{base}/{leaf}", {"k": VALUE})
    got = list(s.list(base))
    assert got == [f"{base}/a", f"{base}/b"], f"got {got}"
    assert all(VALUE not in str(x) for x in got)


@SUITE.check(
    "lease-ttl-must-be-positive", "a zero, negative or non-finite (nan, inf) ttl is refused"
)
def _(s):
    p = _path(s)
    s.put(p, {"k": "v"})
    for ttl in (0, -5, -0.5, float("nan"), float("inf"), float("-inf")):
        raises(lambda t=ttl: s.lease(p, t), f"ttl {ttl}", LeaseError, ValueError)


@SUITE.check(
    "lease-expires",
    "a lease is invalid after its ttl (clock hook if offered, else real time; never skipped)",
)
def _(s):
    p = _path(s)
    s.put(p, {"k": "v"})
    lease = s.lease(p, 1)
    assert s.lease_valid(lease.id), "fresh lease not valid"
    assert expires(s, lambda: s.lease_valid(lease.id), 1), "lease still valid after its ttl"


@SUITE.check("unknown-lease-invalid", "a lease id the store never issued is not valid")
def _(s):
    p = _path(s)
    s.put(p, {"k": "v"})
    real = s.lease(p, 300)
    for ghost in (uniq("lease-ghost"), "", real.id + "x", "lease-0"):
        assert not s.lease_valid(ghost), f"never-issued lease id {ghost!r} reported valid"


@SUITE.check("revoke-ends-lease", "a revoked lease is invalid; revoking twice is harmless")
def _(s):
    p = _path(s)
    s.put(p, {"k": "v"})
    lease = s.lease(p, 300)
    s.revoke(lease.id)
    s.revoke(lease.id)
    assert not s.lease_valid(lease.id), "lease valid after revoke"


def make_fake():
    return FakeSecretStore()


MUTANTS = {
    "error-leaks-value": Mutant(
        LeakyErrorSecretStore,
        "errors-never-contain-values",
        "the invalid-path error echoes the submitted values",
    ),
    "error-cause-leaks-value": Mutant(
        ChainedLeakSecretStore,
        "errors-never-contain-values",
        "the invalid-path error is raised from an exception that carries the values",
    ),
    "version-error-leaks-value": Mutant(
        VersionErrorLeaksSecretStore,
        "errors-never-contain-values",
        "the no-such-version error of a path that holds a secret echoes the latest value",
    ),
    "version-zero-is-latest": Mutant(
        VersionZeroIsLatestSecretStore,
        "missing-secret-raises",
        "version 0 is read as no version, so it returns the latest",
    ),
    "negative-version-indexes-from-end": Mutant(
        NegativeVersionSecretStore,
        "missing-secret-raises",
        "a negative version reads an older version through Python negative indexing",
    ),
    "delete-drops-latest-only": Mutant(
        DeletesLatestOnlySecretStore,
        "delete-removes-all-versions",
        "delete removes the latest version and leaves the older ones readable",
    ),
    "stores-caller-mapping": Mutant(
        AliasingSecretStore,
        "stored-data-is-a-copy",
        "the caller's mapping is stored and returned by reference",
    ),
    "version-coerced": Mutant(
        CoercingVersionSecretStore,
        "missing-secret-raises",
        "the version is coerced with int(): True reads 1, 1.9 reads 1, '2' reads 2",
    ),
    "put-after-delete-revives-history": Mutant(
        TombstoneSecretStore,
        "delete-removes-all-versions",
        "delete tombstones the path and a later put revives the deleted versions",
    ),
    "deleted-path-listed-under-parent": Mutant(
        ListsDeletedSecretStore,
        "delete-removes-all-versions",
        "a deleted path is still listed under its parent prefix",
    ),
    "lease-shares-stored-mapping": Mutant(
        LeaseAliasingSecretStore,
        "stored-data-is-a-copy",
        "lease hands back the stored mapping, so changing lease.data rewrites the secret",
    ),
    "non-finite-lease-ttl-accepted": Mutant(
        NonFiniteLeaseSecretStore,
        "lease-ttl-must-be-positive",
        "a nan or inf lease ttl is accepted (the reference fake did this)",
    ),
    "lease-never-expires": Mutant(
        NeverExpiringSecretStore, "lease-expires", "lease_valid ignores the expiry time"
    ),
    "unknown-lease-valid": Mutant(
        UnknownLeaseValidSecretStore, "unknown-lease-invalid", "any unknown lease id is valid"
    ),
    "negative-ttl-accepted": Mutant(
        NegativeTtlSecretStore, "lease-ttl-must-be-positive", "only ttl == 0 is refused"
    ),
}
