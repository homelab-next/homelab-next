# SPDX-License-Identifier: Apache-2.0
"""``secrets``: versioned secrets with leases - and no value ever in an error or a repr."""

from __future__ import annotations

from conformance.fakes.secret_store import FakeSecretStore, LeakyErrorSecretStore
from conformance.protocols.secrets import (
    InvalidPath,
    LeaseError,
    SecretNotFound,
)
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

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


@SUITE.check("missing-secret-raises", "an absent path or version raises SecretNotFound")
def _(s):
    p = _path(s)
    raises(lambda: s.get(p), "absent path", SecretNotFound)
    s.put(p, {"k": "v"})
    raises(lambda: s.get(p, version=9), "absent version", SecretNotFound)


@SUITE.check("delete-removes-all-versions", "after delete the path is gone; deleting again raises")
def _(s):
    p = _path(s)
    s.put(p, {"k": "v"})
    s.delete(p)
    raises(lambda: s.get(p), "get after delete", SecretNotFound)
    raises(lambda: s.delete(p), "second delete", SecretNotFound)


@SUITE.check("invalid-paths-rejected", "empty segments and '..' are refused")
def _(s):
    for bad in ("", "a//b", "../x", "a/../b", "/lead"):
        raises(lambda b=bad: s.put(b, {"k": "v"}), f"path {bad!r}", InvalidPath, ValueError)


@SUITE.check("errors-never-contain-values", "no error message includes a submitted secret value")
def _(s):
    text = []
    for fn in (
        lambda: s.put("../bad", {"password": VALUE}),
        lambda: s.put("", {"password": VALUE}),
        lambda: s.get(_path(s)),
        lambda: s.get("../" + _path(s)),
    ):
        try:
            fn()
        except Exception as exc:
            text.append(f"{exc} {exc!r}")
    assert text, "no error was raised at all"
    leaked = [t for t in text if VALUE in t]
    assert not leaked, f"secret value appeared in an error: {leaked[0][:120]}"


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


@SUITE.check("lease-ttl-must-be-positive", "a zero or negative ttl is refused")
def _(s):
    p = _path(s)
    s.put(p, {"k": "v"})
    raises(lambda: s.lease(p, 0), "ttl 0", LeaseError, ValueError)


@SUITE.check("lease-expires", "a lease is invalid after its ttl", requires=["clock-control"])
def _(s):
    p = _path(s)
    s.put(p, {"k": "v"})
    lease = s.lease(p, 30)
    assert s.lease_valid(lease.id), "fresh lease not valid"
    s.tick(31)
    assert not s.lease_valid(lease.id), "lease still valid after ttl"


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
}
