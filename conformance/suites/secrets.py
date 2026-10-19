# SPDX-License-Identifier: Apache-2.0
"""``secrets``: versioned secrets with leases - and no value ever in an error or a repr."""

from __future__ import annotations

from conformance.fakes.secret_store import (
    ChainedLeakSecretStore,
    FakeSecretStore,
    LeakyErrorSecretStore,
    NegativeTtlSecretStore,
    NeverExpiringSecretStore,
    UnknownLeaseValidSecretStore,
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


@SUITE.check(
    "errors-never-contain-values",
    "no error - message, repr, attributes, cause chain or traceback - includes a secret value",
)
def _(s):
    text = []
    for fn in (
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


@SUITE.check("lease-ttl-must-be-positive", "a zero or negative ttl is refused")
def _(s):
    p = _path(s)
    s.put(p, {"k": "v"})
    for ttl in (0, -5, -0.5):
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
