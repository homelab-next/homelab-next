# SPDX-License-Identifier: Apache-2.0
"""``idp``: token issue and verify - altered, expired, revoked or garbage tokens never pass."""

from __future__ import annotations

from conformance.fakes.identity import FakeIdentityProvider, UnsignedIdentityProvider
from conformance.protocols.idp import Forbidden, InvalidToken
from homelabnext.conform.core import Mutant, Skip, Suite

from ._util import raises, uniq

SUITE = Suite(
    "idp",
    "issue/verify short-lived bearer tokens; forged, expired, revoked and garbage tokens fail",
    "conformance.protocols.idp:IdentityProvider",
)


@SUITE.check("issue-verify-roundtrip", "verify returns the subject and scopes that were issued")
def _(p):
    who = uniq("user")
    claims = p.verify(p.issue(who, ["read", "write"], 60))
    assert claims.subject == who and set(claims.scopes) == {"read", "write"}, f"claims {claims}"


@SUITE.check("tokens-are-unique", "two tokens for the same subject differ")
def _(p):
    who = uniq("user")
    assert p.issue(who, ["read"], 60) != p.issue(who, ["read"], 60)


@SUITE.check("expiry-matches-ttl", "expires_at - issued_at equals the requested ttl")
def _(p):
    c = p.verify(p.issue(uniq("user"), ["read"], 120))
    assert abs((c.expires_at - c.issued_at) - 120) < 1.5, f"lifetime {c.expires_at - c.issued_at}"


@SUITE.check(
    "altered-token-rejected", "changing a character in the middle of a token invalidates it"
)
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    for pos in (len(tok) // 4, len(tok) // 2):
        swap = "A" if tok[pos] != "A" else "B"
        bad = tok[:pos] + swap + tok[pos + 1 :]
        raises(lambda b=bad: p.verify(b), f"token altered at {pos}", InvalidToken)


@SUITE.check("payload-splice-rejected", "one token's payload with another's signature is forged")
def _(p):
    a = p.issue(uniq("alice"), ["read"], 60)
    b = p.issue(uniq("mallory"), ["admin"], 60)
    if a.count(".") != 1:
        raise Skip("tokens are opaque (no payload.signature structure)")
    forged = b.split(".")[0] + "." + a.split(".")[1]
    raises(lambda: p.verify(forged), "spliced token", InvalidToken)


@SUITE.check("unsigned-token-rejected", "a payload with no signature is not a token")
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    if tok.count(".") != 1:
        raise Skip("tokens are opaque (no payload.signature structure)")
    raises(lambda: p.verify(tok.split(".")[0] + "."), "unsigned token", InvalidToken)
    raises(lambda: p.verify(tok.split(".")[0]), "payload only", InvalidToken)


@SUITE.check("garbage-is-invalid-not-a-crash", "empty and nonsense strings raise InvalidToken only")
def _(p):
    for junk in ("", " ", "x", "....", "a.b", "e30.e30", "\u0000", "A" * 5000):
        raises(lambda j=junk: p.verify(j), f"garbage {junk[:8]!r}", InvalidToken)


@SUITE.check(
    "expired-token-rejected",
    "a token is invalid once its ttl has passed",
    requires=["clock-control"],
)
def _(p):
    tok = p.issue(uniq("user"), ["read"], 30)
    p.verify(tok)
    p.tick(31)
    raises(lambda: p.verify(tok), "expired token", InvalidToken)


@SUITE.check("scope-enforced", "a valid token without the required scope is Forbidden, not invalid")
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    assert p.verify(tok, required_scope="read").scopes == ("read",)
    exc = raises(lambda: p.verify(tok, required_scope="admin"), "missing scope", Forbidden)
    assert isinstance(exc, Forbidden)


@SUITE.check("revoked-token-rejected", "a revoked token fails verification")
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    p.revoke(tok)
    raises(lambda: p.verify(tok), "revoked token", InvalidToken)


@SUITE.check("revoke-is-idempotent-and-total", "revoking twice or revoking garbage is harmless")
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    p.revoke(tok)
    p.revoke(tok)
    p.revoke("not-a-token")


@SUITE.check("issue-validates-input", "empty subject and non-positive ttl are refused")
def _(p):
    raises(lambda: p.issue("", ["read"], 60), "empty subject", ValueError)
    raises(lambda: p.issue(uniq("user"), ["read"], 0), "ttl 0", ValueError)
    raises(lambda: p.issue(uniq("user"), ["read"], -5), "negative ttl", ValueError)


def make_fake():
    return FakeIdentityProvider()


MUTANTS = {
    "signature-not-checked": Mutant(
        UnsignedIdentityProvider,
        "payload-splice-rejected",
        "verify trusts the payload without checking the signature",
    ),
}
