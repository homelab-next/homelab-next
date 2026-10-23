# SPDX-License-Identifier: Apache-2.0
"""``idp``: token issue and verify - altered, expired, revoked or garbage tokens never pass."""

from __future__ import annotations

import base64
import json
import string

from conformance.fakes.identity import (
    AlgNoneIdentityProvider,
    CaseInsensitiveScopeIdentityProvider,
    CharacterScopesIdentityProvider,
    DecodedSignatureIdentityProvider,
    EmptyScopeIsNoScopeIdentityProvider,
    FakeIdentityProvider,
    NoExpiryIdentityProvider,
    NonFiniteTtlIdentityProvider,
    OAuthStringScopesIdentityProvider,
    ScopeBeforeSignatureIdentityProvider,
    ScopedSkipsRevocationIdentityProvider,
    SpaceDelimitedScopeIdentityProvider,
    SubstringScopeIdentityProvider,
    UnsignedIdentityProvider,
)
from conformance.protocols.idp import Forbidden, InvalidToken
from homelabnext.conform.core import Mutant, Suite

from ._util import expires, raises, uniq

SUITE = Suite(
    "idp",
    "issue/verify short-lived bearer tokens; forged, expired, revoked and garbage tokens fail",
    "conformance.protocols.idp:IdentityProvider",
)

# The structural forgeries below run on every token shape and never skip: a token with dots is
# treated as ``[header.]payload.signature`` (JWT and compact HMAC tokens), one without dots as an
# opaque string, for which the same intent is applied to its halves.

_URL = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
_STD = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _flip_last(tok: str) -> str:
    """Change the last character so that a *significant* bit of the signature changes.

    The low bits of a final base64 character can be padding that decoders ignore; flipping the
    top bit of its 6-bit value always changes the decoded bytes."""
    c = tok[-1]
    for alpha in (_URL, _STD):
        if c in alpha:
            return tok[:-1] + alpha[alpha.index(c) ^ 32]
    return tok[:-1] + ("A" if c != "A" else "B")


def _splice(a: str, b: str) -> str:
    """``a`` with the payload of ``b``: every part of ``a`` except the second-to-last."""
    pa, pb = a.split("."), b.split(".")
    if len(pa) >= 2 and len(pa) == len(pb):
        return ".".join([*pa[:-2], pb[-2], pa[-1]])
    half = len(a) // 2
    return b[:half] + a[half:]


def _forged(p, token, what):
    """A forged token is InvalidToken whether or not a scope is required, and whichever scope:
    the signature is checked before any claim is read (a scope test on the unverified payload
    answers Forbidden for a forgery that lacks the scope)."""
    for scope in (None, "read", "admin"):
        exc = raises(lambda s=scope: p.verify(token, required_scope=s), f"{what}, scope {scope!r}")
        assert isinstance(exc, InvalidToken), (
            f"{what}, scope {scope!r}: raised {type(exc).__name__}, not InvalidToken"
        )


@SUITE.check("issue-verify-roundtrip", "verify returns the subject and scopes that were issued")
def _(p):
    who = uniq("user")
    claims = p.verify(p.issue(who, ["read", "write"], 60))
    # scopes are a set: order is free, but each comes back whole and exactly once
    assert claims.subject == who and sorted(claims.scopes) == ["read", "write"], f"claims {claims}"


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
        _forged(p, bad, f"token altered at {pos}")


@SUITE.check("payload-splice-rejected", "one token's payload with another's signature is forged")
def _(p):
    a = p.issue(uniq("alice"), ["read"], 60)
    b = p.issue(uniq("mallory"), ["admin"], 60)
    for forged in (_splice(a, b), _splice(b, a)):
        _forged(p, forged, "spliced token")


@SUITE.check("unsigned-token-rejected", "a token with its signature emptied or removed is invalid")
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    parts = tok.split(".")
    if len(parts) >= 2:
        body = ".".join(parts[:-1])
        forged = [body + ".", body, parts[-2], parts[-2] + "."]
    else:
        forged = [tok[: len(tok) // 2], tok + ".", "." + tok]
    for f in forged:
        _forged(p, f, f"unsigned form {f[-12:]!r}")


@SUITE.check(
    "signature-tamper-rejected",
    "flipping a significant bit of the last signature character, or dropping it, invalidates",
)
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    for bad in (_flip_last(tok), tok[:-1]):
        _forged(p, bad, f"tampered ending {bad[-6:]!r}")


@SUITE.check(
    "alg-none-rejected",
    "a JWT with alg 'none' (any spelling) or an empty signature is never accepted",
)
def _(p):
    who = uniq("user")
    tok = p.issue(who, ["read"], 60)
    parts = tok.split(".")
    payloads = [
        _b64(
            json.dumps(
                {"sub": who, "scp": ["admin"], "iat": 0, "exp": 4_102_444_800, "jti": "forged"}
            ).encode()
        )
    ]
    if len(parts) == 3:
        payloads.append(parts[1])
    for alg in ("none", "None", "NONE", "nOnE", ""):
        header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
        for payload in payloads:
            for forged in (
                f"{header}.{payload}.",
                f"{header}.{payload}",
                f"{header}.{payload}.{parts[-1]}",
            ):
                raises(lambda f=forged: p.verify(f), f"alg={alg!r} token", InvalidToken)


@SUITE.check("garbage-is-invalid-not-a-crash", "empty and nonsense strings raise InvalidToken only")
def _(p):
    for junk in ("", " ", "x", "....", "a.b", "e30.e30", "\u0000", "A" * 5000):
        raises(lambda j=junk: p.verify(j), f"garbage {junk[:8]!r}", InvalidToken)


@SUITE.check(
    "expired-token-rejected",
    "a token is invalid once its ttl has passed (clock hook if offered, else real time)",
)
def _(p):
    tok = p.issue(uniq("user"), ["read"], 1)
    p.verify(tok)

    def valid() -> bool:
        try:
            p.verify(tok)
        except InvalidToken:
            return False
        return True

    assert expires(p, valid, 1), "token still verifies after its ttl"


@SUITE.check(
    "scope-enforced",
    "a valid token without the required scope is Forbidden, not invalid; scopes match exactly",
)
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    assert p.verify(tok, required_scope="read").scopes == ("read",)
    # another scope, another case, another codepoint (no NFKC): Forbidden
    for other in ("admin", "READ", "Read", "\uff52\uff45\uff41\uff44"):
        exc = raises(lambda s=other: p.verify(tok, required_scope=s), f"scope {other!r}", Forbidden)
        assert isinstance(exc, Forbidden), f"scope {other!r}: {type(exc).__name__}"
    # a required scope that is not a scope token at all (a misconfigured route): never granted;
    # Forbidden, or a louder ValueError
    for bad in ("", " read", "read "):
        raises(
            lambda s=bad: p.verify(tok, required_scope=s), f"scope {bad!r}", Forbidden, ValueError
        )
    # a scope is a whole name: neither part of a granted scope nor a run across two of them
    wide = p.issue(uniq("user"), ["readwrite", "admin"], 60)
    assert p.verify(wide, required_scope="readwrite").subject
    for part in ("read", "write", "adm", "readwrite admin", "write admin"):
        raises(lambda s=part: p.verify(wide, required_scope=s), f"scope {part!r}", Forbidden)


@SUITE.check(
    "revoked-token-rejected", "a revoked token fails verification, with or without a scope"
)
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    p.revoke(tok)
    raises(lambda: p.verify(tok), "revoked token", InvalidToken)
    raises(lambda: p.verify(tok, required_scope="read"), "revoked token, scoped", InvalidToken)


@SUITE.check("revoke-is-idempotent-and-total", "revoking twice or revoking garbage is harmless")
def _(p):
    tok = p.issue(uniq("user"), ["read"], 60)
    p.revoke(tok)
    p.revoke(tok)
    p.revoke("not-a-token")


@SUITE.check(
    "scopes-are-opaque-tokens",
    "issue refuses a scope that is not an RFC 6749 scope-token (empty, whitespace, non-ASCII) and "
    "a bare string for the scope list",
)
def _(p):
    for scopes in (
        ["read admin"],
        [""],
        ["read", "a\tb"],
        ["read\n"],
        ["\uff52\uff45\uff41\uff44"],
    ):
        raises(lambda s=scopes: p.issue(uniq("user"), s, 60), f"scopes {scopes!r}", ValueError)
    # a str is a sequence of characters: "read" is refused, never ('r','e','a','d') nor ('read',)
    for bare in ("read", "read admin"):
        raises(
            lambda s=bare: p.issue(uniq("user"), s, 60), f"scopes {bare!r}", ValueError, TypeError
        )


@SUITE.check(
    "issue-validates-input", "empty subject and a non-positive or non-finite ttl are refused"
)
def _(p):
    raises(lambda: p.issue("", ["read"], 60), "empty subject", ValueError)
    for ttl in (0, -5, float("nan"), float("inf"), float("-inf")):
        raises(lambda t=ttl: p.issue(uniq("user"), ["read"], t), f"ttl {ttl}", ValueError)


def make_fake():
    return FakeIdentityProvider()


MUTANTS = {
    "signature-not-checked": Mutant(
        UnsignedIdentityProvider,
        "payload-splice-rejected",
        "verify trusts the payload without checking the signature",
    ),
    "alg-none-accepted": Mutant(
        AlgNoneIdentityProvider,
        "alg-none-rejected",
        "the token header is trusted, so alg=none disables the signature check",
    ),
    "empty-signature-accepted": Mutant(
        DecodedSignatureIdentityProvider,
        "unsigned-token-rejected",
        "the signature is compared only when present",
    ),
    "scope-matched-as-substring": Mutant(
        SubstringScopeIdentityProvider,
        "scope-enforced",
        "the required scope is matched as a substring, so readwrite satisfies read",
    ),
    "empty-scope-is-no-scope": Mutant(
        EmptyScopeIsNoScopeIdentityProvider,
        "scope-enforced",
        "required_scope='' is read as no scope required, so any valid token passes",
    ),
    "scope-case-insensitive": Mutant(
        CaseInsensitiveScopeIdentityProvider,
        "scope-enforced",
        "scopes are compared case-insensitively, so read satisfies READ",
    ),
    "space-delimited-scopes": Mutant(
        SpaceDelimitedScopeIdentityProvider,
        "scopes-are-opaque-tokens",
        "a scope holding a space is accepted and split on verify, so 'read admin' grants admin",
    ),
    "bare-string-scopes-split-into-characters": Mutant(
        CharacterScopesIdentityProvider,
        "scopes-are-opaque-tokens",
        "issue('u', 'read', ttl) grants ('r', 'e', 'a', 'd') (the reference fake did this)",
    ),
    "bare-string-scopes-split-on-spaces": Mutant(
        OAuthStringScopesIdentityProvider,
        "scopes-are-opaque-tokens",
        "issue accepts the OAuth string form 'read admin' for the scope list",
    ),
    "scope-checked-before-signature": Mutant(
        ScopeBeforeSignatureIdentityProvider,
        "payload-splice-rejected",
        "the scope is read from the unverified payload first, so a forgery is Forbidden",
    ),
    "revocation-skipped-when-scoped": Mutant(
        ScopedSkipsRevocationIdentityProvider,
        "revoked-token-rejected",
        "revocation is checked only when no scope is required",
    ),
    "non-finite-ttl-accepted": Mutant(
        NonFiniteTtlIdentityProvider,
        "issue-validates-input",
        "a nan or inf ttl mints a token that never expires",
    ),
    "exp-not-enforced": Mutant(
        NoExpiryIdentityProvider, "expired-token-rejected", "exp is issued but never checked"
    ),
}
