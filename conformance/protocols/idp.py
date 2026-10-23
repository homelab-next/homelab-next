# SPDX-License-Identifier: Apache-2.0
"""Contract for ``idp``: issue and verify short-lived bearer tokens.

``issue`` returns an opaque string; ``verify`` returns the claims or raises.  Whatever the
product (OIDC provider, signed JWTs, opaque introspection), a token that was altered, expired,
revoked, empty or garbage is *always* ``InvalidToken`` - never a crash, never accepted, whether
or not a scope is required.

Scopes are opaque tokens with the grammar of an OAuth ``scope-token`` (RFC 6749 section 3.3,
``1*( %x21 / %x23-5B / %x5D-7E )``), which a JWT carries space-delimited: printable ASCII with no
space, compared exactly - codepoint for codepoint, case-sensitive, no Unicode normalisation - and
a token holds a set of them.  ``issue`` takes a list of them: it refuses a scope outside that
grammar (``""``, ``"read admin"``, which would read back as two scopes, a fullwidth look-alike of
``read``) with ``ValueError``, and a bare string for the list (``"read"`` is not ``['read']``,
and never ``('r', 'e', 'a', 'd')``) with ``TypeError`` or ``ValueError``.  ``required_scope`` names
one scope exactly: it is granted only when it is one of the token's scopes - never by matching
part of one, another case or another normalisation of one - so ``"READ"`` for ``read`` is
``Forbidden``; a required scope outside the grammar (``""``, ``" read"``, ``"read admin"``) is
never granted (``Forbidden``, or ``ValueError`` for a misconfigured route).  A forged token is
``InvalidToken`` whatever scope is required: the signature is checked before any claim is read.

A provider that adds default scopes to every token (Keycloak adds ``profile`` and ``email``, and
``openid`` where requested, unless the client's default client scopes are removed) returns more
scopes than were asked for, and fails the exact round trip; configure the test client without them.

Expiry allows at most one second of leeway: a token must fail to verify once one second has
passed beyond its ttl, so a JWT library's clock-skew allowance must be configured at or below 1s.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = ["Claims", "Forbidden", "IdentityProvider", "IdpError", "InvalidToken"]


class IdpError(Exception):
    pass


class InvalidToken(IdpError):
    pass


class Forbidden(IdpError):
    """The token is valid but lacks a required scope."""


@dataclass(frozen=True)
class Claims:
    subject: str
    scopes: tuple[str, ...]
    issued_at: float
    expires_at: float
    token_id: str


@runtime_checkable
class IdentityProvider(Protocol):
    def issue(self, subject: str, scopes: Sequence[str], ttl: float) -> str:
        """Raises ValueError for an empty subject, a scope that is empty or contains whitespace,
        or a ttl that is not a positive, finite number of seconds (``nan`` and ``inf`` included:
        either would never expire)."""

    def verify(self, token: str, required_scope: str | None = None) -> Claims: ...

    def revoke(self, token: str) -> None:
        """Idempotent; revoking garbage is not an error."""
