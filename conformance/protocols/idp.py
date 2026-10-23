# SPDX-License-Identifier: Apache-2.0
"""Contract for ``idp``: issue and verify short-lived bearer tokens.

``issue`` returns an opaque string; ``verify`` returns the claims or raises.  Whatever the
product (OIDC provider, signed JWTs, opaque introspection), a token that was altered, expired,
revoked, empty or garbage is *always* ``InvalidToken`` - never a crash, never accepted, whether
or not a scope is required.  ``required_scope`` names one scope exactly: it is granted only when it
is one of the token's scopes, never by matching part of one.
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
        """Raises ValueError for an empty subject, or a ttl that is not a positive, finite
        number of seconds (``nan`` and ``inf`` included: either would never expire)."""

    def verify(self, token: str, required_scope: str | None = None) -> Claims: ...

    def revoke(self, token: str) -> None:
        """Idempotent; revoking garbage is not an error."""
