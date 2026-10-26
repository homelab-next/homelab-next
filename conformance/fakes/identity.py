# SPDX-License-Identifier: Apache-2.0
"""In-memory identity provider: HS256 JWT-shaped tokens (``header.payload.signature``) with an
injected clock.  The header is checked, not trusted: only the one algorithm it issues verifies."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable, Sequence

from conformance.protocols.idp import Claims, Forbidden, InvalidToken

_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FakeIdentityProvider:
    features = frozenset({"clock-control"})

    def __init__(self, key: bytes = b"fake-signing-key", clock: Callable[[], float] | None = None):
        self._key = key
        self._now = 1_700_000_000.0
        self._clock = clock or (lambda: self._now)
        self._revoked: set[str] = set()
        self._n = 0

    def tick(self, seconds: float) -> None:
        self._now += seconds

    _HEADER = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, sort_keys=True).encode("utf-8"))

    def _sign(self, signing_input: str) -> str:
        return _b64(hmac.new(self._key, signing_input.encode("ascii"), hashlib.sha256).digest())

    @staticmethod
    def _check_ttl(ttl: float) -> None:
        # ``nan <= 0`` is False and ``now + inf`` never passes: both would mint an immortal token
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("ttl must be a positive, finite number of seconds")

    @staticmethod
    def _check_scopes(scopes: Sequence[str]) -> None:
        # a bare str is a sequence of characters: refused, never read as ('r', 'e', 'a', 'd')
        if isinstance(scopes, str | bytes):
            raise TypeError("scopes is a list of scope tokens, not a string")
        # RFC 6749 section 3.3 scope-token: 1*( %x21 / %x23-5B / %x5D-7E ), so no whitespace (a
        # space inside one would read back as two scopes) and no non-ASCII look-alike
        for s in scopes:
            if not isinstance(s, str) or not _SCOPE_TOKEN.fullmatch(s):
                raise ValueError("a scope is an RFC 6749 scope-token: printable ASCII, no space")

    def issue(self, subject: str, scopes: Sequence[str], ttl: float) -> str:
        if not subject:
            raise ValueError("subject is required")
        self._check_scopes(scopes)
        self._check_ttl(ttl)
        self._n += 1
        now = self._clock()
        body = {
            "sub": subject,
            "scp": list(scopes),
            "iat": now,
            "exp": now + ttl,
            "jti": f"t{self._n}",
        }
        payload = _b64(json.dumps(body, sort_keys=True).encode("utf-8"))
        signing_input = f"{self._HEADER}.{payload}"
        return f"{signing_input}.{self._sign(signing_input)}"

    def _decode(self, token: str) -> dict:
        if not isinstance(token, str) or token.count(".") != 2:
            raise InvalidToken("malformed token")
        header, payload, sig = token.split(".")
        # the header is compared, never interpreted: alg=none or any other algorithm is refused
        if not hmac.compare_digest(header.encode(), self._HEADER.encode()):
            raise InvalidToken("unexpected token header")
        if not sig or not hmac.compare_digest(
            sig.encode("ascii", "replace"), self._sign(f"{header}.{payload}").encode()
        ):
            raise InvalidToken("bad signature")
        return self._parse(payload)

    @staticmethod
    def _parse(payload: str) -> dict:
        try:
            return json.loads(_unb64(payload))
        except (ValueError, TypeError) as exc:
            raise InvalidToken("malformed token") from exc

    def verify(self, token: str, required_scope: str | None = None) -> Claims:
        body = self._decode(token)
        if body["jti"] in self._revoked:
            raise InvalidToken("token revoked")
        if self._clock() >= body["exp"]:
            raise InvalidToken("token expired")
        claims = Claims(body["sub"], tuple(body["scp"]), body["iat"], body["exp"], body["jti"])
        if required_scope is not None and required_scope not in claims.scopes:
            raise Forbidden(f"missing scope {required_scope!r}")
        return claims

    def revoke(self, token: str) -> None:
        try:
            self._revoked.add(self._decode(token)["jti"])
        except InvalidToken:
            return


class UnsignedIdentityProvider(FakeIdentityProvider):
    """Defect: the signature is never checked, so an altered payload is accepted."""

    def _decode(self, token: str) -> dict:
        if not isinstance(token, str) or token.count(".") != 2:
            raise InvalidToken("malformed token")
        return self._parse(token.split(".")[1])


class AlgNoneIdentityProvider(FakeIdentityProvider):
    """Defect: the header is trusted, so ``alg: none`` turns signature checking off."""

    def _decode(self, token: str) -> dict:
        if isinstance(token, str) and token.count(".") == 2:
            header = token.split(".")[0]
            try:
                alg = json.loads(_unb64(header)).get("alg")
            except (ValueError, TypeError, AttributeError):
                alg = None
            if isinstance(alg, str) and alg.lower() == "none":
                return self._parse(token.split(".")[1])
        return super()._decode(token)


class DecodedSignatureIdentityProvider(FakeIdentityProvider):
    """Defect: the signature is compared only when present, so an empty one is skipped."""

    def _decode(self, token: str) -> dict:
        if not isinstance(token, str) or token.count(".") != 2:
            raise InvalidToken("malformed token")
        header, payload, sig = token.split(".")
        if header != self._HEADER:
            raise InvalidToken("unexpected token header")
        try:
            got = _unb64(sig)
        except (ValueError, TypeError) as exc:
            raise InvalidToken("bad signature") from exc
        if got and got != _unb64(self._sign(f"{header}.{payload}")):
            raise InvalidToken("bad signature")
        return self._parse(payload)


class NoExpiryIdentityProvider(FakeIdentityProvider):
    """Defect: ``exp`` is issued but never enforced."""

    def verify(self, token: str, required_scope: str | None = None) -> Claims:
        real = self._clock
        self._clock = lambda: float("-inf")
        try:
            return super().verify(token, required_scope)
        finally:
            self._clock = real


class SubstringScopeIdentityProvider(FakeIdentityProvider):
    """Defect: the required scope is matched as a substring of the granted scopes, so a token
    for ``readwrite`` passes a check for ``read``."""

    def verify(self, token: str, required_scope: str | None = None) -> Claims:
        claims = super().verify(token)
        if required_scope is not None and required_scope not in " ".join(claims.scopes):
            raise Forbidden(f"missing scope {required_scope!r}")
        return claims


class ScopedSkipsRevocationIdentityProvider(FakeIdentityProvider):
    """Defect: revocation is checked only when no scope is required, so a revoked token still
    passes every scoped check."""

    def verify(self, token: str, required_scope: str | None = None) -> Claims:
        if required_scope is None:
            return super().verify(token)
        body = self._decode(token)
        if self._clock() >= body["exp"]:
            raise InvalidToken("token expired")
        claims = Claims(body["sub"], tuple(body["scp"]), body["iat"], body["exp"], body["jti"])
        if required_scope not in claims.scopes:
            raise Forbidden(f"missing scope {required_scope!r}")
        return claims


class NonFiniteTtlIdentityProvider(FakeIdentityProvider):
    """Defect: only ``ttl <= 0`` is refused, so ``nan`` (which compares false with everything)
    and ``inf`` mint a token that never expires."""

    @staticmethod
    def _check_ttl(ttl: float) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")


class EmptyScopeIsNoScopeIdentityProvider(FakeIdentityProvider):
    """Defect: ``if required_scope:`` instead of ``is not None``, so ``required_scope=""`` (a
    misconfigured route) accepts any valid token."""

    def verify(self, token: str, required_scope: str | None = None) -> Claims:
        return super().verify(token, required_scope or None)


class CaseInsensitiveScopeIdentityProvider(FakeIdentityProvider):
    """Defect: scopes are compared case-insensitively, so ``read`` satisfies ``READ``."""

    def verify(self, token: str, required_scope: str | None = None) -> Claims:
        claims = super().verify(token)
        held = {s.lower() for s in claims.scopes}
        if required_scope is not None and required_scope.lower() not in held:
            raise Forbidden(f"missing scope {required_scope!r}")
        return claims


class SpaceDelimitedScopeIdentityProvider(FakeIdentityProvider):
    """Defect: scopes are kept OAuth-style as one space-delimited claim and any scope is
    accepted on issue, so a token issued for the one scope ``"read admin"`` grants ``admin``."""

    @staticmethod
    def _check_scopes(scopes: Sequence[str]) -> None:
        return None

    def verify(self, token: str, required_scope: str | None = None) -> Claims:
        claims = super().verify(token)
        held = tuple(" ".join(claims.scopes).split())
        claims = Claims(claims.subject, held, claims.issued_at, claims.expires_at, claims.token_id)
        if required_scope is not None and required_scope not in held:
            raise Forbidden(f"missing scope {required_scope!r}")
        return claims


class CharacterScopesIdentityProvider(FakeIdentityProvider):
    """Defect (the reference fake did this): a bare string is taken as the scope list, so
    ``issue("u", "read", ttl)`` grants the scopes ``('r', 'e', 'a', 'd')``."""

    @staticmethod
    def _check_scopes(scopes: Sequence[str]) -> None:
        FakeIdentityProvider._check_scopes(list(scopes))


class OAuthStringScopesIdentityProvider(FakeIdentityProvider):
    """Defect: ``issue`` accepts the OAuth wire form, one space-delimited string, for the scope
    list (``"read admin"`` -> ``('read', 'admin')``)."""

    def issue(self, subject: str, scopes: Sequence[str], ttl: float) -> str:
        return super().issue(subject, scopes.split() if isinstance(scopes, str) else scopes, ttl)


class ScopeBeforeSignatureIdentityProvider(FakeIdentityProvider):
    """Defect: a scope gate reads the unverified payload before the signature is checked (the
    ``verify_signature=False`` routing idiom), so a forged token lacking the scope is Forbidden
    instead of InvalidToken."""

    def verify(self, token: str, required_scope: str | None = None) -> Claims:
        if required_scope is not None and isinstance(token, str) and token.count(".") == 2:
            try:
                body = self._parse(token.split(".")[1])
            except InvalidToken:
                body = None
            if isinstance(body, dict) and required_scope not in body.get("scp", []):
                raise Forbidden(f"missing scope {required_scope!r}")
        return super().verify(token, required_scope)
