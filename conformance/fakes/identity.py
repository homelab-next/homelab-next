# SPDX-License-Identifier: Apache-2.0
"""In-memory identity provider: HS256 JWT-shaped tokens (``header.payload.signature``) with an
injected clock.  The header is checked, not trusted: only the one algorithm it issues verifies."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Callable, Sequence

from conformance.protocols.idp import Claims, Forbidden, InvalidToken


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

    def issue(self, subject: str, scopes: Sequence[str], ttl: float) -> str:
        if not subject:
            raise ValueError("subject is required")
        if ttl <= 0:
            raise ValueError("ttl must be positive")
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
