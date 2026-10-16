# SPDX-License-Identifier: Apache-2.0
"""In-memory identity provider: HMAC-signed compact tokens with an injected clock."""

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

    def _sign(self, payload: str) -> str:
        return _b64(hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).digest())

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
        return f"{payload}.{self._sign(payload)}"

    def _decode(self, token: str) -> dict:
        if not isinstance(token, str) or token.count(".") != 1:
            raise InvalidToken("malformed token")
        payload, sig = token.split(".")
        if not hmac.compare_digest(sig, self._sign(payload)):
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
        if not isinstance(token, str) or token.count(".") != 1:
            raise InvalidToken("malformed token")
        return self._parse(token.split(".")[0])
