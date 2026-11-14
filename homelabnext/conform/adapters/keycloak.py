# SPDX-License-Identifier: Apache-2.0
"""The ``idp`` contract on Keycloak (pinned: 26.8), stdlib HTTP and RS256.

``make(**config)`` returns a :class:`KeycloakIdP` on ``HNX_ENDPOINT_IDP`` (https only, verified
against the lab CA file named by ``ca_file_env``, which is required).  The adapter signs
in as the break-glass admin (the master realm's ``admin-cli``; the variables named by
``admin_user_env`` and ``admin_password_env``, read at each sign-in) and works **only in a scratch
realm of its own**, ``hnxconf-<hex>``, created when the target is built and deleted by
``close()``: the lab's realm, its users and its flows are never touched.

The contract's operations, on the product's own mechanisms (nothing is simulated):

* ``issue(subject, scopes, ttl)``: one confidential client per subject in the scratch realm
  (``hnxconf-s-<sha256 of the subject>``), a service account with **no default client scopes**,
  each requested scope an optional client scope of the realm (``include.in.token.scope``), a
  hard-coded ``hnx_sub`` claim carrying the subject, and the client's access token lifespan set
  to the ttl; the token is the IdP's own, from ``grant_type=client_credentials`` with
  ``scope=<the scopes>``.
* ``verify(token, required_scope)``: the signature first (RS256 against the realm's JWKS, the
  ``kid`` in the header; any other ``alg`` is refused before a key is looked at), then the
  issuer (the realm's, from its discovery document), ``typ: Bearer``, the expiry (at most one
  second of leeway), and the IdP's own introspection (``active``: a revoked token is inactive),
  and only then the scope, compared exactly.
* ``revoke(token)``: the IdP's revocation endpoint, authenticated as the client the token was
  issued to; garbage and an already revoked token are ignored.

Findings (fidelity limits of the product, not of this adapter):

* The IdP counts whole seconds and truncates ``iat``, so a token asked for ``ttl`` seconds is
  given a lifespan of ``ceil(ttl) + 1``: it lives at least ``ttl`` seconds from the moment it is
  issued and at most ``ttl + 1`` (within the suite's tolerance of 1.5s).
* The subject is a claim this adapter's client mapper adds (``hnx_sub``), because a
  client-credentials token's ``sub`` is the service account's id.  The lab's users sign in
  through the browser flow (a password and a passkey), which no conformance suite can drive.
* Scope names are the realm's client scopes: one is created for each name the suite asks for,
  in the scratch realm only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any

from conformance.protocols.idp import Claims, Forbidden, InvalidToken
from homelabnext._http import credential_opener, read_bounded

from ._env import AdapterConfigError, env_reader, resolve

__all__ = ["KeycloakIdP", "make"]

#: RFC 6749 section 3.3 scope-token: printable ASCII except space, ``"`` and ``\``
SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+\Z")
#: EMSA-PKCS1-v1_5's DigestInfo prefix for SHA-256 (RFC 8017 section 9.2, note 1)
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
SUBJECT_CLAIM = "hnx_sub"
LEEWAY = 1.0
MAX_BYTES = 4 * 1024 * 1024
_B64URL = re.compile(r"[A-Za-z0-9_-]*\Z")


class KeycloakError(RuntimeError):
    """The IdP answered an operation with an error (never a verify failure)."""


def _b64d(part: str) -> bytes:
    if not isinstance(part, str) or not _B64URL.match(part):
        raise InvalidToken("not base64url")
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (binascii.Error, ValueError):
        raise InvalidToken("not base64url") from None


def _int(b64: str) -> int:
    return int.from_bytes(_b64d(b64), "big")


def rs256_valid(n: int, e: int, signing_input: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 section 8.2.2): the signature's length is the
    modulus's, and the whole encoded message is rebuilt and compared in constant time (never
    parsed, so no trailing-garbage or short-padding forgery)."""
    k = (n.bit_length() + 7) // 8
    if k < 256 or len(signature) != k or e < 3:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = SHA256_PREFIX + hashlib.sha256(signing_input).digest()
    want = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, want)


def _encoded(body: Any, form: dict | None) -> tuple[dict[str, str], bytes | None]:
    """The request's headers and bytes: a form (OAuth endpoints) or a JSON body (admin API)."""
    if form is not None:
        return {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }, urllib.parse.urlencode(form).encode()
    if body is not None:
        return {"Accept": "application/json", "Content-Type": "application/json"}, json.dumps(
            body
        ).encode()
    return {"Accept": "application/json"}, None


class KeycloakIdP:
    """:class:`conformance.protocols.idp.IdentityProvider` in a scratch realm of one Keycloak."""

    features = frozenset()

    def __init__(
        self,
        base_url: str,
        admin: Callable[[], tuple[str, ...]],
        *,
        ca_file: str | None = None,
        timeout: float = 15.0,
        realm: str | None = None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not base_url.startswith("https://"):
            raise ValueError("base_url must be an https URL supplied by the caller")
        self._base = base_url.rstrip("/")
        self._admin = admin
        self._clock = clock
        self._monotonic = monotonic
        self._opener = credential_opener(ca_file)
        self.timeout = timeout
        self.realm = realm or f"hnxconf-{secrets.token_hex(6)}"
        if not self.realm.startswith("hnxconf-"):
            raise ValueError("the adapter works only in a scratch realm named hnxconf-*")
        self._admin_token: tuple[str, float] | None = None
        self._clients: dict[str, tuple[str, str, str]] = {}  # subject -> (clientId, uuid, secret)
        self._by_client: dict[str, str] = {}  # clientId -> secret
        self._scopes: dict[str, str] = {}  # scope name -> client scope id
        self._keys: dict[str, tuple[int, int]] = {}
        self._verifier: tuple[str, str] | None = None
        self._created = False
        try:
            self._create_realm()
            self.issuer = self._discover()
        except BaseException:
            # a realm created before the failure is deleted: nothing is left on the IdP
            self.close()
            raise

    def __repr__(self) -> str:
        return f"KeycloakIdP(realm={self.realm!r})"

    # ---------------------------------------------------------------- HTTP
    def _call(
        self, method: str, path: str, *, body: Any = None, form: dict | None = None,
        token: str | None = None, auth: tuple[str, str] | None = None, ok=(200,),
    ) -> tuple[int, Any]:  # fmt: skip
        headers, data = _encoded(body, form)
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        elif auth is not None:
            pair = f"{urllib.parse.quote(auth[0], safe='')}:{urllib.parse.quote(auth[1], safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
        req = urllib.request.Request(self._base + path, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status, raw = resp.status, read_bounded(resp, MAX_BYTES)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, b""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise KeycloakError(f"{method} {path.split('?')[0]}: {type(exc).__name__}") from None
        if status not in ok:
            raise KeycloakError(f"{method} {path.split('?')[0]}: HTTP {status}")
        try:
            return status, json.loads(raw) if raw.strip() else None
        except ValueError:
            return status, None

    def _admin_call(self, method: str, path: str, **kw) -> tuple[int, Any]:
        now = self._monotonic()
        if self._admin_token is None or self._admin_token[1] <= now:
            user, password = self._admin()
            _, body = self._call(
                "POST", "/realms/master/protocol/openid-connect/token",
                form={"grant_type": "password", "client_id": "admin-cli",
                      "username": user, "password": password},
            )  # fmt: skip
            token = (body or {}).get("access_token")
            if not isinstance(token, str):
                raise KeycloakError("the admin sign-in returned no token")
            life = float((body or {}).get("expires_in", 60))
            self._admin_token = (token, now + max(5.0, life - 10.0))
        return self._call(method, f"/admin/realms{path}", token=self._admin_token[0], **kw)

    def _realm(self, path: str = "") -> str:
        """An admin path under the scratch realm (after ``/admin/realms``)."""
        return f"/{urllib.parse.quote(self.realm, safe='')}{path}"

    def _oidc(self, path: str) -> str:
        """A public path of the scratch realm (discovery, token, keys, introspection)."""
        return f"/realms/{urllib.parse.quote(self.realm, safe='')}{path}"

    # ---------------------------------------------------------------- set-up
    def _create_realm(self) -> None:
        self._admin_call(
            "POST", "",
            body={"realm": self.realm, "enabled": True, "sslRequired": "all",
                  "registrationAllowed": False, "resetPasswordAllowed": False,
                  "bruteForceProtected": True, "accessTokenLifespan": 300,
                  "defaultDefaultClientScopes": [], "defaultOptionalClientScopes": []},
            ok=(201,),
        )  # fmt: skip
        self._created = True
        secret = secrets.token_urlsafe(32)
        self._admin_call(
            "POST", self._realm("/clients"),
            body={"clientId": "hnxconf-verifier", "secret": secret, "publicClient": False,
                  "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                  "serviceAccountsEnabled": False, "defaultClientScopes": [],
                  "optionalClientScopes": [], "protocol": "openid-connect"},
            ok=(201,),
        )  # fmt: skip
        self._verifier = ("hnxconf-verifier", secret)

    def _discover(self) -> str:
        _, doc = self._call("GET", self._oidc("/.well-known/openid-configuration"))
        issuer = (doc or {}).get("issuer")
        if not isinstance(issuer, str) or not issuer.endswith("/realms/" + self.realm):
            raise KeycloakError("the scratch realm's discovery document names no issuer")
        return issuer

    def close(self) -> None:
        if self._created:
            try:
                self._admin_call("DELETE", self._realm(), ok=(204, 404))
            finally:
                self._created = False

    def _scope_id(self, name: str) -> str:
        if name not in self._scopes:
            sid = None
            self._admin_call(
                "POST", self._realm("/client-scopes"),
                body={"name": name, "protocol": "openid-connect",
                      "attributes": {"include.in.token.scope": "true",
                                     "display.on.consent.screen": "false"}},
                ok=(201, 409),
            )  # fmt: skip
            _, listed = self._admin_call("GET", self._realm("/client-scopes"))
            for s in listed or []:
                if s.get("name") == name:
                    sid = s["id"]
            if not sid:
                raise KeycloakError("a client scope was not created")
            self._scopes[name] = sid
        return self._scopes[name]

    def _client(self, subject: str) -> tuple[str, str, str]:
        if subject not in self._clients:
            cid = "hnxconf-s-" + hashlib.sha256(subject.encode()).hexdigest()[:32]
            secret = secrets.token_urlsafe(32)
            self._admin_call(
                "POST", self._realm("/clients"),
                body={"clientId": cid, "secret": secret, "publicClient": False,
                      "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                      "serviceAccountsEnabled": True, "protocol": "openid-connect",
                      "defaultClientScopes": [], "optionalClientScopes": [],
                      "fullScopeAllowed": False,
                      "protocolMappers": [{
                          "name": "hnx subject", "protocol": "openid-connect",
                          "protocolMapper": "oidc-hardcoded-claim-mapper",
                          "config": {"claim.name": SUBJECT_CLAIM, "claim.value": subject,
                                     "jsonType.label": "String", "access.token.claim": "true",
                                     "id.token.claim": "false", "userinfo.token.claim": "false",
                                     "introspection.token.claim": "true"}}]},
                ok=(201,),
            )  # fmt: skip
            _, listed = self._admin_call("GET", self._realm(f"/clients?clientId={cid}"))
            uuid = next((c["id"] for c in listed or [] if c.get("clientId") == cid), None)
            if not uuid:
                raise KeycloakError("a client was not created")
            self._clients[subject] = (cid, uuid, secret)
            self._by_client[cid] = secret
        return self._clients[subject]

    # ---------------------------------------------------------------- the contract
    def issue(self, subject: str, scopes: Sequence[str], ttl: float) -> str:
        if not isinstance(subject, str) or not subject:
            raise ValueError("subject must be a non-empty string")
        if isinstance(scopes, str) or not isinstance(scopes, Sequence):
            raise TypeError("scopes is a list of scope tokens, not one string")
        scopes = list(scopes)
        for s in scopes:
            if not isinstance(s, str) or not SCOPE_TOKEN.match(s):
                raise ValueError("a scope is not an RFC 6749 scope-token")
        if isinstance(ttl, bool) or not isinstance(ttl, int | float):
            raise ValueError("ttl must be a number of seconds")
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("ttl must be a positive, finite number of seconds")
        cid, uuid, secret = self._client(subject)
        _, rep = self._admin_call("GET", self._realm(f"/clients/{uuid}"))
        attrs = dict((rep or {}).get("attributes") or {})
        attrs["access.token.lifespan"] = str(math.ceil(ttl) + 1)
        self._admin_call(
            "PUT", self._realm(f"/clients/{uuid}"), body={**(rep or {}), "attributes": attrs},
            ok=(204,),
        )  # fmt: skip
        for s in dict.fromkeys(scopes):
            self._admin_call(
                "PUT", self._realm(f"/clients/{uuid}/optional-client-scopes/{self._scope_id(s)}"),
                ok=(204,),
            )  # fmt: skip
        _, body = self._call(
            "POST", self._oidc("/protocol/openid-connect/token"),
            form={"grant_type": "client_credentials", "scope": " ".join(scopes)},
            auth=(cid, secret),
        )  # fmt: skip
        token = (body or {}).get("access_token")
        if not isinstance(token, str) or not token:
            raise KeycloakError("the token endpoint returned no access token")
        return token

    def _key(self, kid: str) -> tuple[int, int]:
        if kid not in self._keys:
            _, jwks = self._call("GET", self._oidc("/protocol/openid-connect/certs"))
            for k in (jwks or {}).get("keys") or []:
                if k.get("kty") == "RSA" and k.get("use", "sig") == "sig" and k.get("kid"):
                    try:
                        self._keys[k["kid"]] = (_int(k["n"]), _int(k["e"]))
                    except (InvalidToken, KeyError, TypeError):
                        continue
        if kid not in self._keys:
            raise InvalidToken("unknown key")
        return self._keys[kid]

    def _claims(self, token: str) -> dict:
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise InvalidToken("not a token")
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise InvalidToken("not a signed JWT")
        try:
            header = json.loads(_b64d(parts[0]))
        except (ValueError, UnicodeDecodeError):
            raise InvalidToken("unreadable header") from None
        if not isinstance(header, dict) or header.get("alg") != "RS256":
            raise InvalidToken("the algorithm is not RS256")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidToken("no key id")
        n, e = self._key(kid)
        if not rs256_valid(n, e, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64d(parts[2])):
            raise InvalidToken("bad signature")
        try:
            claims = json.loads(_b64d(parts[1]))
        except (ValueError, UnicodeDecodeError):
            raise InvalidToken("unreadable payload") from None
        if not isinstance(claims, dict):
            raise InvalidToken("the payload is not an object")
        return claims

    def verify(self, token: str, required_scope: str | None = None) -> Claims:
        claims = self._claims(token)
        if claims.get("iss") != self.issuer or claims.get("typ") != "Bearer":
            raise InvalidToken("not an access token of this realm")
        exp, iat = claims.get("exp"), claims.get("iat")
        if not all(isinstance(v, int | float) and not isinstance(v, bool) for v in (exp, iat)):
            raise InvalidToken("no lifetime")
        if self._clock() >= exp + LEEWAY:
            raise InvalidToken("expired")
        subject = claims.get(SUBJECT_CLAIM)
        if not isinstance(subject, str) or not subject:
            raise InvalidToken("no subject")
        assert self._verifier is not None
        try:
            _, info = self._call(
                "POST",
                self._oidc("/protocol/openid-connect/token/introspect"),
                form={"token": token, "token_type_hint": "access_token"},
                auth=self._verifier,
            )
        except KeycloakError:
            raise InvalidToken("introspection refused the token") from None
        if not isinstance(info, dict) or info.get("active") is not True:
            raise InvalidToken("inactive (revoked or expired)")
        raw = claims.get("scope", "")
        scopes = (
            tuple(dict.fromkeys(s for s in raw.split(" ") if s)) if isinstance(raw, str) else ()
        )
        if required_scope is not None:
            if not isinstance(required_scope, str) or not SCOPE_TOKEN.match(required_scope):
                raise Forbidden("the required scope is not a scope token")
            if required_scope not in scopes:
                raise Forbidden("the token lacks the required scope")
        return Claims(
            subject=subject,
            scopes=scopes,
            issued_at=float(iat),
            expires_at=float(exp),
            token_id=str(claims.get("jti", "")),
        )

    def revoke(self, token: str) -> None:
        try:
            claims = self._claims(token)
        except (InvalidToken, KeycloakError):
            return  # garbage, or a token this realm never signed: nothing to revoke
        cid = claims.get("azp")
        secret = self._by_client.get(cid) if isinstance(cid, str) else None
        if secret is None:
            return
        try:
            self._call(
                "POST",
                self._oidc("/protocol/openid-connect/revoke"),
                form={"token": token, "token_type_hint": "access_token"},
                auth=(cid, secret),
            )
        except KeycloakError:
            return


def make(
    *,
    admin_user_env: str = "HNX_IDP_ADMIN_USER",
    admin_password_env: str = "HNX_IDP_ADMIN_PASSWORD",
    ca_file_env: str = "HNX_IDP_CA_FILE",
    timeout: float = 15.0,
    capability: str = "idp",
) -> KeycloakIdP:
    """A target on the ``idp`` endpoint (``HNX_ENDPOINT_IDP``, https): the admin's name and
    password from the named variables (read now, so a missing one fails at once, and again at
    each sign-in), the server verified against the CA file named by ``ca_file_env`` (required:
    the lab CA, so the admin's password reaches only the internal name)."""
    import os

    admin = env_reader(admin_user_env, admin_password_env)
    # the admin's password goes only to the server the lab CA vouches for (the internal name),
    # never to whatever the system roots trust (the public name, through the edge)
    ca_file = os.environ.get(ca_file_env or "")
    if not ca_file or not os.path.isfile(ca_file):
        raise AdapterConfigError(f"{ca_file_env} must name the lab CA's certificate file")
    ep = resolve(capability, env_only=True, schemes=("https",))
    return KeycloakIdP(ep.url, admin, ca_file=ca_file, timeout=timeout)
