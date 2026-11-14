# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for the parts of Keycloak's HTTP API the ``keycloak`` module uses: the
role's admin-API script (modules/keycloak/roles/keycloak/files/keycloak_api.py) and the idp
conformance adapter (homelabnext.conform.adapters.keycloak).

It is shaped after Keycloak 26's admin REST API and OIDC endpoints, over **HTTPS** with a
certificate from a throwaway CA (``openssl``), and signs real RS256 tokens with a throwaway RSA
key (``openssl genrsa``; signing is textbook RSA with PKCS#1 v1.5 padding, done here so the test
needs no crypto library). It is a test double, not an IdP: it keeps everything in memory, knows
one admin, and answers 501 to anything it does not implement, so a client that strays from what
it was written against fails loudly.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import re
import ssl
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the stand-in listens on loopback only
SERVER_NAME = "idp.svc.example.internal"
FRONTEND = "sso.example.internal"


def _openssl(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["openssl", *args], check=True, capture_output=True, text=True, timeout=60, cwd=cwd
    ).stdout


def make_pki(d: Path) -> dict:
    """A CA, a server certificate for :data:`SERVER_NAME` (and loopback) and an RSA signing key
    (its modulus and exponents read from ``openssl rsa -text``)."""
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-days", "2", "-keyout", "ca.key", "-out", "ca.crt", "-subj", "/CN=test-lab-ca",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)  # fmt: skip
    (d / "server.ext").write_text(
        f"subjectAltName=DNS:{SERVER_NAME},IP:{LOOPBACK}\nextendedKeyUsage=serverAuth\n"
        "basicConstraints=CA:FALSE\n"
    )
    _openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=idp", cwd=d)  # fmt: skip
    _openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
             "-set_serial", "4242", "-days", "2", "-out", "server.crt",
             "-extfile", "server.ext", cwd=d)  # fmt: skip
    _openssl("genrsa", "-out", "sign.key", "2048", cwd=d)
    text = _openssl("rsa", "-in", "sign.key", "-text", "-noout", cwd=d)

    def field(name: str) -> int:
        m = re.search(rf"^{name}:\s*\n((?:\s+[0-9a-f:]+\n)+)", text, re.M)
        assert m, name
        return int(re.sub(r"[\s:]", "", m.group(1)), 16)

    e = int(re.search(r"publicExponent: (\d+)", text).group(1))
    return {
        "ca": d / "ca.crt",
        "cert": d / "server.crt",
        "key": d / "server.key",
        "rsa": (field("modulus"), e, field("privateExponent")),
    }


_IDS = itertools.count(1)


def _id() -> str:
    """A fresh object id, in the IdP's UUID shape (a counter, so runs are reproducible)."""
    return f"00000000-0000-4000-8000-{next(_IDS):012d}"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class _Realm:
    def __init__(self, rep: dict):
        rep = copy.deepcopy(rep)
        self.name = rep["realm"]
        self.clients: list[dict] = []
        self.roles: dict[str, list[dict]] = {}
        self.groups: list[dict] = []
        self.users: list[dict] = []
        self.scopes: list[dict] = []
        self.mappings: dict[tuple[str, str], set[str]] = {}
        self.revoked: set[str] = set()
        self.flows = {f["alias"]: f for f in rep.pop("authenticationFlows", None) or []}
        self.actions = {a["alias"]: a for a in rep.pop("requiredActions", None) or []}
        comps = (rep.pop("components", None) or {}).get(
            "org.keycloak.userprofile.UserProfileProvider"
        )
        self.profile = (
            json.loads(comps[0]["config"]["kc.user.profile.config"][0])
            if comps
            else {"attributes": [{"name": "username", "validations": {}}]}
        )
        for c in rep.pop("clients", None) or []:
            self.add_client(c)
        for client, roles in ((rep.pop("roles", None) or {}).get("client") or {}).items():
            for r in roles:
                self.add_role(client, r)
        for g in rep.pop("groups", None) or []:
            self.add_group(g)
        rep.pop("users", None)
        self.settings = rep

    # ------------------------------------------------------------- objects
    def client(self, cid: str) -> dict | None:
        return next((c for c in self.clients if c["id"] == cid), None)

    def by_client_id(self, client_id: str) -> dict | None:
        return next((c for c in self.clients if c["clientId"] == client_id), None)

    def add_client(self, rep: dict) -> dict:
        c = copy.deepcopy(rep)
        c["id"] = _id()
        c.setdefault("attributes", {})
        c.setdefault("secret", f"generated-{_id()}")
        c.setdefault("optionalClientScopes", [])
        c.setdefault("defaultClientScopes", [])
        for m in c.setdefault("protocolMappers", []):
            m["id"] = _id()
        self.clients.append(c)
        return c

    def add_role(self, client_id: str, rep: dict) -> None:
        roles = self.roles.setdefault(client_id, [])
        if not any(r["name"] == rep["name"] for r in roles):
            roles.append({**rep, "id": _id()})

    def add_group(self, rep: dict) -> None:
        if any(g["name"] == rep["name"] for g in self.groups):
            return
        g = {"id": _id(), "name": rep["name"], "path": f"/{rep['name']}"}
        self.groups.append(g)
        for client_id, names in (rep.get("clientRoles") or {}).items():
            c = self.by_client_id(client_id)
            if c is not None:
                self.mappings.setdefault((g["id"], c["id"]), set()).update(names)

    def executions(self, alias: str, level: int = 0) -> list[dict]:
        out = []
        for i, e in enumerate(
            sorted(self.flows[alias]["authenticationExecutions"], key=lambda e: e["priority"])
        ):
            if e.get("authenticatorFlow"):
                out.append({"id": _id(), "level": level, "index": i,
                            "displayName": e["flowAlias"], "authenticationFlow": True,
                            "requirement": e["requirement"]})  # fmt: skip
                out += self.executions(e["flowAlias"], level + 1)
            else:
                out.append({"id": _id(), "level": level, "index": i,
                            "providerId": e["authenticator"], "authenticationFlow": False,
                            "requirement": e["requirement"]})  # fmt: skip
        return out

    def username_ok(self, name: str) -> bool:
        for a in self.profile.get("attributes") or []:
            if a.get("name") == "username":
                pat = ((a.get("validations") or {}).get("pattern") or {}).get("pattern")
                # Java's Matcher.matches(): the whole value
                return pat is None or re.fullmatch(pat, name) is not None
        return True


class StandIn:
    """The stand-in: ``with StandIn(tmp, admin=(user, password)) as kc:`` serves on
    ``kc.port`` (loopback) with ``kc.pki`` (``ca``, ``cert``, ``key``)."""

    def __init__(self, tmp: Path, admin: tuple[str, str], *, pki: dict | None = None):
        self.pki = pki or make_pki(tmp)
        self.admin = admin
        self.realms: dict[str, _Realm] = {}
        self.admin_tokens: set[str] = set()
        self.requests: list[tuple[str, str]] = []
        self.lock = threading.Lock()
        self.kid = "k-stand-in"

    # ------------------------------------------------------------- signing
    def sign(self, claims: dict) -> str:
        n, _, d = self.pki["rsa"]
        header = _b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": self.kid}).encode())
        body = _b64(json.dumps(claims).encode())
        k = (n.bit_length() + 7) // 8
        t = SHA256_PREFIX + hashlib.sha256(f"{header}.{body}".encode()).digest()
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        sig = pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")
        return f"{header}.{body}.{_b64(sig)}"

    def check(self, token: str) -> dict | None:
        """The claims of a token this stand-in signed, unaltered; else None."""
        n, e, _ = self.pki["rsa"]
        try:
            h, b, s = token.split(".")
            if json.loads(_b64d(h)).get("alg") != "RS256":
                return None
            k = (n.bit_length() + 7) // 8
            sig = _b64d(s)
            if len(sig) != k:
                return None
            t = SHA256_PREFIX + hashlib.sha256(f"{h}.{b}".encode()).digest()
            want = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
            if pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big") != want:
                return None
            return json.loads(_b64d(b))
        except (ValueError, TypeError):
            return None

    def jwks(self) -> dict:
        n, e, _ = self.pki["rsa"]
        size = (n.bit_length() + 7) // 8
        return {"keys": [{"kid": self.kid, "kty": "RSA", "alg": "RS256", "use": "sig",
                          "n": _b64(n.to_bytes(size, "big")), "e": _b64(e.to_bytes(3, "big"))}]}  # fmt: skip

    # ------------------------------------------------------------- server
    def __enter__(self) -> StandIn:
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status: int, body=None):
                data = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                ctype = self.headers.get("Content-Type", "")
                if "x-www-form-urlencoded" in ctype:
                    return dict(urllib.parse.parse_qsl(raw.decode()))
                return json.loads(raw) if raw else None

            def _do(self, method: str):
                url = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(url.query))
                parts = [urllib.parse.unquote(p) for p in url.path.strip("/").split("/")]
                body = self._body()
                with stand_in.lock:
                    stand_in.requests.append((method, url.path))
                    status, out = stand_in.route(method, parts, query, body, self.headers)
                self._send(status, out)

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

            def do_PUT(self):
                self._do("PUT")

            def do_DELETE(self):
                self._do("DELETE")

        self.httpd = ThreadingHTTPServer((LOOPBACK, 0), Handler)
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(str(self.pki["cert"]), str(self.pki["key"]))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, args=(0.05,), daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    # ------------------------------------------------------------- routing
    def _basic(self, headers) -> tuple[str, str] | None:
        auth = headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return None
        user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
        return urllib.parse.unquote(user), urllib.parse.unquote(pw)

    def route(self, method, parts, query, body, headers):
        if parts[:1] == ["realms"] and len(parts) >= 2:
            return self.public(method, parts[1], parts[2:], query, body, headers)
        if parts[:2] != ["admin", "realms"]:
            return 404, None
        if headers.get("Authorization", "")[7:] not in self.admin_tokens:
            return 401, None
        rest = parts[2:]
        if not rest:
            if method == "POST":
                if body["realm"] in self.realms:
                    return 409, None
                self.realms[body["realm"]] = _Realm(body)
                return 201, None
            return 501, None
        realm = self.realms.get(rest[0])
        if realm is None:
            return 404, None
        return self.admin_api(method, realm, rest[1:], query, body)

    def public(self, method, name, rest, query, body, headers):
        issuer = f"https://{FRONTEND}/realms/{name}"
        if name == "master":
            if rest == [".well-known", "openid-configuration"]:
                return 200, {"issuer": issuer}
            if rest == ["protocol", "openid-connect", "token"] and method == "POST":
                if (body.get("username"), body.get("password")) == self.admin and body.get(
                    "client_id"
                ) == "admin-cli":
                    tok = f"admin-{_id()}"
                    self.admin_tokens.add(tok)
                    return 200, {"access_token": tok, "expires_in": 60}
                return 401, {"error": "invalid_grant"}
            return 404, None
        realm = self.realms.get(name)
        if realm is None:
            return 404, None
        if rest == [".well-known", "openid-configuration"]:
            return 200, {"issuer": issuer, "jwks_uri": issuer + "/protocol/openid-connect/certs"}
        if rest == ["protocol", "openid-connect", "certs"]:
            return 200, self.jwks()
        cred = self._basic(headers)
        client = realm.by_client_id(cred[0]) if cred else None
        if client is None or client.get("secret") != cred[1]:
            return 401, {"error": "invalid_client"}
        if rest == ["protocol", "openid-connect", "token"] and method == "POST":
            if body.get("grant_type") != "client_credentials" or not client.get(
                "serviceAccountsEnabled"
            ):
                return 400, {"error": "unauthorized_client"}
            allowed = {
                s["name"]: s for s in realm.scopes if s["id"] in client["optionalClientScopes"]
            }
            asked = [s for s in body.get("scope", "").split(" ") if s]
            granted = [s for s in asked if s in allowed]
            now = int(time.time())  # hermetic: allow tokens expire in real time (the suite waits)
            life = int(client["attributes"].get("access.token.lifespan", 300))
            claims = {"iss": issuer, "typ": "Bearer", "iat": now, "exp": now + life,
                      "jti": _id(), "azp": client["clientId"],
                      "scope": " ".join(dict.fromkeys(granted))}  # fmt: skip
            for m in client.get("protocolMappers") or []:
                if m.get("protocolMapper") == "oidc-hardcoded-claim-mapper":
                    claims[m["config"]["claim.name"]] = m["config"]["claim.value"]
            jwt = self.sign(claims)
            return 200, {"access_token": jwt}
        if rest == ["protocol", "openid-connect", "token", "introspect"] and method == "POST":
            claims = self.check(body.get("token", ""))
            active = bool(
                claims
                and claims.get("iss") == issuer
                and claims.get("exp", 0) > time.time()  # hermetic: allow real-time expiry
                and claims.get("jti") not in realm.revoked
            )
            return 200, ({**claims, "active": True} if active else {"active": False})
        if rest == ["protocol", "openid-connect", "revoke"] and method == "POST":
            claims = self.check(body.get("token", ""))
            if claims and claims.get("azp") == client["clientId"]:
                realm.revoked.add(claims.get("jti"))
            return 200, None
        return 501, None

    def admin_api(self, method, realm: _Realm, rest, query, body):
        r = rest
        if not r:
            if method == "GET":
                return 200, {**realm.settings, "realm": realm.name}
            if method == "PUT":
                realm.settings.update(body)
                return 204, None
            if method == "DELETE":
                del self.realms[realm.name]
                return 204, None
        if r == ["authentication", "flows"] and method == "GET":
            return 200, [
                {"alias": a, "topLevel": f.get("topLevel", False)} for a, f in realm.flows.items()
            ]
        if r[:2] == ["authentication", "flows"] and r[3:] == ["executions"] and method == "GET":
            return (200, realm.executions(r[2])) if r[2] in realm.flows else (404, None)
        if r == ["authentication", "required-actions"] and method == "GET":
            return 200, list(realm.actions.values())
        if r[:2] == ["authentication", "required-actions"] and method == "PUT":
            realm.actions[r[2]] = {**realm.actions.get(r[2], {}), **body}
            return 204, None
        if r == ["authentication", "unregistered-required-actions"]:
            return 200, []
        if r == ["users", "profile"]:
            if method == "PUT":
                realm.profile = body
                return 200, body
            return 200, realm.profile
        if r == ["users"] and method == "GET":
            name = query.get("username", "").lower()
            return 200, [u for u in realm.users if name in u["username"]]
        if r == ["users"] and method == "POST":
            if not realm.username_ok(body["username"]):
                return 400, {"errorMessage": "hnx-reserved-username"}
            realm.users.append({"id": _id(), "username": body["username"].lower()})
            return 201, None
        if r == ["partialImport"] and method == "POST":
            for c in body.get("clients") or []:
                if realm.by_client_id(c["clientId"]) is None:
                    realm.add_client(c)
            for client, roles in ((body.get("roles") or {}).get("client") or {}).items():
                for role in roles:
                    realm.add_role(client, role)
            for g in body.get("groups") or []:
                realm.add_group(g)
            return 200, {"added": 0}
        if r == ["partial-export"] and method == "POST":
            clients = [{**c, "secret": "**********"} for c in realm.clients]
            return 200, {"realm": realm.name, "clients": clients, "groups": realm.groups}
        if r[:1] == ["clients"]:
            return self.clients_api(method, realm, r[1:], query, body)
        if r == ["client-scopes"]:
            if method == "POST":
                if any(s["name"] == body["name"] for s in realm.scopes):
                    return 409, None
                realm.scopes.append({**body, "id": _id()})
                return 201, None
            return 200, realm.scopes
        if r == ["groups"] and method == "GET":
            return 200, realm.groups
        if r[:1] == ["groups"] and r[2:4] == ["role-mappings", "clients"]:
            key = (r[1], r[4])
            have = realm.mappings.setdefault(key, set())
            if method == "GET":
                c = realm.client(r[4])
                roles = realm.roles.get(c["clientId"], []) if c else []
                return 200, [x for x in roles if x["name"] in have]
            if method == "POST":
                have.update(x["name"] for x in body)
                return 204, None
            if method == "DELETE":
                have.difference_update(x["name"] for x in body)
                return 204, None
        return 501, None

    def clients_api(self, method, realm: _Realm, r, query, body):
        if not r:
            if method == "POST":
                if realm.by_client_id(body["clientId"]):
                    return 409, None
                realm.add_client(body)
                return 201, None
            listed = realm.clients
            if "clientId" in query:
                listed = [c for c in listed if c["clientId"] == query["clientId"]]
            return 200, [{k: v for k, v in c.items() if k != "secret"} for c in listed]
        c = realm.client(r[0])
        if c is None:
            return 404, None
        rest = r[1:]
        if not rest:
            if method == "GET":
                return 200, {k: v for k, v in c.items() if k != "secret"}
            if method == "PUT":
                keep = c["id"]
                c.update({k: v for k, v in body.items() if k != "id"})
                c["id"] = keep
                return 204, None
        if rest == ["client-secret"]:
            return 200, {"type": "secret", "value": c.get("secret")}
        if rest == ["roles"]:
            if method == "POST":
                realm.add_role(c["clientId"], body)
                return 201, None
            return 200, realm.roles.get(c["clientId"], [])
        if rest == ["protocol-mappers", "models"]:
            if method == "POST":
                c["protocolMappers"].append({**body, "id": _id()})
                return 201, None
            return 200, c["protocolMappers"]
        if rest[:2] == ["protocol-mappers", "models"] and method == "PUT":
            for m in c["protocolMappers"]:
                if m["id"] == rest[2]:
                    m.update(body)
            return 204, None
        if rest[:1] == ["optional-client-scopes"] and method == "PUT":
            if rest[1] not in c["optionalClientScopes"]:
                c["optionalClientScopes"].append(rest[1])
            return 204, None
        return 501, None
