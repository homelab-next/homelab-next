# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: keycloak-api
#   kind: tool
#   purpose: Import or converge the generated realm through the IdP's admin API, and check it (the keycloak role's sync, health and export).
#   owner: platform
#   trigger: [role:keycloak]
#   inputs: "the mode as the one argument (wait, sync, health, export); every setting, the admin's password and the client secrets as one JSON document on stdin"
#   outputs: one JSON document on stdout (sync - created and changed; health - problems; export - the realm's partial export)
#   exit:
#     "0": the mode did its work (health reports its findings in problems)
#     "1": refused input, an error from the IdP, or flow drift sync will not touch (the reason on stderr)
#     "2": usage error
"""The keycloak role's one client of the IdP's admin API (modules/keycloak/README.md).

    python3 -I keycloak_api.py wait|sync|health|export   < settings.json

Every setting, the break-glass admin's password and the client secrets among them, arrives as
one JSON document on stdin, never as an argument, so no secret is in a process list or a log.
The result is one JSON document on stdout; exit 0 when the mode did its work (``health`` reports
its findings in ``problems`` and exits 0, the role asserts on them), 1 with a reason on stderr
when it could not (refused input, the IdP answering an error, drift ``sync`` will not touch).

The connection goes to the guest's own address and verifies the server's certificate against
the lab CA (``cafile``) **by name** (``server_name``, the name the certificate is issued for),
never by address and never unverified, so the admin password is sent only to the IdP that holds
that certificate.

Modes:

* ``wait``: until the master realm's discovery document answers (the server is up), or fail.
* ``sync``: make the realm what the rendered document (``doc``, the ``idp_realm`` generator's
  ``idp/realm.json``) says.  An absent realm is created from the whole document (its client
  secrets substituted from ``client_secrets``).  On an existing realm it converges what is safe
  to change on a live realm: the realm's settings and flow bindings, the required actions, the
  user profile (the reserved usernames), missing clients, client roles and groups, each
  rendered client's settings, mappers and secret, and each rendered group's client roles.
  **Authentication flows are created when missing and never edited in place**: a bound flow
  that differs from the document is drift ``sync`` refuses (exit 1), because editing a flow a
  sign-in is running through could open a window without the second factor.  Users are never
  touched.
* ``health``: the realm's OIDC discovery answers with the expected issuer and a key set; the
  bound flows are the rendered ones, the browser flow requires the passkey and no flow offers a
  one-time code, the direct grant refuses everyone; the enrolment actions are as rendered; the
  user profile refuses the reserved usernames; **no user holds a reserved username**; every
  rendered client and group exists and each group holds exactly its rendered client roles.
* ``export``: the realm's partial export (clients, groups, roles, flows, settings; the IdP
  masks every client secret and exports no user), returned as ``realm`` for the role to write.
"""

from __future__ import annotations

import copy
import http.client
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse

MAX_BYTES = 16 * 1024 * 1024
PLACEHOLDER = re.compile(r"\$\(env:[A-Z0-9_]+\)\Z")
OTP_AUTHENTICATORS = {
    "auth-otp-form",
    "auth-conditional-otp-form",
    "direct-grant-validate-otp",
    "reset-otp",
}
SECOND_FACTOR = "webauthn-authenticator"
REFUSAL = "deny-access-authenticator"
PROFILE_PROVIDER = "org.keycloak.userprofile.UserProfileProvider"
#: the realm settings ``sync`` converges on an existing realm (the rest of the document is
#: converged through its own endpoints: flows, required actions, the user profile, clients,
#: groups); ``attributes`` is merged, never replaced
REALM_SETTINGS = (
    "browserFlow",
    "bruteForceProtected",
    "directGrantFlow",
    "displayName",
    "editUsernameAllowed",
    "enabled",
    "registrationAllowed",
    "resetPasswordAllowed",
    "sslRequired",
)
WEBAUTHN_PREFIX = "webAuthnPolicy"
CLIENT_FIELDS = (
    "attributes",
    "clientAuthenticatorType",
    "defaultClientScopes",
    "description",
    "directAccessGrantsEnabled",
    "enabled",
    "fullScopeAllowed",
    "implicitFlowEnabled",
    "name",
    "optionalClientScopes",
    "protocol",
    "publicClient",
    "redirectUris",
    "rootUrl",
    "serviceAccountsEnabled",
    "standardFlowEnabled",
    "webOrigins",
)


class Refused(Exception):
    """The mode cannot go on: the reason is printed, the exit status is 1."""


# ----------------------------------------------------------------------------- the connection


class _Pinned(http.client.HTTPSConnection):
    """An HTTPS connection to ``address`` whose certificate is verified for ``name``."""

    def __init__(self, address: str, name: str, port: int, context: ssl.SSLContext, timeout):
        super().__init__(name, port, timeout=timeout, context=context)
        self._address = address
        self._ctx = context

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


class Api:
    def __init__(self, cfg: dict):
        for key in ("address", "server_name", "cafile"):
            if not isinstance(cfg.get(key), str) or not cfg[key]:
                raise Refused(f"settings: {key} is required")
        self.address = cfg["address"]
        self.name = cfg["server_name"]
        self.port = int(cfg.get("port", 8443))
        self.timeout = float(cfg.get("timeout", 15))
        ctx = ssl.create_default_context(cafile=cfg["cafile"])
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.ctx = ctx
        self.token: str | None = None

    def call(self, method: str, path: str, body=None, *, form=None, ok=(200,), auth=True):
        """(status, parsed body or None); a status outside ``ok`` is a :class:`Refused`."""
        headers = {"Accept": "application/json"}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = "Bearer " + (self.token or "")
        conn = _Pinned(self.address, self.name, self.port, self.ctx, self.timeout)
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(MAX_BYTES + 1)
            status = resp.status
        finally:
            conn.close()
        if len(raw) > MAX_BYTES:
            raise Refused(f"{method} {_safe(path)}: the answer is over {MAX_BYTES} bytes")
        parsed = None
        if raw.strip():
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
        if status not in ok:
            raise Refused(f"{method} {_safe(path)}: HTTP {status}")
        return status, parsed

    def sign_in(self, user: str, password: str) -> None:
        """The break-glass admin's token, from the master realm (password grant on admin-cli:
        the master realm keeps the IdP's built-in flows; the lab realm refuses direct grants)."""
        _, body = self.call(
            "POST",
            "/realms/master/protocol/openid-connect/token",
            form={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": user,
                "password": password,
            },
            auth=False,
        )
        token = (body or {}).get("access_token")
        if not isinstance(token, str) or not token:
            raise Refused("the admin sign-in returned no token")
        self.token = token


def _text(value) -> str:
    """A scalar as the IdP stores it: booleans and numbers as strings, nothing as the empty string."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def covers(live, want) -> bool:
    """Does the live representation hold what the rendered one says?  The IdP normalises what it
    stores (attributes and mapper settings come back as strings, with defaults of its own added;
    a set comes back in its own order; an empty value may be absent), so a byte comparison of the
    two never settles and every run would report a change.  A rendered dict is held when each of
    its keys is (extra keys on the live side are the IdP's own); a rendered list of scalars when
    the live one has the same members in any order; a rendered scalar when the live one reads the
    same.  Anything that differs in a rendered key, a member or a value is still a difference."""
    if isinstance(want, dict):
        if not isinstance(live, dict):
            return not want
        return all(covers(live.get(k), v) for k, v in want.items())
    if isinstance(want, list):
        if not isinstance(live, list):
            return not want
        if all(not isinstance(x, (dict, list)) for x in want + live):
            return sorted(map(_text, live)) == sorted(map(_text, want))
        return len(live) == len(want) and all(covers(a, b) for a, b in zip(live, want, strict=True))
    return _text(live) == _text(want)


def _safe(path: str) -> str:
    return path.split("?", 1)[0]


def _q(text: str) -> str:
    return urllib.parse.quote(text, safe="")


# ----------------------------------------------------------------------------- the document


def _flows(doc: dict) -> dict:
    return {f["alias"]: f for f in doc.get("authenticationFlows") or []}


def expected_executions(doc: dict, alias: str, level: int = 0) -> list[tuple]:
    """The rendered flow ``alias`` flattened the way the admin API lists executions:
    ``(level, kind, name, requirement)`` in priority order, a subflow followed by its own."""
    flows = _flows(doc)
    out = []
    for e in sorted(flows[alias]["authenticationExecutions"], key=lambda e: e["priority"]):
        if e.get("authenticatorFlow"):
            out.append((level, "flow", e["flowAlias"], e["requirement"]))
            out += expected_executions(doc, e["flowAlias"], level + 1)
        else:
            out.append((level, "step", e["authenticator"], e["requirement"]))
    return out


def live_executions(listed) -> list[tuple]:
    """The admin API's flat list (already in flow order: a subflow followed by its own) in the
    form of :func:`expected_executions`."""
    out = []
    for e in listed or []:
        if e.get("authenticationFlow"):
            out.append((e.get("level", 0), "flow", e.get("displayName"), e.get("requirement")))
        else:
            out.append((e.get("level", 0), "step", e.get("providerId"), e.get("requirement")))
    return out


def profile_config(doc: dict) -> dict:
    comps = (doc.get("components") or {}).get(PROFILE_PROVIDER) or []
    if len(comps) != 1:
        raise Refused("the rendered realm carries no user profile (render it with idp_realm)")
    return json.loads(comps[0]["config"]["kc.user.profile.config"][0])


def username_pattern(config: dict):
    for a in config.get("attributes") or []:
        if a.get("name") == "username":
            return ((a.get("validations") or {}).get("pattern") or {}).get("pattern")
    return None


def username_validations(config: dict) -> dict:
    for a in config.get("attributes") or []:
        if a.get("name") == "username":
            return a.get("validations") or {}
    return {}


def top_flows(doc: dict) -> list[str]:
    return sorted(f["alias"] for f in doc.get("authenticationFlows") or [] if f.get("topLevel"))


def check_doc(doc: dict, realm: str) -> None:
    if not isinstance(doc, dict) or doc.get("realm") != realm:
        raise Refused(f"the rendered realm is not {realm!r} (render idp_realm for this lab)")
    for c in doc.get("clients") or []:
        if not PLACEHOLDER.match(str(c.get("secret", ""))):
            raise Refused(f"client {c.get('clientId')}: the rendered secret is not a reference")
    for binding in ("browserFlow", "directGrantFlow"):
        if doc.get(binding) not in _flows(doc):
            raise Refused(f"the rendered realm binds {binding} to no rendered flow")
    if not username_pattern(profile_config(doc)):
        raise Refused("the rendered user profile has no reserved-username pattern")


def with_secrets(doc: dict, secrets: dict) -> dict:
    out = copy.deepcopy(doc)
    for c in out.get("clients") or []:
        value = secrets.get(c["clientId"])
        if not isinstance(value, str) or len(value) < 32:
            raise Refused(
                f"client {c['clientId']}: no secret of 32 characters or more was given "
                f"(its name in the secret store's idp/clients area: {c['clientId']})"
            )
        c["secret"] = value
    return out


# ----------------------------------------------------------------------------- modes


def wait(api: Api, cfg: dict) -> dict:
    deadline = time.monotonic() + float(cfg.get("wait_s", 300))
    last = "no answer"
    while True:
        try:
            api.call("GET", "/realms/master/.well-known/openid-configuration", auth=False)
            return {"ready": True}
        except (Refused, OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last = type(exc).__name__ if not isinstance(exc, Refused) else str(exc)
        if time.monotonic() >= deadline:
            raise Refused(f"the IdP did not answer within {cfg.get('wait_s', 300)}s ({last})")
        time.sleep(3)


def _realm_path(realm: str) -> str:
    return f"/admin/realms/{_q(realm)}"


def _client_ids(api: Api, base: str) -> dict:
    _, listed = api.call("GET", f"{base}/clients?max=1000")
    return {c["clientId"]: c for c in listed or []}


def _groups(api: Api, base: str) -> dict:
    _, listed = api.call("GET", f"{base}/groups?max=1000&briefRepresentation=false")
    return {g["name"]: g for g in listed or []}


def _group_roles(api: Api, base: str, gid: str, cid: str) -> set:
    _, listed = api.call("GET", f"{base}/groups/{_q(gid)}/role-mappings/clients/{_q(cid)}")
    return {r["name"] for r in listed or []}


def _create_flow(api: Api, base: str, doc: dict, alias: str, top: bool, parent: str = "") -> None:
    """Create a rendered flow that the realm lacks, with its executions and requirements."""
    flow = _flows(doc)[alias]
    if top:
        api.call(
            "POST",
            f"{base}/authentication/flows",
            {
                "alias": alias,
                "builtIn": False,
                "description": flow.get("description", ""),
                "providerId": "basic-flow",
                "topLevel": True,
            },
            ok=(201,),
        )
    for e in sorted(flow["authenticationExecutions"], key=lambda e: e["priority"]):
        if e.get("authenticatorFlow"):
            sub = _flows(doc)[e["flowAlias"]]
            api.call(
                "POST",
                f"{base}/authentication/flows/{_q(alias)}/executions/flow",
                {
                    "alias": e["flowAlias"],
                    "description": sub.get("description", ""),
                    "provider": "registration-page-form",
                    "type": "basic-flow",
                },
                ok=(201,),
            )
        else:
            api.call(
                "POST",
                f"{base}/authentication/flows/{_q(alias)}/executions/execution",
                {"provider": e["authenticator"]},
                ok=(201,),
            )
    _, listed = api.call("GET", f"{base}/authentication/flows/{_q(alias)}/executions")
    mine = [x for x in listed or [] if x.get("level") == 0]
    wanted = sorted(flow["authenticationExecutions"], key=lambda e: e["priority"])
    if len(mine) != len(wanted):
        raise Refused(
            f"flow {alias}: the IdP lists {len(mine)} executions, {len(wanted)} were made"
        )
    for have, want in zip(mine, wanted, strict=True):
        if have.get("requirement") != want["requirement"]:
            api.call(
                "PUT",
                f"{base}/authentication/flows/{_q(alias)}/executions",
                {**have, "requirement": want["requirement"]},
                ok=(202, 204),
            )
        if want.get("authenticatorFlow"):
            _create_flow(api, base, doc, want["flowAlias"], False, alias)


def _flow_drift(api: Api, base: str, doc: dict, existing: set) -> list[str]:
    out = []
    for alias in top_flows(doc):
        if alias not in existing:
            continue
        _, listed = api.call("GET", f"{base}/authentication/flows/{_q(alias)}/executions")
        if live_executions(listed) != expected_executions(doc, alias):
            out.append(f"flow {alias} differs from the rendered one")
    return out


def sync(api: Api, cfg: dict) -> dict:
    realm = cfg["realm"]
    doc = cfg["doc"]
    check_doc(doc, realm)
    full = with_secrets(doc, cfg.get("client_secrets") or {})
    api.sign_in(cfg["admin_user"], cfg["admin_password"])
    base = _realm_path(realm)
    changed: list[str] = []
    # the master realm (the break-glass admin's, password only): brute-force protection on
    _, master = api.call("GET", "/admin/realms/master")
    if (master or {}).get("bruteForceProtected") is not True:
        api.call("PUT", "/admin/realms/master", {"bruteForceProtected": True}, ok=(204,))
        changed.append("master brute-force protection")
    status, current = api.call("GET", base, ok=(200, 404))
    if status == 404:
        api.call("POST", "/admin/realms", full, ok=(201,))
        return {"created": True, "changed": ["realm", *changed]}
    # 1. flows: create the missing ones, refuse drift in the existing ones (never edited)
    _, listed = api.call("GET", f"{base}/authentication/flows")
    existing = {f["alias"] for f in listed or []}
    drift = _flow_drift(api, base, doc, existing)
    if drift:
        raise Refused(
            "; ".join(drift)
            + ": sync never edits a flow in place (a sign-in may be running through it); "
            "follow the README's 'Flow drift' procedure"
        )
    for alias in top_flows(doc):
        if alias not in existing:
            _create_flow(api, base, doc, alias, True)
            changed.append(f"flow {alias}")
    # 2. required actions: registered when missing, then each as rendered
    _, listed = api.call("GET", f"{base}/authentication/required-actions")
    have = {a["alias"]: a for a in listed or []}
    for want in doc.get("requiredActions") or []:
        if want["alias"] not in have:
            _, unreg = api.call("GET", f"{base}/authentication/unregistered-required-actions")
            if want["providerId"] in {u.get("providerId") for u in unreg or []}:
                api.call(
                    "POST",
                    f"{base}/authentication/register-required-action",
                    {"providerId": want["providerId"], "name": want["name"]},
                    ok=(204,),
                )
            elif not want["enabled"]:
                continue  # a disabled action the IdP does not offer: nothing to turn off
            else:
                raise Refused(f"required action {want['alias']}: the IdP does not offer it")
        cur = have.get(want["alias"], {})
        if any(cur.get(k) != want[k] for k in ("enabled", "defaultAction", "priority")):
            api.call(
                "PUT",
                f"{base}/authentication/required-actions/{_q(want['alias'])}",
                {**cur, **{k: want[k] for k in ("alias", "name", "providerId", "enabled",
                                                 "defaultAction", "priority", "config")}},
                ok=(204,),
            )  # fmt: skip
            changed.append(f"required action {want['alias']}")
    # 3. the user profile (the reserved usernames)
    _, live_profile = api.call("GET", f"{base}/users/profile")
    want_profile = profile_config(doc)
    if live_profile != want_profile:
        api.call("PUT", f"{base}/users/profile", want_profile)
        changed.append("user profile")
    # 4. settings and bindings (every rendered flow now exists and is as rendered)
    patch = {k: doc[k] for k in REALM_SETTINGS if k in doc and current.get(k) != doc[k]}
    patch.update(
        {k: v for k, v in doc.items() if k.startswith(WEBAUTHN_PREFIX) and current.get(k) != v}
    )
    attrs = dict(current.get("attributes") or {})
    if any(attrs.get(k) != v for k, v in (doc.get("attributes") or {}).items()):
        attrs.update(doc.get("attributes") or {})
        patch["attributes"] = attrs
    if patch:
        api.call("PUT", base, patch, ok=(204,))
        changed += [f"setting {k}" for k in sorted(patch)]
    # 5. missing clients, roles and groups (never overwritten: SKIP keeps what exists)
    before_clients, before_groups = set(_client_ids(api, base)), set(_groups(api, base))
    api.call(
        "POST",
        f"{base}/partialImport",
        {
            "ifResourceExists": "SKIP",
            "clients": full.get("clients") or [],
            "groups": full.get("groups") or [],
            "roles": full.get("roles") or {},
        },
    )
    clients = _client_ids(api, base)
    changed += [f"client {c}" for c in sorted(set(clients) - before_clients)]
    # 6. each rendered client: settings, roles, mappers, secret
    for want in full.get("clients") or []:
        live = clients.get(want["clientId"])
        if live is None:
            raise Refused(f"client {want['clientId']} was not created")
        cid = live["id"]
        diff = {k: want[k] for k in CLIENT_FIELDS if k in want and not covers(live.get(k), want[k])}
        if diff:
            api.call("PUT", f"{base}/clients/{_q(cid)}", {**live, **diff}, ok=(204,))
            changed.append(f"client {want['clientId']} settings")
        _, secret = api.call("GET", f"{base}/clients/{_q(cid)}/client-secret")
        if (secret or {}).get("value") != want["secret"]:
            api.call(
                "PUT", f"{base}/clients/{_q(cid)}", {**live, **diff, "secret": want["secret"]},
                ok=(204,),
            )  # fmt: skip
            changed.append(f"client {want['clientId']} secret")
        _, mappers = api.call("GET", f"{base}/clients/{_q(cid)}/protocol-mappers/models")
        by_name = {m["name"]: m for m in mappers or []}
        for m in want.get("protocolMappers") or []:
            cur = by_name.get(m["name"])
            if cur is None:
                api.call("POST", f"{base}/clients/{_q(cid)}/protocol-mappers/models", m, ok=(201,))
                changed.append(f"client {want['clientId']} mapper {m['name']}")
            elif not covers(
                {k: cur.get(k) for k in ("protocolMapper", "config")},
                {k: m[k] for k in ("protocolMapper", "config") if k in m},
            ):
                api.call(
                    "PUT",
                    f"{base}/clients/{_q(cid)}/protocol-mappers/models/{_q(cur['id'])}",
                    {**cur, **m},
                    ok=(204,),
                )
                changed.append(f"client {want['clientId']} mapper {m['name']}")
        _, roles = api.call("GET", f"{base}/clients/{_q(cid)}/roles")
        names = {r["name"] for r in roles or []}
        for r in (full.get("roles") or {}).get("client", {}).get(want["clientId"], []):
            if r["name"] not in names:
                api.call("POST", f"{base}/clients/{_q(cid)}/roles", r, ok=(201,))
                changed.append(f"client {want['clientId']} role {r['name']}")
    # 7. each rendered group: exactly its rendered roles on the rendered clients
    groups = _groups(api, base)
    changed += [f"group {g}" for g in sorted(set(groups) - before_groups)]
    rendered_clients = {c["clientId"] for c in full.get("clients") or []}
    for want in full.get("groups") or []:
        g = groups.get(want["name"])
        if g is None:
            raise Refused(f"group {want['name']} was not created")
        for client in sorted(rendered_clients):
            cid = clients[client]["id"]
            have_roles = _group_roles(api, base, g["id"], cid)
            want_roles = set((want.get("clientRoles") or {}).get(client, []))
            if have_roles == want_roles:
                continue
            _, defined = api.call("GET", f"{base}/clients/{_q(cid)}/roles")
            reps = {r["name"]: r for r in defined or []}
            path = f"{base}/groups/{_q(g['id'])}/role-mappings/clients/{_q(cid)}"
            add = [reps[n] for n in sorted(want_roles - have_roles)]
            drop = [reps[n] for n in sorted(have_roles - want_roles) if n in reps]
            if add:
                api.call("POST", path, add, ok=(204,))
            if drop:
                api.call("DELETE", path, drop, ok=(204,))
            changed.append(f"group {want['name']} roles on {client}")
    return {"created": False, "changed": changed}


def health(api: Api, cfg: dict) -> dict:
    realm = cfg["realm"]
    doc = cfg["doc"]
    check_doc(doc, realm)
    problems: list[str] = []
    # 1. OIDC discovery: the issuer the edge's auth proxy is configured with, and a key set
    _, disc = api.call("GET", f"/realms/{_q(realm)}/.well-known/openid-configuration", auth=False)
    if (disc or {}).get("issuer") != cfg["issuer"]:
        problems.append(
            f"discovery: the issuer is {(disc or {}).get('issuer')!r}, not {cfg['issuer']!r}"
        )
    _, jwks = api.call("GET", f"/realms/{_q(realm)}/protocol/openid-connect/certs", auth=False)
    if not (jwks or {}).get("keys"):
        problems.append("discovery: the realm publishes no signing key")
    api.sign_in(cfg["admin_user"], cfg["admin_password"])
    base = _realm_path(realm)
    _, rep = api.call("GET", base)
    # 2. the bound flows: the rendered ones; the passkey required; no code; direct grant refused
    for binding in ("browserFlow", "directGrantFlow"):
        if rep.get(binding) != doc[binding]:
            problems.append(f"{binding} is {rep.get(binding)!r}, not {doc[binding]!r}")
    for flag in ("registrationAllowed", "resetPasswordAllowed", "editUsernameAllowed"):
        if rep.get(flag) is not False:
            problems.append(f"{flag} is not false")
    if rep.get("webAuthnPolicyUserVerificationRequirement") != "required":
        problems.append("the WebAuthn policy does not require user verification")
    _, brokers = api.call("GET", f"{base}/identity-provider/instances")
    if brokers:
        problems.append("an identity provider is configured (a broker login flow)")
    _, master = api.call("GET", "/admin/realms/master")
    if (master or {}).get("bruteForceProtected") is not True:
        problems.append("the master realm has no brute-force protection")
    _, flows = api.call("GET", f"{base}/authentication/flows")
    names = {f["alias"] for f in flows or []}
    for binding in ("browserFlow", "directGrantFlow"):
        alias = rep.get(binding)
        if alias not in names:
            continue
        _, listed = api.call("GET", f"{base}/authentication/flows/{_q(alias)}/executions")
        live = live_executions(listed)
        if alias in _flows(doc) and live != expected_executions(doc, alias):
            problems.append(f"flow {alias} differs from the rendered one")
        steps = {(n, r) for _, kind, n, r in live if kind == "step"}
        if any(n in OTP_AUTHENTICATORS for n, _ in steps):
            problems.append(f"flow {alias} offers a one-time code")
        if binding == "browserFlow" and (SECOND_FACTOR, "REQUIRED") not in steps:
            problems.append(f"flow {alias}: WebAuthn is not REQUIRED in the approvers' sign-in")
        if binding == "directGrantFlow" and (REFUSAL, "REQUIRED") not in steps:
            problems.append(f"flow {alias}: the direct grant is not refused")
    # 3. enrolment: the passkey's registration is a default action, a code's is off
    _, actions = api.call("GET", f"{base}/authentication/required-actions")
    by_alias = {a["alias"]: a for a in actions or []}
    reg = by_alias.get("webauthn-register") or {}
    if not (reg.get("enabled") and reg.get("defaultAction")):
        problems.append("webauthn-register is not an enabled default action")
    if (by_alias.get("CONFIGURE_TOTP") or {}).get("enabled"):
        problems.append("CONFIGURE_TOTP is enabled (a one-time code is offered)")
    # 4. the user profile refuses the reserved usernames
    _, live_profile = api.call("GET", f"{base}/users/profile")
    want = username_pattern(profile_config(doc))
    if username_pattern(live_profile or {}) != want:
        problems.append("the user profile's reserved-username pattern differs from the rendered")
    if username_validations(live_profile or {}) != username_validations(profile_config(doc)):
        problems.append("the user profile's username validators differ from the rendered")
    # 5. no user holds a reserved username (an import or a restore bypasses the validator)
    reserved = sorted(
        {n.lower() for n in cfg.get("reserved") or []}
        | {
            n
            for n in str((doc.get("attributes") or {}).get("hnx.reserved_usernames", "")).split(",")
            if n
        }
    )
    if not reserved:
        problems.append("no reserved username is listed (the rendered realm lists them)")
    for name in reserved:
        _, users = api.call(
            "GET", f"{base}/users?username={_q(name)}&exact=false&max=1000&briefRepresentation=true"
        )
        held = sorted(
            u.get("username", "") for u in users or [] if str(u.get("username", "")).lower() == name
        )
        if held:
            problems.append(f"a user holds the reserved username {name!r}")
    # 6. every rendered client and group, each group with exactly its rendered roles; no client
    #    (rendered or the IdP's own) overrides a flow binding
    clients = _client_ids(api, base)
    for cid, c in sorted(clients.items()):
        if c.get("authenticationFlowBindingOverrides"):
            problems.append(f"client {cid} overrides a flow binding")
    for c in doc.get("clients") or []:
        if c["clientId"] not in clients:
            problems.append(f"client {c['clientId']} is missing")
    groups = _groups(api, base)
    for g in doc.get("groups") or []:
        live = groups.get(g["name"])
        if live is None:
            problems.append(f"group {g['name']} is missing")
            continue
        for client in sorted(c["clientId"] for c in doc.get("clients") or []):
            if client not in clients:
                continue
            have = _group_roles(api, base, live["id"], clients[client]["id"])
            if have != set((g.get("clientRoles") or {}).get(client, [])):
                problems.append(f"group {g['name']}: its roles on {client} differ")
        # 7. trust on first use: every enabled member holds a registered passkey (until they do,
        #    whoever first signs in with their password registers one)
        _, members = api.call(
            "GET", f"{base}/groups/{_q(live['id'])}/members?max=1000&briefRepresentation=true"
        )
        for u in members or []:
            if not u.get("enabled", True):
                continue
            _, creds = api.call("GET", f"{base}/users/{_q(u['id'])}/credentials")
            if not any(c.get("type") == "webauthn" for c in creds or []):
                problems.append(
                    f"user {u.get('username')!r} in group {g['name']} has no passkey registered "
                    "(register it in person: the first sign-in registers whoever's key)"
                )
    return {"problems": problems}


def export(api: Api, cfg: dict) -> dict:
    """The realm's partial export, returned (the role writes it, 0600)."""
    api.sign_in(cfg["admin_user"], cfg["admin_password"])
    _, body = api.call(
        "POST",
        f"{_realm_path(cfg['realm'])}/partial-export?exportClients=true&exportGroupsAndRoles=true",
    )
    if not isinstance(body, dict) or body.get("realm") != cfg["realm"]:
        raise Refused("the partial export is not the realm's")
    return {"realm": body, "clients": len(body.get("clients") or [])}


MODES = {"wait": wait, "sync": sync, "health": health, "export": export}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in MODES:
        print(f"usage: keycloak_api.py {'|'.join(MODES)} < settings.json", file=sys.stderr)
        return 2
    try:
        cfg = json.loads(sys.stdin.read(MAX_BYTES))
        if not isinstance(cfg, dict):
            raise Refused("settings: not a JSON object")
        result = MODES[argv[1]](Api(cfg), cfg)
    except Refused as exc:
        print(f"keycloak: {exc}", file=sys.stderr)
        return 1
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError, KeyError) as exc:
        # never the exception's text: it could hold a request body
        print(f"keycloak: {argv[1]} failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
