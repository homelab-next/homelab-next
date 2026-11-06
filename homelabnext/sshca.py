# SPDX-License-Identifier: Apache-2.0
"""``hnx ssh-ca``: the secrets store's SSH user-certificate configuration, as code.

    hnx ssh-ca check SPEC
    hnx ssh-ca render SPEC [--format json|sh]

SSH single sign-on without an LDAP outpost (docs/private-overlay.md, "SSH certificates"): a person
logs in to the secrets store (OpenBao) with OIDC against the identity provider, and the store's SSH
secrets engine signs their public key into a certificate valid for hours; the deploy job signs a
key it generates per job with its AppRole token, valid for minutes. Hosts trust the CA
(``ssh_hardening_trusted_user_ca_keys``) and map local accounts to principals
(``ssh_hardening_authorized_principals``).

``SPEC`` (``lab/ssh-ca.yml``, start from ``examples/private-overlay/lab/ssh-ca.yml``) names the
signing roles. ``render`` turns it into the writes that configure the store, one per API path, in
order: an ACL policy per role that may only sign with that role, the SSH role (user certificates
only, the principals, the TTLs, the extensions, optional ``source-address``), and, for a person's
role, the OIDC login role bound to the identity provider's groups claim with a short token TTL.
``--format json`` prints ``[{"path", "data"}]``; ``--format sh`` prints one
``"$BAO_CLI" write PATH -`` per write with the JSON on standard input, for the operator to run with
an admin token. The writes overwrite (they are the configuration, not data), so rendering and
applying again converges. Enabling the engine, generating the CA key and the OIDC method's client
configuration (it holds the client secret) are one-time operator steps, not rendered here.

Refused (exit 1, before anything is printed): an unknown key, a duplicate role, a principal that is
not a plain name or is ``root``, a TTL above its maximum or above the cap for its kind (deploy 1 h,
person 24 h), an extension outside OpenSSH's set, forwarding or user-rc extensions on a deploy role,
a person's role without groups or a deploy role with them, a source address that is not a
network, and an ``oidc.user_claim`` other than :data:`homelabnext.edge_identity.USERNAME_CLAIM`
(``preferred_username``: the claim the status hub's approver allowlist names people by too, so a
person is one name on their certificate's key id and on the allowlist). Exit 2 is a usage error.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shlex
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from homelabnext.edge_identity import USERNAME_CLAIM

#: role, mount and group names (also the policy's and login role's names)
NAME = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?\Z")
#: a certificate principal: a plain account-like name, as the hosts' principals files hold them
PRINCIPAL = re.compile(r"[a-z_][a-z0-9_.-]{0,31}\Z")
#: a claim name in the identity provider's ID token
CLAIM = re.compile(r"[A-Za-z_][A-Za-z0-9_.:/-]{0,63}\Z")
DURATION = re.compile(r"([1-9][0-9]{0,5})([smh])\Z")
UNIT = {"s": 1, "m": 60, "h": 3600}
#: the certificate extensions OpenSSH knows
EXTENSIONS = (
    "permit-pty",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-X11-forwarding",
    "permit-user-rc",
)
#: what a deploy certificate may carry: a terminal at most, never a forwarding or a user rc file
DEPLOY_EXTENSIONS = ("permit-pty",)
#: the longest certificate per kind of holder
CAP = {"deploy": 3600, "human": 24 * 3600}
KINDS = tuple(CAP)
ROLE_KEYS = {
    "name",
    "for",
    "principals",
    "ttl",
    "max_ttl",
    "extensions",
    "groups",
    "source_addresses",
}
TOP_KEYS = {"ssh_ca_version", "ssh_mount", "oidc_mount", "oidc", "roles"}
OIDC_KEYS = {"audience", "redirect_uris", "user_claim", "groups_claim", "scopes", "login_ttl"}
#: the CLI's local listener for an OIDC login (the store's documented default callback)
DEFAULT_REDIRECT = "http://localhost:8250/oidc/callback"  # no-raw-endpoint: allow the CLI's own loopback OIDC callback
LOGIN_TTL_CAP = 3600


class SpecError(ValueError):
    """The spec is not one this module will render."""


@dataclass(frozen=True)
class Role:
    name: str
    kind: str
    principals: tuple[str, ...]
    ttl: str
    max_ttl: str
    extensions: tuple[str, ...]
    groups: tuple[str, ...]
    source_addresses: tuple[str, ...]

    @property
    def policy(self) -> str:
        return f"hnx-ssh-{self.name}"


@dataclass(frozen=True)
class Spec:
    ssh_mount: str
    oidc_mount: str
    audience: str
    redirect_uris: tuple[str, ...]
    user_claim: str
    groups_claim: str
    scopes: tuple[str, ...]
    login_ttl: str
    roles: tuple[Role, ...]


def seconds(where: str, value: Any) -> int:
    m = DURATION.match(value) if isinstance(value, str) else None
    if not m:
        raise SpecError(f"{where}: a duration is a whole number of s, m or h (got {value!r})")
    return int(m.group(1)) * UNIT[m.group(2)]


def _names(where: str, value: Any, pattern: re.Pattern[str], *, required: bool) -> tuple[str, ...]:
    if value is None:
        value = []
    if not isinstance(value, list) or not all(
        isinstance(v, str) and pattern.match(v) for v in value
    ):
        raise SpecError(f"{where}: expected a list of plain names")
    if required and not value:
        raise SpecError(f"{where}: expected at least one")
    if len(set(value)) != len(value):
        raise SpecError(f"{where}: a name is listed twice")
    return tuple(value)


def _role(where: str, raw: Any) -> Role:
    if not isinstance(raw, dict):
        raise SpecError(f"{where}: expected a mapping")
    extra = set(raw) - ROLE_KEYS
    if extra:
        raise SpecError(f"{where}: unknown key(s) {sorted(extra)}")
    name = raw.get("name")
    if not isinstance(name, str) or not NAME.match(name):
        raise SpecError(f"{where}: name is a plain lower-case name")
    where = f"{where} ({name})"
    kind = raw.get("for")
    if kind not in KINDS:
        raise SpecError(f"{where}: for is one of {', '.join(KINDS)}")
    principals = _names(f"{where}: principals", raw.get("principals"), PRINCIPAL, required=True)
    if "root" in principals:
        raise SpecError(f"{where}: principals: root is never a principal (hosts refuse root login)")
    ttl, max_ttl = raw.get("ttl"), raw.get("max_ttl", raw.get("ttl"))
    t, mt = seconds(f"{where}: ttl", ttl), seconds(f"{where}: max_ttl", max_ttl)
    if t > mt:
        raise SpecError(f"{where}: ttl {ttl} is longer than max_ttl {max_ttl}")
    if mt > CAP[kind]:
        raise SpecError(f"{where}: max_ttl {max_ttl} is longer than a {kind} certificate may live")
    ext = raw.get("extensions", ["permit-pty"] if kind == "human" else [])
    if not isinstance(ext, list) or not all(e in EXTENSIONS for e in ext):
        raise SpecError(f"{where}: extensions are some of {', '.join(EXTENSIONS)}")
    if len(set(ext)) != len(ext):
        raise SpecError(f"{where}: an extension is listed twice")
    if kind == "deploy" and set(ext) - set(DEPLOY_EXTENSIONS):
        raise SpecError(
            f"{where}: a deploy certificate carries no forwarding or user rc "
            f"(got {sorted(set(ext) - set(DEPLOY_EXTENSIONS))})"
        )
    groups = _names(f"{where}: groups", raw.get("groups"), NAME, required=kind == "human")
    if kind == "deploy" and groups:
        raise SpecError(f"{where}: a deploy role signs for the deploy's AppRole, not for groups")
    sources = raw.get("source_addresses") or []
    if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
        raise SpecError(f"{where}: source_addresses is a list of networks")
    nets = []
    for s in sources:
        try:
            nets.append(str(ipaddress.ip_network(s, strict=True)))
        except ValueError:
            raise SpecError(f"{where}: source_addresses: {s!r} is not a network") from None
    return Role(name, kind, principals, ttl, max_ttl, tuple(ext), groups, tuple(nets))


def parse(doc: Any, where: str = "spec") -> Spec:
    if not isinstance(doc, dict) or doc.get("ssh_ca_version") != 1:
        raise SpecError(f"{where}: expected a mapping with ssh_ca_version: 1")
    extra = set(doc) - TOP_KEYS
    if extra:
        raise SpecError(f"{where}: unknown key(s) {sorted(extra)}")
    mounts = {}
    for key, default in (("ssh_mount", "ssh"), ("oidc_mount", "oidc")):
        mounts[key] = doc.get(key, default)
        if not isinstance(mounts[key], str) or not NAME.match(mounts[key]):
            raise SpecError(f"{where}: {key} is a plain mount name")
    raw_roles = doc.get("roles")
    if not isinstance(raw_roles, list) or not raw_roles:
        raise SpecError(f"{where}: roles is a non-empty list")
    roles = tuple(_role(f"{where}: roles[{i}]", r) for i, r in enumerate(raw_roles))
    seen = [r.name for r in roles]
    if len(set(seen)) != len(seen):
        raise SpecError(f"{where}: a role name is used twice")
    oidc = doc.get("oidc") or {}
    if not isinstance(oidc, dict):
        raise SpecError(f"{where}: oidc is a mapping")
    extra = set(oidc) - OIDC_KEYS
    if extra:
        raise SpecError(f"{where}: oidc: unknown key(s) {sorted(extra)}")
    people = any(r.kind == "human" for r in roles)
    audience = oidc.get("audience", "")
    if not isinstance(audience, str) or (people and not CLAIM.match(audience)):
        raise SpecError(
            f"{where}: oidc.audience is the identity provider's client id (required "
            "with a person's role)"
        )
    uris = oidc.get("redirect_uris", [DEFAULT_REDIRECT])
    if (
        not isinstance(uris, list)
        or not uris
        or not all(
            isinstance(u, str)
            and re.match(r"https?://[A-Za-z0-9.:\[\]-]+(/[A-Za-z0-9._~/-]*)?\Z", u)
            for u in uris
        )
    ):
        raise SpecError(f"{where}: oidc.redirect_uris is a list of http(s) URLs")
    claims = {}
    for key, default in (("user_claim", USERNAME_CLAIM), ("groups_claim", "groups")):
        claims[key] = oidc.get(key, default)
        if not isinstance(claims[key], str) or not CLAIM.match(claims[key]):
            raise SpecError(f"{where}: oidc.{key} is a claim name")
    if claims["user_claim"] != USERNAME_CLAIM:
        # one person, one name: the status hub's approver allowlist names people by this claim
        # too (homelabnext.edge_identity), so a certificate keyed on another would not match it
        raise SpecError(
            f"{where}: oidc.user_claim is {USERNAME_CLAIM} (the platform's one username claim, "
            "homelabnext.edge_identity); drop the key or set it to that"
        )
    scopes = _names(f"{where}: oidc.scopes", oidc.get("scopes", ["openid"]), CLAIM, required=True)
    login_ttl = oidc.get("login_ttl", "10m")
    if seconds(f"{where}: oidc.login_ttl", login_ttl) > LOGIN_TTL_CAP:
        raise SpecError(f"{where}: oidc.login_ttl: the login token only signs a key; at most 1h")
    return Spec(
        mounts["ssh_mount"],
        mounts["oidc_mount"],
        audience,
        tuple(uris),
        claims["user_claim"],
        claims["groups_claim"],
        scopes,
        login_ttl,
        roles,
    )


def load(path: str | Path) -> Spec:
    from homelabnext._yaml import load_unique

    p = Path(path)
    return parse(load_unique(p, SpecError), str(p))


def writes(spec: Spec) -> list[dict[str, Any]]:
    """The configuration writes, in order: policy, SSH role, then (a person's role) OIDC role."""
    out: list[dict[str, Any]] = []
    for r in spec.roles:
        policy = f'path "{spec.ssh_mount}/sign/{r.name}" {{\n  capabilities = ["update"]\n}}\n'
        out.append({"path": f"sys/policies/acl/{r.policy}", "data": {"policy": policy}})
        role: dict[str, Any] = {
            "key_type": "ca",
            "allow_user_certificates": True,
            "allow_host_certificates": False,
            "allowed_users": ",".join(r.principals),
            "default_user": r.principals[0],
            "allow_user_key_ids": False,
            "key_id_format": "{{role_name}}-{{token_display_name}}",
            "allowed_extensions": ",".join(r.extensions),
            "default_extensions": dict.fromkeys(r.extensions, ""),
            "allowed_critical_options": "",
            "default_critical_options": (
                {"source-address": ",".join(r.source_addresses)} if r.source_addresses else {}
            ),
            "ttl": r.ttl,
            "max_ttl": r.max_ttl,
        }
        out.append({"path": f"{spec.ssh_mount}/roles/{r.name}", "data": role})
        if r.kind == "human":
            out.append(
                {
                    "path": f"auth/{spec.oidc_mount}/role/{r.name}",
                    "data": {
                        "role_type": "oidc",
                        "bound_audiences": [spec.audience],
                        "allowed_redirect_uris": list(spec.redirect_uris),
                        "user_claim": spec.user_claim,
                        "groups_claim": spec.groups_claim,
                        "bound_claims": {spec.groups_claim: list(r.groups)},
                        "oidc_scopes": list(spec.scopes),
                        "token_policies": [r.policy],
                        "token_ttl": spec.login_ttl,
                        "token_max_ttl": spec.login_ttl,
                        "token_type": "service",
                    },
                }
            )
    return out


def render_sh(spec: Spec) -> str:
    lines = [
        "# hnx ssh-ca render: run with an admin token; BAO_CLI is the secrets store's CLI",
        'set -eu\n: "${BAO_CLI:?set BAO_CLI to the secrets store CLI}"',
    ]
    for w in writes(spec):
        body = json.dumps(w["data"], sort_keys=True, separators=(",", ":"))
        lines.append(
            f'printf "%s\\n" {shlex.quote(body)} | "$BAO_CLI" write {shlex.quote(w["path"])} -'
        )
    deploy = [r.policy for r in spec.roles if r.kind == "deploy"]
    if deploy:
        lines.append("# add to the deploy AppRole's token_policies: " + ", ".join(deploy))
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx ssh-ca", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="validate the spec and list its roles")
    c.add_argument("spec")
    r = sub.add_parser("render", help="print the store's configuration writes")
    r.add_argument("spec")
    r.add_argument("--format", choices=("json", "sh"), default="json")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    try:
        spec = load(args.spec)
    except SpecError as exc:
        print(f"hnx ssh-ca: {exc}", file=sys.stderr)
        return 1
    if args.cmd == "check":
        for role in spec.roles:
            print(
                f"{role.name}: {role.kind}, principals {','.join(role.principals)}, ttl {role.ttl} "
                f"(max {role.max_ttl}), extensions {','.join(role.extensions) or 'none'}"
                + (f", groups {','.join(role.groups)}" if role.groups else "")
            )
        return 0
    if args.format == "sh":
        sys.stdout.write(render_sh(spec))
    else:
        print(json.dumps(writes(spec), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
