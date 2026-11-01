# SPDX-License-Identifier: Apache-2.0
"""The eleven built-in generators."""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict

import yaml

from homelabnext.edge_identity import (
    AUTH_PROXY_CALLBACK,
    AUTH_PROXY_CAPABILITY,
    AUTH_PROXY_CHECK,
    AUTH_PROXY_PREFIX,
    AUTH_PROXY_SIGN_IN,
    IDENTITY_HEADERS,
    IdentityHeaders,
)
from homelabnext.registry.model import Registry, Service, secret_env_name

from .core import MARKER, register
from .safe import check_fields, checked
from .templates import render


def _hdr(reg: Registry, comment: str = "#") -> str:
    return f"{comment} {MARKER} (homelabnext) from services.yml sha256:{reg.digest[:16]}; do not edit\n"


def _json_doc(reg: Registry, body: dict) -> str:
    doc = {
        "_generated": f"{MARKER} (homelabnext) from services.yml sha256:{reg.digest[:16]}; do not edit"
    }
    doc.update(body)
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def _yaml_doc(reg: Registry, body) -> str:
    return _hdr(reg) + yaml.safe_dump(body, sort_keys=True, default_flow_style=False, width=100)


def _endpoint_url(reg: Registry, svc: Service) -> str:
    return f"{svc.scheme}://{reg.alias(svc.capability)}:{svc.port}"


def _l4(svc: Service) -> str:
    return "udp" if svc.protocol in ("udp", "dns") else "tcp"


def _rrtype(addr: str) -> str:
    return "A" if ipaddress.ip_address(addr).version == 4 else "AAAA"


def _dependants(reg: Registry) -> dict[str, list[Service]]:
    deps: dict[str, list[Service]] = defaultdict(list)
    for s in reg.sorted_services():
        for up in s.upstreams:
            deps[up].append(s)
    return deps


# 1 ---------------------------------------------------------------- DNS zones
@register(
    "dns_zone",
    "RFC 1035 zone files: capability aliases (A, SRV, TXT) and host records",
    "DNS server / Technitium adapter",
)
def dns_zone(reg: Registry) -> dict[str, str]:
    zone = reg.alias_zone
    dns_svc = reg.by_capability("dns")
    mname = reg.alias("dns") if dns_svc else f"ns.{zone}"
    out = {}
    lines = [
        _hdr(reg, ";"),
        f"$ORIGIN {zone}.",
        "$TTL 60",
        f"@ IN SOA {mname}. hostmaster.{reg.domain}. ( 1 3600 600 86400 60 )",
    ]
    if dns_svc:
        lines.append(f"@ IN NS {mname}.")
    for s in reg.sorted_services():
        host = reg.host_of(s)
        check_fields("zone", {"capability": s.capability, "address": host.address})
        lines.append(f"{s.capability} IN {_rrtype(host.address)} {host.address}")
    for s in reg.sorted_services():
        lines.append(f"_{s.capability}._{_l4(s)} IN SRV 0 0 {s.port} {s.capability}.{zone}.")
        scheme = s.scheme
        lines.append(f'_{s.capability}._{_l4(s)} IN TXT "scheme={scheme}"')
    out[f"dns/{zone}.zone"] = "\n".join(lines) + "\n"
    hl = [_hdr(reg, ";"), f"$ORIGIN {reg.domain}.", "$TTL 300"]
    for name in sorted(reg.hosts):
        h = reg.hosts[name]
        hl.append(f"{name} IN {_rrtype(h.address)} {h.address}")
    out[f"dns/{reg.domain}.hosts.zone"] = "\n".join(hl) + "\n"
    return out


# 2 ---------------------------------------------------------------- hosts file
HOSTS_BEGIN = "# BEGIN homelabnext"
HOSTS_END = "# END homelabnext"


def apply_hosts_block(existing: str, block: str) -> str:
    """Replace (or append) the managed block in an existing hosts file. Idempotent."""
    lines = existing.splitlines()
    if HOSTS_BEGIN in "\n".join(lines):
        start = next(i for i, ln in enumerate(lines) if ln.startswith(HOSTS_BEGIN))
        end = next(i for i, ln in enumerate(lines) if ln.startswith(HOSTS_END))
        lines[start : end + 1] = block.rstrip("\n").splitlines()
    else:
        lines += block.rstrip("\n").splitlines()
    return "\n".join(lines) + "\n"


@register(
    "hosts_file",
    "hosts(5) block mapping host and capability names to addresses (resolver fallback)",
    "/etc/hosts via base role",
)
def hosts_file(reg: Registry) -> dict[str, str]:
    by_addr: dict[str, list[str]] = defaultdict(list)
    for name in sorted(reg.hosts):
        by_addr[reg.hosts[name].address].append(f"{name}.{reg.domain}")
    for s in reg.sorted_services():
        by_addr[reg.host_of(s).address].append(reg.alias(s.capability))
    lines = [f"{HOSTS_BEGIN} sha256:{reg.digest[:16]} ({MARKER}; do not edit)"]
    for addr in sorted(by_addr, key=lambda a: ipaddress.ip_address(a)):
        lines.append(f"{addr} " + " ".join(sorted(by_addr[addr])))
    lines.append(HOSTS_END)
    return {"hosts/hosts.block": "\n".join(lines) + "\n"}


# 3 ---------------------------------------------------------------- Caddy
def _forward_auth_snippet(endpoint: str, identity: IdentityHeaders | None = None) -> str:
    """The ``hnx_forward_auth`` snippet (ADR-0034): the auth proxy's own paths, then the check.

    ``handle /oauth2/*`` proxies the auth proxy's sign-in, callback and sign-out under the site's
    own host (Caddy sorts ``handle`` before ``route``).  Every other request goes through
    ``forward_auth`` to the auth proxy's check: a 2xx copies the identity headers of
    :data:`~homelabnext.edge_identity.IDENTITY_HEADERS` onto the request, a 401 redirects to the
    sign-in page.  Before ``forward_auth`` runs, every identity header a *client* sent is deleted
    (``request_header -*auth-request*`` and ``-*auth_request*``: Caddy matches a ``*x*`` delete
    case-insensitively anywhere in the name, so every separator and case spelling goes): Caddy
    2.9.0 to 2.11.1 keep a client-sent header that the auth proxy's answer omits, so without the
    strip a client could name its own user or groups to the service.  The delete and
    ``forward_auth`` sit in one ``route``, which runs its directives in the order written
    (``forward_auth`` otherwise sorts before ``request_header``, and the strip would delete the
    auth proxy's own headers instead)."""
    identity = identity or IDENTITY_HEADERS
    strip = identity.strip_lines("\t\t")
    return (
        "(hnx_forward_auth) {\n"
        f"\thandle {AUTH_PROXY_PREFIX} {{\n"
        f"\t\treverse_proxy {endpoint} {{\n"
        "\t\t\theader_up X-Real-IP {remote_host}\n"
        "\t\t\theader_up X-Forwarded-Uri {uri}\n"
        "\t\t}\n"
        "\t}\n"
        "\troute {\n"
        "\t\t# client-sent identity headers never reach the service, whatever the auth proxy answers\n"
        f"{strip}"
        f"\t\tforward_auth {endpoint} {{\n"
        f"\t\t\turi {AUTH_PROXY_CHECK}\n"
        "\t\t\theader_up X-Real-IP {remote_host}\n"
        f"\t\t\tcopy_headers {' '.join(identity.headers)}\n"
        "\t\t\t@hnx_sign_in status 401\n"
        "\t\t\thandle_response @hnx_sign_in {\n"
        f"\t\t\t\tredir * {AUTH_PROXY_SIGN_IN}?rd={{scheme}}://{{host}}{{uri}}\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "}\n"
    )


def _auth_proxy(reg: Registry) -> Service | None:
    """The forward-auth proxy, required as soon as one public service has ``auth: idp``: without
    it such a site would be published with no login at all, so generation fails instead."""
    proxy = reg.by_capability(AUTH_PROXY_CAPABILITY)
    if proxy is None:
        gated = [s.name for s in reg.sorted_services() if s.auth == "idp" and s.public_hostname]
        if gated:
            raise ValueError(
                f"caddy: {', '.join(gated)} need(s) auth: idp at the edge but no service provides "
                f"capability {AUTH_PROXY_CAPABILITY!r} (the forward-auth proxy, ADR-0034)"
            )
    return proxy


@register(
    "caddy", "Caddyfile site snippets for services with a public hostname", "reverse proxy (edge)"
)
def caddy(reg: Registry) -> dict[str, str]:
    proxy = _auth_proxy(reg)
    parts = [_hdr(reg)]
    if proxy:
        parts.append(
            _forward_auth_snippet(
                checked(_endpoint_url(reg, proxy), "auth-proxy endpoint", "caddy")
            )
        )
    strip = IDENTITY_HEADERS.strip_lines("\t")
    for s in reg.sorted_services():
        if not s.public_hostname:
            continue
        # every site strips the client's identity headers at site level, before every handle
        # and route of the site (Caddy sorts request_header first): a path that never reaches
        # the snippet's route (a handle added beside it, a matcher on a route) and a site with
        # no forward auth that reaches the same service under another name still reach it
        # without them; the route-level strip in the snippet stays as well
        auth_block = strip + ("\timport hnx_forward_auth\n" if s.auth == "idp" else "")
        proxy_block = ""
        if s.front_door and s.auth == "idp":
            # the shared secret that tells the service this request came through the edge (and
            # so its identity headers are the auth proxy's): from the environment, never in the file
            header = checked(s.front_door["header"], "front_door.header", "caddy")
            env = checked(secret_env_name(s.front_door["secret"]), "front_door.secret", "caddy")
            proxy_block = f" {{\n\t\theader_up {header} {{env.{env}}}\n\t}}"
        parts.append(
            render(
                "caddy_site",
                raw={"auth_block": auth_block, "proxy_block": proxy_block},
                hostname=s.public_hostname,
                service=s.name,
                capability=s.capability,
                owner=s.owner,
                scheme=s.scheme,
                alias=reg.alias(s.capability),
                port=str(s.port),
            )
        )
    return {"caddy/sites.caddy": "\n".join(parts)}


# 4 ---------------------------------------------------------------- Prometheus
@register(
    "prometheus",
    "Prometheus scrape_configs for services exposing metrics",
    "monitoring (Prometheus)",
)
def prometheus(reg: Registry) -> dict[str, str]:
    jobs = []
    for s in reg.sorted_services():
        if not s.metrics:
            continue
        port = s.metrics.get("port", s.port)
        jobs.append(
            {
                "job_name": s.capability,
                "metrics_path": s.metrics["path"],
                "scheme": s.scheme if s.scheme in ("http", "https") else "http",
                "static_configs": [
                    {
                        "targets": [f"{reg.alias(s.capability)}:{port}"],
                        "labels": {"owner": s.owner, "service": s.name, "version": s.version},
                    }
                ],
            }
        )
    return {"prometheus/scrape_configs.yml": _yaml_doc(reg, {"scrape_configs": jobs})}


# 5 ---------------------------------------------------------------- blackbox
@register(
    "blackbox",
    "Blackbox exporter file_sd target lists (HTTP and TCP probes)",
    "monitoring (blackbox exporter)",
)
def blackbox(reg: Registry) -> dict[str, str]:
    http, tcp = [], []
    for s in reg.sorted_services():
        kind = s.health.get("kind", "none")
        alias = reg.alias(s.capability)
        if kind == "http":
            http.append(
                {
                    "targets": [
                        f"{s.scheme if s.scheme in ('http', 'https') else 'http'}://{alias}:{s.port}{s.health['path']}"
                    ],
                    "labels": {
                        "expect_status": str(s.health.get("expect_status", 200)),
                        "module": "http_2xx"
                        if s.health.get("expect_status", 200) < 300
                        else "http_any",
                        "owner": s.owner,
                        "service": s.name,
                    },
                }
            )
        elif kind == "tcp":
            tcp.append(
                {
                    "targets": [f"{alias}:{s.port}"],
                    "labels": {"module": "tcp_connect", "owner": s.owner, "service": s.name},
                }
            )
    return {
        "blackbox/targets_http.yml": _yaml_doc(reg, http),
        "blackbox/targets_tcp.yml": _yaml_doc(reg, tcp),
    }


# 6 ---------------------------------------------------------------- systemd
@register(
    "systemd_env",
    "systemd drop-ins with Environment= endpoints for each service's upstreams",
    "systemd units (base role)",
)
def systemd_env(reg: Registry) -> dict[str, str]:
    out = {}
    for s in reg.sorted_services():
        if not s.upstreams:
            continue
        lines = [_hdr(reg), "[Service]"]
        for up in sorted(s.upstreams):
            u = reg.by_capability(up)
            check_fields("systemd", {"env_var": u.endpoint_env_var, "url": _endpoint_url(reg, u)})
            lines.append(f'Environment="{u.endpoint_env_var}={_endpoint_url(reg, u)}"')
        out[f"systemd/{s.name}.service.d/10-hnx-endpoints.conf"] = "\n".join(lines) + "\n"
    return out


# 7 ---------------------------------------------------------------- MCP
@register(
    "mcp_config",
    "Agent MCP client configuration for services that expose an MCP endpoint",
    "agent runtime",
)
def mcp_config(reg: Registry) -> dict[str, str]:
    servers = {}
    for s in reg.sorted_services():
        if not s.mcp or s.mcp.get("transport", "http") == "stdio":
            continue
        servers[s.mcp["name"]] = {
            "type": s.mcp.get("transport", "http"),
            "url": _endpoint_url(reg, s) + s.mcp.get("path", "/mcp"),
        }
    return {"agents/mcp.json": _json_doc(reg, {"mcpServers": servers})}


# 8 ---------------------------------------------------------------- firewall
def firewall_rules(reg: Registry) -> list[tuple[str, str, str, int, str, str]]:
    merged: dict[tuple[str, str, str, int, str], set[str]] = defaultdict(set)
    rules = set()
    for s in reg.sorted_services():
        dst_zone = reg.host_of(s).zone
        for up in s.upstreams:
            u = reg.by_capability(up)
            uz = reg.host_of(u).zone
            if uz != reg.host_of(s).zone:
                rules.add(
                    (
                        reg.host_of(s).zone,
                        uz,
                        _l4(u),
                        u.port,
                        u.name,
                        f"{s.name} depends on {u.name}",
                    )
                )
        for z in s.clients:
            if z != dst_zone:
                rules.add((z, dst_zone, _l4(s), s.port, s.name, f"zone {z} is a declared client"))
    for src, dst, proto, port, svc, why in rules:
        merged[(src, dst, proto, port, svc)].add(why)
    return [(*k, "; ".join(sorted(v))) for k, v in sorted(merged.items())]


@register(
    "firewall_matrix",
    "Inter-zone allow matrix (markdown) and rule list (CSV); everything else is denied",
    "firewall / network policy",
)
def firewall_matrix(reg: Registry) -> dict[str, str]:
    rules = firewall_rules(reg)
    zones = sorted(reg.zones)
    cell: dict[tuple[str, str], int] = defaultdict(int)
    for src, dst, *_ in rules:
        cell[(src, dst)] += 1
    md = [
        _hdr(reg, "<!--").rstrip("\n") + " -->",
        "",
        "# Zone allow matrix",
        "",
        "Rows are source zones, columns destination zones; cells count allow rules. "
        "Traffic inside a zone is out of scope and everything not listed is denied.",
        "",
        "| from \\ to | " + " | ".join(zones) + " |",
        "|---|" + "---|" * len(zones),
    ]
    for src in zones:
        md.append(
            f"| {src} | "
            + " | ".join(str(cell[(src, d)]) if cell[(src, d)] else "-" for d in zones)
            + " |"
        )
    md += [
        "",
        "## Rules",
        "",
        "| source | destination | proto/port | service | reason |",
        "|---|---|---|---|---|",
    ]
    for src, dst, proto, port, svc, why in rules:
        check_fields("markdown", {"zone": src, "zone ": dst, "service": svc, "reason": why})
        md.append(f"| {src} | {dst} | {proto}/{port} | {svc} | {why} |")
    csv = [_hdr(reg), "src_zone,dst_zone,proto,port,service,reason"]
    for src, dst, proto, port, svc, why in rules:
        csv.append(f"{src},{dst},{proto},{port},{svc},{why}")
    return {
        "firewall/zone_matrix.md": "\n".join(md) + "\n",
        "firewall/rules.csv": "\n".join(csv) + "\n",
    }


# 9 ---------------------------------------------------------------- IdP realm
#: the browser flow every sign-in goes through: a session cookie, or a password AND a second factor
MFA_BROWSER_FLOW = "hnx-browser-mfa"
#: the scopes a token carries without asking (everything else only when requested)
DEFAULT_CLIENT_SCOPES = ("basic",)
OPTIONAL_CLIENT_SCOPES = ("email", "profile")
#: the claims the IdP's tokens carry the user's groups and this client's roles in
GROUPS_CLAIM, ROLES_CLAIM = "groups", "roles"


def client_secret_ref(service: str) -> str:
    """The secret-store reference of a service's OIDC client secret (never a value)."""
    return f"secret:idp/clients/{service}"


def _execution(requirement: str, priority: int, *, authenticator: str = "", flow: str = "") -> dict:
    out = {"authenticatorFlow": bool(flow), "priority": priority, "requirement": requirement}
    out.update({"flowAlias": flow} if flow else {"authenticator": authenticator})
    out["userSetupAllowed"] = False
    return out


def _mfa_flows() -> list[dict]:
    """The browser flow: the session cookie, or the username/password form followed by a
    required second factor (OTP, or a WebAuthn key once registered; a user with neither is made
    to set up OTP, the first alternative, before the sign-in completes)."""

    def flow(alias: str, top: bool, executions: list[dict], what: str) -> dict:
        return {
            "alias": alias,
            "authenticationExecutions": executions,
            "builtIn": False,
            "description": what,
            "providerId": "basic-flow",
            "topLevel": top,
        }

    forms, second = f"{MFA_BROWSER_FLOW}-forms", f"{MFA_BROWSER_FLOW}-second-factor"
    return [
        flow(
            MFA_BROWSER_FLOW,
            True,
            [
                _execution("ALTERNATIVE", 10, authenticator="auth-cookie"),
                _execution("ALTERNATIVE", 20, flow=forms),
            ],
            "browser sign-in: a session, or a password and a second factor (ADR-0034)",
        ),
        flow(
            forms,
            False,
            [
                _execution("REQUIRED", 10, authenticator="auth-username-password-form"),
                _execution("REQUIRED", 20, flow=second),
            ],
            "username and password, then a second factor",
        ),
        flow(
            second,
            False,
            [
                _execution("ALTERNATIVE", 10, authenticator="auth-otp-form"),
                _execution("ALTERNATIVE", 20, authenticator="webauthn-authenticator"),
            ],
            "OTP or a WebAuthn key",
        ),
    ]


def _mappers(client: str) -> list[dict]:
    """The claims every client's tokens carry beyond the trimmed scopes: the audience (the
    client itself), the user's groups (names, not paths) and the user's roles of this client."""

    def mapper(name: str, kind: str, config: dict[str, str]) -> dict:
        tokens = {"access.token.claim": "true", "id.token.claim": "true"}
        return {
            "config": {**tokens, **config},
            "consentRequired": False,
            "name": name,
            "protocol": "openid-connect",
            "protocolMapper": kind,
        }

    return [
        mapper("audience", "oidc-audience-mapper", {"included.client.audience": client}),
        mapper(
            "client roles",
            "oidc-usermodel-client-role-mapper",
            {
                "claim.name": ROLES_CLAIM,
                "jsonType.label": "String",
                "multivalued": "true",
                "usermodel.clientRoleMapping.clientId": client,
                "userinfo.token.claim": "true",
            },
        ),
        mapper(
            "groups",
            "oidc-group-membership-mapper",
            {"claim.name": GROUPS_CLAIM, "full.path": "false", "userinfo.token.claim": "true"},
        ),
    ]


def _client(name: str, owner: str, redirects: list[str], root: str | None) -> dict:
    """One confidential OIDC client: authorization code with PKCE only, the trimmed scopes, and
    the secret by reference (``$(env:...)``, substituted at import from the secret store)."""
    env = secret_env_name(client_secret_ref(name))
    out = {
        "attributes": {"pkce.code.challenge.method": "S256"},
        "clientAuthenticatorType": "client-secret",
        "clientId": name,
        "defaultClientScopes": list(DEFAULT_CLIENT_SCOPES),
        "description": f"owner {owner}",
        "directAccessGrantsEnabled": False,
        "enabled": True,
        "fullScopeAllowed": False,
        "implicitFlowEnabled": False,
        "name": name,
        "optionalClientScopes": list(OPTIONAL_CLIENT_SCOPES),
        "protocol": "openid-connect",
        "protocolMappers": _mappers(name),
        "publicClient": False,
        "redirectUris": redirects,
        "secret": f"$(env:{env})",
        "serviceAccountsEnabled": False,
        "standardFlowEnabled": bool(redirects),
        "webOrigins": ["+"] if redirects else [],
    }
    if root:
        out["attributes"]["post.logout.redirect.uris"] = f"{root}/*"
        out["rootUrl"] = root
    return out


def realm_grants(realm: dict) -> dict[str, dict[str, set[str]]]:
    """``{group: {client: {role, ...}}}`` as a rendered realm grants it (what the realm check and
    the tests compare with the registry's roles)."""
    return {
        g["name"]: {c: set(r) for c, r in (g.get("clientRoles") or {}).items()}
        for g in realm.get("groups", [])
    }


def registry_grants(reg: Registry) -> dict[str, dict[str, set[str]]]:
    """``{group: {service: {role, ...}}}`` from the registry's group-to-role table."""
    out: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for s in reg.sorted_services():
        for role, groups in s.roles.items():
            for g in groups:
                out[g][s.name].add(role)
    return {g: dict(c) for g, c in out.items()}


@register(
    "idp_realm",
    "OIDC IdP realm (clients, groups and their roles, MFA browser flow) for services with auth=idp",
    "identity provider (realm import)",
)
def idp_realm(reg: Registry) -> dict[str, str]:
    """The IdP's realm as an importable realm document (ADR-0034): one confidential OIDC client
    per ``auth: idp`` service (redirects under its public hostname) and one for the auth proxy
    (its callback on every site it guards), the client roles each service's ``roles`` names, a
    group per group named there holding exactly those roles, and the MFA browser flow.  No
    secret is in it: each client secret is a secret-store reference."""
    gated = [s for s in reg.sorted_services() if s.auth == "idp"]
    clients, roles = [], {}
    for s in gated:
        root = f"https://{s.public_hostname}" if s.public_hostname else None
        clients.append(_client(s.name, s.owner, [f"{root}/*"] if root else [], root))
        if s.roles:
            roles[s.name] = [
                {"clientRole": True, "description": f"{s.name} {r}", "name": r} for r in s.roles
            ]
    proxy = reg.by_capability(AUTH_PROXY_CAPABILITY)
    if proxy is not None and proxy not in gated:
        callbacks = sorted(
            f"https://{s.public_hostname}{AUTH_PROXY_CALLBACK}" for s in gated if s.public_hostname
        )
        clients.append(_client(proxy.name, proxy.owner, callbacks, None))
    clients.sort(key=lambda c: c["clientId"])
    groups = [
        {
            "clientRoles": {c: sorted(r) for c, r in sorted(grants.items())},
            "name": g,
            "path": f"/{g}",
        }
        for g, grants in sorted(registry_grants(reg).items())
    ]
    body = {
        "attributes": {"hnx.generated": _hdr(reg, "").strip()},
        "authenticationFlows": _mfa_flows(),
        "browserFlow": MFA_BROWSER_FLOW,
        "bruteForceProtected": True,
        "clients": clients,
        "displayName": reg.lab_name,
        "enabled": True,
        "groups": groups,
        "realm": reg.lab_name,
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "roles": {"client": roles},
        "sslRequired": "all",
    }
    return {"idp/realm.json": json.dumps(body, indent=2, sort_keys=True) + "\n"}


# 10 --------------------------------------------------------------- docs
@register(
    "service_docs",
    "Markdown service catalogue page (host table and per-service cards)",
    "documentation site",
)
def service_docs(reg: Registry) -> dict[str, str]:
    deps = _dependants(reg)
    md = [
        _hdr(reg, "<!--").rstrip("\n") + " -->",
        "",
        f"# Services of {reg.lab_name}",
        "",
        f"Alias zone: `{reg.alias_zone}`. {len(reg.services)} services on {len(reg.hosts)} hosts.",
        "",
        "## Hosts",
        "",
        "| host | address | zone | role |",
        "|---|---|---|---|",
    ]
    for name in sorted(reg.hosts):
        h = reg.hosts[name]
        check_fields("markdown", {"host": name, "address": h.address, "role": h.role})
        md.append(f"| {name} | {h.address} | {h.zone} | {h.role or '-'} |")
    md += [
        "",
        "## Capabilities",
        "",
        "| capability | implementation | version | endpoint | owner |",
        "|---|---|---|---|---|",
    ]
    for s in reg.sorted_services():
        check_fields(
            "markdown", {"impl": s.impl, "version": s.version, "owner": s.owner, "service": s.name}
        )
        md.append(
            f"| {s.capability} | {s.impl or '-'} | {s.version} | `{_endpoint_url(reg, s)}` | {s.owner} |"
        )
    md += ["", "## Service cards", ""]
    for s in reg.sorted_services():
        h = reg.host_of(s)
        health = s.health.get("kind", "none")
        if health == "http":
            path = checked(s.health["path"], f"{s.name}.health.path", "markdown")
            health = f"http {path} expect {s.health.get('expect_status', 200)}"
        check_fields("markdown", {"upstream": "".join(s.upstreams), "tag": "".join(s.tags)})
        md.append(
            render(
                "service_section",
                raw={
                    "upstreams": ", ".join(f"`{u}`" for u in sorted(s.upstreams)) or "none",
                    "dependants": ", ".join(f"`{d.capability}`" for d in deps.get(s.capability, []))
                    or "none",
                },
                service=s.name,
                alias=reg.alias(s.capability),
                impl=s.impl or "-",
                version=s.version,
                host=s.host,
                zone=h.zone,
                protocol=s.protocol,
                port=str(s.port),
                tls=s.tls,
                auth=s.auth,
                owner=s.owner,
                health=health,
                backup=s.backup_job or "none",
                tags=", ".join(s.tags) or "none",
            )
        )
    return {"docs/services.md": "\n".join(md)}


# 11 --------------------------------------------------------------- env files
@register(
    "env_files",
    "Per-service environment files (compose env_file / EnvironmentFile) plus an aggregate",
    "container and unit runtime",
)
def env_files(reg: Registry) -> dict[str, str]:
    out = {}
    for s in reg.sorted_services():
        lines = [
            _hdr(reg),
            f"HNX_SERVICE={checked(s.name, 'service', 'env')}",
            f"HNX_LISTEN_PORT={s.port}",
        ]
        for up in sorted(s.upstreams):
            u = reg.by_capability(up)
            check_fields("env", {"env_var": u.endpoint_env_var, "url": _endpoint_url(reg, u)})
            lines.append(f"{u.endpoint_env_var}={_endpoint_url(reg, u)}")
        out[f"env/{s.name}.env.generated"] = "\n".join(lines) + "\n"
    allv = [_hdr(reg)] + [
        f"{s.endpoint_env_var}={_endpoint_url(reg, s)}"
        for s in sorted(reg.sorted_services(), key=lambda x: x.endpoint_env_var)
    ]
    out["env/_all.env.generated"] = "\n".join(allv) + "\n"
    return out
