# SPDX-License-Identifier: Apache-2.0
"""The eleven built-in generators.

Each reads the registry's primaries (``Registry.services``) and, where ADR-0039 decision 2 gives
it a non-primary tier, reads that tier through ``Registry.rows`` by name, so a tier a generator
does not name never reaches its output:

* DNS zone and hosts block: an ``eval`` or ``retiring`` row gets its row-name address record
  (``<row>.<svc_label>.<domain>``), never the capability alias, SRV or TXT;
* endpoint variables (the aggregate env file): an ``eval`` or ``retiring`` row's
  ``HNX_ENDPOINT_<ROW>``, naming its row-name record;
* metrics and uptime targets: primary and ``eval`` rows, by the name each answers by;
* the IdP realm: rendered only for an ``idp`` row whose ``impl`` is the realm format's product,
  primary or ``eval``; clients for ``auth: idp`` rows that are primary or ``eval``;
* the edge: primaries only, and the forward-auth check needs a primary ``auth-proxy``; with the
  ``edge_hosts`` option, only the sites of rows on those hosts (one deployment's edge), and a dial
  outside them is refused.

A ``legacy`` row reaches no output.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from pathlib import PurePosixPath
from urllib.parse import quote

import yaml

from homelabnext.edge_identity import (
    AUTH_PROXY_CALLBACK,
    AUTH_PROXY_CAPABILITY,
    AUTH_PROXY_CHECK,
    AUTH_PROXY_PREFIX,
    AUTH_PROXY_SIGN_IN,
    IDENTITY_HEADERS,
    USERNAME_CLAIM,
    IdentityHeaders,
    foreign_strip_lines,
)
from homelabnext.registry.model import (
    ANSWERING_TIERS,
    STANDINGS,
    Registry,
    Service,
    edge_tls_problems,
    secret_env_name,
)

from .core import MARKER, register
from .realm_format import REALM_PRODUCT, USER_PROFILE_PROVIDER
from .safe import GeneratorRefusal, check_fields, checked
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
    """The URL ``svc`` answers by: a primary's capability alias, an eval or retiring row's
    row-name record (ADR-0039 decision 2)."""
    return f"{svc.scheme}://{reg.address_of(svc)}:{svc.port}"


#: the tiers whose metrics and uptime targets are rendered (ADR-0039 decision 2)
OBSERVED_TIERS = ("primary", "eval")


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
    # an eval or retiring row answers by its row name only: its address record, no SRV or TXT
    # (those, like the capability alias, belong to the primary alone; ADR-0039 decision 2)
    for s in reg.rows(*ANSWERING_TIERS):
        host = reg.host_of(s)
        check_fields("zone", {"service": s.name, "address": host.address})
        lines.append(f"{s.name} IN {_rrtype(host.address)} {host.address}")
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
    # the resolver's fallback for a row-name record (ADR-0039 decision 2)
    for s in reg.rows(*ANSWERING_TIERS):
        by_addr[reg.host_of(s).address].append(reg.address_of(s))
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
    auth proxy's own headers instead).

    **Who is let in.**  The snippet takes one argument, the site's allowed groups (a site
    imports it as ``import hnx_forward_auth <group>,<group>``, see :func:`allowed_groups_arg`),
    and asks the check ``/oauth2/auth?allowed_groups=<them>``: the auth proxy answers 2xx only
    for a signed-in user in one of them and **403** for any other signed-in user, so being in
    the realm is not enough to reach an app.  Only a 401 (not signed in) goes to the sign-in
    page; a 403 is passed to the browser as it is, never redirected (signing in again would
    answer 403 again, a loop).  The return target ``rd`` is the request URI query-escaped
    (``{http.request.uri_escaped}``), so a query with ``&`` comes back whole."""
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
        f"\t\t\turi {AUTH_PROXY_CHECK}?{ALLOWED_GROUPS_PARAM}={{args[0]}}\n"
        "\t\t\theader_up X-Real-IP {remote_host}\n"
        f"\t\t\tcopy_headers {' '.join(identity.headers)}\n"
        "\t\t\t@hnx_sign_in status 401\n"
        "\t\t\thandle_response @hnx_sign_in {\n"
        f"\t\t\t\tredir * {AUTH_PROXY_SIGN_IN}?rd={{scheme}}://{{host}}{{http.request.uri_escaped}}\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t}\n"
        "}\n"
    )


#: the auth proxy check's query parameter naming the groups a signed-in user must be in one of
ALLOWED_GROUPS_PARAM = "allowed_groups"
_GROUP = re.compile(r"[a-z][a-z0-9-]{0,62}")


def allowed_groups_arg(s: Service) -> str:
    """The groups a public ``auth: idp`` site lets in, as the ``hnx_forward_auth`` argument: the
    sorted union of the groups of every role in the service's ``roles`` (the group-to-role
    table the realm grants), each URL-encoded, joined by ``,`` (the auth proxy splits the
    ``allowed_groups`` value on ``,``).  A service with no ``roles`` is refused: an empty
    ``allowed_groups`` admits every signed-in user, so such a site would let the whole realm in."""
    groups = sorted({g for gs in s.roles.values() for g in gs})
    if not groups:
        raise GeneratorRefusal(
            f"{s.name} has auth: idp and a public hostname but no roles: the edge lets in "
            "only the groups of a service's group-to-role table, and with none it would let in "
            "every signed-in user (give it roles, ADR-0034)"
        )
    for g in groups:
        if not _GROUP.fullmatch(g):
            raise GeneratorRefusal(f"{s.name}: group {g!r} is not lower case and '-'")
    return ",".join(quote(g, safe="") for g in groups)


def _auth_proxy(reg: Registry, sites: list[Service]) -> Service | None:
    """The forward-auth proxy, required as soon as one of ``sites`` has ``auth: idp``: without
    it such a site would be published with no login at all, so generation fails instead."""
    proxy = reg.by_capability(AUTH_PROXY_CAPABILITY)
    if proxy is None:
        gated = [s.name for s in sites if s.auth == "idp"]
        if gated:
            raise GeneratorRefusal(
                f"caddy: {', '.join(gated)} need(s) auth: idp at the edge but no primary provides "
                f"capability {AUTH_PROXY_CAPABILITY!r} (the forward-auth proxy, ADR-0034; a "
                "non-primary one is not it, ADR-0039)"
            )
    return proxy


#: the snippet every site imports at site level: the deletes of every client-sent copy of another
#: proxy's identity headers (:data:`homelabnext.edge_identity.FOREIGN_IDENTITY`)
FOREIGN_STRIP_SNIPPET = "hnx_strip_foreign_identity"

#: where the edge reads the TLS files of an ``edge_tls`` row: the edge's role writes each secret
#: named there from the secret store to :func:`edge_tls_path` (the generated ``caddy/edge_tls.json``
#: lists them); the Caddyfile names the path, never the material
EDGE_TLS_DIR = "/etc/hnx/edge-tls"
#: the edge's site file, and beside it the list of TLS files its role writes
SITES_FILE = "caddy/sites.caddy"
EDGE_TLS_FILE = str(PurePosixPath(SITES_FILE).with_name("edge_tls.json"))
#: the ``edge_tls`` keys naming a secret, the file each is written as, and its mode
EDGE_TLS_FILES = {"client_cert": "0644", "client_key": "0600", "ca": "0644"}
#: the one spelling a secret reference may take (the registry schema's, held again here for a
#: hand-built model): its path is a file path under :data:`EDGE_TLS_DIR` with no ``..`` or ``/``
#: at either end
_SECRET_REF = re.compile(r"secret:[a-z][a-z0-9_-]*(?:/[a-z][a-z0-9_-]*)*")
_SERVER_NAME = re.compile(
    r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
#: what the edge never renders: certificate verification switched off on an upstream
INSECURE = "insecure_skip_verify"


def edge_tls_path(ref: str) -> str:
    """The file the edge reads secret ``ref`` from: the reference's path under
    :data:`EDGE_TLS_DIR` with ``.pem`` appended (``edge/hub-client-cert`` is
    ``/etc/hnx/edge-tls/edge/hub-client-cert.pem``).  Two references are two paths."""
    if not _SECRET_REF.fullmatch(ref):
        raise GeneratorRefusal(f"edge_tls: {ref!r} is not a secret: reference")
    return f"{EDGE_TLS_DIR}/{ref.removeprefix('secret:')}.pem"


def _edge_tls_problem(s: Service) -> str | None:
    """Why the edge cannot reach public row ``s`` over TLS as its row declares, or None: the
    registry's own rules (:func:`~homelabnext.registry.model.edge_tls_problems`, one copy), held
    to a hand-built model here too, plus what only the rendering needs (https, a CA, a host
    name the Caddyfile can carry)."""
    rules = edge_tls_problems(
        s.name, {"edge_tls": s.edge_tls, "tls": s.tls, "public_hostname": s.public_hostname}
    )
    if rules:
        return rules[0]
    et = s.edge_tls
    if not et:
        return None
    if s.scheme != "https":
        return f"service {s.name}: edge_tls needs a service that answers https"
    if not et.get("ca"):
        return f"service {s.name}: edge_tls without ca: the edge verifies it with the lab's CA"
    name = et.get("server_name")
    if name is not None and not _SERVER_NAME.fullmatch(str(name)):
        return f"service {s.name}: edge_tls.server_name {name!r} is not a host name"
    return None


def _edge_transport(reg: Registry, s: Service) -> list[str]:
    """The ``transport http`` lines of a row with ``edge_tls``: TLS to the upstream verified
    against the lab's CA (``tls_trust_pool file``, never the system roots, never skipped), the
    server name checked, and with ``tls: mtls`` the edge's client certificate presented."""
    et = s.edge_tls or {}
    lines = ["\t\ttransport http {\n", "\t\t\ttls\n"]
    if s.tls == "mtls":
        cert = edge_tls_path(et["client_cert"])
        key = edge_tls_path(et["client_key"])
        lines.append(f"\t\t\ttls_client_auth {cert} {key}\n")
    lines.append(f"\t\t\ttls_trust_pool file {edge_tls_path(et['ca'])}\n")
    name = et.get("server_name") or reg.alias(s.capability)
    if not _SERVER_NAME.fullmatch(name):  # a host name holds no Caddyfile metacharacter
        raise GeneratorRefusal(f"edge: {s.name}: tls server name {name!r} is not a host name")
    lines.append(f"\t\t\ttls_server_name {name}\n")
    lines.append("\t\t}\n")
    return lines


def _edge_tls_manifest(reg: Registry, sites: list[Service]) -> dict[str, str]:
    """:data:`EDGE_TLS_FILE`: every TLS file the sites name, for the edge's role to write from
    the secret store (path, secret, mode, and the sites that read it); nothing when none does."""
    files: dict[str, dict] = {}
    for s in sites:
        for key, mode in EDGE_TLS_FILES.items():
            ref = (s.edge_tls or {}).get(key)
            if not ref or (key != "ca" and s.tls != "mtls"):
                continue
            path = edge_tls_path(ref)
            entry = files.setdefault(path, {"path": path, "secret": ref, "mode": mode, "sites": []})
            if entry["mode"] != mode:
                raise GeneratorRefusal(
                    f"edge: secret {ref} is both a private key and a certificate (edge_tls)"
                )
            entry["sites"].append(s.public_hostname)
    if not files:
        return {}
    listed = [{**files[k], "sites": sorted(files[k]["sites"])} for k in sorted(files)]
    return {EDGE_TLS_FILE: _json_doc(reg, {"files": listed})}


def _edge_sites(reg: Registry, edge_hosts) -> list[Service]:
    """The public primaries this edge publishes: every one, or with ``edge_hosts`` (one
    deployment's hosts) those whose row is on one of them.  An unknown host name is refused (a
    typo must not render a harmless-looking empty edge), and so is a set that publishes nothing."""
    every = [s for s in reg.sorted_services() if s.public_hostname and s.is_primary]
    if edge_hosts is None:
        return every
    if isinstance(edge_hosts, str):
        raise GeneratorRefusal("edge: edge_hosts is a collection of host names, not one string")
    scope = set(edge_hosts)
    unknown = sorted(scope - set(reg.hosts))
    if unknown:
        raise GeneratorRefusal(f"edge: host(s) {', '.join(unknown)} not in the registry")
    sites = [s for s in every if s.host in scope]
    if not sites:
        raise GeneratorRefusal(
            f"edge: no public row is on the edge hosts ({', '.join(sorted(scope))}): the edge "
            "would publish nothing"
        )
    return sites


def _in_scope(reg: Registry, edge_hosts, dial: Service, what: str) -> None:
    """Refuse a dial to a row outside ``edge_hosts``: one deployment's edge never proxies to
    another's hosts (the old lab, ADR-0039 ``legacy``)."""
    if edge_hosts is not None and dial.host not in set(edge_hosts):
        raise GeneratorRefusal(
            f"edge: {what} dials {dial.name} on host {dial.host}, outside the edge hosts "
            f"({', '.join(sorted(set(edge_hosts)))}): this edge never proxies to another "
            "deployment"
        )


@register(
    "caddy",
    "Caddyfile site snippets for services with a public hostname",
    "reverse proxy (edge)",
    options=("edge_hosts",),
)
def caddy(reg: Registry, edge_hosts=None) -> dict[str, str]:
    """The edge's sites.  ``edge_hosts`` (a collection of registry host names, the hosts of one
    deployment: ``hnx registry generate --edge-host``) narrows them to the public rows on those
    hosts, and refuses any dial (a site's upstream, the forward-auth proxy) outside them; without
    it every public primary is a site, as for a registry that is one deployment."""
    sites = _edge_sites(reg, edge_hosts)
    proxy = _auth_proxy(reg, sites)
    realm = realm_idp(reg)
    gated = any(s.auth == "idp" for s in sites)
    parts = [_hdr(reg)]
    if proxy and (edge_hosts is None or gated):
        if gated:
            _in_scope(reg, edge_hosts, proxy, "the forward auth")
        parts.append(
            _forward_auth_snippet(
                checked(_endpoint_url(reg, proxy), "auth-proxy endpoint", "caddy")
            )
        )
    parts.append(f"({FOREIGN_STRIP_SNIPPET}) {{\n{foreign_strip_lines(chr(9))}}}\n")
    strip = IDENTITY_HEADERS.strip_lines("\t") + f"\timport {FOREIGN_STRIP_SNIPPET}\n"
    for s in sites:
        # the site dials its capability's alias, which names the capability's primary: this row
        _in_scope(reg, edge_hosts, reg.by_capability(s.capability) or s, s.public_hostname)
        problem = _edge_tls_problem(s)
        if problem:
            raise GeneratorRefusal(f"edge: {problem}")
        # every site strips the client's identity headers at site level, before every handle
        # and route of the site (Caddy sorts request_header first): a path that never reaches
        # the snippet's route (a handle added beside it, a matcher on a route) and a site with
        # no forward auth that reaches the same service under another name still reach it
        # without them; the route-level strip in the snippet stays as well.  Other proxies'
        # identity headers (X-Forwarded-User, Remote-User, ...) go too, before forward auth runs
        auth_block = strip
        if s.auth == "idp":
            auth_block += f"\timport hnx_forward_auth {allowed_groups_arg(s)}\n"
        inner: list[str] = []
        if s.front_door and s.auth == "idp":
            # the shared secret that tells the service this request came through the edge (and
            # so its identity headers are the auth proxy's): from the environment, never in the file
            header = checked(s.front_door["header"], "front_door.header", "caddy")
            env = checked(secret_env_name(s.front_door["secret"]), "front_door.secret", "caddy")
            inner.append(f"\t\theader_up {header} {{env.{env}}}\n")
        if s.edge_tls:
            inner += _edge_transport(reg, s)
        proxy_block = " {\n" + "".join(inner) + "\t}" if inner else ""
        raw = {"auth_block": auth_block, "proxy_block": proxy_block, "note": "",
               "route_open": "", "route_close": ""}  # fmt: skip
        if realm is not None and s.name == realm.name:
            # the realm's IdP publishes its sign-in pages only: the realm's own paths and the
            # static resources; the master realm (the break-glass admin's, password only) and
            # the admin console answer 404 at the edge (ADR-0034 decision 6)
            # the lab's name is a slug (registry schema), so each path is plain text
            paths = " ".join(realm_paths(reg))
            raw = {
                "auth_block": auth_block,
                "proxy_block": proxy_block.replace("\n\t", "\n\t\t"),
                "note": ": only the realm's paths are published",
                "route_open": f"\t@hnx_published path {paths}\n\thandle @hnx_published {{\n\t",
                "route_close": "\n\t}\n\thandle {\n\t\trespond 404\n\t}",
            }
        parts.append(
            render(
                "caddy_site",
                raw=raw,
                hostname=s.public_hostname,
                service=s.name,
                capability=s.capability,
                owner=s.owner,
                scheme=s.scheme,
                alias=reg.alias(s.capability),
                port=str(s.port),
            )
        )
    text = "\n".join(parts)
    if INSECURE in text:
        raise GeneratorRefusal(f"edge: never renders {INSECURE} (trust the lab's CA)")
    return {SITES_FILE: text, **_edge_tls_manifest(reg, sites)}


# 4 ---------------------------------------------------------------- Prometheus
@register(
    "prometheus",
    "Prometheus scrape_configs for services exposing metrics",
    "monitoring (Prometheus)",
)
def prometheus(reg: Registry) -> dict[str, str]:
    jobs = []
    for s in reg.rows(*OBSERVED_TIERS):
        if not s.metrics:
            continue
        port = s.metrics.get("port", s.port)
        jobs.append(
            {
                # a primary's job is its capability's, an eval row's its row name's
                "job_name": s.answers_by,
                "metrics_path": s.metrics["path"],
                "scheme": s.scheme if s.scheme in ("http", "https") else "http",
                "static_configs": [
                    {
                        "targets": [f"{reg.address_of(s)}:{port}"],
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
    for s in reg.rows(*OBSERVED_TIERS):
        kind = s.health.get("kind", "none")
        alias = reg.address_of(s)
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
#: the browser flow every sign-in goes through: a session cookie, or a password AND a passkey
MFA_BROWSER_FLOW = "hnx-browser-mfa"
#: the direct grant flow (``grant_type=password``, e.g. the IdP's own ``admin-cli``): refused for
#: every user.  A passkey cannot be presented on a direct grant, and a direct grant cannot run a
#: required action, so no direct grant can carry the second factor: the flow is one REQUIRED
#: ``deny-access-authenticator`` (ADR-0034 decision 2, amended 2026-11-13)
MFA_DIRECT_GRANT_FLOW = "hnx-direct-grant-refused"
#: the scopes a token carries without asking (everything else only when requested)
DEFAULT_CLIENT_SCOPES = ("basic",)
OPTIONAL_CLIENT_SCOPES = ("email", "profile")
#: the claims the IdP's tokens carry the user's groups and this client's roles in
GROUPS_CLAIM, ROLES_CLAIM = "groups", "roles"


#: the secret-store area holding each OIDC client's secret, one name per service
IDP_CLIENT_STORE_AREA = "idp/clients"


def client_secret_ref(service: str) -> str:
    """The secret-store reference of a service's OIDC client secret (never a value)."""
    return f"secret:{IDP_CLIENT_STORE_AREA}/{service}"


def _execution(requirement: str, priority: int, *, authenticator: str = "", flow: str = "") -> dict:
    out = {"authenticatorFlow": bool(flow), "priority": priority, "requirement": requirement}
    out.update({"flowAlias": flow} if flow else {"authenticator": authenticator})
    out["userSetupAllowed"] = False
    return out


#: the second factor every browser sign-in requires (a passkey: WebAuthn, the possession of a
#: registered key, verified with its user verification), and the required action that enrols it
SECOND_FACTOR, SECOND_FACTOR_SETUP = "webauthn-authenticator", "webauthn-register"
#: the step that refuses every direct grant (no second factor can be carried on one)
DIRECT_GRANT_REFUSAL = "deny-access-authenticator"
#: the one-time-code factor the operator declined (2026-11-13): never in a flow, and its
#: enrolment action rendered disabled, so the account console offers no way to add one
DECLINED_FACTOR_SETUP = "CONFIGURE_TOTP"


def _action(alias: str, name: str, priority: int, *, enabled: bool, default: bool) -> dict:
    return {
        "alias": alias,
        "config": {},
        "defaultAction": default,
        "enabled": enabled,
        "name": name,
        "priority": priority,
        "providerId": alias,
    }


#: the realm's required actions: a new user registers a passkey at first sign-in (a default
#: action), an admin-set temporary password is changed then, and the declined factors' actions
#: (a one-time code, a passwordless key) are rendered disabled.  Listing them replaces the IdP's
#: defaults, and rendering the disabled ones turns them off on a realm that had them
REALM_REQUIRED_ACTIONS = (
    _action(SECOND_FACTOR_SETUP, "Webauthn Register", 10, enabled=True, default=True),
    _action("UPDATE_PASSWORD", "Update Password", 30, enabled=True, default=False),
    _action(DECLINED_FACTOR_SETUP, "Configure OTP", 40, enabled=False, default=False),
    _action(
        "webauthn-register-passwordless",
        "Webauthn Register Passwordless",
        50,
        enabled=False,
        default=False,
    ),
)

#: the realm's WebAuthn policy (the second factor's): the user verifies themselves on the key
#: (a PIN or biometric: a passkey, not a bare possession check), ES256 or RS256, any authenticator
#: attachment.  The relying party id is left to the IdP, which takes it from the realm's frontend
#: host (the site's public name, never this repository's)
WEBAUTHN_POLICY = {
    "webAuthnPolicyAcceptableAaguids": [],
    "webAuthnPolicyAttestationConveyancePreference": "not specified",
    "webAuthnPolicyAuthenticatorAttachment": "not specified",
    "webAuthnPolicyAvoidSameAuthenticatorRegister": True,
    "webAuthnPolicyCreateTimeout": 0,
    "webAuthnPolicyExtraOrigins": [],
    "webAuthnPolicyRequireResidentKey": "not specified",
    "webAuthnPolicyRpEntityName": "hnx",
    "webAuthnPolicySignatureAlgorithms": ["ES256", "RS256"],
    "webAuthnPolicyUserVerificationRequirement": "required",
}


def _mfa_flows() -> list[dict]:
    """The realm's user sign-in flows: the browser flow (the session cookie, or the
    username/password form AND the WebAuthn form) and the direct grant flow, which refuses every
    user (``deny-access-authenticator``, REQUIRED: a direct grant can carry no passkey, and
    cannot run the enrolment action).  The realm binds both (``browserFlow``,
    ``directGrantFlow``); registration and credential reset are off, so their flows are
    unreachable, and no identity provider is rendered, so no broker login flow runs.

    The second factor is one execution, ``webauthn-authenticator``, **REQUIRED** in the same
    subflow as the password, with no alternative beside it: the only way through the flow
    without a session is a password and a registered passkey.  A REQUIRED authenticator that is
    not configured for the user (no key yet) adds its setup action, ``webauthn-register``, which
    the realm enables as a default action (:data:`REALM_REQUIRED_ACTIONS`): a user with no factor
    is made to register one before the sign-in completes, never let through on the password
    alone (and, were the action disabled, refused).  No one-time code is offered (ADR-0034
    decision 2, amended 2026-11-13): an ALTERNATIVE beside the key is skipped when the user has
    none of it configured, the ambiguity this flow avoids."""

    def flow(alias: str, top: bool, executions: list[dict], what: str) -> dict:
        return {
            "alias": alias,
            "authenticationExecutions": executions,
            "builtIn": False,
            "description": what,
            "providerId": "basic-flow",
            "topLevel": top,
        }

    forms = f"{MFA_BROWSER_FLOW}-forms"
    return [
        flow(
            MFA_BROWSER_FLOW,
            True,
            [
                _execution("ALTERNATIVE", 10, authenticator="auth-cookie"),
                _execution("ALTERNATIVE", 20, flow=forms),
            ],
            "browser sign-in: a session, or a password and a passkey (ADR-0034)",
        ),
        flow(
            forms,
            False,
            [
                _execution("REQUIRED", 10, authenticator="auth-username-password-form"),
                _execution("REQUIRED", 20, authenticator=SECOND_FACTOR),
            ],
            "username and password, then a passkey (registered at first sign-in)",
        ),
        flow(
            MFA_DIRECT_GRANT_FLOW,
            True,
            [_execution("REQUIRED", 10, authenticator=DIRECT_GRANT_REFUSAL)],
            "direct grant: refused for every user; no passkey can be presented (ADR-0034)",
        ),
    ]


#: the usernames the realm refuses whatever the site adds: the Stage 4 proof manifest's approver
#: (``examples/broker/manifest*.yml``, the broker scenario's default ``--approver``), whom
#: whoever held the name could approve as
RESERVED_USERNAMES = ("operator-one",)
#: a reserved name: the IdP's own username rules (lower case, its separators), so the refusal
#: and the health check compare like for like
RESERVED_USERNAME_SHAPE = re.compile(r"[a-z0-9](?:[a-z0-9._@-]{0,62}[a-z0-9])?\Z")
#: the realm attribute listing the reserved names (the module's health hook reads it)
RESERVED_ATTRIBUTE = "hnx.reserved_usernames"
#: the error the user-profile validator answers a reserved name with
RESERVED_ERROR = "hnx-reserved-username"


def reserved_usernames_of(extra=None) -> tuple[str, ...]:
    """The built-in reserved names and ``extra`` (the site's), sorted, each checked; a malformed
    one is refused rather than silently matching nothing."""
    if isinstance(extra, str):
        raise GeneratorRefusal(
            "idp_realm: reserved_usernames is a collection of usernames, not one string"
        )
    try:
        names = set(RESERVED_USERNAMES) | set(extra or ())
    except TypeError:
        raise GeneratorRefusal(
            "idp_realm: reserved_usernames is a collection of usernames"
        ) from None
    bad = sorted(
        repr(n) for n in names if not (isinstance(n, str) and RESERVED_USERNAME_SHAPE.match(n))
    )
    if bad:
        raise GeneratorRefusal(
            f"idp_realm: reserved username(s) {', '.join(bad)} are not usernames the IdP stores "
            "(lower case letters, digits and . _ @ -, starting and ending with a letter or digit, "
            "at most 64): a name in another form would never match one"
        )
    return tuple(sorted(names))


def reserved_username_pattern(names) -> str:
    """The user-profile ``pattern`` that refuses exactly ``names`` (case-insensitive, whole
    value): a negative lookahead the IdP's (Java) regex engine reads as Python's does."""
    alts = "|".join(re.escape(n) for n in names)
    return f"(?i)^(?!(?:{alts})$).+$"


def _user_profile(names) -> dict:
    """The declarative user profile (the IdP's default attributes) with one addition: the
    username refuses a reserved name, for every way a user is created or renamed (the admin API,
    the admin console, a self-service form).  A realm import or partial import of users
    bypasses validators, so the module's health hook also fails while such a user exists."""
    both = {"edit": ["admin", "user"], "view": ["admin", "user"]}

    def attr(name: str, validations: dict, *, required: bool, edit=None) -> dict:
        out = {
            "displayName": "${" + name + "}",
            "multivalued": False,
            "name": name,
            "permissions": {"edit": edit or both["edit"], "view": both["view"]},
            "validations": validations,
        }
        if required:
            out["required"] = {"roles": ["user"]}
        return out

    config = {
        "attributes": [
            attr(
                "username",
                {
                    "length": {"max": 255, "min": 3},
                    "pattern": {
                        "error-message": RESERVED_ERROR,
                        "pattern": reserved_username_pattern(names),
                    },
                    "up-username-not-idn-homograph": {},
                    "username-prohibited-characters": {},
                },
                required=False,
                edit=["admin"],
            ),
            attr("email", {"email": {}, "length": {"max": 255}}, required=True),
            attr(
                "firstName",
                {"length": {"max": 255}, "person-name-prohibited-characters": {}},
                required=True,
            ),
            attr(
                "lastName",
                {"length": {"max": 255}, "person-name-prohibited-characters": {}},
                required=True,
            ),
        ],
        "groups": [
            {
                "displayDescription": "Attributes, which refer to user metadata",
                "displayHeader": "User metadata",
                "name": "user-metadata",
            }
        ],
    }
    return {
        USER_PROFILE_PROVIDER: [
            {
                "config": {
                    "kc.user.profile.config": [
                        json.dumps(config, sort_keys=True, separators=(",", ":"))
                    ]
                },
                "name": "declarative-user-profile",
                "providerId": "declarative-user-profile",
                "subComponents": {},
            }
        ]
    }


def _mappers(client: str) -> list[dict]:
    """The claims every client's tokens carry beyond the trimmed scopes: the audience (the
    client itself), the user's groups (names, not paths), the user's roles of this client and
    the username as :data:`~homelabnext.edge_identity.USERNAME_CLAIM` (the platform's one name
    for a person: the hub's approver and the SSH CA's principal). The username is mapped here,
    not left to the optional ``profile`` scope, so a client that narrows its scopes still gets
    it (without it the hub knows nobody and every approve is ``403``)."""

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
        mapper(
            "username",
            "oidc-usermodel-attribute-mapper",
            {
                "claim.name": USERNAME_CLAIM,
                "jsonType.label": "String",
                "user.attribute": "username",
                "userinfo.token.claim": "true",
            },
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


#: the tiers the realm is rendered for, and whose ``auth: idp`` rows get its clients
REALM_TIERS = ("primary", "eval")


def realm_idp(reg: Registry) -> Service | None:
    """The ``idp`` row the realm is rendered for: the one whose ``impl`` is the realm format's
    product, primary or ``eval`` (the primary when both are), or None.  With none no realm is
    rendered, so a realm in this format is never rendered for another product, nor for a
    ``retiring`` or ``legacy`` row."""
    rows = [s for s in reg.rows(*REALM_TIERS) if s.capability == "idp" and s.impl == REALM_PRODUCT]
    return min(rows, key=lambda s: (not s.is_primary, s.name)) if rows else None


def realm_paths(reg: Registry) -> tuple[str, ...]:
    """The paths the edge publishes for the realm's IdP (:func:`realm_idp`): the realm's own
    (sign-in, its OIDC endpoints, the account pages) and the static resources its pages load.
    Every other path, the master realm and the admin console among them, is a 404 at the edge."""
    return (f"/realms/{reg.lab_name}/*", "/resources/*")


def require_realm_idp(reg: Registry) -> Service:
    """:func:`realm_idp`, refused when there is none: run when the realm is asked for by name
    (``--only idp_realm``), where rendering nothing would read as success."""
    row = realm_idp(reg)
    if row is not None:
        return row
    seen = ", ".join(
        f"{s.name} ({s.standing}, impl {s.impl or 'none'})"
        for s in reg.rows(*STANDINGS)
        if s.capability == "idp"
    )
    raise GeneratorRefusal(
        f"idp_realm: no primary or eval idp row has impl {REALM_PRODUCT!r}, the realm format's "
        f"product (idp rows: {seen or 'none'}); no realm is rendered for another product or "
        "a retiring or legacy row (ADR-0039)"
    )


def registry_grants(reg: Registry) -> dict[str, dict[str, set[str]]]:
    """``{group: {service: {role, ...}}}`` from the group-to-role table of the rows the realm
    has clients for (primary and ``eval``)."""
    out: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for s in reg.rows(*REALM_TIERS):
        for role, groups in s.roles.items():
            for g in groups:
                out[g][s.name].add(role)
    return {g: dict(c) for g, c in out.items()}


@register(
    "idp_realm",
    "OIDC IdP realm (clients, groups and their roles, MFA browser flow) for services with auth=idp",
    "identity provider (realm import)",
    when_named=require_realm_idp,
    dirs=("idp",),
    options=("reserved_usernames",),
)
def idp_realm(reg: Registry, reserved_usernames=None) -> dict[str, str]:
    """The IdP's realm as an importable realm document (ADR-0034): one confidential OIDC client
    per ``auth: idp`` service (redirects under its public hostname) and one for the auth proxy
    (its callback on every site it guards), the client roles each service's ``roles`` names, a
    group per group named there holding exactly those roles, and the MFA browser flow.  A user
    cannot change their own username (``editUsernameAllowed: false``): it is the
    ``preferred_username`` claim the platform names a person by (the status hub's approver
    subject, the SSH CA's principal: :data:`homelabnext.edge_identity.USERNAME_CLAIM`).  No
    secret is in it: each client secret is a secret-store reference.

    It is rendered only for the :func:`realm_idp` row (with none it renders nothing, and a full
    generate prunes a stale realm; asked for by name it is refused), and its clients are for the ``auth: idp``
    rows that are primary or ``eval`` (an eval row has no public hostname, so no redirect); the
    auth proxy's client is the primary auth proxy's (ADR-0039 decision 2).

    ``reserved_usernames`` (the site's, a collection) adds to :data:`RESERVED_USERNAMES`: the
    realm's user profile refuses every one of them as a username (a ``pattern`` validator), and
    the realm attribute :data:`RESERVED_ATTRIBUTE` lists them for the module's health hook."""
    reserved = reserved_usernames_of(reserved_usernames)
    if realm_idp(reg) is None:
        return {}
    gated = [s for s in reg.rows(*REALM_TIERS) if s.auth == "idp"]
    clients, roles = [], {}
    for s in gated:
        # a redirect is under a public route, which is a primary's alone
        root = f"https://{s.public_hostname}" if s.public_hostname and s.is_primary else None
        clients.append(_client(s.name, s.owner, [f"{root}/*"] if root else [], root))
        if s.roles:
            roles[s.name] = [
                {"clientRole": True, "description": f"{s.name} {r}", "name": r} for r in s.roles
            ]
    proxy = reg.by_capability(AUTH_PROXY_CAPABILITY)
    if proxy is not None and proxy.name not in {s.name for s in gated}:
        callbacks = sorted(
            f"https://{s.public_hostname}{AUTH_PROXY_CALLBACK}"
            for s in gated
            if s.public_hostname and s.is_primary
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
        "attributes": {
            "hnx.generated": _hdr(reg, "").strip(),
            RESERVED_ATTRIBUTE: ",".join(reserved),
        },
        "authenticationFlows": _mfa_flows(),
        "browserFlow": MFA_BROWSER_FLOW,
        "directGrantFlow": MFA_DIRECT_GRANT_FLOW,
        "bruteForceProtected": True,
        "clients": clients,
        "components": _user_profile(reserved),
        "displayName": reg.lab_name,
        # the username is the platform's one name for a person (edge_identity.USERNAME_CLAIM):
        # a user who could rename themselves could take a name an allowlist lists
        "editUsernameAllowed": False,
        "enabled": True,
        "groups": groups,
        "realm": reg.lab_name,
        "registrationAllowed": False,
        "requiredActions": [dict(a) for a in REALM_REQUIRED_ACTIONS],
        "resetPasswordAllowed": False,
        "roles": {"client": roles},
        "sslRequired": "all",
        **WEBAUTHN_POLICY,
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
    # an eval or retiring row's variable is its row name's, naming its row-name record
    # (ADR-0039 decision 2): the conformance targets and the shadow lane address it so
    allv = [_hdr(reg)] + [
        f"{s.endpoint_env_var}={_endpoint_url(reg, s)}"
        for s in sorted(reg.rows("primary", *ANSWERING_TIERS), key=lambda x: x.endpoint_env_var)
    ]
    out["env/_all.env.generated"] = "\n".join(allv) + "\n"
    return out
