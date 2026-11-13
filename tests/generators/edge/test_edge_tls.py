# SPDX-License-Identifier: Apache-2.0
"""The edge's upstream TLS (registry 2.10 ``edge_tls``), its deployment scope (``edge_hosts``,
``hnx registry generate --edge-host``) and the strip of other proxies' identity headers.

The fixture (``fixtures/two-lab.services.yml``) holds two deployments in one registry, as an
overlay does while a new lab is built beside an old one: the new lab's hub over mTLS, its IdP over
TLS verified against the lab CA, and two old-lab public rows the new edge must never publish."""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path

import pytest
import yaml

from homelabnext.edge_identity import FOREIGN_IDENTITY, foreign_strip_patterns
from homelabnext.generators import GeneratorRefusal, generate
from homelabnext.generators import builtin as b
from homelabnext.registry import load
from homelabnext.registry.cli import main as registry_main
from homelabnext.registry.model import RegistryError, build_registry

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FIXTURE = HERE / "fixtures" / "two-lab.services.yml"
GOLDEN = HERE / "golden"
REG = load(FIXTURE)
NEW_LAB = ("core-01", "edge-01", "idp-01")


def _doc() -> dict:
    return yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))


def _edge(reg=REG, hosts=NEW_LAB) -> dict[str, str]:
    return generate(reg, ["caddy"], {"edge_hosts": hosts})["caddy"]


def _site(text: str, hostname: str) -> str:
    return text.split(f"\n{hostname} {{\n", 1)[1].split("\n}\n", 1)[0]


def _sites(text: str) -> list[str]:
    return re.findall(r"(?m)^([a-z0-9.-]+\.[a-z]+) \{$", text)


# ------------------------------------------------------------------------- golden
@pytest.mark.parametrize("rel", ["caddy/sites.caddy", "caddy/edge_tls.json"])
def test_the_new_lab_edge_matches_its_golden(rel):
    out = _edge()
    assert sorted(out) == ["caddy/edge_tls.json", "caddy/sites.caddy"]
    assert out[rel] == (GOLDEN / rel).read_text(encoding="utf-8")


# ------------------------------------------------------------------------- mTLS transport
def test_the_hub_is_reached_with_the_edges_client_certificate_and_the_lab_ca():
    site = _site(_edge()["caddy/sites.caddy"], "hub.example.internal")
    hub = REG.services["status-hub"]
    assert f"reverse_proxy https://{REG.alias(hub.capability)}:{hub.port} {{" in site
    transport = site.split("transport http {", 1)[1].split("}", 1)[0]
    assert [ln.strip() for ln in transport.strip().splitlines()] == [
        "tls",
        "tls_client_auth /etc/hnx/edge-tls/edge/hub-client-cert.pem "
        "/etc/hnx/edge-tls/edge/hub-client-key.pem",
        "tls_trust_pool file /etc/hnx/edge-tls/pki/internal-ca.pem",
        "tls_server_name status-hub.svc.example.internal",
    ]
    # the front door still rides on the same proxy
    assert "header_up X-Hnx-Front-Door {env.HNX_SECRET_STATUS_FRONT_DOOR_SECRET}" in site


def test_a_tls_internal_upstream_is_verified_against_the_ca_with_no_client_certificate():
    site = _site(_edge()["caddy/sites.caddy"], "sso.example.internal")
    assert "tls_trust_pool file /etc/hnx/edge-tls/pki/internal-ca.pem" in site
    assert "tls_client_auth" not in site
    # no server_name declared: the alias the edge dials
    assert "tls_server_name idp.svc.example.internal" in site


def test_no_certificate_or_key_material_is_ever_in_the_caddyfile():
    text = _edge()["caddy/sites.caddy"]
    assert "secret:" not in text and "BEGIN" not in text
    files = json.loads(_edge()["caddy/edge_tls.json"])["files"]
    assert {f["secret"]: f["mode"] for f in files} == {
        "secret:edge/hub-client-cert": "0644",
        "secret:edge/hub-client-key": "0600",
        "secret:pki/internal-ca": "0644",
    }
    for f in files:
        assert f["path"] in text and f["path"] == b.edge_tls_path(f["secret"])


def test_without_edge_tls_no_manifest_is_rendered():
    out = generate(load(ROOT / "examples" / "services.yml"), ["caddy"])["caddy"]
    assert sorted(out) == ["caddy/sites.caddy"]


@pytest.mark.parametrize("ref", ["secret:../x", "secret:a//b", "secret:A/b", "edge/key", "secret:"])
def test_a_reference_that_is_not_a_secret_path_is_refused(ref):
    with pytest.raises(GeneratorRefusal):
        b.edge_tls_path(ref)


def _edges() -> dict[str, dict[str, str]]:
    """The edge of every registry in the tree that loads and that the generator renders (a
    schema negative, a non-registry or a fixture the generator refuses has none)."""
    out = {}
    for p in sorted(ROOT.glob("**/*services*.yml")):
        if any(part in ("negative", "_frozen", ".git") for part in p.parts):
            continue
        try:
            out[p.relative_to(ROOT).as_posix()] = generate(load(p), ["caddy"])["caddy"]
        except Exception:  # nothing rendered, so nothing to judge
            continue
    return out


EDGES = _edges()


def test_the_tree_holds_edges_to_judge():
    assert {"examples/services.yml", "tests/generators/edge/fixtures/two-lab.services.yml"} <= set(
        EDGES
    )


@pytest.mark.parametrize("rel", sorted(EDGES))
def test_no_registry_in_the_tree_renders_skipped_verification(rel):
    for text in EDGES[rel].values():
        assert "insecure_skip_verify" not in text


def test_the_generator_refuses_to_render_skipped_verification(monkeypatch):
    """If any path ever wrote it, the generator itself fails instead of publishing it."""
    real = b._edge_transport

    def leaky(reg, s):
        return [*real(reg, s)[:-1], "\t\t\ttls_insecure_skip_verify\n", "\t\t}\n"]

    monkeypatch.setattr(b, "_edge_transport", leaky)
    with pytest.raises(GeneratorRefusal, match="insecure_skip_verify"):
        _edge()


# ------------------------------------------------------------------------- the edge's rules
def _model(row: str, **changes):
    s = dataclasses.replace(REG.services[row], **changes)
    return dataclasses.replace(REG, services={**REG.services, row: s})


@pytest.mark.parametrize(
    ("row", "changes", "match"),
    [
        ("status-hub", {"edge_tls": None}, "a public tls: mtls route needs edge_tls"),
        (
            "status-hub",
            {"edge_tls": {"ca": "secret:pki/internal-ca"}},
            "tls: mtls needs edge_tls.client_cert and client_key",
        ),
        ("idp", {"tls": "public"}, "edge_tls needs tls: internal or mtls"),
        ("idp", {"protocol": "tcp"}, "answers https"),
        (
            "idp",
            {
                "edge_tls": {
                    "ca": "secret:pki/ca",
                    "client_cert": "secret:a",
                    "client_key": "secret:b",
                }
            },
            "edge_tls.client_cert needs tls: mtls",
        ),
        ("idp", {"edge_tls": {"server_name": "idp.example.internal"}}, "without ca"),
        ("idp", {"edge_tls": {"ca": "secret:pki/ca", "server_name": "a b"}}, "not a host name"),
    ],
)
def test_a_hand_built_model_is_held_to_the_registry_rules(row, changes, match):
    with pytest.raises(GeneratorRefusal, match=match):
        _edge(_model(row, **changes))


def test_one_secret_as_a_key_on_one_row_and_a_certificate_on_another_is_refused():
    """Within one row the registry refuses it; across rows the manifest does (the key would be
    written world-readable, or the CA mode 0600)."""
    with pytest.raises(GeneratorRefusal, match="both a private key and a certificate"):
        _edge(_model("idp", edge_tls={"ca": "secret:edge/hub-client-key"}))


# ------------------------------------------------------------------------- deployment scope
def test_the_scoped_edge_publishes_only_its_own_hosts_rows():
    text = _edge()["caddy/sites.caddy"]
    assert _sites(text) == ["sso.example.internal", "hub.example.internal"]
    assert "old-apps" not in text and "dashboards.svc" not in text and "docs.svc" not in text


def test_without_a_scope_every_public_primary_is_a_site_as_before():
    text = generate(REG, ["caddy"])["caddy"]["caddy/sites.caddy"]
    assert set(_sites(text)) == {
        "sso.example.internal",
        "hub.example.internal",
        "dashboards.example.internal",
        "wiki.example.internal",
    }


def test_the_forward_auth_proxy_outside_the_scope_is_refused():
    doc = _doc()
    doc["services"]["auth-proxy"]["host"] = "old-apps"
    with pytest.raises(GeneratorRefusal, match="forward auth dials auth-proxy on host old-apps"):
        _edge(build_registry(doc))


def test_a_scope_with_no_gated_site_renders_no_forward_auth_to_another_lab():
    """The auth proxy is outside the scope but no in-scope site needs it: the snippet that would
    dial it is not rendered at all."""
    text = _edge(hosts=("idp-01",))["caddy/sites.caddy"]
    assert _sites(text) == ["sso.example.internal"]
    assert "hnx_forward_auth" not in text and "auth-proxy" not in text


def test_a_site_dialling_a_row_outside_the_scope_is_refused():
    """A hand-built model whose site sits on an edge host but whose capability's primary (what
    the alias dials) is elsewhere: refused, the edge never proxies across deployments."""
    other = dataclasses.replace(REG.services["status-hub"], name="aa-hub", public_hostname=None)
    other = dataclasses.replace(other, host="old-apps")
    reg = dataclasses.replace(REG, services={"aa-hub": other, **REG.services})
    with pytest.raises(GeneratorRefusal, match="dials aa-hub on host old-apps"):
        _edge(reg)


@pytest.mark.parametrize(
    ("hosts", "match"),
    [(("edge-01", "typo-01"), "typo-01 not in the registry"), (("edge-01",), "publish nothing")],
)
def test_an_unknown_or_empty_scope_is_refused(hosts, match):
    with pytest.raises(GeneratorRefusal, match=match):
        _edge(hosts=hosts)


def test_a_bare_string_scope_is_refused_not_read_by_character():
    with pytest.raises(GeneratorRefusal, match="not one string"):
        _edge(hosts="core-01")


def test_the_cli_scopes_the_edge_and_refuses_an_option_no_generator_takes(tmp_path, capsys):
    hosts = [a for h in NEW_LAB for a in ("--edge-host", h)]
    args = ["generate", str(FIXTURE), str(tmp_path), "--only", "caddy", *hosts]
    assert registry_main(args) == 0
    for rel in ("caddy/sites.caddy", "caddy/edge_tls.json"):
        assert (tmp_path / rel).read_text() == (GOLDEN / rel).read_text()
    assert registry_main(["check", str(FIXTURE), str(tmp_path), "--only", "caddy", *hosts]) == 0
    assert registry_main(["check", str(FIXTURE), str(tmp_path), "--only", "caddy"]) == 1
    capsys.readouterr()
    only_dns = ["generate", str(FIXTURE), str(tmp_path), "--only", "dns_zone", *hosts]
    assert registry_main(only_dns) == 2
    assert "edge_hosts taken by none" in capsys.readouterr().err
    bad = ["generate", str(FIXTURE), str(tmp_path), "--only", "caddy", "--edge-host", "nope"]
    assert registry_main(bad) == 1


# ------------------------------------------------------------------------- the registry
def _problems(doc) -> list[str]:
    try:
        build_registry(doc)
    except RegistryError as exc:
        return exc.problems
    return []


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda s: s.pop("edge_tls"), "a public tls: mtls route needs edge_tls"),
        (lambda s: s["edge_tls"].pop("client_cert"), "client_cert"),
        (lambda s: s.update(tls="internal"), "edge_tls.client_cert needs tls: mtls"),
        (lambda s: s.update(tls="none"), "edge_tls needs tls: internal or mtls"),
        (lambda s: s.pop("public_hostname"), "edge_tls needs a public_hostname"),
        (lambda s: s["edge_tls"].update(client_key="secret:pki/internal-ca"), "certificate or CA"),
        (lambda s: s["edge_tls"].update(client_cert="secret:pki/internal-ca"), "also its CA"),
        (lambda s: s["edge_tls"].update(extra="x"), "Additional properties"),
        (lambda s: s["edge_tls"].pop("ca"), "'ca' is a required property"),
        (lambda s: s["edge_tls"].update(ca="/etc/ca.pem"), "does not match"),
        (lambda s: s["edge_tls"].update(server_name="Hub_1"), "does not match"),
    ],
)
def test_the_registry_holds_edge_tls_to_the_rows_tls(mutate, match):
    doc = _doc()
    mutate(doc["services"]["status-hub"])
    assert any(match in p for p in _problems(doc)), _problems(doc)


def test_a_key_on_one_row_used_as_a_certificate_on_another_is_refused_by_the_registry():
    doc = _doc()
    doc["services"]["idp"]["edge_tls"]["ca"] = "secret:edge/hub-client-key"
    assert any("names as its client_key" in p for p in _problems(doc)), _problems(doc)


def test_the_fixture_is_valid_and_edge_tls_reaches_the_model():
    assert _problems(_doc()) == []
    assert REG.services["status-hub"].edge_tls["client_key"] == "secret:edge/hub-client-key"
    assert REG.services["auth-proxy"].edge_tls is None


def test_edge_tls_references_join_the_secret_collision_check():
    doc = _doc()
    doc["services"]["status-hub"]["edge_tls"]["ca"] = "secret:status/front_door_secret"
    assert any("both delivered in" in p for p in _problems(doc)), _problems(doc)


# ------------------------------------------------------------------------- identity headers
def _example_sites() -> str:
    return generate(load(ROOT / "examples" / "services.yml"), ["caddy"])["caddy"][
        "caddy/sites.caddy"
    ]


@pytest.mark.parametrize(
    "header",
    ["X-Forwarded-User", "X-Forwarded-Groups", "X-Forwarded-Email",
     "X-Forwarded-Preferred-Username", "X-Forwarded-Access-Token", "x_forwarded_user",
     "X-Forwarded_Groups", "X-Forwarded-Username", "Remote-User", "Remote-Group", "X-Remote-User", "Remote_Groups", "X-WEBAUTH-USER"],
)  # fmt: skip
def test_every_spelling_of_another_proxys_identity_header_is_deleted(header):
    """Caddy's ``-*x*`` delete matches case-insensitively anywhere in the name."""
    name = header.lower()
    assert any(p.strip("*") in name for p in foreign_strip_patterns()), header


@pytest.mark.parametrize("header", ["X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"])
def test_caddys_own_forwarding_headers_are_not_deleted(header):
    assert not any(p.strip("*") in header.lower() for p in foreign_strip_patterns())


@pytest.mark.parametrize("text", [_example_sites(), _edge()["caddy/sites.caddy"]])
def test_every_site_strips_them_at_site_level_before_forward_auth(text):
    snippet = text.split(f"({b.FOREIGN_STRIP_SNIPPET}) {{\n", 1)[1].split("\n}\n", 1)[0]
    assert [ln.strip() for ln in snippet.splitlines()] == [
        f"request_header -{p}" for p in foreign_strip_patterns()
    ]
    assert {p.strip("*").replace("_", "-") for p in foreign_strip_patterns()} == set(
        FOREIGN_IDENTITY
    )
    for host in _sites(text):
        lines = [ln.strip() for ln in _site(text, host).splitlines()]
        at = lines.index(f"import {b.FOREIGN_STRIP_SNIPPET}")
        # site level (no matcher, not inside a block), right after the platform strip and before
        # the forward auth and the proxy
        assert lines[at - 2 : at] == [
            "request_header -*auth-request*",
            "request_header -*auth_request*",
        ]
        rest = lines[at + 1 :]
        assert not any(ln.startswith(("handle", "route", "@")) for ln in lines[:at])
        assert any(ln.startswith(("import hnx_forward_auth", "reverse_proxy")) for ln in rest)
