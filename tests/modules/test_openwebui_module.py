# SPDX-License-Identifier: Apache-2.0
"""The chat provider module (module id and role ``openwebui``: the id is the product's; ``chat`` is
the slot and the instance), ``modules/openwebui`` (modules/openwebui/README.md).

* The public tree loads clean; the module's ``roles/`` holds only its one contributed role; the
  image is pinned by tag and digest, its tag the product's version and equal to the core role's.
* The row is public through the edge with the identity provider's sign-in (``auth: idp`` with
  ``roles``, so the realm gets a client named after it), a registry row without the site's
  ``public_hostname`` or a selection without ``grants.public_routes`` is refused; it asks for no
  egress and no model backend, no provider key.
* The secrets the manifest declares are exactly the two the role reads under the module's own
  namespace; the other two the role reads (the gateway's key for this caller and the realm
  generator's client secret) are outside it, by the names the gateway spec and the generator give.
* A fictional overlay that places it on a guest (every other required core slot an incumbent)
  passes ``hnx modules check --overlay`` and renders ``modules.yml`` on ``mod_openwebui_server``.
* The realm generator renders the client the module's row implies, redirecting under its public name.
* The module's probe reads the health and the public configuration from the resolved endpoint only.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.generators import builtin
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.registry import load as load_registry
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "openwebui"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
#: a documentation-range address from the example registry (never connected to)
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["lake-core"]["address"]
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_row() -> dict:
    """The module's row as the overlay binds it: the guest as host, the product's version, and
    the site's own public name in the one field whose value is the site's."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["chat"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "chat-1", "version": version,
            "public_hostname": "chat.lab.example"}  # fmt: skip


def overlay(tmp: Path, *, grant: bool = True) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["chat-1"] = {"address": GUEST, "zone": "mgmt", "role": "work"}
    reg["services"]["chat"] = bound_row()
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "chat-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:chat-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 243, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 4096}\n"
        "  disks: [{name: rootfs, size_gb: 20, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:chat\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    hosts = {"agent-runtime": "runtime-core", "backup": "secrets-core", "broker": "idp-core",
             "edge": "edge-core", "records": "lake-core"}  # fmt: skip
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        if slot not in rows.values():
            reg["services"][f"{slot}-incumbent"] = {
                "capability": slot, "impl": "example", "host": host, "protocol": "tcp",
                "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
                "version": "1.0", "tls": "none",
            }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "chat-pilot",
        "hosts": {"work": {"guest": "guest:chat-1"}},
        "slots": {"chat": [{"provider": "openwebui", "instance": "chat",
                            "placement": {"server": "work"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    if grant:
        sel["grants"] = {"public_routes": {"openwebui": ["chat"]}}
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _args(ov: Path) -> list[str]:
    return ["--root", str(ROOT), "--overlay", str(ov),
            "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
            "--mcp-catalog", str(ROOT / "examples" / "mcp")]  # fmt: skip


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


# ----------------------------------------------------------------------------- the public tree


@pytest.mark.static
def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


@pytest.mark.static
def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["openwebui"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/openwebui"]


def test_the_row_is_public_through_the_edge_behind_the_identity_provider():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == "none"
    assert set(manifest["provides"]["slots"]) == {"chat"}
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["chat"]
    # auth: idp is what makes the realm generator render a client for the row, with roles
    assert row["auth"] == "idp" and row["roles"] and row["capability"] == "chat"
    assert row["protocol"] == "http" and row["tls"] == "none" and row["port"] == 8080
    assert row["health"] == {"kind": "http", "path": "/health", "expect_status": 200}
    assert row["public_hostname"].endswith(".example.internal")
    assert row["upstreams"] == ["inference"]  # its one backend is the gateway
    assert "version" not in row and "clients" not in row


@pytest.mark.static
def test_the_manifest_asks_for_the_gateway_and_the_identity_provider_and_no_provider_key():
    manifest = ld.load_yaml(MODULE / "module.yml")
    caps = {c["cap"] for c in manifest["requires"]["capabilities"]}
    assert caps == {"cap:secrets", "cap:inference", "cap:idp"}
    text = "".join(p.read_text() for p in MODULE.rglob("*.yml")).lower()
    assert "api.openai" not in text and "anthropic" not in text  # no provider named at all


@pytest.mark.static
def test_the_secrets_are_the_two_the_manifest_declares_plus_the_two_others_by_name():
    manifest = ld.load_yaml(MODULE / "module.yml")
    declared = sorted(c["secret"] for c in manifest["credentials"])
    assert declared == ["secret:openwebui/admin-password", "secret:openwebui/session-key"]
    defaults = ld.load_yaml(MODULE / "roles" / "openwebui" / "defaults" / "main.yml")
    refs = sorted(v for k, v in defaults.items() if k.endswith("_ref") and v)
    assert refs == sorted([*declared, "secret:gateway/key-openwebui"])
    text = "".join(p.read_text() for p in (MODULE / "roles").rglob("*.yml"))
    names = sorted(set(re.findall(r"secret:[a-z0-9/_.-]+", text)))
    assert names == sorted(
        {*declared, "secret:gateway/key-openwebui"}
    )  # the client's is the site's


@pytest.mark.static
def test_the_image_is_pinned_its_tag_the_product_version_and_equal_to_the_core_roles():
    defaults = ld.load_yaml(MODULE / "roles" / "openwebui" / "defaults" / "main.yml")
    core = ld.load_yaml(ROOT / "ansible" / "roles" / "open_webui" / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    image = defaults["openwebui_image"]
    assert image == core["open_webui_image"]
    ref, digest = image.split("@")
    assert digest.startswith("sha256:") and len(digest) == 71
    assert ref.endswith(f":v{version}")


@pytest.mark.static
def test_pin_freshness_watches_the_image():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import pin_freshness as pf
    finally:
        sys.path.pop(0)
    ids = {p.id for p in pf.inventory(ROOT)}
    assert "role:openwebui/openwebui_image" in ids
    assert pf.check_inventory(pf.inventory(ROOT)) == []


# ----------------------------------------------------------------------------- the realm client


def test_the_realm_generator_renders_the_client_the_row_implies(tmp_path):
    """One confidential client named after the row, PKCE, redirects under its public hostname, the
    row's roles as client roles: what the role's OpenID Connect settings assume."""
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["services"]["chat"] = {**bound_row(), "host": next(iter(reg["hosts"]))}
    path = tmp_path / "services.yml"
    path.write_text(_dump(reg))
    realm = json.loads(builtin.idp_realm(load_registry(path))["idp/realm.json"])
    client = next(c for c in realm["clients"] if c["clientId"] == "chat")
    assert client["redirectUris"] == ["https://chat.lab.example/*"]
    assert client["publicClient"] is False and client["directAccessGrantsEnabled"] is False
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert client["secret"] == "$(env:HNX_SECRET_IDP_CLIENTS_CHAT)"  # idp/clients/chat
    claims = {m["config"].get("claim.name") for m in client["protocolMappers"]}
    assert {"roles", "groups", "preferred_username"} <= claims  # what OAUTH_* settings read
    scopes = set(client["optionalClientScopes"])
    assert {"email", "profile"} <= scopes  # the role asks for 'openid email profile'
    granted = {  # the row's roles are rendered as the client's roles
        role["name"] for role in realm["roles"]["client"]["chat"]
    }
    assert granted == {
        "user",
        "admin",
    }  # the role maps these to Open WebUI's allowed and admin roles
    app = (ROOT / "ansible" / "roles" / "open_webui" / "tasks" / "app.yml").read_text()
    for setting in ("'OAUTH_ROLES_CLAIM': 'roles'", "'OAUTH_USERNAME_CLAIM': 'preferred_username'",
                    "'OAUTH_CODE_CHALLENGE_METHOD': 'S256'", "'OAUTH_SCOPES': 'openid email profile'"):  # fmt: skip
        assert setting in app, setting


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == "mod_openwebui_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/openwebui/roles/openwebui")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": "hnx-openwebui-server.slice"}


def test_a_registry_row_without_the_sites_public_name_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    del reg["services"]["chat"]["public_hostname"]
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert "registry: services.chat.public_hostname: openwebui (instance chat) declares one" in out


def test_a_row_that_drops_the_sign_in_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["chat"]["auth"] = "own"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.chat.auth" in out, out


def test_the_public_row_needs_a_public_routes_grant(tmp_path, capsys):
    ov = overlay(tmp_path, grant=False)
    code, out = _check(ov, capsys)
    assert code == 1
    assert "openwebui: service chat is public without grants.public_routes" in out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "chat-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


# ----------------------------------------------------------------------------- the probe


class _App:
    """The two anonymous endpoints the probe reads."""

    def __init__(self, config):
        self.paths = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.paths.append(self.path)
                body = {"/health": {"status": True}, "/api/config": config}.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._httpd = ThreadingHTTPServer((socket.gethostbyname("localhost"), 0), H)

    def __enter__(self):
        threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def addr(self):
        return self._httpd.server_address[:2]


DEPLOYED = {"features": {"enable_signup": False}, "oauth": {"providers": {"oidc": "SSO"}}}


def test_the_probe_reads_health_and_the_public_configuration_from_the_resolved_endpoint(
    monkeypatch,
):
    from homelabnext.conform.adapters.chat import make

    monkeypatch.delenv("HNX_ENDPOINT_CHAT", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_CHAT"):
        make()  # no default endpoint
    with _App(DEPLOYED) as app:
        monkeypatch.setenv("HNX_ENDPOINT_CHAT", "http://{}:{}".format(*app.addr))
        probe = make()
        assert probe.health() and probe.deployed() and probe.providers() == ["oidc"]
        assert set(app.paths) == {"/health", "/api/config"}
    probe.close()


@pytest.mark.parametrize(
    "config",
    [
        {**DEPLOYED, "onboarding": True},  # no administrator yet: the first visitor becomes one
        {"features": {"enable_signup": True}, "oauth": {"providers": {}}},
    ],
)
def test_the_probe_does_not_call_an_open_instance_deployed(monkeypatch, config):
    from homelabnext.conform.adapters.chat import make

    with _App(config) as app:
        monkeypatch.setenv("HNX_ENDPOINT_CHAT", "http://{}:{}".format(*app.addr))
        assert make().deployed() is False


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(MODULE / "roles" / "openwebui")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
