# SPDX-License-Identifier: Apache-2.0
"""The edge provider module, ``modules/caddy`` (modules/caddy/README.md).

* The public tree loads clean; ``roles/`` holds only the two contributed roles; the image pin is
  the product's version, the auth proxy's 7.15.5.
* A fictional overlay that places it on a guest (``idp`` and every other required core slot an
  incumbent) passes ``hnx modules check --overlay`` with its egress grant, and renders a play on
  ``mod_caddy_edge`` with both roles and both preflights; without the grant, with a row that
  differs, or with a guest whose capability is not ``cap:edge`` it is refused.
* The ``edge`` suite through the module's target against a real Caddy (``$HNX_CADDY`` or
  ``caddy``; CI's ``schemas`` job installs the pinned release and requires it, HNX_EDGE_SERVER_REQUIRED=1): every MUST passes,
  ``forwarded-for-appended`` (SHOULD) is the documented finding, and the same configuration
  without the identity strip fails ``spoofed-identity-header-stripped``.
* The role's Caddyfile with the generator's sites for the two-lab fixture is what Caddy adapts:
  one HTTPS server whose only certificate is the loaded one, no certificate automation, every
  site's first handlers deleting every spelling of the identity headers, the catch-all last.
* role_lint passes both roles and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conformance.suites import edge as edge_suite
from homelabnext.conform.core import run_checks
from homelabnext.conform.target import load_target, make_factory
from homelabnext.generators import generate
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.registry import load as load_registry
from tests.suite_policy import require_tool

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "caddy"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
TWO_LAB = ROOT / "tests" / "generators" / "edge" / "fixtures" / "two-lab.services.yml"
GUEST = "192.0.2.41"  # no-raw-endpoint: allow a documentation-range guest address
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the health site and the probe's stand-ins are local
HUB = "status-hub.svc.example.internal"  # the golden's hub (H2): the probe dials a stand-in instead
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


def caddy_binary() -> str:
    """The real Caddy (``$HNX_CADDY``, else ``caddy`` on PATH), or a skip; a failure under
    HNX_REQUIRE_TOOLS=caddy or HNX_EDGE_SERVER_REQUIRED=1 (CI's schemas job, which installs the
    pinned release: a skip there would hide the edge's conformance run)."""
    path = os.environ.get("HNX_CADDY")
    if path:
        return path
    if os.environ.get("HNX_EDGE_SERVER_REQUIRED") == "1" and not shutil.which("caddy"):
        pytest.fail(
            "caddy is not on PATH, and HNX_EDGE_SERVER_REQUIRED=1 requires it", pytrace=False
        )
    return require_tool("caddy")


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_row() -> dict:
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["edge"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "edge-1", "version": version}


def overlay(tmp: Path, *, grant: bool = True, capability: str = "cap:edge") -> Path:
    """A fictional overlay adopting the module: the example registry with the bound row (and one
    incumbent row for each required core slot it has none for), one guest, and a selection
    placing caddy on it, every other required core slot an incumbent."""
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["edge-1"] = {"address": GUEST, "zone": "mgmt", "role": "edge"}
    reg["services"]["edge"] = bound_row()
    hosts = {"agent-runtime": "runtime-core", "backup": "secrets-core", "broker": "idp-core",
             "notify": "lake-core", "records": "lake-core"}  # fmt: skip
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        reg["services"][f"{slot}-incumbent"] = {
            "capability": slot, "impl": "example", "host": host, "protocol": "tcp",
            "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
            "version": "1.0", "tls": "none",
        }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "edge-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:edge-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 2048}\n"
        "  disks: [{name: rootfs, size_gb: 16, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        f"capability: {capability}\nbackup: {{policy: none}}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
        if slot != "edge"
    }
    sel = {
        "profile": "edge-pilot",
        "hosts": {"edge-1": {"guest": "guest:edge-1"}},
        "slots": {"edge": [{"provider": "caddy", "instance": "edge",
                            "placement": {"edge": "edge-1"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    if grant:
        sel["grants"] = {"egress": {"caddy": {"edge": ["internet"]}}}
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


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_roles_holds_only_the_contributed_roles():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["caddy", "caddy_auth_proxy"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    files = [c["file"] for c in manifest["contributes"]["roles"]]
    assert files == ["roles/caddy", "roles/caddy_auth_proxy"]
    (host,) = manifest["requires"]["hosts"]
    assert host["roles"] == ["role:caddy", "role:caddy_auth_proxy"]  # Caddy first


def test_the_manifest_fills_edge_reaches_only_the_internet_and_publishes_nothing():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert list(manifest["provides"]["slots"]) == ["edge"]
    assert manifest["egress"] == [
        {"host": "edge", "to": ["internet"], "purpose": manifest["egress"][0]["purpose"]}
    ]
    rows = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]
    assert list(rows) == ["edge"]  # auth-proxy is no slot: the overlay keeps that row
    assert "public_hostname" not in rows["edge"] and "version" not in rows["edge"]
    assert {c["secret"] for c in manifest["credentials"]} == {
        "secret:caddy/acme-dns-token", "secret:caddy/auth-proxy-cookie-secret",
        "secret:caddy/hub-client-cert", "secret:caddy/hub-client-key",
    }  # fmt: skip


def test_the_pins():
    manifest = ld.load_yaml(MODULE / "module.yml")
    caddy = ld.load_yaml(MODULE / "roles" / "caddy" / "defaults" / "main.yml")
    auth = ld.load_yaml(MODULE / "roles" / "caddy_auth_proxy" / "defaults" / "main.yml")
    ref = caddy["caddy_image"]
    assert ref.split("@")[0] == f"docker.io/library/caddy:{manifest['product']['version']}-alpine"
    assert ref.split("@")[1].startswith("sha256:") and len(ref.split("@")[1]) == 71
    assert auth["caddy_auth_proxy_image"].split("@")[0].endswith(":v7.15.5-alpine")
    assert caddy["caddy_lego_checksums_release"] == caddy["caddy_lego_version"]
    # the ACME client's pin equal to the secrets role's, and CI's Caddy equal to the product:
    # tools/tests/test_pin_consistency.py


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_caddy_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    assert "warning: caddy/edge on edge-1: egress to internet is NOT enforced" in out, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    (play,) = [p for p in books if p["hosts"] == "mod_caddy_edge"]
    assert play["become"] is True
    assert [r["role"].rsplit("/", 1)[1] for r in play["roles"]] == ["caddy", "caddy_auth_proxy"]
    pre = [t["ansible.builtin.include_role"] for t in play["pre_tasks"]]
    assert [(p["name"].rsplit("/", 1)[1], p["tasks_from"]) for p in pre] == [
        ("caddy", "readiness"), ("caddy_auth_proxy", "readiness")
    ]  # fmt: skip
    assert play["vars"] == {"hnx_module_slice": "hnx-caddy-edge.slice"}
    assert (dest / "checks" / "caddy.yml").is_file()


def test_without_the_egress_grant_it_is_refused(tmp_path, capsys):
    code, out = _check(overlay(tmp_path, grant=False), capsys)
    assert code == 1 and "site: caddy: host edge egresses to internet without a grant" in out, out


def test_a_guest_that_is_not_an_edge_is_refused(tmp_path, capsys):
    code, out = _check(overlay(tmp_path, capability="cap:notify"), capsys)
    assert code == 1 and "cap:edge" in out, out


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["edge"]["port"] = 8443
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert "registry: services.edge.port: caddy (instance edge) contributes 443" in out, out


# ----------------------------------------------------------------------------- conformance


def _factory():
    target = load_target(str(MODULE / "conformance" / "target.yml"), root=ROOT)
    binding = target.binding("edge")
    assert binding.adapter == "homelabnext.conform.adapters.caddy:make"
    assert binding.config == {"caddy_env": "HNX_CADDY"}
    return make_factory(binding, root=ROOT)


def test_the_edge_suite_passes_through_the_target_against_a_real_caddy(monkeypatch):
    monkeypatch.setenv("HNX_CADDY", caddy_binary())
    results = run_checks(edge_suite.SUITE, _factory())
    failed = sorted(r.check for r in results if r.status != "pass")
    assert failed == ["forwarded-for-appended"], results  # SHOULD: Caddy replaces a client's XFF
    assert next(r for r in results if r.check == "forwarded-for-appended").severity == "should"


@pytest.mark.parametrize("dropped", ["request_header -*auth", "import hnx_strip_foreign_identity"])
def test_without_a_strip_the_spoof_check_fails(monkeypatch, dropped):
    """The platform's strip and the foreign-identity strip each matter: drop either from the
    configuration and the forgery reaches the upstream."""
    from homelabnext.conform.adapters import caddy as adapter

    monkeypatch.setenv("HNX_CADDY", caddy_binary())
    real = adapter.CaddyEdge.caddyfile

    def unstripped(self):
        return "\n".join(line for line in real(self).split("\n") if dropped not in line)

    monkeypatch.setattr(adapter.CaddyEdge, "caddyfile", unstripped)
    results = run_checks(edge_suite.SUITE, _factory())
    failed = {r.check for r in results if r.status != "pass"}
    assert "spoofed-identity-header-stripped" in failed, results


# ----------------------------------------------------------------------------- the Caddyfile


def _role_caddyfile() -> str:
    role = MODULE / "roles" / "caddy"
    v = {**ld.load_yaml(role / "defaults" / "main.yml"), **ld.load_yaml(role / "vars" / "main.yml")}
    v["caddy_logical_id"] = "edge"
    text = (role / "templates" / "Caddyfile.j2").read_text()
    assert "{%" not in text  # plain substitutions only, so no Jinja is needed to render it here
    return re.sub(r"\{\{ ([a-z_]+) \}\}", lambda m: str(v[m[1]]), text)


def test_caddy_adapts_the_role_caddyfile_with_the_generated_sites(tmp_path):
    binary = caddy_binary()
    files = generate(
        load_registry(TWO_LAB), ["caddy"], {"edge_hosts": ["edge-01", "core-01", "idp-01"]}
    )
    sites = files["caddy"]["caddy/sites.caddy"]
    (tmp_path / "Caddyfile").write_text(_role_caddyfile())
    (tmp_path / "sites.caddy").write_text(sites)
    r = subprocess.run(
        [binary, "adapt", "--config", str(tmp_path / "Caddyfile"), "--adapter", "caddyfile"],
        capture_output=True, text=True, env={"PATH": os.environ.get("PATH", ""),
                                             "HOME": str(tmp_path), "HNX_SECRET_STATUS_FRONT_DOOR_SECRET": "x"},
    )  # fmt: skip
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["apps"]["tls"]["certificates"]["load_files"] == [
        {"certificate": "/etc/hnx-edge/certs/edge.crt", "key": "/etc/hnx-edge/certs/edge.key",
         "tags": ["cert0"]}
    ]  # fmt: skip
    assert "automation" not in doc["apps"]["tls"]  # Caddy obtains no certificate itself
    servers = doc["apps"]["http"]["servers"]
    (https,) = [s for s in servers.values() if s["listen"] == [":8443"]]
    assert https["automatic_https"] == {"disable_certificates": True, "disable_redirects": True}
    assert https["tls_connection_policies"] == [{"certificate_selection": {"any_tag": ["cert0"]}}]
    assert https["protocols"] == ["h1", "h2"]
    hosts = [h for r_ in https["routes"] for m in r_.get("match", []) for h in m.get("host", [])]
    assert sorted(hosts) == ["hub.example.internal", "sso.example.internal"]
    for route in https["routes"]:
        if not route.get("match"):
            continue
        first = route["handle"][0]["routes"][0]
        assert "match" not in first
        deleted = {d for h in first["handle"] if h["handler"] == "headers"
                   for d in h["request"]["delete"]}  # fmt: skip
        assert {"*auth-request*", "*auth_request*", "*remote-user*"} <= deleted
    catch_all = https["routes"][-1]
    assert "match" not in catch_all  # the last route: every name no site has
    assert catch_all["handle"][0]["routes"][0]["handle"] == [
        {"handler": "static_response", "status_code": 404, "body": "no such site"}
    ]
    (health,) = [s for s in servers.values() if s["listen"] == [f"{LOOPBACK}:8081"]]
    assert health["routes"][0]["match"] == [{"host": [LOOPBACK]}]


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_roles_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run(
        [*lint, str(MODULE / "roles" / "caddy"), str(MODULE / "roles" / "caddy_auth_proxy")],
        capture_output=True, text=True,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    "script", ["caddy_export_script", "caddy_restore_script", "caddy_probe_script"]
)
def test_the_roles_scripts_compile(script):
    v = ld.load_yaml(MODULE / "roles" / "caddy" / "vars" / "main.yml")
    compile(v[script], script, "exec")


# ----------------------------------------------------------------------------- the health probe


def _pki(tmp: Path) -> dict[str, Path]:
    """A throwaway CA, a server certificate for the hub's name and a client certificate."""
    openssl = require_tool("openssl")

    def run(*args):
        subprocess.run([openssl, *args], check=True, capture_output=True, cwd=tmp)

    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=test-ca",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")  # fmt: skip
    for name, ext, use in (("server", "status-hub.svc.example.internal", "serverAuth"),
                           ("client", "edge-01", "clientAuth")):  # fmt: skip
        run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={ext}")  # fmt: skip
        (tmp / f"{name}.ext").write_text(
            f"subjectAltName=DNS:{ext}\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={use}\n"
        )
        run("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", f"{name}.pem", "-days", "1", "-extfile", f"{name}.ext")  # fmt: skip
    return {k: tmp / k for k in ("ca.pem", "server.pem", "server.key", "client.pem", "client.key")}


class _Upstream:
    """A loopback TLS server answering 403 (the hub without a front door), optionally requiring
    a client certificate from the CA."""

    def __init__(self, pki: dict[str, Path], require: bool):
        import socket
        import ssl
        import threading

        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(pki["server.pem"], pki["server.key"])
        if require:
            self.ctx.load_verify_locations(pki["ca.pem"])
            self.ctx.verify_mode = ssl.CERT_REQUIRED
        self.sock = socket.create_server((LOOPBACK, 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        import contextlib
        import ssl

        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with (
                contextlib.suppress(OSError, ssl.SSLError),
                conn,
                self.ctx.wrap_socket(conn, server_side=True) as s,
            ):
                s.recv(1024)
                s.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

    def close(self):
        self.sock.close()


def _probe(tmp: Path, pki: dict[str, Path], port: int) -> dict:
    v = ld.load_yaml(MODULE / "roles" / "caddy" / "vars" / "main.yml")
    tls = tmp / "edge-tls"
    (tls / "edge").mkdir(parents=True)
    (tls / "pki").mkdir()
    shutil.copy(pki["client.pem"], tls / "edge" / "hub-client-cert.pem")
    shutil.copy(pki["client.key"], tls / "edge" / "hub-client-key.pem")
    shutil.copy(pki["ca.pem"], tls / "pki" / "internal-ca.pem")
    sites = (
        GOLDEN_SITES.read_text()
        .replace(f"https://{HUB}:8099", f"https://{LOOPBACK}:{port}")
    )  # fmt: skip
    spec = {"bind": LOOPBACK, "port": 1, "names": [], "bundle": str(pki["ca.pem"]),
            "timeout": 5, "sites": sites, "tls_dir": "/etc/hnx/edge-tls", "tls_root": str(tls),
            "marks": v["caddy_identity_marks"]}  # fmt: skip
    r = subprocess.run([sys.executable, "-I", "-c", v["caddy_probe_script"], json.dumps(spec)],
                       input="null", capture_output=True, text=True, timeout=60)  # fmt: skip
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


GOLDEN_SITES = ROOT / "tests" / "generators" / "edge" / "golden" / "caddy" / "sites.caddy"


@pytest.mark.parametrize(("require", "without"), [(True, "refused"), (False, "answered")])
def test_the_health_probe_tells_an_mtls_upstream_that_refuses_from_one_that_does_not(
    tmp_path, require, without
):
    pki = _pki(tmp_path)
    up = _Upstream(pki, require)
    try:
        found = _probe(tmp_path, pki, up.port)
    finally:
        up.close()
    # the hub's site: refused without the edge's client certificate (only when the upstream
    # requires one), answered with it, verified against the lab CA by the hub's name
    assert found["mtls"] == {"hub.example.internal": {"without": without, "with": "answered"}}
    assert set(found["upstream_tls"]) == {"sso.example.internal"}  # the IdP: TLS, no client cert
