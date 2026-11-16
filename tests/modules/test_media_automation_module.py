# SPDX-License-Identifier: Apache-2.0
"""The media automation provider module, ``modules/media-automation`` (its README.md).

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: the four secret references the deploy seeds (and no other),
  internet egress the site must grant, every image pinned by digest, a writable library at a path
  variable, no public route.
* A fictional overlay that places it on a guest (and grants its egress) passes ``hnx modules check
  --overlay`` and renders ``modules.yml`` on ``mod_media_automation_server``; a registry row that
  differs, an ungranted egress and a guest without the ``base`` baseline are refused.
* The module's own probe reads the request app's status from the resolved endpoint only.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODULE = ROOT / "modules" / "media-automation"
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
REQUIRED = sorted(
    s
    for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def _args(ov: Path) -> list[str]:
    return [
        "--root",
        str(ROOT),
        "--overlay",
        str(ov),
        "--keyring",
        str(ROOT / "examples" / "keyring" / "keyring.json"),
        "--mcp-catalog",
        str(ROOT / "examples" / "mcp"),
    ]


def bound_row() -> dict:
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["media-automation"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {
        **copy.deepcopy(row),
        "host": "media-1",
        "version": version,
    }


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["media-1"] = {"address": GUEST, "zone": "mgmt", "role": "media"}
    reg["services"]["media-requests"] = bound_row()
    hosts = {
        "agent-runtime": "runtime-core",
        "backup": "secrets-core",
        "broker": "idp-core",
        "edge": "edge-core",
        "records": "lake-core",
    }
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        reg["services"][f"{slot}-incumbent"] = {
            "capability": slot,
            "impl": "example",
            "host": host,
            "protocol": "tcp",
            "port": 7001 + i,
            "health": {"kind": "none"},
            "owner": "platform-team",
            "version": "1.0",
            "tls": "none",
        }
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "media-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:media-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 241, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 6}\n  memory: {size_mb: 12288}\n"
        "  disks: [{name: rootfs, size_gb: 60, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:media-automation\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "media-automation-pilot",
        "hosts": {"media": {"guest": "guest:media-1"}},
        "slots": {
            "media-automation": [
                {
                    "provider": "media-automation",
                    "instance": "media-requests",
                    "placement": {"server": "media"},
                }
            ]
        },
        "incumbents": incumbents,
        "grants": {"egress": {"media-automation": {"server": ["internet"]}}},
    }
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


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


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["media_automation"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/media_automation"]
    assert (MODULE / "README.md").is_file()


def test_the_manifest_names_exactly_the_four_secrets_the_deploy_seeds_and_asks_for_internet():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["secret"] for c in manifest["credentials"]] == [
        "secret:media-automation/vpn-wireguard-private-key",
        "secret:media-automation/vpn-wireguard-preshared-key",
        "secret:media-automation/vpn-wireguard-addresses",
        "secret:media-automation/qbittorrent-password",
    ]
    assert manifest["egress"][0]["to"] == ["internet"]
    defaults = ld.load_yaml(MODULE / "roles" / "media_automation" / "defaults" / "main.yml")
    refs = sorted(v for k, v in defaults.items() if k.endswith("_ref"))
    assert refs == sorted(
        c["secret"] for c in manifest["credentials"]
    )  # the role reads what the manifest names
    # the server hostnames are a plain optional variable, never a secret
    assert defaults["media_automation_vpn_server_hostnames"] == ""


def test_the_row_is_internal_only_with_its_own_login():
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["media-automation"]
    assert row["auth"] == "own" and row["port"] == 5055 and "public_hostname" not in row
    assert "version" not in row  # a provider's row takes product.version


def test_every_image_is_pinned_by_tag_and_digest_and_the_product_version_is_the_request_apps():
    defaults = ld.load_yaml(MODULE / "roles" / "media_automation" / "defaults" / "main.yml")
    images = {k: v for k, v in defaults.items() if k.endswith("_image")}
    assert len(images) == 10
    for k, v in images.items():
        ref, digest = v.split("@")
        assert digest.startswith("sha256:") and len(digest) == 71, k
        assert not ref.endswith(":latest"), k
    product = ld.load_yaml(MODULE / "module.yml")["product"]["name"]
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    assert (
        images[f"media_automation_{product}_image"]
        .split("@")[0]
        .rsplit(":", 1)[1]
        .lstrip("v")
        .startswith(version)
    )


def test_the_defaults_are_a_writable_library_at_a_path_variable_with_downloads_inside_it():
    d = ld.load_yaml(MODULE / "roles" / "media_automation" / "defaults" / "main.yml")
    assert d["media_automation_library_path"] == "/srv/media"
    assert d["media_automation_downloads_subdir"] == "downloads"
    assert d["media_automation_uid"] == 101000 == d["media_automation_gid"]  # the old files' owner
    app = (MODULE / "roles" / "media_automation" / "tasks" / "app.yml").read_text()
    assert ":ro" not in app  # the library is writable


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
    plays = [p for p in books if p["hosts"] == "mod_media_automation_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/media-automation/roles/media_automation")
    assert plays[0]["vars"] == {"hnx_module_slice": "hnx-media_automation-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["media-requests"]["auth"] = "idp"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.media-requests.auth" in out, out


def test_a_public_route_the_row_does_not_declare_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["media-requests"]["public_hostname"] = "requests.lab.example.internal"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "public_hostname" in out, out


def test_an_ungranted_egress_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    del sel["grants"]["egress"]
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "internet" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "media-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


# ----------------------------------------------------------------------------- the probe


class _Front(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        paths.append(self.path)
        body = json.dumps({"version": "3.5.1"}).encode() if self.path == "/api/v1/status" else b""
        self.send_response(200 if body else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


paths: list[str] = []


def test_the_probe_reads_the_status_from_the_resolved_endpoint(monkeypatch):
    from homelabnext.conform.adapters.media_automation import make

    monkeypatch.delenv("HNX_ENDPOINT_MEDIA_AUTOMATION", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_MEDIA_AUTOMATION"):
        make()  # no default endpoint
    httpd = ThreadingHTTPServer(("localhost", 0), _Front)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv(
            "HNX_ENDPOINT_MEDIA_AUTOMATION", "http://{}:{}".format(*httpd.server_address[:2])
        )
        probe = make()
        assert probe.healthy() and probe.status() == {"version": "3.5.1"}
        assert paths == ["/api/v1/status", "/api/v1/status"]  # read only
        monkeypatch.setenv(
            "HNX_ENDPOINT_MEDIA_AUTOMATION", "ftp://{}:{}".format(*httpd.server_address[:2])
        )
        with pytest.raises(AdapterConfigError):
            make()
    finally:
        httpd.shutdown()
        httpd.server_close()
    probe.close()


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run(
        [*lint, str(MODULE / "roles" / "media_automation")], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
