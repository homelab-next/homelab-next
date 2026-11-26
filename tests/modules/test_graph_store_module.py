# SPDX-License-Identifier: Apache-2.0
"""The graph-store provider module, ``modules/<id>`` (its README.md).

* The public tree loads clean and the module's ``roles/`` holds only its one contributed role.
* The manifest says what the README says: root's secret by reference, no egress, no public route, an
  image pinned by tag and digest whose version is the product's, an unprivileged container.
* A fictional overlay that places it on a guest (no egress grant needed, no public route) passes
  ``hnx modules check --overlay`` and renders ``modules.yml`` on ``mod_<id>_server``; a registry row
  that differs and a guest without the ``base`` baseline are refused.
* The module's own probe reads the active service and the refused anonymous call from the resolved
  endpoint only, trusting the service's own certificate and nothing else.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.graph_store_front import NAME, Server
from tests.modules.graph_store_module import MID, MODULE, ROLE, ROLE_DIR, P, ref
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]

FIXTURES = Path(__file__).resolve().parent / "fixtures"
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
        "--root", str(ROOT), "--overlay", str(ov),
        "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
        "--mcp-catalog", str(ROOT / "examples" / "mcp"),
    ]  # fmt: skip


def bound_row() -> dict:
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["graph-store"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "graph-1", "version": version}


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["graph-1"] = {"address": GUEST, "zone": "mgmt", "role": "graph"}
    reg["services"]["graph"] = bound_row()
    hosts = {"agent-runtime": "runtime-core", "backup": "secrets-core", "broker": "idp-core",
             "edge": "edge-core", "records": "lake-core"}  # fmt: skip
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        reg["services"][f"{slot}-incumbent"] = {
            "capability": slot, "impl": "example", "host": host, "protocol": "tcp",
            "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
            "version": "1.0", "tls": "none",
        }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "graph-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:graph-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 243, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 8192}\n"
        "  disks: [{name: rootfs, size_gb: 100, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:documents\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "graph-pilot",
        "hosts": {"graph": {"guest": "guest:graph-1"}},
        "slots": {"graph-store": [{"provider": MID, "instance": "graph", "placement": {"server": "graph"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


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
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [ROLE]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == [f"roles/{ROLE}"]


def test_the_manifest_names_the_roots_secret_no_egress_and_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["secret"] for c in manifest["credentials"]] == [ref("root-password")]
    assert manifest["egress"] == "none"
    assert list(manifest["provides"]["slots"]) == ["graph-store"]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["graph-store"]
    assert row["auth"] == "own" and row["port"] == 4443 and row["protocol"] == "https"
    assert row["health"]["path"] == "/api/v1/active"
    assert "public_hostname" not in row  # private: the consumers call it directly
    assert "version" not in row  # a provider's row takes product.version


def test_the_role_defaults_carry_the_roots_reference_and_no_account_the_site_did_not_name():
    d = ld.load_yaml(ROLE_DIR / "defaults" / "main.yml")
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert d[P + "root_login_ref"] in {c["secret"] for c in manifest["credentials"]}
    assert d[P + "users"] == [] and d[P + "roles"] == []  # nothing granted by default
    assert d[P + "telepath_port"] == 0  # the HTTPS API alone unless the site asks


def test_the_image_pin_is_the_product_version_and_a_digest():
    defaults = ld.load_yaml(ROLE_DIR / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    image = defaults[P + "image"]
    assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71
    assert image.split("@")[0].endswith(":v" + version)


@pytest.mark.static
def test_the_container_runs_unprivileged_with_the_services_own_backup_directory():
    text = (ROLE_DIR / "tasks" / "app.yml").read_text()
    assert "user:" in text and "SYN_CORTEX_BACKUP_DIR" in text
    assert "privileged:" not in text and "cap_add:" not in text
    assert "PASSWD" not in text.upper().replace("PASSWORD", "")  # no password in the environment


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
    plays = [p for p in books if p["hosts"] == f"mod_{ROLE}_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{ROLE}")
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{ROLE}-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["graph"]["auth"] = "idp"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "registry: services.graph.auth" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "graph-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


# ----------------------------------------------------------------------------- the probe


def test_the_probe_reads_the_active_service_and_the_refused_call_trusting_only_its_certificate(
    monkeypatch, tmp_path
):
    from homelabnext.conform.adapters.graph_store import make

    monkeypatch.delenv("HNX_ENDPOINT_GRAPH_STORE", raising=False)
    with pytest.raises(AdapterConfigError, match="ca_file"):
        make()  # the service's own certificate is required
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_GRAPH_STORE"):
        make({"ca_file": str(tmp_path / "x.pem"), "server_name": NAME})  # no default endpoint
    with Server(tmp_path) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_GRAPH_STORE", "https://{}:{}".format(*srv.addr))
        probe = make({"ca_file": str(srv.cert), "server_name": NAME})
        assert probe.health() and probe.api_is_private()
        assert srv.paths == ["/api/v1/active", "/api/v1/storm/nodes"]
    probe.close()


def test_the_probe_does_not_trust_a_certificate_it_was_not_given(monkeypatch, tmp_path):
    import ssl

    from homelabnext.conform.adapters.graph_store import make
    from tests.modules.graph_store_front import make_cert

    other = tmp_path / "other"
    other.mkdir()
    other_cert, _ = make_cert(other)
    with Server(tmp_path) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_GRAPH_STORE", "https://{}:{}".format(*srv.addr))
        with pytest.raises((ssl.SSLError, OSError)):
            make({"ca_file": str(other_cert), "server_name": NAME}).health()


def test_the_probe_refuses_a_name_the_certificate_does_not_carry(monkeypatch, tmp_path):
    import ssl

    from homelabnext.conform.adapters.graph_store import make

    with Server(tmp_path) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_GRAPH_STORE", "https://{}:{}".format(*srv.addr))
        with pytest.raises(AdapterConfigError, match="server_name"):
            make({"ca_file": str(srv.cert)})
        with pytest.raises(ssl.SSLError):
            make({"ca_file": str(srv.cert), "server_name": "other.example.internal"}).health()


def test_the_probe_says_so_when_the_api_accepts_an_anonymous_call(monkeypatch, tmp_path):
    from homelabnext.conform.adapters.graph_store import make

    with Server(tmp_path, open_api=True) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_GRAPH_STORE", "https://{}:{}".format(*srv.addr))
        assert make({"ca_file": str(srv.cert), "server_name": NAME}).api_is_private() is False


def test_the_probe_says_so_when_the_service_is_not_the_active_one(monkeypatch, tmp_path):
    from homelabnext.conform.adapters.graph_store import make

    with Server(tmp_path, active=False) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_GRAPH_STORE", "https://{}:{}".format(*srv.addr))
        assert make({"ca_file": str(srv.cert), "server_name": NAME}).health() is False


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE_DIR)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
