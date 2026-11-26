# SPDX-License-Identifier: Apache-2.0
"""The endpoint-forensics provider module, ``modules/<id>`` (its README.md).

* The public tree loads clean and the module's ``roles/`` holds only its two contributed roles.
* The manifest says what the README says: the secrets by reference, no egress, no public route, a
  provisional slot, the GUI as the registry row, one server image pinned by tag and digest whose
  tag is the product version and the client release the same version, criteria that run the check
  script the role installs.
* A fictional overlay that places both host roles (no egress grant: none is declared) passes
  ``hnx modules check --overlay`` and renders ``modules.yml`` on ``mod_<id>_server`` and
  ``mod_<id>_endpoint``; a registry row that differs and a guest without the ``base`` baseline are
  refused.
* A change to the artifact allow-list is classified human-approve by the review tier.
* The module's own probe verifies both ports' certificates against the authority under the name
  the server's certificates are issued to, and says so when the GUI does not ask for a sign-in, the
  clients' port does not serve its certificate or the authority is another.
* role_lint passes both roles and the lifecycle playbooks.
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
from homelabnext.modules import review_tier as rt
from tests.modules.endpoint_forensics_front import LOOP, NAME, Server
from tests.modules.endpoint_forensics_module import (
    CLIENT,
    MID,
    MODULE,
    SERVER,
    SLOT,
    SP,
    ref,
    server_defaults,
)
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
HOSTS = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]
GUEST = HOSTS["dns-core"]["address"]
PORT = 8890
GUEST2 = HOSTS["lake-core"]["address"]
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
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"][SLOT]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "forensics-1", "version": version}


def _guest(name: str, vmid: int, ip: str, cap: str | None) -> str:
    return (
        "# SPDX-License-Identifier: Apache-2.0\n"
        f"id: guest:{name}\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        f"placement: {{node: hv-01, vmid: {vmid}, vmid_scheme: freeform}}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 4096}\n"
        "  disks: [{name: rootfs, size_gb: 60, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {ip}}}\n"
        + (f"capability: {cap}\n" if cap else "")
        + "backup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["forensics-1"] = {"address": GUEST, "zone": "mgmt", "role": "forensics"}
    reg["hosts"]["endpoint-1"] = {"address": GUEST2, "zone": "mgmt", "role": "endpoint"}
    reg["services"]["forensics"] = bound_row()
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
    (lab / "guests" / "forensics-1.yml").write_text(
        _guest("forensics-1", 243, GUEST, f"cap:{SLOT}")
    )
    (lab / "guests" / "endpoint-1.yml").write_text(_guest("endpoint-1", 244, GUEST2, "cap:metrics"))
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "forensics-pilot",
        "hosts": {"forensics": {"guest": "guest:forensics-1"}, "endpoints": {"guest": "guest:endpoint-1"}},
        "slots": {SLOT: [{"provider": MID, "instance": "forensics",
                          "placement": {"server": "forensics", "endpoint": "endpoints"}}]},
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


@pytest.mark.static
def test_roles_holds_only_the_two_contributed_roles():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [CLIENT.name, SERVER.name]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert sorted(c["file"] for c in manifest["contributes"]["roles"]) == [
        f"roles/{CLIENT.name}", f"roles/{SERVER.name}",
    ]  # fmt: skip


@pytest.mark.static
def test_the_manifest_names_the_secrets_no_egress_and_a_provisional_slot():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["secret"] for c in manifest["credentials"]] == [
        ref("admin-password"), ref("client-config"),
    ]  # fmt: skip
    assert [c["holder"] for c in manifest["credentials"]] == ["provider", "granted"]
    assert manifest["egress"] == "none"
    assert list(manifest["provides"]["slots"]) == [SLOT]
    slot = manifest["provides"]["slots"][SLOT]
    assert slot["provisional"] is True and slot["migration"]["formats"] == ["object-tree"]
    assert [h["role"] for h in manifest["requires"]["hosts"]] == ["server", "endpoint"]
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"][SLOT]
    assert row["auth"] == "own" and row["port"] == 8890 and row["protocol"] == "https"
    assert "public_hostname" not in row and "version" not in row
    slots = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
    assert slots[SLOT]["contract"] is None and not slots[SLOT].get("privileged")
    assert slots[SLOT]["stateful"] is True


def test_the_pins_agree_on_one_release_and_the_image_is_pinned_by_tag_and_digest():
    manifest = ld.load_yaml(MODULE / "module.yml")
    version = str(manifest["product"]["version"])
    image = server_defaults()[f"{SP}image"]
    assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71
    assert image.split("@")[0].endswith(":" + version)
    client = ld.load_yaml(CLIENT / "defaults" / "main.yml")
    pins = ld.load_yaml(CLIENT / "vars" / "main.yml")
    assert client[f"{MID}_client_version"] == version
    assert version in pins[f"{MID}_client_checksums"]


@pytest.mark.static
def test_the_defaults_carry_only_the_modules_references():
    manifest = ld.load_yaml(MODULE / "module.yml")
    declared = {c["secret"] for c in manifest["credentials"]}
    for role in (SERVER, CLIENT):
        d = ld.load_yaml(role / "defaults" / "main.yml")
        refs = {v for k, v in d.items() if k.endswith("_ref") and v}
        assert refs <= declared, role.name
    # the name the clients dial has no default: it is the site's, fixed at the first start
    assert f"{SP}frontend_hostname" not in server_defaults()
    spec = yaml.safe_load((SERVER / "meta" / "argument_specs.yml").read_text())["argument_specs"]
    for hook in ("main", "health", "export", "restore"):
        assert spec[hook]["options"][f"{SP}frontend_hostname"]["required"] is True


def test_the_servers_start_command_runs_the_stock_entrypoint_only_when_there_is_no_configuration():
    v = ld.load_yaml(SERVER / "vars" / "main.yml")
    cmd = v[f"{SP}command"]
    assert cmd[:2] == ["/bin/sh", "-c"]
    script = cmd[2]
    assert script.startswith("if [ -s /etc/") and script.count("entrypoint") == 1
    assert script.index("then exec") < script.index("else exec /bin/sh /bin/entrypoint")


# ----------------------------------------------------------------------------- the criteria


@pytest.mark.static
def test_the_criteria_run_the_check_script_the_role_installs():
    manifest = ld.load_yaml(MODULE / "module.yml")
    (entry,) = manifest["contributes"]["invariants"]
    crit = ld.load_yaml(MODULE / entry["file"])["criteria"]
    assert [c["id"] for c in crit] == [
        f"{MID}/{n}" for n in ("service-up", "clients-enrolled", "clients-fresh")
    ]
    installed = ld.load_yaml(SERVER / "vars" / "main.yml")[f"{SP}check_script"]
    header = next((SERVER / "files").glob(f"hnx_{MID}_check.py")).read_text()
    assert f"installs_to: {installed}" in header
    for c in crit:
        assert c["evidence"] == "auto" and c["observable"].startswith(installed + " ")
        assert c["observable"].split()[-1] == c["id"].split("/")[1]
        assert len(c["remediation"]) > 40


# ----------------------------------------------------------------------------- the review tier


def test_a_change_to_the_artifact_allow_list_or_a_role_file_is_human_approve():
    manifest = ld.load_yaml(MODULE / "module.yml")
    refs = rt._references(manifest)
    allow = f"roles/{SERVER.name}/files/baseline-artifacts.yml"
    for at_base in (True, False):
        got = rt._file_change(allow, refs, refs, at_base=at_base, privileged_provider=False)
        assert got.tier == rt.HUMAN, (at_base, got)
    new_artifact = f"roles/{SERVER.name}/files/custom_artifacts/Custom.Example.New.yaml"
    assert (
        rt._file_change(new_artifact, refs, refs, at_base=False, privileged_provider=False).tier
        == rt.HUMAN
    )
    # the criteria and the README are the owner's
    for rel in ("invariants/criteria.yml", "README.md"):
        assert (
            rt._file_change(rel, refs, refs, at_base=True, privileged_provider=False).tier
            == rt.OWNER
        ), rel


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_both_host_roles_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    server = [p for p in books if p["hosts"] == f"mod_{MID}_server"]
    endpoint = [p for p in books if p["hosts"] == f"mod_{MID}_endpoint"]
    assert len(server) == 1 and len(endpoint) == 1
    assert server[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{SERVER.name}")
    assert endpoint[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{CLIENT.name}")
    assert without_footprint(server[0]["vars"]) == {"hnx_module_slice": f"hnx-{MID}-server.slice"}


def test_a_registry_row_that_differs_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = yaml.safe_load((ov / "lab" / "services.yml").read_text())
    reg["services"]["forensics"]["port"] = 9999
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "services.forensics.port" in out, out


def test_a_guest_with_no_baseline_at_all_is_still_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "forensics-1.yml"
    g.write_text(g.read_text().replace("baseline: {names: [base]}", "baseline: {names: []}"))
    code, out = _check(ov, capsys)
    assert code == 1, out


def test_both_host_roles_accept_a_physical_host_and_ask_for_no_guest_baseline():
    # a capture host that is a physical machine (kind host, a baseline exemption) carries the server and
    # the client baseline: the roles are kind any and name no guest baseline of their own
    manifest = ld.load_yaml(MODULE / "module.yml")
    roles = {h["role"]: h for h in manifest["requires"]["hosts"]}
    assert {r: h["kind"] for r, h in roles.items()} == {"server": "any", "endpoint": "any"}
    assert not any("guest" in h for h in roles.values())


# ----------------------------------------------------------------------------- the probe


def _probe(tmp_path, srv, **cfg):
    from homelabnext.conform.adapters.endpoint_forensics import EndpointForensicsProbe

    p = EndpointForensicsProbe(
        f"https://{LOOP}:{srv.gui_port}", str(srv.ca), server_name=cfg.pop("server_name", NAME),
        frontend_port=srv.frontend_port, timeout=5.0,
    )  # fmt: skip
    return p


needs_openssl = pytest.mark.requires_tool("openssl")


@needs_openssl
def test_the_probe_verifies_both_certificates_and_reads_only_the_two_public_paths(tmp_path):
    with Server(tmp_path) as srv:
        p = _probe(tmp_path, srv)
        assert p.health() is True and p.gui_is_private() is True
        assert srv.paths == ["/server.pem", "/app/index.html"]  # nothing else is ever asked


@needs_openssl
def test_the_probe_says_so_when_the_gui_does_not_ask_for_a_sign_in(tmp_path):
    with Server(tmp_path, gui_status="200 OK") as srv:
        assert _probe(tmp_path, srv).gui_is_private() is False


@needs_openssl
def test_the_probe_says_so_when_the_clients_port_does_not_serve_its_certificate(tmp_path):
    with Server(tmp_path, serve_pem=False) as srv:
        assert _probe(tmp_path, srv).health() is False


@needs_openssl
def test_the_probe_refuses_another_authority_and_another_name(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    with Server(tmp_path) as srv, Server(other, tag="other") as stranger:
        wrong_ca = _probe(tmp_path, stranger)  # trusts the other authority, dials this one's ports
        wrong_ca._frontend_port, wrong_ca._gui_port = srv.frontend_port, srv.gui_port
        assert wrong_ca.health() is False and wrong_ca.gui_is_private() is False
        wrong_name = _probe(tmp_path, srv, server_name="SomeoneElse")
        assert wrong_name.health() is False and wrong_name.gui_is_private() is False


def test_the_probe_wants_its_endpoint_an_authority_and_a_name(monkeypatch, tmp_path):
    from homelabnext.conform.adapters.endpoint_forensics import EndpointForensicsProbe, make

    monkeypatch.delenv("HNX_ENDPOINT_ENDPOINT_FORENSICS", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_ENDPOINT_FORENSICS"):
        make()  # no default endpoint
    monkeypatch.setenv("HNX_ENDPOINT_ENDPOINT_FORENSICS", f"http://{LOOP}:{PORT}")
    with pytest.raises(AdapterConfigError):
        make({"ca_file": str(tmp_path / "ca.pem"), "server_name": NAME})  # plain http is refused
    monkeypatch.setenv("HNX_ENDPOINT_ENDPOINT_FORENSICS", f"https://{LOOP}:{PORT}")
    with pytest.raises(AdapterConfigError, match="server_name"):
        make({"ca_file": str(tmp_path / "ca.pem")})
    with pytest.raises(AdapterConfigError, match="ca_file"):
        EndpointForensicsProbe(f"https://{LOOP}:{PORT}", "", server_name=NAME)


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_both_roles_and_the_lifecycle_playbooks():
    for target in (SERVER, CLIENT, *sorted((MODULE / "playbooks").glob("*.yml"))):
        flag = ["--playbook"] if target.suffix == ".yml" else []
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "role_lint.py"), *flag, str(target)],
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.static
def test_pin_freshness_watches_the_server_image():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import pin_freshness as pf
    finally:
        sys.path.pop(0)
    ids = {p.id for p in pf.inventory(ROOT)}
    assert f"role:{MID}_server/{SP}image" in ids
    assert pf.check_inventory(pf.inventory(ROOT)) == []
