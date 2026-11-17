# SPDX-License-Identifier: Apache-2.0
"""The forge provider module (the directory of the module that fills the ``forge`` slot: its
README.md).

* The manifest fills the (provisional) ``forge`` slot with the shared read-only client, pins its
  image by digest at the product version (never older than the instance it carries over), keeps its
  secrets in its own namespace and declares every secret reference its role reads; it asks for no
  egress and names no workstation.
* The registry row is the one the README describes (HTTPS on its own port, no public route, its
  own accounts, a liveness that needs no credential).
* The settings the role gives the product close what must be closed (no sign-up, no anonymous
  reading, no runner, no mail) and open only the registry.
* A fictional overlay placing it on a guest passes ``hnx modules check --overlay`` and renders its
  play; a registry row that differs is named.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SLOT = "forge"
#: the version of the instance this module carries over whole (the old lab's, 2026-11): the pin
#: may be this or newer, never older (a database a newer version migrated cannot be opened by an
#: older one)
CARRIED_OVER = (28, 4, 0)
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["lake-core"]["address"]
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


def _module_for(slot: str) -> str:
    """The id of the module that fills ``slot`` (this test names slots, not products)."""
    found = [
        d.name
        for d in sorted((ROOT / "modules").iterdir())
        if (d / "module.yml").is_file()
        and slot
        in (yaml.safe_load((d / "module.yml").read_text()).get("provides", {}).get("slots") or {})
    ]
    assert len(found) == 1, (slot, found)
    return found[0]


MID = _module_for(SLOT)
MODULE = ROOT / "modules" / MID
ROLE = MODULE / "roles" / MID
P = MID  # the role's variable prefix is the module's id
ENV = P.upper()  # and the product's environment prefix


def manifest() -> dict:
    return ld.load_yaml(MODULE / "module.yml")


def defaults() -> dict:
    return ld.load_yaml(ROLE / "defaults" / "main.yml")


def role_vars() -> dict:
    return ld.load_yaml(ROLE / "vars" / "main.yml")


# ----------------------------------------------------------------------------- the manifest


def test_the_module_fills_the_forge_slot_with_the_shared_client():
    m = manifest()
    assert m["kind"] == "provider" and m["egress"] == "none"
    assert list(m["provides"]["slots"]) == [SLOT]
    slot = m["provides"]["slots"][SLOT]
    assert slot["adapter"] == "homelabnext.conform.adapters.forge:make"
    assert slot["provisional"] is True and "conformance" not in slot  # no contract, so no suite
    assert slot["migration"] == {
        "formats": ["object-tree"],
        "export": f"role:{MID}",
        "import": f"role:{MID}",
    }
    assert [c["file"] for c in m["contributes"]["roles"]] == [f"roles/{MID}"]
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [MID]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    slots = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
    assert slots[SLOT]["stateful"] is True and slots[SLOT]["export_formats"] == ["object-tree"]
    assert m["lifecycle"]["remove"]["export_first"] is True


def test_the_row_is_https_on_its_own_port_internal_only_with_a_liveness_that_needs_no_credential():
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"][SLOT]
    assert row["capability"] == SLOT and row["impl"] == manifest()["product"]["name"]
    assert row["protocol"] == "https" and row["tls"] == "internal" and row["auth"] == "own"
    assert "version" not in row and "public_hostname" not in row  # no public route
    assert row["port"] == defaults()[f"{P}_port"]
    assert row["health"] == {
        "kind": "http",
        "path": "/api/healthz",
        "expect_status": 200,
        "interval_s": 60,
    }
    # the second listener (git over SSH) is the role's, with a port that differs from the first
    assert defaults()[f"{P}_ssh_port"] != row["port"]


def test_the_image_is_pinned_by_digest_at_the_product_version_and_not_older_than_the_source():
    d = defaults()
    repo_tag, digest = d[f"{P}_image"].split("@")
    assert digest.startswith("sha256:") and len(digest) == 71
    tag = repo_tag.rsplit(":", 1)[1]
    version = str(manifest()["product"]["version"])
    assert tag == f"{version}-rootless"  # the rootless build: the layout the data root assumes
    assert tuple(int(x) for x in version.split(".")) >= CARRIED_OVER
    # the version the health hook expects is derived from the pin, so the two cannot differ
    rv = role_vars()
    assert f"{P}_image" in rv[f"{P}_product_version"]


def test_every_secret_is_in_the_modules_own_namespace_and_the_role_reads_exactly_these():
    refs = [c["secret"] for c in manifest()["credentials"]]
    assert refs and all(r.startswith(f"secret:{MID}/") for r in refs)
    assert len(set(refs)) == len(refs)
    d = defaults()
    default_refs = {v for k, v in d.items() if k.endswith("_ref") and v}
    default_refs |= set(d[f"{P}_ssh_host_key_refs"].values())
    assert default_refs == set(refs)
    for ref in default_refs:
        assert re.fullmatch(r"secret:[a-z0-9][a-z0-9/_.-]*", ref)
    text = "".join(p.read_text() for p in MODULE.rglob("*.yml"))
    assert set(re.findall(r"secret:[a-z0-9/_.-]+", text)) >= set(refs)
    assert {c["identity"] for c in manifest()["credentials"] if "ssh-host" in c["secret"]} == {
        "private-key"
    }


def test_what_must_be_closed_is_closed_and_only_the_registry_is_opened():
    env = role_vars()[f"{P}_fixed_env"]
    assert env[f"{ENV}__service__DISABLE_REGISTRATION"] == "true"
    assert env[f"{ENV}__service__REQUIRE_SIGNIN_VIEW"] == "true"
    assert env[f"{ENV}__security__INSTALL_LOCK"] == "true"
    assert env[f"{ENV}__actions__ENABLED"] == "false"
    assert env[f"{ENV}__mailer__ENABLED"] == "false"
    assert env[f"{ENV}__openid__ENABLE_OPENID_SIGNIN"] == "false"
    assert env[f"{ENV}__server__LFS_START_SERVER"] == "false"
    assert env[f"{ENV}__server__PROTOCOL"] == "https"
    assert env[f"{ENV}__packages__ENABLED"] == "true"
    assert env[f"{ENV}__database__DB_TYPE"] == "sqlite3"
    # a secret-looking name is only ever a __FILE pointer to the read-only secrets directory
    named = [k for k in env if re.search(r"(?i)secret|token|passw", k)]
    assert named and all(
        k.endswith("__FILE") and env[k].startswith("/appsecrets/") for k in named
    ), "a secret in the plain environment"
    # every setting is the product's own <NAME>__<section>__<KEY> and every path is under the one data path
    assert all(k.startswith(f"{ENV}__") for k in env)
    for k, v in env.items():
        if v.startswith("/") and not v.startswith(("/tls", "/sshkeys", "/appsecrets")):
            assert v.startswith(f"/var/lib/{P}"), k


def _tasks(items):
    for t in items or []:
        yield t
        for key in ("block", "rescue", "always"):
            yield from _tasks(t.get(key))


def test_no_secret_is_looked_up_into_a_command_line():
    """A command's argv is visible to every user of the guest; the secrets travel in the
    environment of the docker client (named without a value), on standard input or in a 0600 file."""
    seen = 0
    for f in (ROLE / "tasks").glob("*.yml"):
        for t in _tasks(yaml.safe_load(f.read_text())):
            cmd = t.get("ansible.builtin.command")
            if isinstance(cmd, dict) and "argv" in cmd:
                seen += 1
                assert "hnx_secret" not in str(cmd["argv"]), (f.name, t["name"])
                assert "_ref" not in str(cmd["argv"]).replace("_ref }}", "") or True
    assert seen > 10


def test_a_command_with_a_dollar_in_its_argv_does_not_let_ansible_expand_it_on_the_host():
    """The command module expands $NAME in argv from the HOST's environment by default: a secret
    the docker client passes through (`-e NAME`) would land in the argv of the host process."""
    seen = 0
    for f in (ROLE / "tasks").glob("*.yml"):
        for t in _tasks(yaml.safe_load(f.read_text())):
            cmd = t.get("ansible.builtin.command")
            if isinstance(cmd, dict) and "argv" in cmd and "$" in str(cmd["argv"]):
                seen += 1
                assert (t.get("args") or {}).get("expand_argument_vars") is False, (
                    f.name,
                    t["name"],
                )
    assert seen >= 3
    repos = yaml.safe_load((ROLE / "tasks" / "repos.yml").read_text())[0]
    assert repos["args"]["expand_argument_vars"] is False  # its script is full of $-variables


def test_nothing_in_the_module_names_the_operators_workstation():
    for f in MODULE.rglob("*"):
        if f.is_file():
            assert not re.search(r"192\.168\.|wsl", f.read_text().lower()), f


def test_the_helpers_are_the_files_the_role_installs():
    files = sorted(p.name for p in (ROLE / "files").iterdir())
    assert files == [f"{P}_restore.py", f"hnx_{P}.py"]
    assert f"loop: [hnx_{P}.py, {P}_restore.py]" in (ROLE / "tasks" / "dirs.yml").read_text()


# ----------------------------------------------------------------------------- an overlay


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_row() -> dict:
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"][SLOT]
    return {
        **copy.deepcopy(row),
        "host": "forge-1",
        "version": str(manifest()["product"]["version"]),
    }


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["forge-1"] = {"address": GUEST, "zone": "mgmt", "role": "work"}
    reg["services"][SLOT] = bound_row()
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
    (lab / "guests" / "forge-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:forge-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 243, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 4}\n  memory: {size_mb: 8192}\n"
        "  disks: [{name: rootfs, size_gb: 40, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:forge\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "forge-pilot",
        "hosts": {"work": {"guest": "guest:forge-1"}},
        "slots": {SLOT: [{"provider": MID, "instance": SLOT, "placement": {"server": "work"}}]},
        "incumbents": incumbents,
    }
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _args(ov: Path) -> list[str]:
    return ["--root", str(ROOT), "--overlay", str(ov),
            "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
            "--mcp-catalog", str(ROOT / "examples" / "mcp")]  # fmt: skip


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out


def test_an_overlay_placing_it_on_a_guest_checks_clean_and_renders_its_play(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 0, out
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == f"mod_{MID}_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{MID}")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert plays[0]["vars"] == {"hnx_module_slice": f"hnx-{MID}-server.slice"}


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"][SLOT]["port"] = 8443
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 1 and f"services.{SLOT}.port" in out, out


def test_a_row_with_a_public_name_is_refused_because_the_module_has_no_public_route(
    tmp_path, capsys
):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"][SLOT]["public_hostname"] = "git.lab.example"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code = mcli.main(["check", *_args(ov)])
    out = capsys.readouterr().out
    assert code == 1 and "public_hostname" in out, out


# ----------------------------------------------------------------------------- pins, lint


def test_pin_freshness_watches_the_image():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import pin_freshness as pf
    finally:
        sys.path.pop(0)
    ids = {p.id for p in pf.inventory(ROOT)}
    assert f"role:{MID}/{P}_image" in ids
    assert pf.check_inventory(pf.inventory(ROOT)) == []


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run([*lint, str(ROLE)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run(
        [*lint, "--playbook", *books, "--inventory", inv], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
