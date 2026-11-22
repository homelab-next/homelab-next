# SPDX-License-Identifier: Apache-2.0
"""The SIEM provider module, ``modules/<id>`` (its README.md), found by the slots it fills.

* The public tree loads clean; the module's ``roles/`` holds only its one contributed role; its three
  images are pinned by tag and digest and are one release, the tag being the product's version.
* The two rows are internal and carry no public route; the secrets the manifest declares are exactly
  the five the role reads, under the module's name.
* A fictional overlay that places it on a guest renders ``modules.yml`` on ``mod_<id>_server``.
* The role refuses what it must (a bad image, a mixed release, a secret it cannot use) before a
  container sees it; the manager acts on no host; the config carries the settings the contract names.
* Pin freshness watches the three images.
"""

from __future__ import annotations

import copy
import re
import shutil
import sys
from pathlib import Path

import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SLOTS = ("siem-source", "hot-index")
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["lake-core"]["address"]
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


def _find() -> Path:
    found = []
    for manifest in sorted((ROOT / "modules").glob("*/module.yml")):
        doc = yaml.safe_load(manifest.read_text())
        if set(SLOTS) <= set(doc.get("provides", {}).get("slots", {})):
            found.append(manifest.parent)
    assert len(found) == 1, f"exactly one module fills {SLOTS}: {found}"
    return found[0]


MODULE = _find()
MID = MODULE.name
ROLE = MID.replace("-", "_")
P = ROLE + "_"
ROLE_DIR = MODULE / "roles" / ROLE


def defaults() -> dict:
    return yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text())


def role_text(*parts: str) -> str:
    return (ROLE_DIR.joinpath(*parts)).read_text()


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_rows() -> dict:
    rows = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    out = {}
    for slot, name in (("siem-source", "siem"),):
        out[name] = {**copy.deepcopy(rows[slot]), "host": "siem-1", "version": version}
    return out


def overlay(tmp: Path) -> Path:
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    reg["hosts"]["siem-1"] = {"address": GUEST, "zone": "mgmt", "role": "work"}
    reg["services"].update(bound_rows())
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "siem-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:siem-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 244, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 12}\n  memory: {size_mb: 32768}\n"
        "  disks: [{name: rootfs, size_gb: 400, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {GUEST}}}\n"
        "capability: cap:siem-source\nbackup: {policy: none}\n"
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
        "profile": "siem-pilot",
        "hosts": {"work": {"guest": "guest:siem-1"}},
        "slots": {
            "siem-source": [{"provider": MID, "instance": "siem", "placement": {"server": "work"}}],
            "hot-index": [{"provider": MID, "instance": "siem"}],
        },
        "incumbents": incumbents,
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _args(ov: Path) -> list[str]:
    return ["--root", str(ROOT), "--overlay", str(ov),
            "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
            "--mcp-catalog", str(ROOT / "examples" / "mcp")]  # fmt: skip


# ----------------------------------------------------------------------------- the public tree


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == [ROLE]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == [f"roles/{ROLE}"]


def test_the_rows_are_internal_with_the_products_own_accounts_and_no_public_route():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == "none"
    assert set(manifest["provides"]["slots"]) == set(SLOTS)
    for slot in SLOTS:
        assert manifest["provides"]["slots"][slot]["provisional"] is True
    assert manifest["provides"]["slots"]["hot-index"]["migration"]["formats"] == ["jsonl"]
    rows = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]
    assert set(rows) == {"siem-source"}  # one instance for both slots: one row, the agents' port
    row = rows["siem-source"]
    assert row["auth"] == "own" and row["tls"] == "internal" and row["port"] == 1514
    assert row["port"] == defaults()[P + "agent_port"]
    assert "public_hostname" not in row and "version" not in row and "roles" not in row


def test_the_secrets_are_the_five_the_role_reads_and_nothing_else():
    manifest = ld.load_yaml(MODULE / "module.yml")
    declared = sorted(c["secret"] for c in manifest["credentials"])
    assert len(declared) == 5 and all(s.startswith(f"secret:{MID}/") for s in declared)
    holders = {c["secret"].split("/")[1]: c["holder"] for c in manifest["credentials"]}
    assert holders["enrollment-password"] == "consumers"  # the agents read it by this name
    assert {h for n, h in holders.items() if n != "enrollment-password"} == {"provider"}
    refs = sorted(
        v for k, v in defaults().items() if k.endswith("_ref") and str(v).startswith("secret:")
    )
    assert refs == declared
    text = "".join(p.read_text() for p in MODULE.rglob("*.yml"))
    assert sorted(set(re.findall(r"secret:[a-z0-9/_.-]+", text))) == declared


def test_the_images_are_pinned_and_are_one_release_the_products_version():
    d = defaults()
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    for key in ("manager_image", "indexer_image", "dashboard_image"):
        ref, digest = d[P + key].split("@")
        assert digest.startswith("sha256:") and len(digest) == 71, key
        assert ref.endswith(f":{version}"), key
    # the same release as the agent role's pin: an agent is never newer than its manager
    agent = yaml.safe_load((ROOT / f"ansible/roles/{ROLE}_agent/defaults/main.yml").read_text())
    assert agent[f"{ROLE}_agent_version"] == version


def test_the_slots_are_registered_provisional_and_classified():
    slots = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
    for slot in SLOTS:
        assert slots[slot]["contract"] is None
    assert slots["hot-index"]["export_formats"] == ["jsonl"]


def test_pin_freshness_watches_the_three_images():
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import pin_freshness as pf
    finally:
        sys.path.pop(0)
    ids = {p.id for p in pf.inventory(ROOT)}
    assert {
        f"role:{ROLE}/{P}{k}" for k in ("manager_image", "indexer_image", "dashboard_image")
    } <= ids
    assert pf.check_inventory(pf.inventory(ROOT)) == []


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == f"mod_{ROLE}_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith(f"modules/{MID}/roles/{ROLE}")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {"hnx_module_slice": f"hnx-{ROLE}-server.slice"}


# ----------------------------------------------------------------------------- what the role renders


def test_the_manager_acts_on_no_host():
    conf = role_text("templates", "ossec.conf.j2")
    assert re.search(r"<active-response>\s*<disabled>yes</disabled>", conf)
    assert "<command>" not in conf  # no response command is even defined
    tasks = role_text("tasks", "rules.yml")
    assert (
        "logcollector.remote_commands=0" in tasks and f"{ROLE}_command.remote_commands=0" in tasks
    )


def test_enrolment_needs_the_password_and_the_stack_has_no_demo_accounts():
    conf = role_text("templates", "ossec.conf.j2")
    assert "<use_password>yes</use_password>" in conf
    users = role_text("templates", "internal_users.yml.j2")
    accounts = re.findall(r"^([a-z{][^:]*):$", users, re.M)
    assert accounts == [f"{{{{ {P}indexer_user }}}}", f"{{{{ {P}dashboard_user }}}}"]


def test_the_alert_integration_is_only_rendered_with_a_forwarder_and_reads_its_level():
    conf = role_text("templates", "ossec.conf.j2")
    block = conf[conf.index("{% if " + P + "alert_forward_url") :]
    assert "custom-hnx-alert" in block and P + "alert_forward_level" in block
    assert "<alert_format>json</alert_format>" in block


def test_every_container_runs_with_a_dropped_capability_set_and_no_privilege():
    app = role_text("tasks", "app.yml")
    assert "privileged" not in app and "docker.sock" not in app
    manager = app[app.index("manager:") : app.index("dashboard:")]
    caps = re.search(r"cap_add: \[([A-Z_, ]+)\]", manager).group(1).split(", ")
    assert "SYS_ADMIN" not in caps and "NET_ADMIN" not in caps and "SYS_PTRACE" not in caps


def test_the_healthcheck_of_the_manager_reads_live_processes_not_the_status_command():
    app = role_text("tasks", "app.yml")
    health = role_text("tasks", "health.yml")
    status = f"{MID}-control status"
    assert status not in app and status not in health
    assert "pgrep" in app and "pgrep" in health


def test_published_ports_name_the_guests_address_never_all_interfaces():
    app = role_text("tasks", "app.yml")
    for line in re.findall(r'ports: \[?"?(\{\{[^\n]*)', app):
        assert P + "bind" in line
    assert "0.0.0.0:" not in app


def test_validation_refuses_bad_inputs_by_name():
    text = role_text("tasks", "validate.yml")
    for key in (
        "logical_id",
        "bind",
        "manager_image",
        "syslog_allowed_ips",
        "detection_ids",
        "alert_forward_url",
        "indexer_heap",
    ):
        assert P + key in text, key
    assert f"{P}bind != '0.0.0.0'" in text


def test_the_dashboard_has_no_demo_credential_and_reads_its_password_from_the_secret_env():
    assert "DASHBOARD_PASSWORD" in role_text("tasks", "main.yml")
    assert "DASHBOARD_PASSWORD" not in role_text("tasks", "app.yml")
    assert "kibanaserver" not in role_text("defaults", "main.yml")


def test_the_indexer_heap_is_half_its_container_limit_by_default():
    d = defaults()
    gib = lambda v: int(v[:-1])  # noqa: E731
    assert gib(d[P + "indexer_heap"]) * 2 == gib(d[P + "indexer_mem_limit"])
