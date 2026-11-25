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
import subprocess
import sys
from pathlib import Path

import pytest
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


def test_the_generic_json_decoder_is_excluded_only_when_the_site_asks():
    conf = role_text("templates", "ossec.conf.j2")
    block = re.search(
        r"\{% if " + P + r"json_exclude_effective \| bool %\}\s*"
        r"<decoder_exclude>ruleset/decoders/0006-json_decoders\.xml</decoder_exclude>\s*\{% endif %\}",
        conf,
    )
    assert block, "the exclusion must be conditional on the variable"
    assert conf.index(block.group(0)) > conf.index("<decoder_dir>ruleset/decoders</decoder_dir>")
    assert re.search(rf"^{P}json_decoder_excluded: false$", role_text("defaults", "main.yml"), re.M)


def _task_names(*parts: str) -> list[str]:
    return [t["name"] for t in yaml.safe_load(role_text(*parts)) if "name" in t]


def test_the_json_decoder_exclusion_waits_for_the_replacement_on_a_first_install():
    """First start: the product's decoder file excluded with no replacement makes the manager refuse
    its rules and never become healthy, so the render must hold the exclusion back until the site's
    native decoders are in, and the role applies it (one restart) after they are installed."""
    conf = role_text("templates", "ossec.conf.j2")
    assert P + "json_exclude_effective | bool" in conf
    assert P + "json_decoder_excluded" not in conf, "the template must read the effective value"
    cfg = role_text("tasks", "config.yml")
    decide = cfg.index(f"{P}json_exclude_effective:")
    assert cfg.index("json_decoder.yml") < decide < cfg.index("src: ossec.conf.j2")
    assert f"{P}json_decoder_excluded | bool and {P}json_native_present | bool" in cfg
    main = role_text("tasks", "main.yml")
    loaded = (
        main.index("tasks: rules.yml") if "tasks: rules.yml" in main else main.index("rules.yml")
    )
    applied = main.index("Apply the json decoder exclusion")
    assert loaded < applied < main.index("retention.yml")
    block = main[applied : main.index("retention.yml")]
    assert "not ansible_check_mode" in block and f"not {P}json_exclude_effective" in block
    assert "restart, manager" in block and "probe.yml" in block
    # the refusal comes before the exclusion is ever rendered
    assert main.index("Refuse to exclude the product") < applied


def test_the_native_json_decoder_probe_finds_only_a_replacement_in_the_manager(tmp_path):
    from tests.roles.rolerun import run_role

    def probe(data_root: Path):
        out = run_role(
            tmp_path,
            ROLE,
            "json_decoder",
            {P + "data_root": str(data_root)},
            env={"ANSIBLE_ROLES_PATH": str(MODULE / "roles")},
            verbose=True,
        )
        assert out.returncode == 0, out.stdout + out.stderr
        return out.stdout

    root = tmp_path / "data"
    assert f'"{P}json_native_present": false' in probe(root)  # no etc yet
    decoders = root / "manager" / "etc" / "decoders"
    decoders.mkdir(parents=True)
    (decoders / "0006-json_decoders.xml").write_text('<decoder name="json"></decoder>\n')
    (decoders / "hnx-other.xml").write_text('<decoder name="json-other"></decoder>\n')
    assert f'"{P}json_native_present": false' in probe(
        root
    )  # the product's own file is no replacement
    (decoders / "hnx-zjson.xml").write_text('<decoder name="json">\n</decoder>\n')
    assert f'"{P}json_native_present": true' in probe(root)


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


def test_the_sigma_lane_is_proved_and_compiled_on_the_controller_and_loads_after_the_native_files():
    """docs/detections.md, "The Sigma lane on the engine": each root is linted, its fixtures run
    (reference and compiled), its det map checked, then compiled; a bundle that cannot be built fails
    the deploy, and it loads as zz-sigma-<n>.xml, after every native file (a rule's parent first),
    through the same configuration test and rollback as the native files."""
    d = defaults()
    assert d[P + "sigma_roots"] == [] and d[P + "hnx_cli"] == ["hnx"]
    tasks = yaml.safe_load(role_text("tasks", "rules.yml"))
    block = next(t for t in tasks if "block" in t and "Sigma" in t["name"])
    assert block["when"] == f"{P}sigma_roots | length > 0"
    assert block["delegate_to"] == "localhost" and block["check_mode"] is False
    prove, comp = block["block"][1], block["block"][2]
    assert (
        "product(['lint', 'run', 'map'])" in prove["loop"]
        and "'--check'" in prove["ansible.builtin.command"]["argv"]
    )
    assert (
        "'compile'" in comp["ansible.builtin.command"]["argv"]
        and "'--out'" in comp["ansible.builtin.command"]["argv"]
    )
    assert "failed_when" not in comp and "ignore_errors" not in comp
    text = role_text("tasks", "rules.yml")
    assert "rules/zz-sigma-" in text
    names = [t["name"] for t in tasks]
    assert names.index("Stage the compiled Sigma bundles") < names.index(
        "Test, load and restart (the previous set comes back when either fails)"
    )
    v = role_text("tasks", "validate.yml")
    assert f"{P}sigma_roots | reject('match', {P}path_pattern)" in v
    assert f"{P}hnx_cli is sequence" in v


def _sigma_play(tmp_path, roots: list[str]) -> subprocess.CompletedProcess:
    """The role's Sigma tasks (the controller block, the wanted list, the name check) run for
    real with a stand-in hnx that writes the bundle compile names; then every staged source the
    stage task would copy must exist on the controller."""
    import json
    import stat

    tasks = yaml.safe_load(role_text("tasks", "rules.yml"))
    i = next(n for n, t in enumerate(tasks) if "block" in t and "Sigma" in t["name"])
    picked = tasks[i : i + 3]  # the block, the wanted list, the reserved-name check
    fake = tmp_path / "hnx"
    log = tmp_path / "calls.jsonl"
    fake.write_text(
        "#!/usr/bin/env python3\nimport json, sys\n"
        f"open({str(log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "a = sys.argv[1:]\n"
        "if 'compile' in a: open(a[a.index('--out') + 1], 'w').write('<group/>')\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    check = {
        "name": "every bundle the stage task copies exists",
        "ansible.builtin.assert": {
            "that": [
                "(" + P + "sigma_scratch.path ~ '/' ~ (item | basename)) is file",
                "item is match('^rules/zz-sigma-[0-9]+[.]xml$')",
            ]
        },
        "loop": "{{ " + P + "sigma_wanted }}",
    }
    play = [{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {P + "sigma_roots": roots, P + "hnx_cli": [str(fake)],
                 P + "native_wanted": ["rules/native-one.xml"]},
        "tasks": [*picked, check, {"ansible.builtin.debug": {"var": P + "sigma_wanted"}}],
    }]  # fmt: skip
    (tmp_path / "p.yml").write_text(yaml.safe_dump(play))
    r = subprocess.run(["ansible-playbook", "-i", "localhost,", str(tmp_path / "p.yml")],
                       capture_output=True, text=True, cwd=tmp_path)  # fmt: skip
    r.calls = [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    return r


@pytest.mark.requires_tool("ansible-playbook")
def test_the_sigma_bundles_are_compiled_to_the_names_the_stage_task_copies(tmp_path):
    roots = [str(tmp_path / "a" / "detections"), str(tmp_path / "b" / "detections")]
    r = _sigma_play(tmp_path, roots)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "rules/zz-sigma-0.xml" in r.stdout and "rules/zz-sigma-1.xml" in r.stdout
    assert sorted((c[2], c[3]) for c in r.calls) == sorted(
        (root, verb) for root in roots for verb in ("lint", "run", "map", "compile")
    )


# ----------------------------------------------------------------------------- liveness and pid files


def _liveness():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "liveness", ROLE_DIR / "files" / f"hnx_{MID}_liveness.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_managers_pid_directory_is_a_tmpfs_so_no_pid_file_survives_a_hard_reset():
    manager = role_text("tasks", "app.yml")
    manager = manager[manager.index("manager:") : manager.index("dashboard:")]
    assert re.search(r"tmpfs:\s*\n\s*- \{target: /var/ossec/var/run,", manager)
    # nothing but the one pid directory is a tmpfs: the state under it is not lost on a restart
    assert manager.count("target:") == 1


def test_the_liveness_metrics_say_which_daemon_is_down_and_a_missing_stream_is_stale():
    mod = _liveness()
    up = dict.fromkeys(mod.DAEMONS, True)
    up[f"{MID}-db"] = False
    text = mod.render(up, 30.4, 1000.0)
    assert 'siem_manager_daemon_up{daemon="' + f"{MID}-db" + '"} 0' in text
    assert f"siem_manager_daemons_expected {len(up)}" in text
    assert f"siem_manager_daemons_running {len(up) - 1}" in text
    assert "siem_alerts_file_age_seconds 30" in text and "siem_alerts_file_present 1" in text
    missing = mod.render(up, None, 1000.0)
    assert "siem_alerts_file_present 0" in missing
    assert f"siem_alerts_file_age_seconds {mod.ABSENT_AGE}" in missing


def test_the_liveness_writer_reads_the_stream_age_and_refuses_an_unsafe_output(tmp_path):
    mod = _liveness()
    f = tmp_path / "alerts.json"
    f.write_text("{}")
    assert mod.alerts_age(f, f.stat().st_mtime + 90) == pytest.approx(90)
    assert mod.alerts_age(tmp_path / "none.json", 1.0) is None
    out = tmp_path / "text" / "siem_manager.prom"
    out.parent.mkdir()
    mod.write_atomic(out, "a 1\n")
    assert out.read_text() == "a 1\n" and not list(out.parent.glob(".hnx-liveness-*"))
    assert (out.stat().st_mode & 0o777) == 0o640  # never world-readable
    with pytest.raises(ValueError):
        mod.write_atomic(Path("/x.prom"), "a 1\n")
    with pytest.raises(ValueError):
        mod.write_atomic(out.with_suffix(".txt"), "a 1\n")


def test_health_fails_on_a_stale_alert_stream_and_the_timer_is_wired_to_the_textfile_dir():
    health = role_text("tasks", "health.yml")
    assert "alerts/alerts.json" in health and P + "alerts_max_age_seconds" in health
    assert P + "textfile_dir" in role_text("tasks", "main.yml")
    unit = role_text("templates", f"hnx-{MID}-liveness.service.j2")
    assert P + "textfile_dir" in unit and "alerts/alerts.json" in unit
    d = defaults()
    assert d[P + "alerts_max_age_seconds"] >= 120 and d[P + "textfile_dir"].startswith("/")
