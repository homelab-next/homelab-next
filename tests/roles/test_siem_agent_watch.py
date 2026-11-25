# SPDX-License-Identifier: Apache-2.0
"""The siem-agent control's watch configuration (siem_agent_watch): the managed <ossec_config> block
with file-integrity paths and, where the guest has a kernel audit system, the audit log; the
remote-command switches forced to 0; refusal of bad paths; idempotence; the health hook; and the
including role's wiring (the agent restarts once when the configuration changed)."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml
from rolerun import run_role

ROOT = Path(__file__).resolve().parents[2]
ROLES = ROOT / "ansible" / "roles"
ROLE = "siem_agent_watch"
pytestmark = pytest.mark.requires_tool("ansible-playbook")
VENDOR = "<ossec_config>\n  <syscheck><disabled>no</disabled></syscheck>\n</ossec_config>\n"
BLOCK = re.compile(
    r"<!-- BEGIN homelabnext siem-agent -->(.*)<!-- END homelabnext siem-agent -->", re.S
)


def setup(tmp_path, **kw):
    conf = tmp_path / "ossec.conf"
    conf.write_text(VENDOR)
    daemon = tmp_path / "auditd"
    daemon.write_text("")
    return {
        "siem_agent_watch_auditd": "auto",
        "siem_agent_watch_config_file": str(conf),
        "siem_agent_watch_local_options_file": str(tmp_path / "local_internal_options.conf"),
        "siem_agent_watch_auditd_binary": str(daemon),
        "siem_agent_watch_manifest_dir": str(tmp_path / "manifest"),
        **kw,
    }


def managed(conf: Path):
    """The managed block parsed as XML (the whole file must stay well formed, several roots)."""
    text = conf.read_text()
    ET.fromstring(f"<root>{text}</root>")
    m = BLOCK.search(text)
    assert m, text
    return ET.fromstring(f"<root>{m.group(1)}</root>")


def test_fim_paths_and_the_audit_log_are_written_once(tmp_path):
    v = setup(tmp_path)
    conf = Path(v["siem_agent_watch_config_file"])
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    root = managed(conf)
    real = [d.text for d in root.iter("directories") if d.get("realtime") == "yes"]
    sched = [d.text for d in root.iter("directories") if d.get("realtime") is None]
    assert real == [
        "/etc/ssh",
        "/etc/pam.d",
        "/etc/sudoers.d",
        "/etc/audit/rules.d",
        "/etc/cron.d",
        "/etc/systemd/system",
        "/etc/profile.d",
    ]
    assert [i.text for i in root.iter("ignore")] == [
        r"\.dpkg-(new|old|dist|tmp|bak)$",
        r"\.ucf-(new|old|dist)$",
        r"\.swp$",
        "~$",
    ]
    assert all(i.get("type") == "sregex" for i in root.iter("ignore"))
    assert sched == ["/usr/local/bin", "/usr/local/sbin"]
    assert [x.text for x in root.iter("location")] == ["/var/log/audit/audit.log"]
    assert [x.text for x in root.iter("log_format")] == ["audit"]
    text = conf.read_text()
    assert text.startswith(VENDOR) and text.count("BEGIN homelabnext siem-agent") == 1
    again = run_role(tmp_path, ROLE, "main", v)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    assert conf.read_text() == text


def test_the_manager_is_never_allowed_to_run_commands(tmp_path):
    v = setup(tmp_path)
    opts = Path(v["siem_agent_watch_local_options_file"])
    opts.write_text("logcollector.remote_commands=1\nsyscheck.debug=2\n")
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    assert sorted(opts.read_text().splitlines()) == [
        "logcollector.remote_commands=0",
        "sca.remote_commands=0",
        "syscheck.debug=2",
    ]


@pytest.mark.parametrize(
    ("over", "audit"),
    [
        ({}, True),  # auto, audit daemon present, not a container
        ({"siem_agent_watch_auditd": "disabled"}, False),
        ({"siem_agent_watch_auditd_binary": "/nonexistent/auditd"}, False),
        ({"ansible_facts": {"virtualization_type": "lxc"}}, False),
        (
            {"siem_agent_watch_auditd": "enabled", "ansible_facts": {"virtualization_type": "lxc"}},
            True,
        ),
    ],
    ids=["auto-vm", "disabled", "auto-no-daemon", "auto-container", "enabled-forced"],
)
def test_the_audit_log_is_a_source_only_where_the_guest_has_one(tmp_path, over, audit):
    v = setup(tmp_path, **over)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert bool(list(managed(Path(v["siem_agent_watch_config_file"])).iter("localfile"))) is audit
    h = run_role(tmp_path, ROLE, "health", v)
    assert h.returncode == 0, h.stdout + h.stderr  # health agrees with main for every case


@pytest.mark.parametrize(
    "over",
    [
        {"siem_agent_watch_fim_paths": ["/etc/<x>"]},
        {"siem_agent_watch_fim_paths": ["/usr/local/bin</directories><x/>"]},
        {"siem_agent_watch_fim_realtime_paths": ["relative/path"]},
        {"siem_agent_watch_fim_ignore": ["x</ignore><y/>"]},
        {"siem_agent_watch_auditd": "sometimes"},
        {"siem_agent_watch_audit_log": "audit.log"},
    ],
)
def test_bad_paths_and_modes_are_refused_before_the_file_is_touched(tmp_path, over):
    v = setup(tmp_path, **over)
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode != 0, over
    assert Path(v["siem_agent_watch_config_file"]).read_text() == VENDOR


def test_health_fails_on_a_missing_block_and_on_a_switch_turned_on(tmp_path):
    v = setup(tmp_path)
    assert run_role(tmp_path, ROLE, "health", v).returncode != 0  # nothing rendered yet
    assert run_role(tmp_path, ROLE, "main", v).returncode == 0
    assert run_role(tmp_path, ROLE, "health", v).returncode == 0
    opts = Path(v["siem_agent_watch_local_options_file"])
    opts.write_text(opts.read_text().replace("sca.remote_commands=0", "sca.remote_commands=1"))
    assert run_role(tmp_path, ROLE, "health", v).returncode != 0


def test_the_agent_role_includes_the_watch_role_and_restarts_only_on_a_change():
    """Exactly one role (the siem-agent control's) includes the watch role."""
    includers = []
    for main in sorted(ROLES.glob("*/tasks/main.yml")):
        tasks = yaml.safe_load(main.read_text()) or []
        if any(t.get("ansible.builtin.include_role", {}).get("name") == ROLE for t in tasks):
            includers.append((main, tasks))
    ((_, tasks),) = includers
    names = [t["name"] for t in tasks]
    (inc,) = [
        i
        for i, t in enumerate(tasks)
        if t.get("ansible.builtin.include_role", {}).get("name") == ROLE
    ]
    (svc,) = [i for i, t in enumerate(tasks) if "ansible.builtin.systemd_service" in t]
    assert inc < svc, names  # configured before the final enable-and-start
    state = tasks[svc]["ansible.builtin.systemd_service"]["state"]
    assert "restarted" in state and "started" in state and "siem_agent_watch_changed" in state
    assert tasks[inc]["vars"]["siem_agent_watch_auditd"]  # the required input is passed
