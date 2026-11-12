# SPDX-License-Identifier: Apache-2.0
"""The control plane's roles (ansible/playbooks/control_plane.yml; docs/broker.md "Deploying with
Ansible"): hnx_runtime, events_bus, broker and status_hub.

They create system users, install packages and start units, so what runs here is each role's
input validation (every refusal shown failing on a bad input and passing on a good one) and its
templates rendered with the role's own defaults; the install path is proven by
``--syntax-check`` of the playbook and on a real host (the broker scenario,
compose/lab-in-a-box/broker_e2e.py, against the deployed units)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from rolerun import run_cases

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
ROLES = ANSIBLE / "roles"
pytestmark = pytest.mark.requires_tool("ansible-playbook")
SHA = "a" * 64
HUB_ADDR = "198.51.100.7"  # no-raw-endpoint: allow a documentation address the hub binds under test
LOOP = "127.0.0.1"  # no-raw-endpoint: allow loopback, what the bus and the hub may bind
PLAIN_REMOTE_BUS = "nats://events.lab.example:4222"  # no-raw-endpoint: allow the refused endpoint

RUNTIME = {
    "hnx_runtime_wheel": "/srv/dist/homelabnext-0.1.0-py3-none-any.whl",
    "hnx_runtime_wheel_sha256": SHA,
    "hnx_runtime_constraints": str(ROOT / "constraints/ci.txt"),
    "hnx_runtime_bootstrap": str(ROOT / "constraints/bootstrap.txt"),
}
BUS_USERS = [
    {"user": "hnx-broker", "password_ref": "secret:events/broker",
     "publish": ["lab.homelabnext.decision.>", "$JS.API.STREAM.INFO.LAB"],
     "subscribe": ["_INBOX.hnx-broker.>"]},
    {"user": "hnx-events-admin", "password_ref": "secret:events/admin",
     "publish": ["$JS.API.STREAM.CREATE.LAB"], "subscribe": ["_INBOX.hnx-events-admin.>"]},
]  # fmt: skip
EVENTS = {
    "events_bus_logical_id": "events",
    "events_bus_archive_url": "https://releases.example.internal/nats-server-v2.15.1-linux-amd64.tar.gz",
    "events_bus_archive_sha256": SHA,
    "events_bus_users": BUS_USERS,
    "events_bus_streams": [{"name": "LAB", "subject_prefix": "lab", "max_bytes": 1048576}],
    "events_bus_admin_user": "hnx-events-admin",
    "events_bus_admin_password_ref": "secret:events/admin",
}
BROKER = {
    "broker_logical_id": "broker",
    "broker_manifest": str(ROOT / "examples/broker/manifest.production.yml"),
    "broker_handlers": [
        str(p) for p in sorted((ROOT / "examples/broker/handlers").glob("service-*"))
    ],
    "broker_client_users": ["hnx-agent-triage", "hnx-hub"],
    "broker_secret_refs": {"DEMO_API_TOKEN": "secret:broker/demo-api-token"},
    "broker_relay_events_endpoint": "nats://127.0.0.1:4222",  # no-raw-endpoint: allow loopback bus under test
    "broker_relay_password_ref": "secret:events/broker",
    "broker_relay_stream": "LAB",
    "broker_relay_subject_prefix": "lab",
}
HUB = {
    "status_hub_logical_id": "status-hub",
    "status_hub_registry": str(ROOT / "examples/services.yml"),
    "status_hub_bind_address": HUB_ADDR,
    "status_hub_allowed_hosts": ["status.lab.example"],
    "status_hub_secret_refs": [
        "secret:status/front-door-secret",
        "secret:status/approvals-csrf-secret",
    ],
    "status_hub_approvals_socket": "/run/hnx-broker/broker.sock",
    "status_hub_approvals_csrf_key_ref": "secret:status/approvals-csrf-secret",
    "status_hub_public_origin": "https://status.lab.example",
}


def _refusals(tmp_path, role, good, bad):
    results = run_cases(tmp_path, role, "validate", good, [{}, *bad], parallel=True)
    assert results[0] == (False, results[0][1]), results[0]
    refused = [failed for failed, _ in results[1:]]
    assert all(refused), [b for b, r in zip(bad, refused, strict=True) if not r]


def test_hnx_runtime_refuses_bad_inputs(tmp_path):
    _refusals(tmp_path, "hnx_runtime", RUNTIME, [
        {"hnx_runtime_wheel_sha256": "abc"},
        {"hnx_runtime_wheel": "/srv/dist/evil.whl"},
        {"hnx_runtime_extras": ["core]; rm"]},
        {"hnx_runtime_prefix": "/opt/../etc"},
        {"hnx_runtime_source_commit": "main"},
    ])  # fmt: skip


def test_events_bus_refuses_bad_inputs(tmp_path):
    wide = [dict(BUS_USERS[0], publish=["$JS.API.>"]), BUS_USERS[1]]
    inbox = [dict(BUS_USERS[0], subscribe=["_INBOX.>"]), BUS_USERS[1]]
    _refusals(tmp_path, "events_bus", EVENTS, [
        {"events_bus_listen_address": "0.0.0.0"},  # no-raw-endpoint: allow the refused wildcard
        {"events_bus_archive_url": "http://releases.example.internal/nats-server-v2.15.1-linux-amd64.tar.gz"},
        {"events_bus_archive_url": "https://releases.example.internal/nats-server-v2.14.0-linux-amd64.tar.gz"},
        {"events_bus_archive_sha256": "0"},
        {"events_bus_users": wide},
        {"events_bus_users": inbox},
        {"events_bus_users": [dict(BUS_USERS[0], password_ref="hunter2")]},
        {"events_bus_admin_user": "nobody"},
        {"events_bus_streams": [{"name": "lab", "subject_prefix": "lab", "max_bytes": 1}]},
    ])  # fmt: skip


def test_broker_refuses_bad_inputs(tmp_path):
    _refusals(tmp_path, "broker", BROKER, [
        # a password over plaintext to another host
        {"broker_relay_events_endpoint": PLAIN_REMOTE_BUS},
        {"broker_socket_mode": "666"},
        {"broker_socket_dir": "/tmp/hnx-broker"},
        {"broker_clients_group": "hnx-broker"},
        {"broker_client_users": ["root"]},
        {"broker_secret_refs": {"TOKEN": "a-literal-value"}},
        {"broker_approvals_url": "http://status.lab.example/approvals"},
        {"broker_relay_stream": "lab"},
        {"broker_handlers": ["/x/a.sh", "/y/a.sh"]},
    ])  # fmt: skip


def test_status_hub_refuses_bad_inputs(tmp_path):
    _refusals(tmp_path, "status_hub", HUB, [
        {"status_hub_bind_address": "0.0.0.0"},  # no-raw-endpoint: allow the refused wildcard
        {"status_hub_allowed_hosts": []},  # off loopback without a host name
        {"status_hub_public_origin": "http://status.lab.example"},
        {"status_hub_approvals_csrf_key_ref": "secret:status/not-delivered"},
        {"status_hub_secret_refs": ["plain"]},
        {"status_hub_title": "a\nExecStart=/bin/sh"},
    ])  # fmt: skip


# ---------------------------------------------------------------- the rendered files
def _render(tmp_path, role, extra):
    """Every template of ``role`` rendered with its defaults, vars and ``extra``."""
    defaults = yaml.safe_load((ROLES / role / "defaults/main.yml").read_text())
    fixed = ROLES / role / "vars/main.yml"
    vars_ = {**defaults, **(yaml.safe_load(fixed.read_text()) if fixed.is_file() else {}), **extra}
    out = tmp_path / role
    out.mkdir()
    play = [{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"inventory_hostname_short": "host"},
        "tasks": [{"ansible.builtin.copy": {
            "dest": f"{out}/{{{{ (item | basename)[:-3] }}}}",
            "content": "{{ lookup('template', item) }}"},
            "loop": [str(p) for p in sorted((ROLES / role / "templates").glob("*.j2"))]}],
    }]  # fmt: skip
    (tmp_path / "play.yml").write_text(yaml.safe_dump(play))
    (tmp_path / "vars.json").write_text(
        json.dumps({"ansible_python_interpreter": sys.executable, **vars_})
    )
    r = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", f"@{tmp_path / 'vars.json'}", str(tmp_path / "play.yml")],
        capture_output=True, text=True, cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin:" + str(Path(sys.executable).parent), "ANSIBLE_CONFIG": str(ANSIBLE / "ansible.cfg"),
             "ANSIBLE_HOME": str(tmp_path / ".ansible"), "ANSIBLE_NOCOLOR": "1"},
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    return {p.name: p.read_text() for p in out.iterdir()}


def _directives(unit: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in unit.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out.setdefault(k, []).append(v)
    return out


def test_broker_units_keep_the_socket_and_the_outbox_reachable(tmp_path):
    files = _render(tmp_path, "broker", {**BROKER, "broker_runtime_release": "1234123412341234"})
    unit = _directives(files["hnx-broker.service"])
    # systemd resets an exec directory to User:Group for every command it starts: a chgrp in
    # ExecStartPre is undone, so the role makes the directories and the unit names none
    assert not {"RuntimeDirectory", "StateDirectory", "ExecStartPre"} & set(unit)
    # outbox files are opened 0640 for the relay's group: a stricter umask makes them unreadable
    assert unit["UMask"] == ["0027"]
    # --socket-group chowns the socket: @chown must stay allowed
    assert "~@privileged" not in " ".join(unit["SystemCallFilter"])
    assert unit["PrivateNetwork"] == ["yes"] and unit["RestrictAddressFamilies"] == ["AF_UNIX"]
    assert "/run/hnx-broker" in unit["ReadWritePaths"][0]
    assert "HNX_RUNTIME_RELEASE=1234123412341234" in unit["Environment"]
    relay = _directives(files["hnx-broker-relay.service"])
    assert relay["User"] == ["hnx-broker-relay"]
    assert relay["ReadOnlyPaths"] == ["/var/lib/hnx-broker/state/outbox"]
    assert relay["InaccessiblePaths"] == ["-/srv/agents -/run/hnx-broker"]
    target = yaml.safe_load(files["events-target.yml"])
    config = target["capabilities"]["events"]["config"]
    assert config["password_secret"] == "secret:events/broker" and "password" not in config


def test_broker_unit_gets_a_network_only_when_asked(tmp_path):
    files = _render(tmp_path, "broker", {**BROKER, "broker_network": True, "broker_relay": False})
    unit = _directives(files["hnx-broker.service"])
    assert "PrivateNetwork" not in unit
    assert unit["RestrictAddressFamilies"] == ["AF_UNIX AF_INET AF_INET6"]


def test_status_hub_renders_agents_and_views_its_schemas_accept(tmp_path):

    files = _render(tmp_path, "status_hub", HUB)
    unit = _directives(files["hnx-hub.service"])
    argv = unit["ExecStart"][0].split()
    assert argv[argv.index("--bind") + 1] == HUB_ADDR and "--allow-remote" in argv
    assert argv[argv.index("--allowed-host") + 1] == "status.lab.example"
    assert unit["SupplementaryGroups"] == ["hnx-broker-clients"]
    agents = yaml.safe_load(files["agents.yml"])
    assert agents["approvals"]["csrf_key"] == "secret:status/approvals-csrf-secret"
    assert agents["private"] == {"service": "status-hub", "access_log": "access.jsonl"}
    views = yaml.safe_load(files["views.yml"])
    assert {"id": "approvals", "title": "Approvals", "panel": "approvals", "group": "private",
            "tlp": "red"} in views["menu"]  # fmt: skip
    import jsonschema

    for name, schema in (("agents", "agents"), ("views", "views")):
        doc = yaml.safe_load(files[f"{name}.yml"])
        jsonschema.validate(
            doc, json.loads((ROOT / f"schemas/status/{schema}.schema.json").read_text())
        )


def test_status_hub_on_loopback_needs_no_remote_flag(tmp_path):
    files = _render(tmp_path, "status_hub", {**HUB, "status_hub_bind_address": LOOP,
                                             "status_hub_approvals_socket": ""})  # fmt: skip
    unit = _directives(files["hnx-hub.service"])
    assert "--allow-remote" not in unit["ExecStart"][0] and "SupplementaryGroups" not in unit
    assert "approvals" not in yaml.safe_load(files["agents.yml"])


def test_events_bus_config_grants_each_user_its_allow_lists_only(tmp_path):
    users = [{"user": u["user"], "password_hash": "$2a$11$" + "x" * 53, "publish": u["publish"],
              "subscribe": u["subscribe"]} for u in BUS_USERS]  # fmt: skip
    files = _render(tmp_path, "events_bus", {**EVENTS, "events_bus_rendered_users": users,
                                             "inventory_hostname": "bus-01.example.internal"})  # fmt: skip
    text = "\n".join(
        line for line in files["nats.conf"].splitlines() if not line.lstrip().startswith("#")
    )
    conf = json.loads(text)
    assert conf["listen"].startswith(LOOP + ":") and conf["http"].startswith(LOOP + ":")
    got = conf["accounts"]["HNX"]["users"]
    assert [set(u) for u in got] == [{"user", "password", "permissions"}] * 2
    assert got[0]["permissions"] == {"publish": {"allow": BUS_USERS[0]["publish"]},
                                     "subscribe": {"allow": BUS_USERS[0]["subscribe"]}}  # fmt: skip
    assert all(u["password"].startswith("$2a$") for u in got)
    unit = _directives(files["hnx-events.service"])
    assert unit["User"] == ["hnx-events"] and unit["ReadWritePaths"] == ["/var/lib/hnx-events"]


def test_the_playbook_parses_and_targets_capability_groups():
    r = subprocess.run(
        ["ansible-playbook", "--syntax-check", "-i", str(ANSIBLE / "inventory/example/hosts.yml"),
         str(ANSIBLE / "playbooks/control_plane.yml")],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin:" + str(Path(sys.executable).parent),
                                             "ANSIBLE_CONFIG": str(ANSIBLE / "ansible.cfg")},
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
