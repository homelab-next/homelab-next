# SPDX-License-Identifier: Apache-2.0
"""The control plane's roles (ansible/playbooks/control_plane.yml; docs/broker.md "Deploying with
Ansible"): hnx_runtime, events_bus, broker and status_hub.

They create system users, install packages and start units, so what runs here is each role's
input validation (every refusal shown failing on a bad input and passing on a good one) and its
templates rendered with the role's own defaults; the install path is proven by
``--syntax-check`` of the playbook and on a real host (the broker scenario,
compose/lab-in-a-box/broker_e2e.py, against the deployed units)."""

import grp
import hashlib
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_cases, run_role

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
ROLES = ANSIBLE / "roles"
pytestmark = pytest.mark.requires_tool("ansible-playbook")
SHA = "a" * 64
HUB_ADDR = "198.51.100.7"  # no-raw-endpoint: allow a documentation address the hub binds under test
LOOP = "127.0.0.1"  # no-raw-endpoint: allow loopback, what the bus and the hub may bind
PLAIN_REMOTE_BUS = "nats://events.lab.example:4222"  # no-raw-endpoint: allow the refused endpoint
NAMED_LOOP_BUS = "nats://localhost:4222"  # no-raw-endpoint: allow refused, a name is not an address
LOOKALIKE_BUS = "nats://127.0.0.1.10:4222"  # no-raw-endpoint: allow refused, not an address
V6_OTHER_BUS = "nats://[::2]:4222"  # no-raw-endpoint: allow refused, not loopback
V6_LOOP_BUS = "nats://[::1]:4222"  # no-raw-endpoint: allow the IPv6 loopback bus
TLS_BUS = "tls://events.lab.example:4222"  # no-raw-endpoint: allow a remote bus over TLS
REGISTRY = ANSIBLE / "inventory/example/registry.yml"

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
#: a pull durable for the bridge (events_bus_durables) and the users that go with it: the bridge
#: holds its INFO, MSG.NEXT and acks; the provisioner its INFO and filtered CREATE
DURABLE = {"stream": "LAB", "durable": "bridge-x", "user": "hnx-bus-bridge",
           "filter": "lab.homelabnext.decision.returned", "ack_wait": 30, "max_deliver": 5}  # fmt: skip
BRIDGE_USER = {"user": "hnx-bus-bridge", "password_ref": "secret:events/bus-bridge",
               "publish": ["$JS.API.STREAM.INFO.LAB",
                           "$JS.API.CONSUMER.INFO.LAB.bridge-x",
                           "$JS.API.CONSUMER.MSG.NEXT.LAB.bridge-x",
                           "$JS.ACK.LAB.bridge-x.*.*.*.*.*",
                           "$JS.ACK._.hKkTAyOX.LAB.bridge-x.*.*.*.*.>"],
               "subscribe": ["_INBOX.hnx-bus-bridge.>"]}  # fmt: skip
PROVISIONER = dict(BUS_USERS[1], publish=[
    *BUS_USERS[1]["publish"], "$JS.API.CONSUMER.INFO.LAB.bridge-x",
    "$JS.API.CONSUMER.CREATE.LAB.bridge-x.lab.homelabnext.decision.returned"])  # fmt: skip
BRIDGE_CASE = {"events_bus_users": [BUS_USERS[0], PROVISIONER, BRIDGE_USER],
               "events_bus_durables": [DURABLE]}  # fmt: skip
PRODUCTION_MANIFEST = ROOT / "examples/broker/manifest.production.yml"


def _manifest(tmp_path, manifest_id, builtin_only=False):
    """The example production manifest under another id (``-proof``: the stand-in handlers may be
    deployed while handlers share the broker's uid), optionally with its exec actions removed."""
    doc = yaml.safe_load(PRODUCTION_MANIFEST.read_text())
    doc["manifest_id"] = manifest_id
    if builtin_only:
        doc["actions"] = [a for a in doc["actions"] if a["handler"].startswith("builtin/")]
        doc.pop("handler_docs", None)
    path = tmp_path / f"{manifest_id}.yml"
    path.write_text(yaml.safe_dump(doc))
    return str(path)


BROKER = {
    "broker_logical_id": "broker",
    "broker_manifest": str(PRODUCTION_MANIFEST),
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
    def broker_grant(**kw):
        return [dict(BUS_USERS[0], **kw), BUS_USERS[1]]

    _refusals(tmp_path, "events_bus", EVENTS, [
        {"events_bus_listen_address": "0.0.0.0"},  # no-raw-endpoint: allow the refused wildcard
        # loopback only until the role has a TLS listener (a password would cross the wire)
        {"events_bus_listen_address": HUB_ADDR},
        {"events_bus_archive_url": "http://releases.example.internal/nats-server-v2.15.1-linux-amd64.tar.gz"},
        {"events_bus_archive_url": "https://releases.example.internal/nats-server-v2.14.0-linux-amd64.tar.gz"},
        {"events_bus_archive_sha256": "0"},
        # the subject ceiling, token by token (not only the literal spellings)
        {"events_bus_users": broker_grant(publish=["$JS.API.>"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.*.>"])},
        {"events_bus_users": broker_grant(publish=["$JS.>"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.STREAM.>"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.STREAM.PURGE.LAB"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.STREAM.DELETE.*"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.STREAM.UPDATE.LAB"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.STREAM.MSG.DELETE.LAB"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.STREAM.*.LAB"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.STREAM.MSG.*.LAB"])},
        {"events_bus_users": broker_grant(publish=[">"])},
        {"events_bus_users": broker_grant(publish=["*.homelabnext.decision.>"])},
        {"events_bus_users": broker_grant(subscribe=["$SYS.>"])},
        {"events_bus_users": broker_grant(subscribe=["$SYS.ACCOUNT.*.CONNECT"])},
        {"events_bus_users": broker_grant(subscribe=["_INBOX.>"])},
        {"events_bus_users": broker_grant(subscribe=["_INBOX.*"])},
        {"events_bus_users": broker_grant(subscribe=["_INBOX.*.>"])},
        {"events_bus_users": broker_grant(subscribe=["_INBOX.hnx-events-admin.>"])},
        {"events_bus_users": broker_grant(subscribe=["_INBOX.hnx-broker"])},
        {"events_bus_users": broker_grant(publish=["lab..decision"])},
        {"events_bus_users": broker_grant(publish=["lab.>.decision"])},
        {"events_bus_users": [dict(BUS_USERS[0], password_ref="hunter2")]},
        # an allow-list, not a deny-list, under $JS/$KV/$O: nothing but the named-stream calls
        {"events_bus_users": broker_grant(publish=["$JS.API.CONSUMER.DELETE.LAB.bridge-x"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.STREAM.CREATE.LAB"])},  # not the admin
        {"events_bus_users": broker_grant(publish=["$JS.API.STREAM.SNAPSHOT.LAB"])},
        {"events_bus_users": broker_grant(publish=["$JS.API.CONSUMER.MSG.NEXT.LAB.*"])},
        {"events_bus_users": broker_grant(publish=["$KV.>"])},
        {"events_bus_users": broker_grant(publish=["$O.store.>"])},
        {"events_bus_users": [BUS_USERS[0], dict(BUS_USERS[1], publish=["$JS.API.STREAM.DELETE.LAB"])]},
        # NATS reads an empty publish allow-list as no restriction: refused unless subscribe-only
        {"events_bus_users": broker_grant(publish=[])},
        {"events_bus_users": [{k: v for k, v in BUS_USERS[0].items() if k != "publish"}, BUS_USERS[1]]},
        {"events_bus_users": broker_grant(subscribe_only=True)},  # but it publishes
        {"events_bus_users": broker_grant(publish=[], subscribe_only="yes")},
        {"events_bus_admin_user": "nobody"},
        {"events_bus_streams": [{"name": "lab", "subject_prefix": "lab", "max_bytes": 1}]},
        # round 4: a consumer create is the provisioner's alone (it can push the stream to any
        # subject), no one holds STREAM.UPDATE (it deletes by shrinking), acks are exact
        {"events_bus_users": broker_grant(publish=["$JS.API.CONSUMER.CREATE.LAB.bridge-x.lab.x"])},
        {"events_bus_users": [BUS_USERS[0], dict(BUS_USERS[1], publish=["$JS.API.STREAM.UPDATE.LAB"])]},
        # a consumer grant on a durable not declared for that user (two users naming one, the
        # other create forms, NAMES and loose acks: tests/roles/test_hnx_bus_filter.py)
        {"events_bus_users": broker_grant(publish=["$JS.API.CONSUMER.MSG.NEXT.LAB.bridge-x"])},
        # a push durable (a deliver_subject)
        {**BRIDGE_CASE, "events_bus_durables": [dict(DURABLE, deliver_subject="_INBOX.hnx-broker.x")]},
        # provisioning a durable needs the provisioner's INFO and filtered CREATE of it
        {**BRIDGE_CASE, "events_bus_provision_durables": True,
         "events_bus_users": [*BRIDGE_CASE["events_bus_users"][:1], BUS_USERS[1],
                              BRIDGE_CASE["events_bus_users"][2]]},
        # a boolean, not a string that merely reads as one
        {**BRIDGE_CASE, "events_bus_provision_durables": "yes"},
        # round 5: a client lives in an account of its own and subscribes to its own replies
        # alone (it reads the stream through a durable); MSG.GET reads every stored message (the
        # provisioner's alone); a v2 ack names the domain "_" and the account's 8-character hash
        {"events_bus_users": [BUS_USERS[0], BUS_USERS[1], dict(READER, subscribe=[
            "lab.homelabnext.decision.>", "_INBOX.hnx-reader.>"])]},
        {**BRIDGE_CASE, "events_bus_users": [BUS_USERS[0], PROVISIONER, dict(BRIDGE_USER, publish=[
            *BRIDGE_USER["publish"], "$JS.API.STREAM.MSG.GET.LAB"])]},
        {**BRIDGE_CASE, "events_bus_users": [BUS_USERS[0], PROVISIONER, dict(BRIDGE_USER, publish=[
            *BRIDGE_USER["publish"][:-1], "$JS.ACK.dom.hKkTAyOX.LAB.bridge-x.*.*.*.*.>"])]},
        # round 6: the v2 ack hash is the bus account's own (another account's, any other)
        {**BRIDGE_CASE, "events_bus_users": [BUS_USERS[0], PROVISIONER, dict(BRIDGE_USER, publish=[
            *BRIDGE_USER["publish"][:-1], "$JS.ACK._.ABCDEFGH.LAB.bridge-x.*.*.*.*.>"])]},
        {**BRIDGE_CASE, "events_bus_account": "OTHER"},  # hKkTAyOX is HNX's, not OTHER's
        # a client that publishes nothing receives nothing (it subscribes to its own _INBOX)
        {"events_bus_users": [*BUS_USERS, READER]},
        # a client's grants: under a declared stream's prefix, no server _ subject
        {"events_bus_users": broker_grant(publish=["other.homelabnext.decision.>"])},
        {"events_bus_users": broker_grant(publish=["lab.homelabnext.decision.>", "_R_.x.>"])},
        # the provisioner neither pulls nor acks (it lives in the JetStream account)
        {**BRIDGE_CASE, "events_bus_users": [BUS_USERS[0], dict(PROVISIONER, publish=[
            *PROVISIONER["publish"], "$JS.API.CONSUMER.MSG.NEXT.LAB.bridge-x"]), BRIDGE_USER]},
        # the monitor: a name of its own (not one of the users) and a secret: reference
        {"events_bus_monitor_user": "hnx-broker", "events_bus_monitor_password_ref": "secret:events/w"},
        {"events_bus_monitor_user": "hnx-watch"},
        {"events_bus_monitor_user": "Bad Name", "events_bus_monitor_password_ref": "secret:events/w"},
    ])  # fmt: skip


def test_events_bus_accepts_the_narrow_grants_a_bridge_needs(tmp_path):
    """Single JetStream calls inside the refused sets stay allowed: the ceiling refuses reach, not
    the API's prefix (the StackStorm bridge's grants in docs/broker.md), with its durable declared
    for it; the provisioner may create and delete a named durable."""
    admin = dict(PROVISIONER, publish=[*PROVISIONER["publish"],
                                       "$JS.API.CONSUMER.DELETE.LAB.e2e-scratch"])  # fmt: skip
    results = run_cases(tmp_path, "events_bus", "validate", EVENTS, [
        BRIDGE_CASE,
        {**BRIDGE_CASE, "events_bus_provision_durables": True},
        {**BRIDGE_CASE, "events_bus_users": [BUS_USERS[0], admin, BRIDGE_USER],
         "events_bus_monitor_user": "hnx-watch",
         "events_bus_monitor_password_ref": "secret:events/watch"},
    ])  # fmt: skip
    assert results == [(False, "")] * 3, results


def _here_registry(tmp_path) -> str:
    """The example registry with the events bus on the host the tests run the role on
    (``localhost``): a loopback relay endpoint is accepted only when the bus is this host's."""
    doc = yaml.safe_load(REGISTRY.read_text())
    doc["services"]["events"]["host"] = "localhost"
    path = tmp_path / "registry-here.yml"
    path.write_text(yaml.safe_dump(doc))
    return str(path)


def test_broker_refuses_bad_inputs(tmp_path):
    proof = {**BROKER, "broker_manifest": _manifest(tmp_path, "lab-broker-proof"),
             "hnx_registry_file": _here_registry(tmp_path)}  # fmt: skip
    _refusals(tmp_path, "broker", proof, [
        # a password over plaintext to another host
        {"broker_relay_events_endpoint": PLAIN_REMOTE_BUS},
        # loopback is an address the bus role calls loopback, never a name or a look-alike
        {"broker_relay_events_endpoint": NAMED_LOOP_BUS},
        {"broker_relay_events_endpoint": LOOKALIKE_BUS},
        {"broker_relay_events_endpoint": V6_OTHER_BUS},
        # a loopback endpoint while the registry puts the bus on another host, or another port
        {"hnx_registry_file": str(REGISTRY)},
        {"broker_relay_events_endpoint": f"nats://{LOOP}:4223"},  # not the row's port
        # the bus by its registry id: a row that is not the events capability
        {"broker_relay_events_id": "query-core"},
        {"broker_socket_mode": "666"},
        {"broker_socket_dir": "/tmp/hnx-broker"},
        {"broker_clients_group": "hnx-broker"},
        {"broker_client_users": ["root"]},
        {"broker_secret_refs": {"TOKEN": "a-literal-value"}},
        {"broker_approvals_url": "http://status.lab.example/approvals"},
        {"broker_relay_stream": "lab"},
        {"broker_handlers": ["/x/a.sh", "/y/a.sh"]},
        # an exec handler outside a proof manifest, while handlers run as the broker's uid
        {"broker_manifest": str(PRODUCTION_MANIFEST)},
        # the events bus role's account on this host: the relay's prefix must be its import's
        {"events_bus_account": "HNX", "broker_relay_api_prefix": "$JS.API"},
        {"events_bus_account": "LAB", "broker_relay_api_prefix": "JS.HNX.API"},
        # round 7: the account declared in the broker's argspec, checked as the bus role does
        {"events_bus_account": "hnx", "broker_relay_api_prefix": "JS.hnx.API"},
    ])  # fmt: skip


def test_broker_deploys_builtin_only_manifests_under_any_id(tmp_path):
    """The handler-uid gate refuses exec handlers only: lanes (builtin/) run in the broker.  And
    a loopback bus is accepted in either family when the registry puts it on this host."""
    here = {**BROKER, "hnx_registry_file": _here_registry(tmp_path)}
    proof = _manifest(tmp_path, "lab-broker-proof")
    # the registry's row in another form of this host's name (compared short on both sides)
    fqdn = yaml.safe_load(REGISTRY.read_text())
    fqdn["services"]["events"]["host"] = "localhost.example.internal"
    (tmp_path / "registry-fqdn.yml").write_text(yaml.safe_dump(fqdn))
    results = run_cases(tmp_path, "broker", "validate", here, [
        {"broker_manifest": _manifest(tmp_path, "lab-broker", builtin_only=True)},
        {"broker_manifest": proof, "broker_relay_events_endpoint": V6_LOOP_BUS},
        {"broker_manifest": proof, "broker_relay_events_endpoint": TLS_BUS},
        {"broker_manifest": proof, "hnx_registry_file": str(tmp_path / "registry-fqdn.yml"),
         "events_bus_account": "HNX"},  # JS.HNX.API, the default prefix
    ])  # fmt: skip
    assert results == [(False, "")] * 4, results


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
        json.dumps({"ansible_python_interpreter": sys.executable,
                    "hnx_registry_file": str(REGISTRY), **vars_})
    )  # fmt: skip
    r = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", f"@{tmp_path / 'vars.json'}", str(tmp_path / "play.yml")],
        capture_output=True, text=True, cwd=tmp_path,
        env=dict(os.environ, ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
                 ANSIBLE_HOME=str(tmp_path / ".ansible"), ANSIBLE_NOCOLOR="1"),
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
    # the socket takes the clients' group from its setgid directory: serve chowns nothing, so the
    # whole of @privileged (@chown included) stays denied and the unit needs no extra group
    assert unit["SystemCallFilter"] == ["@system-service", "~@privileged @resources"]
    assert "--socket-group" not in unit["ExecStart"][0] and "SupplementaryGroups" not in unit
    assert unit["ProtectProc"] == ["invisible"] and unit["ProcSubset"] == ["pid"]
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


def test_broker_relay_names_the_bus_by_its_registry_id(tmp_path):
    """Role interface section 4: the relay's endpoint comes from the events row's port (on
    loopback, the bus having no TLS listener), not from a literal in the inventory."""
    extra = {k: v for k, v in BROKER.items() if k != "broker_relay_events_endpoint"}
    files = _render(tmp_path, "broker", extra)
    relay = _directives(files["hnx-broker-relay.service"])
    port = yaml.safe_load(REGISTRY.read_text())["services"]["events"]["port"]
    assert f"HNX_ENDPOINT_EVENTS=nats://{LOOP}:{port}" in relay["Environment"]


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


def test_status_hub_allowed_host_is_the_rows_public_hostname(tmp_path):
    extra = {k: v for k, v in HUB.items() if k != "status_hub_allowed_hosts"}
    files = _render(tmp_path, "status_hub", extra)
    argv = _directives(files["hnx-hub.service"])["ExecStart"][0].split()
    public = yaml.safe_load(REGISTRY.read_text())["services"]["status-hub"]["public_hostname"]
    assert argv[argv.index("--allowed-host") + 1] == public


def test_status_hub_on_loopback_needs_no_remote_flag(tmp_path):
    files = _render(tmp_path, "status_hub", {**HUB, "status_hub_bind_address": LOOP,
                                             "status_hub_approvals_socket": ""})  # fmt: skip
    unit = _directives(files["hnx-hub.service"])
    assert "--allow-remote" not in unit["ExecStart"][0] and "SupplementaryGroups" not in unit
    assert "approvals" not in yaml.safe_load(files["agents.yml"])


#: a client that publishes nothing (subscribe_only): refused (round 6) -- in an account of its
#: own it may subscribe to its own _INBOX alone, so it could receive nothing at all; a reader is a
#: client with a durable and that durable's MSG.NEXT (BRIDGE_USER)
READER = {"user": "hnx-reader", "password_ref": "secret:events/reader", "subscribe_only": True,
          "subscribe": ["_INBOX.hnx-reader.>"]}  # fmt: skip
#: the optional monitor user (events_bus_monitor_user), as main renders it
MONITOR = {"user": "hnx-watch", "password_hash": "$2a$11$" + "m" * 53}


def _rendered_users(users, password=None):
    return [{"user": u["user"], "password_hash": password or "$2a$11$" + "x" * 53,
             "publish": u.get("publish", []), "subscribe": u["subscribe"],
             "subscribe_only": u.get("subscribe_only", False)} for u in users]  # fmt: skip


def _nats_conf(files) -> dict:
    return json.loads("\n".join(
        line for line in files["nats.conf"].splitlines() if not line.lstrip().startswith("#")
    ))  # fmt: skip


def test_events_bus_config_grants_each_user_its_allow_lists_only(tmp_path):
    users = _rendered_users(BUS_USERS)
    files = _render(tmp_path, "events_bus", {**EVENTS, "events_bus_rendered_users": users,
                                             "events_bus_monitor_user": MONITOR["user"],
                                             "events_bus_rendered_monitor": MONITOR,
                                             "inventory_hostname": "bus-01.example.internal"})  # fmt: skip
    conf = _nats_conf(files)
    assert conf["listen"].startswith(LOOP + ":") and conf["http"].startswith(LOOP + ":")
    accounts = conf["accounts"]
    # the account split: the provisioner alone with the streams, each client in its own account
    assert list(accounts) == ["HNX", "HNX-hnx-broker", "HNX-hnx-watch"]
    assert accounts["HNX"]["jetstream"] == "enabled"
    assert [u["user"] for u in accounts["HNX"]["users"]] == ["hnx-events-admin"]
    got = [a["users"][0] for a in accounts.values()]
    assert [set(u) for u in got] == [{"user", "password", "permissions"}] * 3
    # the broker's calls under the client prefix, its stream subjects as they are; the bus
    # account exports exactly those, to that account alone
    broker = accounts["HNX-hnx-broker"]
    assert "jetstream" not in broker
    assert broker["users"][0]["permissions"] == {
        "publish": {"allow": ["lab.homelabnext.decision.>", "JS.HNX.API.STREAM.INFO.LAB"]},
        "subscribe": {"allow": BUS_USERS[0]["subscribe"]}}  # fmt: skip
    assert broker["imports"] == [
        {"service": {"account": "HNX", "subject": "lab.homelabnext.decision.>"}},
        {"service": {"account": "HNX", "subject": "$JS.API.STREAM.INFO.LAB"},
         "to": "JS.HNX.API.STREAM.INFO.LAB"}]  # fmt: skip
    advisories = ["$JS.EVENT.ADVISORY.STREAM.DELETED.>", "$JS.EVENT.ADVISORY.CONSUMER.DELETED.>",
                  "$JS.EVENT.ADVISORY.STREAM.UPDATED.>"]  # fmt: skip
    assert accounts["HNX"]["exports"] == [
        {"service": "$JS.API.STREAM.INFO.LAB", "accounts": ["HNX-hnx-broker"]},
        {"service": "lab.homelabnext.decision.>", "accounts": ["HNX-hnx-broker"]},
        *({"stream": a, "accounts": ["HNX-hnx-watch"]} for a in advisories)]  # fmt: skip
    # the monitor: deny-all publish (never {"allow": []}, which NATS reads as no restriction),
    # the three advisories imported as streams, nothing else
    assert got[2]["permissions"] == {"publish": {"deny": [">"]},
                                     "subscribe": {"allow": advisories}}  # fmt: skip
    assert accounts["HNX-hnx-watch"]["imports"] == [
        {"stream": {"account": "HNX", "subject": a}} for a in advisories]  # fmt: skip
    assert '"allow": []' not in files["nats.conf"]
    assert all(u["password"].startswith("$2a$") for u in got)
    unit = _directives(files["hnx-events.service"])
    assert unit["User"] == ["hnx-events"] and unit["ReadWritePaths"] == ["/var/lib/hnx-events"]


def test_events_bus_listens_on_ipv6_loopback_in_brackets(tmp_path):
    files = _render(tmp_path, "events_bus", {**EVENTS, "events_bus_listen_address": "::1",
                                             "events_bus_rendered_users": _rendered_users(BUS_USERS),
                                             "inventory_hostname": "bus-01.example.internal"})  # fmt: skip
    assert _nats_conf(files)["listen"] == "[::1]:4222"


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind((LOOP, 0))
        return s.getsockname()[1]


class _Nats:
    """A minimal NATS client over the text protocol (no client library in this job): connect
    as a user, publish, request, and read back the -ERR lines the server sends."""

    def __init__(self, port: int, user: str, password: str):
        import socket

        self.sock = socket.create_connection((LOOP, port), timeout=5)
        self.buf = b""
        self._line()  # INFO
        hello = {"user": user, "pass": password, "verbose": False, "pedantic": False,
                 "headers": True, "no_responders": True}  # fmt: skip
        self.sock.sendall(f"CONNECT {json.dumps(hello)}\r\nPING\r\n".encode())
        line = self._line()
        assert line == "PONG", line
        self._inbox = f"_INBOX.{user}.r"  # its own inbox: the replies to request()
        self.sock.sendall(f"SUB {self._inbox} 1\r\n".encode())

    def _line(self) -> str:
        while b"\r\n" not in self.buf:
            chunk = self.sock.recv(65536)
            assert chunk, "the server closed the connection"
            self.buf += chunk
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line.decode()

    def _payload(self, n: int) -> bytes:
        while len(self.buf) < n + 2:
            self.buf += self.sock.recv(65536)
        data, self.buf = self.buf[:n], self.buf[n + 2 :]
        return data

    def publish(self, subject: str, data: bytes = b"x", reply: str = "") -> list[str]:
        """The -ERR lines the server answers this publish with (none: it was let through)."""
        self.sock.sendall(
            f"PUB {subject} {reply} {len(data)}\r\n".encode() + data + b"\r\nPING\r\n"
        )
        errs = []
        while (line := self._line()) != "PONG":
            if line.startswith("-ERR"):
                errs.append(line)
            elif line.startswith(("MSG", "HMSG")):
                self._payload(int(line.split()[-1]))
        return errs

    def request(self, subject: str, body: dict | None) -> dict:
        data = b"" if body is None else json.dumps(body).encode()
        self.sock.sendall(f"PUB {subject} {self._inbox} {len(data)}\r\n".encode() + data + b"\r\n")
        while True:
            line = self._line()
            if line.startswith("MSG"):
                return json.loads(self._payload(int(line.split()[-1])) or b"{}")
            if line.startswith("HMSG"):
                parts = line.split()
                raw = self._payload(int(parts[-1]))
                return json.loads(raw[int(parts[-2]) :] or b"{}")
            if line.startswith("-ERR"):
                raise AssertionError(line)
            if line == "PING":
                self.sock.sendall(b"PONG\r\n")

    def pull(self, subject: str, body: dict) -> tuple[str, bytes] | None:
        """One ``CONSUMER.MSG.NEXT``: the delivery's ack reply subject and data, or None when the
        server answers with a status (nothing to deliver)."""
        data = json.dumps(body).encode()
        self.sock.sendall(f"PUB {subject} {self._inbox} {len(data)}\r\n".encode() + data + b"\r\n")
        while True:
            line = self._line()
            if line.startswith("-ERR"):
                raise AssertionError(line)
            if line == "PING":
                self.sock.sendall(b"PONG\r\n")
                continue
            parts = line.split()
            if parts[0] == "MSG":
                return parts[3], self._payload(int(parts[-1]))
            if parts[0] == "HMSG":
                raw = self._payload(int(parts[-1]))
                if len(parts) == 5:  # no reply subject: a status (404 no messages, 408)
                    return None
                return parts[3], raw[int(parts[-2]) :]

    def pull_many(self, subject: str, body: dict) -> list[str]:
        """One ``CONSUMER.MSG.NEXT`` for a batch: the ack reply subject of every delivery, up to
        the first status message (the batch is over) or ``batch`` deliveries."""
        data = json.dumps(body).encode()
        self.sock.sendall(f"PUB {subject} {self._inbox} {len(data)}\r\n".encode() + data + b"\r\n")
        out: list[str] = []
        while len(out) < body["batch"]:
            line = self._line()
            if line.startswith("-ERR"):
                raise AssertionError(line)
            if line == "PING":
                self.sock.sendall(b"PONG\r\n")
                continue
            parts = line.split()
            self._payload(int(parts[-1]))
            if parts[0] == "HMSG" and len(parts) == 5:  # a status: nothing more to deliver
                break
            out.append(parts[3])
        return out

    def subscribe(self, subject: str, sid: int) -> list[str]:
        """SUB ``subject``: the -ERR lines the server answers it with (none: allowed)."""
        self.sock.sendall(f"SUB {subject} {sid}\r\nPING\r\n".encode())
        errs = []
        while (line := self._line()) != "PONG":
            if line.startswith("-ERR"):
                errs.append(line)
        return errs

    def next_subject(self) -> str:
        """The subject of the next message delivered to any of this client's subscriptions."""
        while True:
            line = self._line()
            if line == "PING":
                self.sock.sendall(b"PONG\r\n")
                continue
            if line.startswith(("MSG", "HMSG")):
                self._payload(int(line.split()[-1]))
                return line.split()[1]

    def close(self):
        self.sock.close()


API = "JS.HNX.API"  # a client account's JetStream calls (role var events_bus_api_prefix)


def _start(server, conf, port):
    import socket
    import time

    proc = subprocess.Popen([server, "-c", str(conf)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)  # fmt: skip
    for _ in range(100):
        try:
            socket.create_connection((LOOP, port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    return proc


def _hnx_bus():
    import importlib.util

    spec = importlib.util.spec_from_file_location("hnx_bus", ANSIBLE / "plugins/filter/hnx_bus.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _rendered_split_bus(tmp_path, server, users, port, monitor, watch=""):
    """The role's configuration for ``users`` (the account split; ``watch``: the monitor user),
    checked by the server."""
    files = _render(tmp_path, "events_bus", {
        **EVENTS, "events_bus_rendered_users": _rendered_users(users, password="pw"),
        "events_bus_monitor_user": watch,
        "events_bus_rendered_monitor": {"user": watch, "password_hash": "pw"} if watch else {},
        "events_bus_users": users, "events_bus_port": port, "events_bus_monitor_port": monitor,
        "events_bus_store_dir": str(tmp_path / "store"), "inventory_hostname": "bus-01.example.internal",
    })  # fmt: skip
    conf = tmp_path / "nats.conf"
    conf.write_text(files["nats.conf"])
    check = subprocess.run([server, "-c", str(conf), "-t"], capture_output=True, text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    return conf


def _denied(errs) -> bool:
    return any("Permissions Violation" in e for e in errs)


def test_events_bus_config_is_enforced_by_the_pinned_server(tmp_path):
    """The rendered configuration, run by the real nats-server (CI's external-tools job installs
    the pinned release): the provisioner alone in the bus account, every client in an account of
    its own that imports its few calls (round 5). A subscribe-only user is refused every publish,
    the relay's user what its list does not name; a stream provisioned the adapter's way can be
    neither purged nor have a message deleted, nor either flag cleared; the bridge pulls and acks
    its own durable across the import -- and no reply subject a client sets reaches the bus
    account's API or its streams: a pull, an ack and every JetStream call answered to
    ``$JS.API.STREAM.DELETE``, ``CONSUMER.DELETE`` or a stream subject deletes, changes and
    stores nothing (the same calls in one account delete the stream: the last block)."""
    import time

    from tests.suite_policy import require_tool

    server = require_tool("nats-server")
    port, monitor = _free_port(), _free_port()
    provisioner = dict(BUS_USERS[1], publish=[
        *(f"$JS.API.STREAM.{v}.{s}" for v in ("INFO", "CREATE") for s in ("LAB", "LAB_DLQ")),
        *PROVISIONER["publish"][1:], "$JS.API.CONSUMER.CREATE.LAB.e2e-scratch",
        "$JS.API.CONSUMER.DELETE.LAB.e2e-scratch"])  # fmt: skip
    # a second publisher whose stream subjects overlap the relay's (lab.homelabnext.> holds the
    # relay's lab.homelabnext.decision.>): each account imports its own grant, the bus account
    # exports both, and neither reaches further than its own list
    emitter = {"user": "hnx-emitter", "password_ref": "secret:events/emitter",
               "publish": ["lab.homelabnext.>"], "subscribe": ["_INBOX.hnx-emitter.>"]}  # fmt: skip
    users = [BUS_USERS[0], provisioner, emitter, BRIDGE_USER]
    # what the role validates: the ceiling, and the durable declared for the bridge alone
    hnx_bus = _hnx_bus()
    for u in users:
        subjects = u.get("publish", []) + u["subscribe"]
        assert hnx_bus.hnx_bus_subject_problems(
            subjects, u["user"], admin=u is provisioner, account="HNX",
            streams=EVENTS["events_bus_streams"]) == [], u  # fmt: skip
    assert hnx_bus.hnx_bus_durable_problems([DURABLE], users, provisioner["user"],
                                            EVENTS["events_bus_streams"], True) == []  # fmt: skip
    conf = _rendered_split_bus(tmp_path, server, users, port, monitor, watch="hnx-watch")
    accounts = _nats_conf({"nats.conf": conf.read_text()})["accounts"]
    assert sorted(accounts) == ["HNX", "HNX-hnx-broker", "HNX-hnx-bus-bridge", "HNX-hnx-emitter",
                                "HNX-hnx-watch"]  # fmt: skip
    assert [u["user"] for u in accounts["HNX"]["users"]] == ["hnx-events-admin"]
    assert all("jetstream" not in a for n, a in accounts.items() if n != "HNX")
    proc = _start(server, conf, port)
    clients = []
    try:
        watch = _Nats(port, "hnx-watch", "pw")
        relay = _Nats(port, "hnx-broker", "pw")
        admin = _Nats(port, "hnx-events-admin", "pw")
        emit = _Nats(port, "hnx-emitter", "pw")
        clients += [watch, relay, admin, emit]
        # the monitor publishes nothing and subscribes to the three advisories alone
        for subject in ("anything", "$JS.API.STREAM.DELETE.LAB", "lab.homelabnext.decision.x"):
            assert _denied(watch.publish(subject)), subject
        assert _denied(watch.subscribe("$JS.EVENT.ADVISORY.>", 7))
        for i, adv in enumerate(("STREAM.DELETED", "CONSUMER.DELETED", "STREAM.UPDATED")):
            assert watch.subscribe(f"$JS.EVENT.ADVISORY.{adv}.>", 10 + i) == [], adv
        assert relay.publish("lab.homelabnext.decision.returned") == []
        for subject in ("$JS.API.STREAM.DELETE.LAB", f"{API}.STREAM.DELETE.LAB",
                        "lab.homelabnext.agent.x"):  # fmt: skip
            assert _denied(relay.publish(subject)), subject

        # the standing stream as provision_streams creates it (the admin's grants: CREATE, INFO)
        from homelabnext.conform.adapters import nats_jetstream as nj

        class Raw:  # the adapter's Wire over this client
            def request(self, subject, payload, *, timeout, headers=None):
                return nj.WireMsg(subject, json.dumps(admin.request(subject, json.loads(payload)
                                  if payload else None)).encode(), {}, "")  # fmt: skip

        made = nj.provision_streams(Raw(), stream="LAB", subject_prefix="lab", max_bytes=1 << 20)
        assert made == ["LAB", "LAB_DLQ"]
        cfg = admin.request("$JS.API.STREAM.INFO.LAB", None)["config"]
        assert cfg["deny_delete"] is True and cfg["deny_purge"] is True
        # round 4, security F1: no user but the provisioner may create a consumer, in any form;
        # here the bridge tries a push durable delivering to the relay's own inbox
        bridge = _Nats(port, "hnx-bus-bridge", "pw")
        clients.append(bridge)
        push = json.dumps({"stream_name": "LAB", "config": {
            "durable_name": "evil", "deliver_subject": "_INBOX.hnx-broker.stolen",
            "ack_policy": "none", "deliver_policy": "all"}}).encode()  # fmt: skip
        for api in ("$JS.API", API):
            for create in (f"{api}.CONSUMER.CREATE.LAB.evil", f"{api}.CONSUMER.DURABLE.CREATE.LAB.evil",
                           f"{api}.CONSUMER.CREATE.LAB.bridge-x.lab.homelabnext.decision.returned"):  # fmt: skip
                assert _denied(bridge.publish(create, push, "_INBOX.hnx-bus-bridge.r")), create
        # round 4, security F2: STREAM.UPDATE is no one's, the provisioner's included
        for who in (admin, bridge, relay):
            for api in ("$JS.API", API):
                assert _denied(who.publish(f"{api}.STREAM.UPDATE.LAB", b"{}")), who
        # the provisioner pre-creates the bridge's pull durable (once), the way the role does
        assert nj.provision_consumers(Raw(), stream="LAB", durables=[DURABLE]) == ["bridge-x"]
        assert nj.provision_consumers(Raw(), stream="LAB", durables=[DURABLE]) == []
        info = admin.request("$JS.API.CONSUMER.INFO.LAB.bridge-x", None)
        assert (
            "deliver_subject" not in info["config"] and info["config"]["ack_policy"] == "explicit"
        )
        # the bridge binds across its account's imports: it pulls what the relay published (a
        # request, so the PubAck says it is stored first) and its v1 ack takes
        stored = relay.request("lab.homelabnext.decision.returned", {"one": 1})
        assert stored.get("stream") == "LAB" and stored.get("seq") == 1, stored
        nxt = f"{API}.CONSUMER.MSG.NEXT.LAB.bridge-x"
        got = bridge.pull(nxt, {"batch": 1, "no_wait": True})
        assert got is not None and got[0].startswith("$JS.ACK.LAB.bridge-x."), got
        assert len(got[0].split(".")) == 9, got
        assert bridge.publish(got[0], b"+ACK") == []
        info = bridge.request(f"{API}.CONSUMER.INFO.LAB.bridge-x", None)
        assert info["num_ack_pending"] == 0 and info["ack_floor"]["stream_seq"] >= 1, info
        assert bridge.pull(nxt, {"batch": 1, "no_wait": True}) is None
        assert bridge.request(f"{API}.STREAM.INFO.LAB", None)["config"]["name"] == "LAB"
        # round 6: overlapping stream grants in two accounts: the emitter stores under its wider
        # prefix (the relay's subject included), the relay still under its own alone
        for subject in ("lab.homelabnext.decision.returned", "lab.homelabnext.agent.job.failed"):
            assert emit.request(subject, {"e": subject}).get("stream") == "LAB", subject
        assert _denied(relay.publish("lab.homelabnext.agent.job.failed"))
        assert _denied(emit.publish("lab.other.x"))
        # a batch of 2 across the import (response_type stream: several answers to one
        # request), both settled with the v2 ack form and the computed account hash
        relay.request("lab.homelabnext.decision.returned", {"b": 2})
        batch = bridge.pull_many(nxt, {"batch": 2, "no_wait": True})
        assert len(batch) == 2 and all(len(r.split(".")) == 9 for r in batch), batch
        account_hash = hnx_bus.hnx_bus_account_hash("HNX")
        assert account_hash == "hKkTAyOX"
        for reply in batch:  # $JS.ACK.<s>.<d>.<dc>.<sseq>.<dseq>.<ts>.<pending> -> v2 + a token
            v2 = ".".join(["$JS", "ACK", "_", account_hash, *reply.split(".")[2:], "r6"])
            assert bridge.publish(v2, b"+ACK") == [], v2
        info = bridge.request(f"{API}.CONSUMER.INFO.LAB.bridge-x", None)
        assert info["num_ack_pending"] == 0 and info["num_pending"] == 0, info
        # a v2 ack under another hash is not the bridge's grant
        assert _denied(bridge.publish(v2.replace(account_hash, "ABCDEFGH"), b"+ACK"))
        # its grants reach its own durable alone
        for other in (f"{API}.CONSUMER.MSG.NEXT.LAB.other", "$JS.ACK.LAB.other.1.1.1.1.0",
                      f"{API}.CONSUMER.DELETE.LAB.bridge-x", "$JS.API.CONSUMER.INFO.LAB.bridge-x",
                      "$JS.API.STREAM.MSG.GET.LAB", f"{API}.STREAM.MSG.GET.LAB"):  # fmt: skip
            assert _denied(bridge.publish(other)), other

        # round 5, the CRITICAL finding: a reply subject is not permission-checked, and JetStream
        # takes its own internal client's messages (a delivery, an ack's answer) as API requests.
        # One more message to hand out, then every reply a client can set: none may delete,
        # change or store anything in the bus account
        relay.request("lab.homelabnext.decision.returned", {"two": 2})
        held = bridge.pull(nxt, {"batch": 1, "no_wait": True})
        assert held is not None
        before = admin.request("$JS.API.STREAM.INFO.LAB", None)["state"]["messages"]
        targets = ("$JS.API.STREAM.DELETE.LAB", "$JS.API.CONSUMER.DELETE.LAB.bridge-x",
                   "$JS.API.STREAM.PURGE.LAB", "lab.homelabnext.agent.job.failed",
                   "lab.homelabnext.decision.returned")  # fmt: skip
        for reply in targets:
            sends = [(bridge, nxt, b'{"batch":1,"no_wait":true}'),  # a pull: the delivery or 404
                     (bridge, held[0], b"+WPI"),  # an ack's answer (in progress: still held)
                     (bridge, f"{API}.CONSUMER.INFO.LAB.bridge-x", b""),
                     (bridge, f"{API}.STREAM.INFO.LAB", b""),
                     (relay, f"{API}.STREAM.INFO.LAB", b""),
                     (relay, "lab.homelabnext.decision.returned", b"{}")]  # its PubAck  # fmt: skip
            for who, subject, body in sends:
                for _ in range(3):
                    assert who.publish(subject, body, reply) == [], (subject, reply)
        time.sleep(0.5)  # anything the server would do with them, done
        after = admin.request("$JS.API.STREAM.INFO.LAB", None)
        assert "error" not in after, after  # the stream is there
        assert after["config"]["deny_delete"] and after["config"]["deny_purge"], after
        # only the relay's own publishes landed (its PubAck went nowhere): nothing injected
        assert after["state"]["messages"] == before + 3 * len(targets), (before, after["state"])
        info = admin.request("$JS.API.CONSUMER.INFO.LAB.bridge-x", None)
        assert "error" not in info and "deliver_subject" not in info["config"], info
        dlq = admin.request("$JS.API.STREAM.INFO.LAB_DLQ", None)
        assert "error" not in dlq, dlq
        # the monitor lists the durable, and it is no push consumer
        import urllib.request

        jsz_url = (
            f"http://{LOOP}:{monitor}/jsz?accounts=true&streams=true&consumers=true&config=true"
        )
        with urllib.request.urlopen(jsz_url, timeout=5) as resp:
            jsz = json.load(resp)
        names = [c["name"] for a in jsz["account_details"] for st in a.get("stream_detail", [])
                 for c in st.get("consumer_detail", [])]  # fmt: skip
        assert names == ["bridge-x"] and hnx_bus.hnx_bus_push_consumers(jsz) == []

        # the health hook's backstops, read the way it reads them: the account split as the
        # server runs it, and both streams with their deny flags
        def mon(path):
            with urllib.request.urlopen(f"http://{LOOP}:{monitor}{path}", timeout=5) as r:
                return json.load(r)

        want = hnx_bus.hnx_bus_expected_accounts(users, "hnx-events-admin", "HNX", "hnx-watch")
        details = [mon(f"/accountz?acc={name}") for name in want]
        assert hnx_bus.hnx_bus_account_problems(
            mon("/accountz"), details, users, "hnx-events-admin", "HNX", "hnx-watch",
            mon("/connz?auth=true")) == []  # fmt: skip
        # (and it is no rubber stamp: had the relay's user been the provisioner, it would be in HNX)
        assert hnx_bus.hnx_bus_account_problems(
            mon("/accountz"), details, users, "hnx-broker", "HNX", "hnx-watch",
            mon("/connz?auth=true"))  # fmt: skip
        assert hnx_bus.hnx_bus_unprotected_streams(jsz, "HNX") == []
        # and the monitor saw what a deletion leaves: the provisioner deletes a scratch durable
        made = admin.request("$JS.API.CONSUMER.CREATE.LAB.e2e-scratch", {"stream_name": "LAB",
            "config": {"durable_name": "e2e-scratch", "ack_policy": "explicit"}})  # fmt: skip
        assert "error" not in made, made
        assert admin.request("$JS.API.CONSUMER.DELETE.LAB.e2e-scratch", None)["success"] is True
        assert watch.next_subject() == "$JS.EVENT.ADVISORY.CONSUMER.DELETED.LAB.e2e-scratch"
    finally:
        for c in clients:
            c.close()
        proc.terminate()
        proc.wait(timeout=10)

    # the flags hold against any user, and cannot be cleared: a server with no permissions at all
    open_conf = tmp_path / "open.conf"
    open_conf.write_text(json.dumps({"listen": f"{LOOP}:{port}", "http": f"{LOOP}:{monitor}",
        "jetstream": {"store_dir": str(tmp_path / "store")}, "accounts": {"HNX": {
        "jetstream": "enabled", "users": [{"user": "root-ish", "password": "pw"}]}}}))  # fmt: skip
    from homelabnext.conform.adapters import nats_jetstream as nj

    class Raw2:
        def __init__(self, c):
            self.c = c

        def request(self, subject, payload, *, timeout, headers=None):
            got = self.c.request(subject, json.loads(payload) if payload else None)
            return nj.WireMsg(subject, json.dumps(got).encode(), {}, "")

    proc = _start(server, open_conf, port)
    try:
        anyone = _Nats(port, "root-ish", "pw")
        try:
            purge = anyone.request("$JS.API.STREAM.PURGE.LAB", None)
            assert purge["error"]["description"] == "stream purge not permitted", purge
            delete = anyone.request("$JS.API.STREAM.MSG.DELETE.LAB", {"seq": 1})
            assert delete["error"]["description"] == "message delete not permitted", delete
            cfg = anyone.request("$JS.API.STREAM.INFO.LAB", None)["config"]
            for flag, why in (("deny_delete", "can not cancel deny message deletes"),
                              ("deny_purge", "can not cancel deny purge")):  # fmt: skip
                got = anyone.request("$JS.API.STREAM.UPDATE.LAB", {**cfg, flag: False})
                assert why in got["error"]["description"], got
            # what a create grant gives (why no user holds one): a push durable that delivers
            # the stream to another user's inbox; the role's check finds it in /jsz
            made = anyone.request("$JS.API.CONSUMER.CREATE.LAB.evil", {"stream_name": "LAB",
                "config": {"durable_name": "evil", "deliver_subject": "_INBOX.hnx-broker.stolen",
                           "ack_policy": "none", "deliver_policy": "all"}})  # fmt: skip
            assert "error" not in made, made
            import urllib.request

            jsz_url = (f"http://{LOOP}:{monitor}/jsz?accounts=true&streams=true&consumers=true"
                       "&config=true")  # fmt: skip
            with urllib.request.urlopen(jsz_url, timeout=5) as resp:
                jsz = json.load(resp)
            assert hnx_bus.hnx_bus_push_consumers(jsz) == [
                "HNX/LAB/evil -> _INBOX.hnx-broker.stolen"
            ]
            # and why the clients live in accounts of their own: in the stream's account, a
            # pull whose reply is STREAM.DELETE deletes the stream, deny_delete notwithstanding
            # (here the 404 of a durable with nothing to deliver is the server's "request")
            probe = dict(DURABLE, durable="probe", deliver_policy="new")
            assert nj.provision_consumers(Raw2(anyone), stream="LAB", durables=[probe]) == ["probe"]
            assert anyone.publish("$JS.API.CONSUMER.MSG.NEXT.LAB.probe",
                                  b'{"batch":1,"no_wait":true}', "$JS.API.STREAM.DELETE.LAB") == []  # fmt: skip
            time.sleep(0.3)
            gone = anyone.request("$JS.API.STREAM.INFO.LAB", None)
            assert gone["error"]["description"] == "stream not found", gone
        finally:
            anyone.close()
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_broker_e2e_reply_attacks_change_nothing_on_the_pinned_server(tmp_path, monkeypatch):
    """The broker scenario's bus-acl checks (compose/lab-in-a-box/broker_e2e.py, what a real
    deployment runs) against the role's account split on the real server: the bridge's user binds
    to the provisioner's durable, pulls and acks across its imports, and every reply-subject
    attack (a pull, an ack, consumer and stream info, as the bridge and as the relay) leaves the
    stream, its flags, its last sequence and the durable as they were."""
    pytest.importorskip("nats")  # CI's external-tools job installs the nats extra
    import importlib.util

    from tests.suite_policy import require_tool

    server = require_tool("nats-server")
    port, monitor = _free_port(), _free_port()
    broker = dict(BUS_USERS[0], publish=[*BUS_USERS[0]["publish"], "$JS.API.STREAM.INFO.LAB_DLQ"])
    provisioner = dict(PROVISIONER, publish=[
        *(f"$JS.API.STREAM.{v}.{s}" for v in ("INFO", "CREATE") for s in ("LAB", "LAB_DLQ")),
        *PROVISIONER["publish"][1:], "$JS.API.STREAM.MSG.GET.LAB"])  # fmt: skip
    bridge = dict(BRIDGE_USER, publish=[*BRIDGE_USER["publish"], "$JS.API.STREAM.INFO.LAB_DLQ"])
    conf = _rendered_split_bus(tmp_path, server, [broker, provisioner, bridge], port, monitor)
    spec = importlib.util.spec_from_file_location(
        "broker_e2e_r", ROOT / "compose/lab-in-a-box/broker_e2e.py"
    )
    e2e = importlib.util.module_from_spec(spec)
    sys.modules["broker_e2e_r"] = e2e
    spec.loader.exec_module(e2e)
    users = {"hnx-broker": "HNX_SECRET_T_BROKER", "hnx-events-admin": "HNX_SECRET_T_ADMIN",
             "hnx-bus-bridge": "HNX_SECRET_T_BRIDGE"}  # fmt: skip
    for var in users.values():
        monkeypatch.setenv(var, "pw")
    monkeypatch.setenv("HNX_ENDPOINT_EVENTS", f"nats://{LOOP}:{port}")
    relay = e2e.Relay("", "", "LAB", "lab", admin="hnx-events-admin", not_broker="hnx-bus-bridge",
                      not_broker_durable="bridge-x", bus_users=users, api_prefix=API)  # fmt: skip
    proc = _start(server, conf, port)
    try:
        assert relay.provision() == ["LAB", "LAB_DLQ"]
        bus = relay.bus_as("hnx-broker")
        try:
            assert bus.publish("homelabnext.decision.returned", b"{}", msg_id="r5-1") == 1
        finally:
            bus.close()
        got = e2e.check_bridge_acks(relay)
        assert "acked 1 delivery(ies)" in got and "changed nothing" in got, got
        assert "reply attacks not sent" not in got
        # round 6: a client left at the default $JS.API is refused (its account has no
        # JetStream of its own), and the adapter's error names the prefix to pass
        from homelabnext.conform.adapters import nats_jetstream as nj

        with pytest.raises(nj.WireError) as refused:
            nj.make(scratch=False, provision=False, stream="LAB", subject_prefix="lab",
                    user="hnx-broker", password_secret="secret:t/broker")  # fmt: skip
        assert refused.value.permanent and "$JS.API.STREAM.INFO.LAB" in str(refused.value)
        assert "pass api_prefix JS.<account>.API" in str(refused.value), refused.value
    finally:
        sys.modules.pop("broker_e2e_r", None)
        proc.terminate()
        proc.wait(timeout=10)


def test_the_playbook_parses_and_targets_capability_groups():
    r = subprocess.run(
        ["ansible-playbook", "--syntax-check", "-i", str(ANSIBLE / "inventory/example/hosts.yml"),
         str(ANSIBLE / "playbooks/control_plane.yml")],
        capture_output=True, text=True, env=dict(os.environ, ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg")),
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr


# ---------------------------------------------------------------- install paths run on localhost
def _me():
    return pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name


def test_broker_bad_manifest_never_replaces_the_live_one(tmp_path):
    """The manifest and its handlers are staged together (``staged/``, so the manifest's
    ``handlers/`` resolve against the staged handlers) and validated by the release's own
    ``hnx broker validate`` before either is copied over the live ones: a set that fails
    validation stops the play and the running broker's manifest and handlers are untouched."""
    user, group = _me()
    conf = tmp_path / "etc"
    (conf / "handlers").mkdir(parents=True)
    (conf / "manifest.yml").write_text("manifest_id: live\n")
    # the release's hnx: `broker validate PATH` refuses a manifest that says bad, or whose
    # handler (beside it, in handlers/) says bad
    hnx = fake(tmp_path / "hnx", "import os, sys\n"
               "assert sys.argv[1:3] == ['broker', 'validate'], sys.argv\n"
               "h = os.path.join(os.path.dirname(sys.argv[3]), 'handlers', 'run.sh')\n"
               "texts = [open(sys.argv[3]).read()] + ([open(h).read()] if os.path.exists(h) else [])\n"
               "sys.exit(1 if any('bad' in t for t in texts) else 0)\n")  # fmt: skip
    src = tmp_path / "src"
    src.mkdir()
    handler = src / "run.sh"
    base = {"broker_config_dir": str(conf), "broker_hnx_bin": hnx, "broker_group": group,
            "broker_config_owner": user, "broker_handlers": [str(handler)]}  # fmt: skip
    good, bad = tmp_path / "good.yml", tmp_path / "bad.yml"
    good.write_text("manifest_id: next\n")
    bad.write_text("manifest_id: bad\n")
    handler.write_text("#!/bin/sh\necho v1\n")

    r = run_role(tmp_path, "broker", "manifest", {**base, "broker_manifest": str(good)})
    assert r.returncode == 0, r.stdout + r.stderr
    assert (conf / "manifest.yml").read_text() == "manifest_id: next\n"
    assert (conf / "handlers" / "run.sh").read_text() == "#!/bin/sh\necho v1\n"
    again = run_role(tmp_path, "broker", "manifest", {**base, "broker_manifest": str(good)})
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    check = run_role(tmp_path, "broker", "manifest", {**base, "broker_manifest": str(good)},
                     check=True)  # fmt: skip
    assert check.returncode == 0 and "changed=0" in check.stdout, check.stdout

    r = run_role(tmp_path, "broker", "manifest", {**base, "broker_manifest": str(bad)})
    assert r.returncode != 0, r.stdout
    assert (conf / "manifest.yml").read_text() == "manifest_id: next\n"
    # a handler the new set fails on never reaches handlers/ either
    handler.write_text("#!/bin/sh\necho bad\n")
    r = run_role(tmp_path, "broker", "manifest", {**base, "broker_manifest": str(good)})
    assert r.returncode != 0, r.stdout
    assert (conf / "handlers" / "run.sh").read_text() == "#!/bin/sh\necho v1\n"
    assert (conf / "manifest.yml").read_text() == "manifest_id: next\n"


def test_broker_restore_keeps_the_relay_reaching_the_outbox(tmp_path):
    """``restore`` copies the backup over the state directory (giving what it writes the broker's
    user and group and the backup's modes, the directory itself included), then puts back what
    main sets: the state directory in the relay's group, 0710 (else the relay cannot reach
    outbox/), outbox/ and relay/ setgid 2750.  The copy is a merge: a consumed approval the
    backup does not have is not undone."""
    user, group = _me()
    # the relay's group: a second group of this user when it has one (CI's runner does), so the
    # test tells the relay's group from the broker's; otherwise the same, and the modes decide
    others = [grp.getgrgid(g).gr_name for g in os.getgroups() if g != os.getgid()]
    relay_group = others[0] if others else group
    root, data = tmp_path / "lib", tmp_path / "agents"
    state = root / "state"
    for d, mode in ((root, 0o710), (state, 0o710), (state / "outbox", 0o2750),
                    (state / "relay", 0o2750), (state / "consumed", 0o700), (data, 0o750)):  # fmt: skip
        d.mkdir(parents=True, exist_ok=True)
        os.chown(
            d,
            -1,
            grp.getgrnam(relay_group if d in (root, state, state / "outbox") else group).gr_gid,
        )
        d.chmod(mode)
    (state / "consumed" / "req-after-the-backup").write_text("{}")
    backup = tmp_path / "backup"
    for d in (backup / "state" / "outbox", backup / "state" / "consumed", backup / "agents"):
        d.mkdir(parents=True)
    (backup / "state").chmod(0o700)
    (backup / "state" / "outbox" / "0001.json").write_text("{}")
    (backup / "state" / "consumed" / "req-before").write_text("{}")
    (backup / "agents" / "note.md").write_text("x")
    r = run_role(tmp_path, "broker", "restore", {
        "broker_start": False, "broker_state_root": str(root), "broker_data_root": str(data),
        "broker_user": user, "broker_group": group, "broker_relay_user": user,
        "broker_relay_group": relay_group, "broker_restore_source": str(backup),
        "broker_systemd_dir": str(tmp_path / "no-units"),
    })  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr

    def mode_group(p):
        st = p.stat()
        return oct(st.st_mode & 0o7777), grp.getgrgid(st.st_gid).gr_name

    assert mode_group(state) == ("0o710", relay_group)
    assert mode_group(state / "outbox") == ("0o2750", relay_group)
    assert mode_group(state / "relay")[0] == "0o2750"
    assert mode_group(data) == ("0o750", group)
    assert (state / "outbox" / "0001.json").is_file() and (data / "note.md").is_file()
    # a merge, never a delete: what was consumed after the backup stays consumed
    assert {p.name for p in (state / "consumed").iterdir()} == {
        "req-before",
        "req-after-the-backup",
    }


@pytest.mark.parametrize("role", ["broker", "events_bus"])
def test_restore_stops_every_unit_that_exists_and_starts_only_when_asked(tmp_path, role):
    """Round 4: the units are stopped for the copy whenever they exist, ``*_start: false``
    included (main never started them; something else may have), and started again only when
    ``*_start`` is true.  systemctl is a stand-in that logs what it is asked."""
    user, group = _me()
    units = tmp_path / "units"
    units.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = bindir / "calls.log"
    # active until it is asked to stop, then inactive until asked to start
    fake(
        bindir / "systemctl",
        f"""import os, sys
log = {str(log)!r}
open(log, "a").write("systemctl " + " ".join(sys.argv[1:]) + "\\n")
said = [l.split()[1] for l in open(log) if l.split()[1] in ("stop", "start")]
state = "inactive" if said and said[-1] == "stop" else "active"
if sys.argv[1] == "show":
    sys.stdout.write(f"Id={{sys.argv[-1]}}\\nLoadState=loaded\\nActiveState={{state}}\\n"
                     "SubState=x\\nUnitFileState=enabled\\n")
""",
    )
    backup = tmp_path / "backup"
    if role == "broker":
        (units / "hnx-broker.service").write_text("[Unit]\n")  # the relay's unit is absent
        for d in (backup / "state", backup / "agents"):
            d.mkdir(parents=True)
        extra = {"broker_state_root": str(tmp_path / "lib"), "broker_data_root": str(tmp_path / "a"),
                 "broker_user": user, "broker_group": group, "broker_relay_user": user,
                 "broker_relay_group": group, "broker_restore_source": str(backup),
                 "broker_systemd_dir": str(units)}  # fmt: skip
        (tmp_path / "lib" / "state").mkdir(parents=True)
        (tmp_path / "a").mkdir()
    else:
        (units / "hnx-events.service").write_text("[Unit]\n")
        backup.mkdir()
        (backup / "jetstream").mkdir()
        extra = {"events_bus_store_dir": str(tmp_path / "store"), "events_bus_user": user,
                 "events_bus_group": group, "events_bus_restore_source": str(backup),
                 "events_bus_systemd_dir": str(units)}  # fmt: skip
        (tmp_path / "store").mkdir()
    env = {"PATH": f"{bindir}:{os.environ['PATH']}"}
    calls = log
    # the broker both ways; the bus's hook has the same shape, so start=false alone there
    for start in (False, True) if role == "broker" else (False,):
        calls.unlink(missing_ok=True)
        flag = {"broker_start" if role == "broker" else "events_bus_start": start}
        r = run_role(tmp_path, role, "restore", {**extra, **flag}, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        asked = [line.split()[1:] for line in calls.read_text().splitlines()
                 if line.split()[1] in ("stop", "start")]  # fmt: skip
        unit = "hnx-broker.service" if role == "broker" else "hnx-events.service"
        assert ["stop", unit] in asked, asked
        assert not any("relay" in " ".join(a) for a in asked if a[0] == "stop"), asked
        assert (["start", unit] in asked) is start, asked


def test_broker_prunes_handlers_no_longer_listed(tmp_path):
    """Round 4: a handler dropped from broker_handlers leaves staged/handlers/ before the
    validation, and (round 5) handlers/ only after the broker restarted onto the validated
    manifest; a re-run is changed=0."""
    user, group = _me()
    conf = tmp_path / "etc"
    (conf / "handlers").mkdir(parents=True)  # main's
    hnx = fake(tmp_path / "hnx", "import sys\nsys.exit(0)\n")
    src = tmp_path / "src"
    src.mkdir()
    keep, drop = src / "keep.sh", src / "drop.sh"
    for h in (keep, drop):
        h.write_text("#!/bin/sh\n")
    manifest = tmp_path / "m.yml"
    manifest.write_text("manifest_id: next\n")
    base = {"broker_config_dir": str(conf), "broker_hnx_bin": hnx, "broker_group": group,
            "broker_config_owner": user, "broker_manifest": str(manifest)}  # fmt: skip
    r = run_role(
        tmp_path, "broker", "manifest", {**base, "broker_handlers": [str(keep), str(drop)]}
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert {p.name for p in (conf / "handlers").iterdir()} == {"keep.sh", "drop.sh"}
    (conf / "handlers" / ".stray").write_text("x")  # anything else there goes too
    r = run_role(tmp_path, "broker", "manifest", {**base, "broker_handlers": [str(keep)]})
    assert r.returncode == 0, r.stdout + r.stderr
    assert {p.name for p in (conf / "staged/handlers").iterdir()} == {"keep.sh"}
    # round 5: the live one stays until the broker has restarted onto the new manifest (main
    # prunes after the restart: the running broker may still name it until then)
    assert {p.name for p in (conf / "handlers").iterdir()} == {"keep.sh", "drop.sh", ".stray"}
    r = run_role(tmp_path, "broker", "prune_handlers", {**base, "broker_handlers": [str(keep)]})
    assert r.returncode == 0, r.stdout + r.stderr
    assert {p.name for p in (conf / "handlers").iterdir()} == {"keep.sh"}
    for entry in ("manifest", "prune_handlers"):
        again = run_role(tmp_path, "broker", entry, {**base, "broker_handlers": [str(keep)]})
        assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    main = yaml.safe_load((ROLES / "broker/tasks/main.yml").read_text())
    names = [t.get("name", "") for t in main]
    start = names.index(next(n for n in names if n.startswith("Enable and start the broker,")))
    assert names.index("Remove the live handlers no longer listed") > start


def _runtime_vars(tmp_path, python):
    wheel = tmp_path / "homelabnext-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"not really a wheel")
    return {**RUNTIME, "hnx_runtime_wheel": str(wheel),
            "hnx_runtime_wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "hnx_runtime_prefix": str(tmp_path / "opt"), "hnx_runtime_python": python,
            "hnx_runtime_os_packages": []}  # fmt: skip


def _release(stdout: str) -> str:
    """The release name the role chose, from ``-v`` output of its set_fact."""
    for line in stdout.splitlines():
        if '"hnx_runtime_release"' in line:
            return line.split('"hnx_runtime_release":')[1].split('"')[1]
    raise AssertionError(stdout)


def test_hnx_runtime_check_mode_on_a_fresh_host_and_the_interpreter_version(tmp_path):
    """``--check`` on a host without the release passes (no wheel there to hash yet), and the
    release is named by the interpreter's full version as well as its path: the same
    /usr/bin/python3 after a distribution upgrade is a new release, built again."""
    python = tmp_path / "python3"
    version = tmp_path / "version"
    fake(python, f"import sys\nprint(open({str(version)!r}).read())\n")
    names = []
    for v in ("3.13.5 (main) [GCC 14]", "3.13.7 (main) [GCC 14]"):
        version.write_text(v)
        r = run_role(tmp_path, "hnx_runtime", "main", _runtime_vars(tmp_path, str(python)),
                     verbose=True, check=True)  # fmt: skip
        assert r.returncode == 0, r.stdout + r.stderr
        assert not (tmp_path / "opt").exists()  # --check wrote nothing
        names.append(_release(r.stdout))
    assert names[0] != names[1]
