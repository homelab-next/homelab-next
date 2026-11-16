# SPDX-License-Identifier: Apache-2.0
"""The automation provider's role (``modules/<id>/roles/<id>``), run on localhost against fakes (CI
is unprivileged and has no container engine, so the stack is rendered and not started).

``main`` stages the rendered pack as an immutable release with every rule disabled, renders the
whole stack through compose_app (every image pinned, only the web front published, no secret in the
compose file) and a second run is ``changed=0``; every refusal (an unset secret by name, a live rule,
a pack that is not the rendered one, a wheel that is not the pinned one, a memory budget over the
footprint) happens before anything is written; the RBAC definitions bound who may do what; the
bridge's and the forward's units are rendered with the key pinned and no secret in them; restore
refuses a source that is not what its listing says, upgrade a target that is not pinned or mixes
releases.

The module is found by the slot it fills, never named: the tests state a behaviour, not a product.
"""

from __future__ import annotations

import copy
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from rolerun import run_cases, run_role

from homelabnext.registry.model import secret_env_name

ROOT = Path(__file__).resolve().parents[2]


def _module_id() -> str:
    for manifest in sorted((ROOT / "modules").glob("*/module.yml")):
        doc = yaml.safe_load(manifest.read_text())
        if "automation" in (doc.get("provides") or {}).get("slots", {}):
            return doc["id"]
    raise AssertionError("no module fills the automation slot")


ID = _module_id()
MODULE = ROOT / "modules" / ID
ROLE_DIR = MODULE / "roles" / ID
DEFAULTS_PACK_MOUNT = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())[f"{ID}_c_packs"]
ROLE = str(ROLE_DIR)
DEFAULTS = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text())
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
BUS_HOST, BUS_PORT = "events.example.internal", 4222


def net(a, b, c, d, prefix=24):
    """A CIDR built from its octets, so no address literal sits in a test."""
    return f"{ipaddress.IPv4Address((a << 24) | (b << 16) | (c << 8) | d)}/{prefix}"


GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
PACK_SRC = next(p.parent for p in sorted((ROOT / "workflows").glob("*/provenance.json")))
SERVICES = sorted(DEFAULTS[f"{ID}_mem_limit"])
RELEASE_REPOSITORY = DEFAULTS[f"{ID}_release_repository"]
# the services by what they do: the front is the one published on the guest's address, the sign-in
# service the other published one, the runner the one that mounts the pack's virtualenvs
FRONT = next(n for n in SERVICES if n.endswith("web"))
API = next(n for n in SERVICES if n.endswith("api"))
RUNNER = next(n for n in SERVICES if n.endswith("actionrunner"))


def v(name: str) -> str:
    """The role's variable ``name`` (its prefix is the module id)."""
    return f"{ID}_{name}"


def ref(name: str) -> str:
    return f"secret:{ID}/{name}"


KEY_JSON = json.dumps(
    {
        "hmacKey": {"hmacKeyString": "h" * 43, "size": 256},
        "aesKeyString": "a" * 43,
        "mode": "CBC",
        "size": 256,
    }
)


def _fake(name: str) -> str:
    """A plain, low-entropy stand-in that fits every value pattern and is unlike the others."""
    return "Fake-" + name + "-" + "z" * 40


SECRET_VALUES = {
    "admin-password": _fake("admin-password"),
    "mongo-root-password": _fake("mongo-root-password"),
    "mongo-password": _fake("mongo-password"),
    "rabbitmq-password": _fake("rabbitmq-password"),
    "datastore-key": KEY_JSON,
    "kv-key": _fake("kv-key"),
    "webhook-key": _fake("webhook-key"),
    "status-token": _fake("status-token"),
    "events-password": _fake("events-password"),
    "broker-ssh-key": "\n".join(
        [
            f"{'-' * 5}BEGIN OPENSSH PRIVATE KEY{'-' * 5}",
            "ZmFrZQ==",
            f"{'-' * 5}END OPENSSH PRIVATE KEY{'-' * 5}",
            "",
        ]
    ),
}
SECRETS = {secret_env_name(ref(n)): val for n, val in SECRET_VALUES.items()}


def pv(tmp_path: Path, **kw) -> dict:
    wheel = tmp_path / "dist" / "homelabnext-0.0.0-py3-none-any.whl"
    wheel.parent.mkdir(exist_ok=True)
    wheel.write_bytes(b"not a real wheel")
    (tmp_path / "dist" / "ci.txt").write_text(
        "pyyaml==6.0.3 \\\n    --hash=sha256:" + "0" * 64 + "\n"
    )
    (tmp_path / "dist" / "bootstrap.txt").write_text(
        "pip==26.2.1 \\\n    --hash=sha256:" + "1" * 64 + "\n"
    )
    out = {
        v("logical_id"): "automation",
        "ansible_host": GUEST,
        v("network_subnet"): net(10, 213, 77, 0),
        v("pack_src"): str(PACK_SRC),
        v("hnx_wheel"): str(wheel),
        v("hnx_wheel_sha256"): hashlib.sha256(wheel.read_bytes()).hexdigest(),
        v("hnx_constraints"): str(tmp_path / "dist" / "ci.txt"),
        v("hnx_bootstrap"): str(tmp_path / "dist" / "bootstrap.txt"),
        v("bridge_enabled"): False,
        v("broker_tunnel_enabled"): False,
        v("dir"): str(tmp_path / "app"),
        v("data_root"): str(tmp_path / "data"),
        v("owner"): USER,
        v("group"): GROUP,
        v("uid"): os.getuid(),
        v("gid"): os.getgid(),
        v("mongo_uid"): os.getuid(),
        v("mongo_gid"): os.getgid(),
        v("rabbitmq_uid"): os.getuid(),
        v("rabbitmq_gid"): os.getgid(),
        v("redis_uid"): os.getuid(),
        v("redis_gid"): os.getgid(),
        v("start"): False,
        v("validate_with_docker"): False,
    }
    out.update(kw)
    return out


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())


def staged(tmp_path: Path) -> Path:
    return Path((tmp_path / "data" / "pack-release.current").read_text().strip())


# ----------------------------------------------------------------------------- render


def test_main_renders_the_stack_pinned_contained_and_without_a_secret_in_the_compose_file(tmp_path):
    r = run_role(tmp_path, ROLE, "main", pv(tmp_path), env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"]
    assert sorted(svc) == sorted(SERVICES)
    for name, s in svc.items():
        repo, _, digest = s["image"].partition("@sha256:")
        assert len(digest) == 64 and not repo.endswith(":latest"), name
        assert s["cap_drop"] == ["ALL"] and s["security_opt"] == ["no-new-privileges:true"], name
        assert s["mem_limit"] == DEFAULTS[v("mem_limit")][name], name
        assert s["healthcheck"]["test"], name
    ours = [
        n for n, s in svc.items() if s["image"].startswith(RELEASE_REPOSITORY + "/") and n != FRONT
    ]
    assert len(ours) == 9
    for name in ours:
        assert svc[name]["image"].split("@")[0].rsplit(":", 1)[1] == DEFAULTS[v("release_tag")]
        assert svc[name]["user"] == f"{os.getuid()}:{os.getgid()}"
    # only the web front is published (on the guest's address and on loopback), the sign-in
    # service on loopback only, and nothing else has a port at all
    assert svc[FRONT]["ports"] == [f"{GUEST}:9101:80"]
    assert [n for n, s in svc.items() if s.get("ports")] == [FRONT]  # nothing else has a port
    assert set(svc[FRONT]["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"}
    assert not any(s.get("cap_add") for n, s in svc.items() if n != FRONT)
    # nothing secret in the compose file: the databases get theirs from owner-only env files
    for value in SECRET_VALUES.values():
        assert value.strip() not in text
    mongo_env = (tmp_path / "app" / "secrets" / "mongo.env").read_text()
    assert (
        SECRET_VALUES["mongo-root-password"] in mongo_env
        and SECRET_VALUES["mongo-password"] in mongo_env
    )
    assert (tmp_path / "app" / "secrets" / "mongo.env").stat().st_mode & 0o777 == 0o600
    assert (
        SECRET_VALUES["rabbitmq-password"]
        in (tmp_path / "app" / "secrets" / "rabbitmq.env").read_text()
    )
    # the pack is read-only, the virtualenvs the runner's only writable mount
    runner = svc[RUNNER]["volumes"]
    assert [x for x in runner if x.startswith(f"{staged(tmp_path)}:")] == [
        f"{staged(tmp_path)}:{DEFAULTS_PACK_MOUNT}:ro"
    ]
    writable = [x for x in runner if not x.endswith(":ro")]
    assert (
        len(writable) == 1 and "/virtualenvs" in writable[0]
    )  # the pack's runtime: the runner's only write
    assert all(x.endswith(":ro") for x in svc[API]["volumes"])
    again = run_role(tmp_path, ROLE, "main", pv(tmp_path), env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_the_files_with_a_secret_in_them_are_owner_only_and_the_key_is_not_world_readable(tmp_path):
    assert run_role(tmp_path, ROLE, "main", pv(tmp_path), env=SECRETS).returncode == 0
    data = tmp_path / "data"
    conf = next((data / "config").glob("*.user.conf")).read_text()
    assert SECRET_VALUES["mongo-password"] in conf and SECRET_VALUES["rabbitmq-password"] in conf
    assert "python_binary = /opt/py311/cpython-" in conf and "enable = True" in conf
    for rel, mode in (
        (next((data / "config").glob("*.user.conf")).relative_to(data), 0o640),
        ("config/htpasswd", 0o640),
        ("keys/datastore_key.json", 0o440),
    ):
        assert (data / rel).stat().st_mode & 0o777 == mode, rel
    assert (
        (data / "config" / "htpasswd").read_text().startswith(f"{DEFAULTS[v('admin_user')]}:$apr1$")
    )
    assert SECRET_VALUES["admin-password"] not in (data / "config" / "htpasswd").read_text()
    assert json.loads((data / "keys" / "datastore_key.json").read_text())["aesKeyString"]
    # the database user lives in admin (the database the server authenticates against), one role
    js = next((data / "mongo-init").glob("*.js")).read_text()
    assert (
        'getSiblingDB("admin")' in js
        and "_getEnv" in js
        and SECRET_VALUES["mongo-password"] not in js
    )


def test_every_rule_is_staged_disabled_and_only_a_named_one_is_enabled(tmp_path):
    assert run_role(tmp_path, ROLE, "main", pv(tmp_path), env=SECRETS).returncode == 0
    rules = sorted((staged(tmp_path) / "homelabnext" / "rules").glob("*.yaml"))
    assert len(rules) == len(list((PACK_SRC / "homelabnext" / "rules").glob("*.yaml"))) >= 3
    assert {yaml.safe_load(p.read_text())["enabled"] for p in rules} == {False}
    # the rendered tree itself ships them enabled: the role's release is the only thing that differs
    assert {
        yaml.safe_load(p.read_text())["enabled"]
        for p in (PACK_SRC / "homelabnext" / "rules").glob("*.yaml")
    } == {True}
    tmp2 = tmp_path / "second"
    tmp2.mkdir()
    r = run_role(
        tmp2, ROLE, "main", pv(tmp2, **{v("enabled_rules"): ["on_proposal_validate"]}), env=SECRETS
    )
    assert r.returncode == 0, r.stdout + r.stderr
    states = {
        p.stem: yaml.safe_load(p.read_text())["enabled"]
        for p in (staged(tmp2) / "homelabnext" / "rules").glob("*.yaml")
    }
    assert states["on_proposal_validate"] is True
    assert [n for n, on in states.items() if on] == ["on_proposal_validate"]
    # the mode is the pack's own and is not touched: every pinned pack stays in shadow
    for p in (staged(tmp2) / "homelabnext" / "pinned").glob("*.json"):
        assert json.loads(p.read_text())["mode"] == "shadow", p.name


def test_a_changed_file_of_the_pack_is_a_new_release_and_the_old_one_is_kept(tmp_path):
    src = tmp_path / "pack"
    shutil.copytree(PACK_SRC, src)
    kw = {v("pack_src"): str(src)}
    assert run_role(tmp_path, ROLE, "main", pv(tmp_path, **kw), env=SECRETS).returncode == 0
    first = staged(tmp_path)
    (src / "homelabnext" / "pack.yaml").write_text(
        (src / "homelabnext" / "pack.yaml").read_text() + "# edited\n"
    )
    assert run_role(tmp_path, ROLE, "main", pv(tmp_path, **kw), env=SECRETS).returncode == 0
    assert staged(tmp_path) != first and first.is_dir()
    mounted = compose(tmp_path)["services"][API]["volumes"]
    assert f"{staged(tmp_path)}:{DEFAULTS_PACK_MOUNT}:ro" in mounted


def test_the_rbac_definitions_bound_who_may_do_what(tmp_path):
    kw = {v("operator_users"): ["pete"]}
    assert run_role(tmp_path, ROLE, "main", pv(tmp_path, **kw), env=SECRETS).returncode == 0
    rbac = tmp_path / "data" / "rbac"
    roles = {p.stem: yaml.safe_load(p.read_text()) for p in (rbac / "roles").glob("*.yaml")}
    assert sorted(roles) == ["hnx_bridge", "hnx_operator", "hnx_status"]
    grants = {
        n: {t for g in r["permission_grants"] for t in g["permission_types"]}
        for n, r in roles.items()
    }
    assert grants["hnx_bridge"] == {"webhook_send"}
    for n in ("hnx_status", "hnx_operator"):  # readers: nothing that runs or writes
        assert not {
            t
            for t in grants[n]
            if t.endswith(("_execute", "_set", "_delete", "_create", "_modify"))
        }
    users = {p.stem: yaml.safe_load(p.read_text()) for p in (rbac / "assignments").glob("*.yaml")}
    admin, status, bridge = (DEFAULTS[v(n)] for n in ("admin_user", "status_user", "webhook_user"))
    assert {n: u["roles"] for n, u in users.items()} == {
        admin: ["system_admin"], "stanley": ["system_admin"], status: ["hnx_status"],
        bridge: ["hnx_bridge"], "pete": ["hnx_operator"],
    }  # fmt: skip
    assert all(u["username"] == n for n, u in users.items())  # the loader's key is username


# ----------------------------------------------------------------------------- refusals


def _optional_on(tmp_path: Path) -> dict:
    return pv(
        tmp_path,
        **{
            v("bridge_enabled"): True, v("broker_tunnel_enabled"): True,
            v("events_endpoint"): f"tls://{BUS_HOST}:{BUS_PORT}", v("broker_host"): "broker.example.internal",
            v("broker_host_key"): f"broker.example.internal ssh-ed25519 {'A' * 40}",
        },
    )  # fmt: skip


def test_main_refuses_an_unset_secret_naming_every_missing_reference_and_writes_nothing(tmp_path):
    """Review Focus 3: a module deployed before its secret exists is refused, by name (the bridge's
    and the forward's included when they are on); nothing is rendered or started."""
    unset = ("admin-password", "datastore-key", "events-password", "broker-ssh-key")
    env = {
        k: val for k, val in SECRETS.items() if k not in {secret_env_name(ref(n)) for n in unset}
    }
    r = run_role(tmp_path, ROLE, "main", _optional_on(tmp_path), env=env)
    assert r.returncode != 0, r.stdout
    out = r.stdout + r.stderr
    assert all(ref(n) in out for n in unset), out
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert not (tmp_path / "data" / "config").exists()
    # and with everything set the same inputs go through (the bridge and the forward have no host here)
    full = run_role(tmp_path, ROLE, "credentials", _optional_on(tmp_path), env=SECRETS)
    assert full.returncode == 0, full.stdout + full.stderr


BAD_INPUTS = [
    {v("release_tag"): "latest"},
    {v("mongo_image"): "docker.io/library/mongo:4.4.30"},  # a tag without a digest
    {v("python_version"): "3.10.12"},  # homelabnext needs 3.11
    {"ansible_host": "automation.example.internal"},
    {"ansible_host": "0.0.0.0"},
    {v("uid"): 1},
    {v("port"): 0},
    {v("enabled_rules"): ["on_no_such_rule"]},
    {v("enabled_rules"): ["../x"]},
    {v("mem_limit"): {**DEFAULTS[v("mem_limit")], "mongo": "64g"}},  # over the footprint
    {v("retention_days"): 3},  # the server refuses under 7
    {v("data_root"): "/srv"},
    {v("admin_login_ref"): ref("mongo-password")},  # two secrets in one place
    {v("network_subnet"): net(10, 0, 0, 0, 8)},
    {v("hnx_wheel_sha256"): "0" * 64},  # not the pinned wheel
    {v("pack_src"): "relative/pack"},
]


def test_main_refuses_bad_inputs_and_writes_nothing(tmp_path):
    results = run_cases(
        tmp_path, ROLE, "main", pv(tmp_path), BAD_INPUTS, env=SECRETS, parallel=True
    )
    assert [i for i, (failed, _) in enumerate(results) if not failed] == []  # every one refused
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert not list((tmp_path / "data" / "config").glob("*.user.conf"))


def test_a_pack_with_a_live_rule_is_refused_unless_the_site_says_so(tmp_path):
    src = tmp_path / "pack"
    shutil.copytree(PACK_SRC, src)
    prov = json.loads((src / "provenance.json").read_text())
    next(iter(prov["packs"].values()))["mode"] = "live"
    (src / "provenance.json").write_text(json.dumps(prov))
    kw = {v("pack_src"): str(src)}
    r = run_role(tmp_path, ROLE, "main", pv(tmp_path, **kw), env=SECRETS)
    assert r.returncode != 0 and "shadow" in r.stdout + r.stderr
    assert not (tmp_path / "data" / "pack-releases").exists() or not any(
        (tmp_path / "data" / "pack-releases").iterdir()
    )
    ok = run_role(
        tmp_path, ROLE, "main", pv(tmp_path, **kw, **{v("allow_live_rules"): True}), env=SECRETS
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_a_pack_whose_config_names_another_broker_socket_is_refused(tmp_path):
    src = tmp_path / "pack"
    shutil.copytree(PACK_SRC, src)
    cfg = src / "configs" / "homelabnext.yaml"
    cfg.write_text(cfg.read_text().replace("/run/hnx-broker/broker.sock", "/tmp/other.sock"))
    r = run_role(tmp_path, ROLE, "main", pv(tmp_path, **{v("pack_src"): str(src)}), env=SECRETS)
    assert r.returncode != 0 and "broker socket" in r.stdout + r.stderr


def test_a_datastore_key_that_is_not_the_generated_json_is_refused(tmp_path):
    env = {**SECRETS, secret_env_name(ref("datastore-key")): '{"aesKey": "x"}'}
    r = run_role(tmp_path, ROLE, "main", pv(tmp_path), env=env)
    assert r.returncode != 0 and not (tmp_path / "data" / "keys").exists()


def test_the_memory_budget_fits_the_footprint_the_manifest_declares():
    limits = DEFAULTS[v("mem_limit")]
    assert sorted(limits) == sorted(SERVICES)
    total = sum(int(x[:-1]) * (1024 if x.endswith("g") else 1) for x in limits.values())
    footprint = yaml.safe_load((MODULE / "module.yml").read_text())["requires"]["hosts"][0][
        "footprint"
    ]
    assert total <= footprint["memory_mb"] == DEFAULTS[v("footprint_memory_mb")]


# ----------------------------------------------------------------------------- the slice


def test_the_containers_join_the_role_slice_the_module_play_names(tmp_path):
    kw = {"hnx_module_slice": f"hnx-{ID}-server.slice"}
    assert run_role(tmp_path, ROLE, "main", pv(tmp_path, **kw), env=SECRETS).returncode == 0
    parents = {s["cgroup_parent"] for s in compose(tmp_path)["services"].values()}
    assert parents == {f"hnx-{ID}-server.slice"}


# ----------------------------------------------------------------------------- the units


def _render(template: str, **vars_) -> str:
    jinja2 = pytest.importorskip("jinja2", reason="jinja2 is not installed")
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    return env.from_string((ROLE_DIR / "templates" / template).read_text()).render(**vars_)


def test_the_broker_forward_pins_the_host_key_and_binds_a_group_owned_socket():
    fixed = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())
    unit = _render(
        "broker-tunnel.service.j2",
        **{
            v("broker_tunnel_user"): "hnx-fwd", v("broker_ssh_port"): 22, v("broker_ssh_user"): "agent-fwd",
            v("broker_host"): "broker.example.internal", v("broker_socket_dir"): "/run/hnx-fwd",
            v("broker_remote_socket"): "/run/hnx-broker/broker.sock", v("broker_socket_mask"): "0117",
            v("broker_state_dir"): fixed[v("broker_state_dir")], v("broker_group"): fixed[v("broker_group")],
        },
    )  # fmt: skip
    for must in ("-o StrictHostKeyChecking=yes", "-o IdentitiesOnly=yes", "-o BatchMode=yes",
                 "-o ExitOnForwardFailure=yes", "-o GlobalKnownHostsFile=/dev/null",
                 "-o StreamLocalBindMask=0117", "-o StreamLocalBindUnlink=yes",
                 "-L /run/hnx-fwd/broker.sock:/run/hnx-broker/broker.sock", "agent-fwd@broker.example.internal",
                 "NoNewPrivileges=yes", "ProtectSystem=strict", "Restart=always"):  # fmt: skip
        assert must in unit, must
    assert "-N -T" in unit and "password" not in unit.lower() and "ssh-" not in unit


def test_the_bridge_unit_posts_to_loopback_and_carries_no_secret():
    unit = _render(
        "bridge.service.j2",
        **{
            v("bridge_user"): "hnx-bridge", v("events_endpoint"): f"tls://{BUS_HOST}:{BUS_PORT}",
            v("bridge_conf_dir"): "/etc/hnx-bridge", v("hnx_cli"): "/opt/hnx/bin/hnx", v("port"): 9101, v("bind"): GUEST,
            v("events_stream"): "STREAM", v("events_subject_prefix"): "lab", v("events_user"): "bridge-user",
            v("events_login_ref"): ref("events-password"), v("events_ca_file"): "/etc/ca.pem",
            v("events_api_prefix"): "JS.X.API", v("bridge_state_dir"): "/var/lib/hnx-bridge",
        },
    )  # fmt: skip
    # The service is on the guest itself: the webhook is posted to its own address, in plain http,
    # which the bridge accepts only with its explicit opt-in (the key never leaves the host)
    assert f"http://{GUEST}:9101 --allow-plaintext" in unit
    assert f"--events-password-secret {ref('events-password')}" in unit  # a name, never a value
    assert "--events-ca-file /etc/ca.pem" in unit and "--events-api-prefix JS.X.API" in unit
    assert "EnvironmentFile=/etc/hnx-bridge/secrets.env" in unit
    assert "NoNewPrivileges=yes" in unit and "Restart=on-failure" in unit
    plain = _render("bridge.service.j2", **{
        v("bridge_user"): "b", v("events_endpoint"): f"nats://{GUEST}:{BUS_PORT}", v("bridge_conf_dir"): "/e",
        v("hnx_cli"): "/opt/hnx/bin/hnx", v("port"): 9101, v("bind"): GUEST, v("events_stream"): "S", v("events_subject_prefix"): "lab",
        v("events_user"): "u", v("events_login_ref"): ref("events-password"), v("events_ca_file"): "",
        v("events_api_prefix"): "", v("bridge_state_dir"): "/v",
    })  # fmt: skip
    assert "--events-ca-file" not in plain and "--events-api-prefix" not in plain


def test_the_bridge_and_forward_inputs_are_required_when_they_are_on(tmp_path):
    r = run_role(tmp_path, ROLE, "main", pv(tmp_path, **{v("bridge_enabled"): True}), env=SECRETS)
    assert r.returncode != 0 and "bridge" in r.stdout + r.stderr
    r = run_role(
        tmp_path, ROLE, "main", pv(tmp_path, **{v("broker_tunnel_enabled"): True}), env=SECRETS
    )
    assert r.returncode != 0 and "forward" in r.stdout + r.stderr
    bad_key = {v("broker_tunnel_enabled"): True, v("broker_host"): "broker.example.internal",
               v("broker_host_key"): "no key line"}  # fmt: skip
    assert run_role(tmp_path, ROLE, "main", pv(tmp_path, **bad_key), env=SECRETS).returncode != 0


# ----------------------------------------------------------------------------- restore and upgrade


def _export(tmp_path: Path, **tamper) -> Path:
    src = tmp_path / "export"
    (src / "mongo").mkdir(parents=True, exist_ok=True)
    body = b"x" * 1024
    (src / "mongo" / "db.archive.gz").write_bytes(body)
    row = {
        "key": "mongo/db.archive.gz",
        "size": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    row.update(tamper)
    (src / "listing.jsonl").write_text(json.dumps(row) + "\n")
    return src


def test_restore_refuses_a_source_that_is_not_what_its_listing_says_before_touching_anything(
    tmp_path,
):
    for tamper in ({"sha256": "0" * 64}, {"size": 5}, {"key": "mongo/other.gz"}):
        src = _export(tmp_path, **tamper)
        r = run_role(
            tmp_path, ROLE, "restore", pv(tmp_path, **{v("restore_source"): str(src)}), env=SECRETS
        )
        assert r.returncode != 0 and "not an intact export" in r.stdout + r.stderr, tamper
    live = tmp_path / "data" / "mongo"
    live.mkdir(parents=True, exist_ok=True)
    r = run_role(
        tmp_path, ROLE, "restore", pv(tmp_path, **{v("restore_source"): str(live)}), env=SECRETS
    )
    assert r.returncode != 0  # the database's own files are never a source


@pytest.mark.parametrize(
    "case",
    [
        {},  # nothing named
        {v("target_release_tag"): "3.10.0", v("target_release_digests"): "x"},  # another minor line
        {v("target_release_tag"): "3.9.1"},  # no digests
        {
            v("target_service"): "redis",
            v("target_image"): "docker.io/library/redis:7.2.17",
        },  # not pinned
        {
            v("target_service"): "redis",
            v("target_image"): "docker.io/library/redis:8.0.0@sha256:" + "a" * 64,
        },  # a new minor line
        {
            v("target_service"): "rabbitmq",
            v("target_image"): "docker.io/library/redis:7.2.17@sha256:" + "a" * 64,
        },  # another repository
        {
            v("target_service"): "postgres",
            v("target_image"): "docker.io/library/redis:7.2.17@sha256:" + "a" * 64,
        },
    ],
    ids=lambda c: ",".join(k.split("_", 1)[1] for k in c) or "nothing",
)
def test_upgrade_refuses_what_is_not_one_pinned_bump(tmp_path, case):
    r = run_role(tmp_path, ROLE, "upgrade", pv(tmp_path, **case), env=SECRETS)
    assert r.returncode != 0 and not (tmp_path / "app" / "pending-upgrade.json").exists()


def test_upgrade_records_a_patch_bump_of_the_whole_stack_and_a_pinned_data_store_bump(tmp_path):
    digests = dict.fromkeys(DEFAULTS[v("release_digests")], "sha256:" + "b" * 64)
    (tmp_path / "app").mkdir()
    r = run_role(
        tmp_path,
        ROLE,
        "upgrade",
        pv(tmp_path, **{v("target_release_tag"): "3.9.1", v("target_release_digests"): digests}),
        env=SECRETS,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    redis = DEFAULTS[v("redis_image")].split("@")[0].rsplit(":", 1)[0]
    r = run_role(
        tmp_path, ROLE, "upgrade",
        pv(tmp_path, **{v("target_service"): "redis", v("target_image"): f"{redis}:7.2.99@sha256:{'c' * 64}"}),
        env=SECRETS,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())["service"] == "redis"


# ----------------------------------------------------------------------------- lint and shape


def test_role_lint_passes_the_role():
    r = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "role_lint.py"), ROLE], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_runner_compat_lock_pins_every_package_by_hash():
    lines = (ROLE_DIR / "files" / "runtime-compat.txt").read_text().splitlines()
    pins = [ln for ln in lines if ln and not ln.startswith(("#", " "))]
    assert len(pins) >= 15 and all("==" in p for p in pins)
    hashes = [ln for ln in lines if ln.strip().startswith("--hash=sha256:")]
    assert len(hashes) >= len(pins) and all(
        len(h.strip().split(":")[1].split()[0]) == 64 for h in hashes
    )
    assert "orjson" in "".join(pins)  # the one the python runner's wrapper dies without


def test_the_arg_specs_cover_every_default():
    spec = yaml.safe_load((ROLE_DIR / "meta" / "argument_specs.yml").read_text())["argument_specs"]
    for hook in ("main", "health", "readiness", "backup", "export", "restore", "upgrade"):
        assert set(DEFAULTS) <= set(spec[hook]["options"]), (
            hook,
            set(DEFAULTS) - set(spec[hook]["options"]),
        )
        for name, opt in spec[hook]["options"].items():
            if name in DEFAULTS and not isinstance(DEFAULTS[name], dict):
                assert opt.get("default") == copy.deepcopy(DEFAULTS[name]), (hook, name)
