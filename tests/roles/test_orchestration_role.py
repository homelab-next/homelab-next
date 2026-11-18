# SPDX-License-Identifier: Apache-2.0
"""Role ``orchestration`` (modules/orchestration/roles/orchestration), run on localhost against
fakes and, where a controller's real answers are the point, against the repository's own binary
(CI is unprivileged, so the service user and root's files are the test user's).

* main renders the configuration, the token digests (never a token), the profiles, the homes and
  the unit; the controller's own ``check`` runs on them; a second run is ``changed=0``.
* an unset or malformed credential, a wrong binary, an empty profiles directory and every
  malformed input are refused before a file is written, and a wrong binary never touches the
  release in use.
* what changed decides start, restart, reload or a profile reload, and nothing else restarts it.
* the gateway and the events forwarder are optional, https unless opted out, and never an address.
* health passes on the real controller (including a smoke job to done) and fails on a rotated token
  the host does not hold; export, backup and restore are checked, and refuse a tampered, foreign or
  extra-file export.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.server
import json
import socket
import sqlite3
import subprocess
import threading
import time
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from tests.conform.controller_rig import controller_binary

__all__ = ["controller_binary"]  # the session fixture, imported for its tests

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "orchestration" / "roles" / "orchestration")
USER = subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()
GROUP = subprocess.run(["id", "-gn"], capture_output=True, text=True, check=True).stdout.strip()
GUEST = ".".join(["192", "0", "2", "40"])  # a documentation-range guest address
LOOP = ".".join(["127", "0", "0", "1"])  # the loopback a stand-in listens on
TOKENS = {
    "ADMIN": "A" * 12 + "a" * 28,
    "JOBS": "B" * 12 + "b" * 28,
    "STATUS": "C" * 12 + "c" * 28,
    "METRICS": "D" * 12 + "d" * 28,
}
SECRETS = {f"HNX_SECRET_ORCHESTRATION_{k}_TOKEN": v for k, v in TOKENS.items()}
PROFILE = (
    "id: agent-a-v1\nagent_key: agent-a\ntoolsets: {real: agent-a, shadow: agent-a}\n"
    "local_only: true\ndefault_task_description: A job.\n"
)
SMOKE_ANSWER = "hnx-orchestration-ok"


def free_port() -> int:
    with contextlib.closing(socket.socket()) as s:
        s.bind((LOOP, 0))
        return s.getsockname()[1]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fake_binary(tmp: Path, name: str = "controller-src") -> Path:
    """A controller stand-in: ``check`` succeeds when the configuration it is given exists."""
    p = Path(
        fake(
            tmp / name,
            "import os, sys\n"
            "if sys.argv[1:2] == ['check'] and os.path.isfile(sys.argv[3]):\n"
            f"    open({str(tmp / 'check.log')!r}, 'a').write(sys.argv[3] + '\\n')\n"
            "    sys.exit(0)\nsys.exit(1)\n",
        )
    )
    return p


def vars_for(tmp: Path, binary: Path, **kw) -> dict:
    prof = tmp / "profiles-src"
    prof.mkdir(exist_ok=True)
    if not any(prof.iterdir()):
        (prof / "agent-a.yaml").write_text(PROFILE)
    v = {
        "orchestration_logical_id": "orchestrator",
        "ansible_host": GUEST,
        "orchestration_binary": str(binary),
        "orchestration_binary_sha256": sha(binary),
        "orchestration_profiles_src": str(prof),
        "orchestration_install_dir": str(tmp / "opt" / "hnx-orchestration"),
        "orchestration_config_dir": str(tmp / "etc" / "orchestration"),
        "orchestration_data_root": str(tmp / "var" / "orchestration"),
        "orchestration_systemd_dir": str(tmp / "units"),
        "orchestration_manage_accounts": False,
        "orchestration_owner": USER,
        "orchestration_owner_group": GROUP,
        "orchestration_user": USER,
        "orchestration_group": GROUP,
        "orchestration_start": False,
    }
    v.update(kw)
    (tmp / "units").mkdir(exist_ok=True)
    return v


def tree_text(tmp: Path) -> str:
    out = []
    for p in tmp.rglob("*"):
        if (
            p.is_file()
            and not p.is_symlink()
            and ".ansible" not in p.parts
            and p.stat().st_size < 1 << 20
        ):
            with contextlib.suppress(OSError):
                out.append(p.read_bytes().decode("utf-8", "replace"))
    return "\n".join(out)


@pytest.fixture
def binary(tmp_path) -> Path:
    return fake_binary(tmp_path)


def main(tmp_path, binary, extra_env=None, **kw):
    v = vars_for(tmp_path, binary, **kw)
    return run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **(extra_env or {})}), v


# ----------------------------------------------------------------------------- main


def test_main_renders_the_set_and_a_second_run_changes_nothing(tmp_path, binary):
    r, v = main(tmp_path, binary)
    assert r.returncode == 0, r.stdout + r.stderr
    etc, var = tmp_path / "etc" / "orchestration", tmp_path / "var" / "orchestration"
    cfg = yaml.safe_load((etc / "controller.yaml").read_text())
    assert cfg["db_path"] == str(var / "controller.db")
    assert cfg["http_addr"] == f"{GUEST}:8088"
    assert cfg["api_auth"] == {"enabled": True, "tokens_file": str(etc / "api-tokens.yaml")}
    assert cfg["runner"]["kind"] == "exec" and cfg["runner"]["env_allowlist"] == []
    assert cfg["runner"]["exec"]["argv"][0] == "/bin/sh"
    assert cfg["backends"]["local"]["name"] == "exec"
    assert cfg["backends"]["local"]["max_concurrent"] == 2 and cfg["concurrency"] == 2
    assert cfg["backends"]["local"]["home"] == str(etc / "homes" / "exec")
    assert "lock_path" not in cfg and cfg["lessons_disabled"] is True
    assert cfg["events"] == {"source": "svc:orchestrator", "gateway_tag_prefix": "hnx/"}
    # only digests of the tokens reach the host, in a file the service group reads
    doc = yaml.safe_load((etc / "api-tokens.yaml").read_text())
    by = {t["caller"]: t for t in doc["tokens"]}
    assert by["broker"]["sha256"] == hashlib.sha256(TOKENS["JOBS"].encode()).hexdigest()
    assert by["operator"]["scopes"] == ["admin"] and by["metrics"]["scopes"] == ["metrics"]
    assert oct((etc / "api-tokens.yaml").stat().st_mode & 0o777) == "0o640"
    for t in TOKENS.values():
        assert t not in tree_text(tmp_path) and t not in r.stdout
    # profiles: the site's, and the health check's one agent (the runner is the smoke session)
    assert sorted(p.name for p in (etc / "profiles").iterdir()) == [
        "agent-a.yaml",
        "hnx-health.yaml",
    ]
    assert oct((var).stat().st_mode & 0o777) == "0o750"
    assert oct((var / "export").stat().st_mode & 0o777) == "0o700"
    # the binary: one release by its pin, the link the unit runs, and the controller's own check ran
    rel = (
        tmp_path / "opt" / "hnx-orchestration" / "releases" / v["orchestration_binary_sha256"][:16]
    )
    assert sha(rel / "controller") == v["orchestration_binary_sha256"]
    assert (tmp_path / "opt" / "hnx-orchestration" / "bin" / "controller").resolve() == (
        rel / "controller"
    )
    assert str(etc / "controller.yaml") in (tmp_path / "check.log").read_text()
    unit = (tmp_path / "units" / "hnx-orchestrator.service").read_text()
    assert (
        f"ExecStart={tmp_path}/opt/hnx-orchestration/bin/controller serve --config {etc}/controller.yaml"
        in unit
    )
    assert "ExecStartPre=" in unit and "check --config" in unit
    for hardening in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectProc=invisible",
                      "SystemCallFilter=@system-service", "CapabilityBoundingSet=", "KillMode=mixed",
                      "RestartPreventExitStatus=3", "ExecReload=/bin/kill -HUP $MAINPID",
                      "TasksMax=512", "MemoryMax=2G", "UMask=0077"):  # fmt: skip
        assert hardening in unit
    assert "EnvironmentFile" not in unit and "Slice=" not in unit
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_the_unit_joins_the_module_slice_when_the_play_sets_one(tmp_path, binary):
    r, _ = main(tmp_path, binary, hnx_module_slice="hnx-orchestration-server.slice")
    assert r.returncode == 0, r.stdout + r.stderr
    unit = (tmp_path / "units" / "hnx-orchestrator.service").read_text()
    assert "Slice=hnx-orchestration-server.slice" in unit


def test_sizing_variables_reach_the_configuration_and_the_unit(tmp_path, binary):
    r, _ = main(
        tmp_path, binary,
        orchestration_concurrency=5, orchestration_api_max_unfinished_per_caller=40,
        orchestration_runner_timeout_seconds=900, orchestration_runner_job_timeout_seconds=2400,
        orchestration_runner_stall_timeout_seconds=300, orchestration_orphan_grace_seconds=120,
        orchestration_tasks_max=64, orchestration_memory_max="6G",
        orchestration_interlock_wait_timeout_seconds=90,
        orchestration_backends=[
            {"name": "engine-a", "max_concurrent": 3, "max_context": 32768, "needs_interlock": True},
            {"name": "engine-b", "max_concurrent": 1, "weight": 2, "tags": ["long"]},
        ],
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    cfg = yaml.safe_load((tmp_path / "etc" / "orchestration" / "controller.yaml").read_text())
    assert cfg["concurrency"] == 5 and cfg["api_max_unfinished_per_caller"] == 40
    assert cfg["runner"]["timeout_seconds"] == 900 and cfg["runner"]["job_timeout_seconds"] == 2400
    assert cfg["runner"]["stall_timeout_seconds"] == 300 and cfg["orphan_grace_seconds"] == 120
    assert cfg["backends"]["local"] | {"home": ""} == {
        "name": "engine-a", "home": "", "max_concurrent": 3, "max_context": 32768,
        "needs_interlock": True,
    }  # fmt: skip
    (extra,) = cfg["backends"]["additional"]
    assert extra["name"] == "engine-b" and extra["weight"] == 2 and extra["tags"] == ["long"]
    assert extra["needs_interlock"] is False
    assert cfg["lock_path"] == "/run/hnx-orchestrator/interlock.lock"
    assert cfg["interlock_wait_timeout_seconds"] == 90
    unit = (tmp_path / "units" / "hnx-orchestrator.service").read_text()
    assert "TasksMax=64" in unit and "MemoryMax=6G" in unit
    assert sorted(p.name for p in (tmp_path / "etc" / "orchestration" / "homes").iterdir()) == [
        "engine-a", "engine-b"]  # fmt: skip


@pytest.mark.parametrize("name", sorted(TOKENS))
def test_an_unset_credential_is_refused_naming_it_and_nothing_is_written(tmp_path, binary, name):
    env = {k: v for k, v in SECRETS.items() if k != f"HNX_SECRET_ORCHESTRATION_{name}_TOKEN"}
    v = vars_for(tmp_path, binary)
    r = run_role(tmp_path, ROLE, "main", v, env=env)
    assert r.returncode != 0
    assert f"orchestration/{name.lower()}-token" in r.stdout + r.stderr
    assert not (tmp_path / "etc").exists() and not (tmp_path / "opt").exists()
    assert not (tmp_path / "units" / "hnx-orchestrator.service").exists()


def test_a_short_token_and_a_token_two_callers_share_are_refused(tmp_path, binary):
    short = dict(SECRETS, HNX_SECRET_ORCHESTRATION_JOBS_TOKEN="too-short")
    r = run_role(tmp_path, ROLE, "main", vars_for(tmp_path, binary), env=short)
    assert r.returncode != 0 and "32 to 256 characters" in r.stdout + r.stderr
    shared = dict(SECRETS, HNX_SECRET_ORCHESTRATION_STATUS_TOKEN=TOKENS["JOBS"])
    r = run_role(tmp_path, ROLE, "main", vars_for(tmp_path, binary), env=shared)
    assert r.returncode != 0 and "shared tokens: True" in r.stdout + r.stderr
    assert TOKENS["JOBS"] not in r.stdout + r.stderr
    assert not (tmp_path / "etc").exists()


def test_a_wrong_binary_is_refused_and_the_release_in_use_is_untouched(tmp_path, binary):
    r, v = main(tmp_path, binary)
    assert r.returncode == 0, r.stdout + r.stderr
    install = tmp_path / "opt" / "hnx-orchestration"
    old = install / "releases" / v["orchestration_binary_sha256"][:16]
    before = (old / "controller").read_bytes()
    # a new pin whose file is some other binary: refused, and nothing in use moves
    other = Path(fake(tmp_path / "other", "import sys\nsys.exit(0)\n"))
    pin = "ab" * 32
    bad = dict(v, orchestration_binary=str(other), orchestration_binary_sha256=pin)
    r = run_role(tmp_path, ROLE, "main", bad, env=SECRETS)
    assert r.returncode != 0 and "the pin is " + pin in r.stdout + r.stderr
    assert (old / "controller").read_bytes() == before
    assert (install / "current").resolve() == old
    assert not list(install.rglob(".controller.incoming"))
    assert (install / "bin" / "controller").resolve() == old / "controller"
    # the right file for a new pin installs beside the old one and switches to it; the old release
    # is kept (a rollback is the old pin again)
    new = Path(fake(tmp_path / "next", "import sys\nsys.exit(0)\n"))
    good = dict(v, orchestration_binary=str(new), orchestration_binary_sha256=sha(new))
    r = run_role(tmp_path, ROLE, "main", good, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (install / "current").resolve().name == sha(new)[:16]
    assert (old / "controller").read_bytes() == before
    # a release that already holds its pinned binary is never recopied: a wrong source file for the
    # old pin changes nothing
    r = run_role(tmp_path, ROLE, "main", dict(v, orchestration_binary=str(other)), env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (old / "controller").read_bytes() == before
    assert (install / "current").resolve() == old


def test_an_empty_profiles_directory_and_a_profile_that_shadows_the_health_check_are_refused(
    tmp_path, binary
):
    v = vars_for(tmp_path, binary)
    empty = tmp_path / "empty"
    empty.mkdir()
    r = run_role(
        tmp_path, ROLE, "main", dict(v, orchestration_profiles_src=str(empty)), env=SECRETS
    )
    assert r.returncode != 0 and "holds no *.yaml profile" in r.stdout + r.stderr
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "hnx-health.yaml").write_text(PROFILE)
    r = run_role(
        tmp_path, ROLE, "main", dict(v, orchestration_profiles_src=str(shadow)), env=SECRETS
    )
    assert r.returncode != 0 and "is the health check's" in r.stdout + r.stderr


def test_a_profile_the_site_dropped_is_removed_and_the_health_profile_follows_the_runner(
    tmp_path, binary
):
    src = tmp_path / "profiles-src"
    src.mkdir()
    (src / "agent-a.yaml").write_text(PROFILE)
    (src / "agent-b.yaml").write_text(PROFILE.replace("agent-a", "agent-b"))
    r, v = main(tmp_path, binary)
    assert r.returncode == 0, r.stdout + r.stderr
    prof = tmp_path / "etc" / "orchestration" / "profiles"
    assert sorted(p.name for p in prof.iterdir()) == [
        "agent-a.yaml",
        "agent-b.yaml",
        "hnx-health.yaml",
    ]
    (src / "agent-b.yaml").unlink()
    (prof / "notes.txt").write_text("not a profile")  # only *.yaml files are the role's
    again = dict(v, orchestration_runner_argv=["/usr/local/bin/real-agent", "--home", "{home}"])
    r = run_role(tmp_path, ROLE, "main", again, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert sorted(p.name for p in prof.iterdir()) == ["agent-a.yaml", "notes.txt"]
    # a real agent's command is never started by a health check
    cfg = yaml.safe_load((tmp_path / "etc" / "orchestration" / "controller.yaml").read_text())
    assert cfg["runner"]["exec"]["argv"] == ["/usr/local/bin/real-agent", "--home", "{home}"]


BAD = [
    ("bind_name", {"orchestration_bind": "orchestrator.example.internal"}),
    ("bind_all", {"orchestration_bind": "0.0.0.0"}),
    ("port", {"orchestration_port": 70000}),
    ("concurrency", {"orchestration_concurrency": 0}),
    ("root_user", {"orchestration_user": "root"}),
    ("shallow_path", {"orchestration_config_dir": "/etc"}),
    ("same_dirs", {"orchestration_config_dir": "{install}"}),
    ("relative_argv", {"orchestration_runner_argv": ["agent", "--run"]}),
    ("memory", {"orchestration_memory_max": "plenty"}),
    ("scope_missing_key", {"orchestration_scope": {"denied_roots": ["owner"]}}),
    ("lessons_on", {"orchestration_lessons_disabled": False}),
    ("health_job", {"orchestration_health_job": "maybe"}),
    ("no_backend", {"orchestration_backends": []}),
    ("dup_backend", {"orchestration_backends": [{"name": "a"}, {"name": "a"}]}),
    ("unknown_backend_key", {"orchestration_backends": [{"name": "a", "base_url": "https://x"}]}),
    ("string_interlock", {"orchestration_backends": [{"name": "a", "needs_interlock": "yes"}]}),
    ("role_without_gateway", {"orchestration_backends": [{"name": "a", "role": "main-reasoner"}]}),
    ("gateway_without_role", {"orchestration_gateway_id": "llm-gateway"}),
    ("private_address_in_a_probe", {"orchestration_backends": [{"name": "a", "health_url": "http://" + ".".join(["10", "1", "2", "3"]) + ":8000/health"}]}),
    ("cgnat_tailnet_address", {"orchestration_backends": [{"name": "a", "health_url": "http://" + ".".join(["100", "100", "100", "100"]) + ":80/h"}]}),
    ("cgnat_low_edge", {"orchestration_backends": [{"name": "a", "endpoint": "http://" + ".".join(["100", "64", "0", "1"]) + ":80"}]}),
    ("localhost_probe", {"orchestration_backends": [{"name": "a", "health_url": "http://local" + "host:8000/health"}]}),
    ("bare_mnt_drive", {"orchestration_runner_argv": ["/mnt" + "/c"]}),
    ("decimal_ipv4_probe", {"orchestration_backends": [{"name": "a", "health_url": "http://" + "32" + "32235777/h"}]}),
    ("hex_ipv4_probe", {"orchestration_backends": [{"name": "a", "health_url": "http://0x" + "7f000001/h"}]}),
    ("ipv6_literal_probe", {"orchestration_backends": [{"name": "a", "health_url": "http://[" + "fd00" + "::1]:8000/h"}]}),
    ("ipv6_link_local_probe", {"orchestration_backends": [{"name": "a", "health_url": "http://[" + "fe80" + "::1%eth0]/h"}]}),
    ("decimal_forwarder_host", {"orchestration_events_forwarder_url": "https://" + "32" + "32235777/in"}),
    ("localhost_forwarder_host", {"orchestration_events_forwarder_url": "https://local" + "host/in"}),
    ("workstation_path", {"orchestration_runner_argv": ["/mnt" + "/c/Users/x/agent.exe"]}),
    ("wsl_in_argv", {"orchestration_runner_argv": ["/usr/bin/wsl", "agent"]}),
    ("plain_http_forwarder", {"orchestration_events_forwarder_url": "http://events.example.internal/in"}),
    ("address_forwarder", {"orchestration_events_forwarder_url": "https://" + ".".join(["198", "51", "100", "9"]) + "/in"}),
    ("caller_scope", {"orchestration_extra_callers": [{"name": "x", "secret": "secret:orchestration/x", "scopes": ["root"]}]}),
    ("caller_reuses_ref", {"orchestration_extra_callers": [{"name": "x", "secret": "secret:orchestration/jobs-token", "scopes": ["jobs"]}]}),
]  # fmt: skip


@pytest.mark.parametrize("case,over", BAD, ids=[c for c, _ in BAD])
def test_malformed_inputs_are_refused_before_a_file_is_written(tmp_path, binary, case, over):
    v = vars_for(tmp_path, binary)
    over = {k: (v["orchestration_install_dir"] if x == "{install}" else x) for k, x in over.items()}
    r = run_role(tmp_path, ROLE, "main", {**v, **over}, env=SECRETS)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "etc").exists() and not (tmp_path / "opt").exists()


# ----------------------------------------------------------------------------- gateway, events


def registry(tmp: Path, **rows) -> Path:
    doc = {
        "services": {
            k: dict(zip(("host", "port", "scheme"), v, strict=True)) for k, v in rows.items()
        }
    }
    p = tmp / "registry.yml"
    p.write_text(yaml.safe_dump(doc))
    return p


def test_a_gateway_is_found_in_the_registry_and_the_homes_name_its_url_and_a_role(tmp_path, binary):
    reg = registry(tmp_path, **{"llm-gateway": ("gateway-01.example.internal", 4000, "https")})
    key = "-".join(["gw", "key", "x" * 10])
    r, _ = main(
        tmp_path, binary, extra_env={"HNX_SECRET_ORCHESTRATION_GATEWAY_KEY": key},
        hnx_registry_file=str(reg), orchestration_gateway_id="llm-gateway",
        orchestration_backends=[
            {"name": "engine-a", "role": "main-reasoner-a", "context_length": 65536},
            {"name": "engine-b", "role": "main-reasoner-b"},
        ],
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    home = tmp_path / "etc" / "orchestration" / "homes" / "engine-a" / "config.yaml"
    cfg = yaml.safe_load(home.read_text())
    assert cfg["model"] == {
        "base_url": "https://gateway-01.example.internal" + ":4000/v1", "default": "main-reasoner-a",
        "context_length": 65536, "api_key": key,
    }  # fmt: skip
    assert oct(home.stat().st_mode & 0o777) == "0o640"
    assert key not in r.stdout
    # no gateway any more: the home is an empty directory again
    v = vars_for(tmp_path, binary)
    r = run_role(tmp_path, ROLE, "main", dict(v, hnx_registry_file=str(reg)), env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not home.parent.exists()  # engine-a is no backend any more: its home is pruned
    assert (home.parent.parent / "exec").is_dir()


def test_a_gateway_over_plain_http_or_an_address_is_refused_unless_opted_in(tmp_path, binary):
    env = {"HNX_SECRET_ORCHESTRATION_GATEWAY_KEY": "-".join(["gw", "key", "x" * 10])}
    base = {"orchestration_gateway_id": "llm-gateway",
            "orchestration_backends": [{"name": "engine-a", "role": "main-reasoner-a"}]}  # fmt: skip
    plain = registry(tmp_path, **{"llm-gateway": ("gateway-01.example.internal", 4000, "http")})
    r, _ = main(tmp_path, binary, extra_env=env, hnx_registry_file=str(plain), **base)
    assert (
        r.returncode != 0 and "https unless orchestration_allow_plain_http" in r.stdout + r.stderr
    )
    ok, _ = main(tmp_path, binary, extra_env=env, hnx_registry_file=str(plain),
                 orchestration_allow_plain_http=True, **base)  # fmt: skip
    assert ok.returncode == 0, ok.stdout + ok.stderr
    other = tmp_path / "ip"
    other.mkdir()
    addr = registry(other, **{"llm-gateway": (".".join(["198", "51", "100", "7"]), 4000, "https")})
    r, _ = main(other, binary, extra_env=env, hnx_registry_file=str(addr), **base)
    assert r.returncode != 0 and "never an address" in r.stdout + r.stderr


def test_the_unit_and_the_configuration_carry_no_secret_value_and_no_environment(tmp_path, binary):
    token = "E" * 12 + "e" * 28
    r, _ = main(
        tmp_path, binary, extra_env={"HNX_SECRET_ORCHESTRATION_EVENTS_TOKEN": token},
        orchestration_events_forwarder_url="https://events.example.internal/forward",
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    unit = (tmp_path / "units" / "hnx-orchestrator.service").read_text()
    assert not [ln for ln in unit.splitlines() if ln.startswith(("Environment", "PassEnvironment"))]
    assert token not in unit
    assert token not in (tmp_path / "etc" / "orchestration" / "controller.yaml").read_text()


def test_the_events_forwarder_token_is_in_a_root_only_file_and_never_in_the_configuration(
    tmp_path, binary
):
    token = "E" * 12 + "e" * 28
    r, _ = main(
        tmp_path, binary, extra_env={"HNX_SECRET_ORCHESTRATION_EVENTS_TOKEN": token},
        orchestration_events_forwarder_url="https://events.example.internal/forward",
        orchestration_events_queue_size=500,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    etc = tmp_path / "etc" / "orchestration"
    cfg = yaml.safe_load((etc / "controller.yaml").read_text())
    assert cfg["events"] == {
        "forwarder_url": "https://events.example.internal/forward", "source": "svc:orchestrator",
        "token_file": "/run/credentials/hnx-orchestrator.service/events-token", "gateway_tag_prefix": "hnx/", "queue_size": 500,
    }  # fmt: skip
    env_file = etc / "events.token"
    assert oct(env_file.stat().st_mode & 0o777) == "0o600"
    assert env_file.read_text().strip() == token
    assert token not in (etc / "controller.yaml").read_text() and token not in r.stdout
    unit = (tmp_path / "units" / "hnx-orchestrator.service").read_text()
    # the token is a systemd credential, never an environment variable of the controller
    assert f"LoadCredential=events-token:{env_file}" in unit and token not in unit
    assert "EnvironmentFile" not in unit and "Environment=" not in unit
    assert not (etc / "events.env").exists()
    # an unset events token is refused when a forwarder is set, and is not needed when it is not
    r = run_role(tmp_path, ROLE, "main", vars_for(
        tmp_path, binary, orchestration_events_forwarder_url="https://events.example.internal/forward"
    ), env=SECRETS)  # fmt: skip
    assert r.returncode != 0 and "orchestration/events-token" in r.stdout + r.stderr


# ----------------------------------------------------------------------------- start, restart, reload


class Stand(http.server.ThreadingHTTPServer):
    """A controller stand-in: /healthz, and the profile reload (recorded)."""

    def __init__(self):
        self.reloads: list[str] = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code):
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                self._send(200 if self.path == "/healthz" else 404)

            def do_POST(self):
                if self.path == "/admin/reload-profiles":
                    outer.reloads.append(self.headers.get("Authorization", ""))
                    return self._send(200)
                self._send(404)

        super().__init__((LOOP, free_port()), H)
        threading.Thread(
            target=self.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()


@pytest.fixture
def stand():
    s = Stand()
    yield s
    s.shutdown()
    s.server_close()


def fake_systemctl(tmp: Path) -> str:
    """Logs each call; is-active is active once started (and stays so), is-enabled once enabled."""
    state = tmp / "systemctl.state"
    return fake(
        tmp / "systemctl",
        "import os, sys\n"
        f"log, st = {str(tmp / 'calls.log')!r}, {str(state)!r}\n"
        "open(log, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        "have = open(st).read().split() if os.path.exists(st) else []\n"
        "c = sys.argv[1]\n"
        "if c == 'is-active':\n"
        "    print('active' if 'start' in have else 'inactive'); sys.exit(0 if 'start' in have else 3)\n"
        "if c == 'is-enabled':\n"
        "    print('enabled' if 'enable' in have else 'disabled'); sys.exit(0 if 'enable' in have else 1)\n"
        "if c in ('start', 'enable'):\n"
        "    open(st, 'a').write(c + '\\n')\n",
    )


def calls(tmp: Path) -> list[str]:
    p = tmp / "calls.log"
    return p.read_text().splitlines() if p.exists() else []


def test_what_changed_decides_start_restart_reload_and_a_profile_reload(tmp_path, binary, stand):
    ctl = fake_systemctl(tmp_path)
    v = vars_for(
        tmp_path, binary, orchestration_start=True, orchestration_systemctl_cli=ctl,
        ansible_host=LOOP, orchestration_bind=LOOP, orchestration_port=stand.server_port,
    )  # fmt: skip
    unit = "hnx-orchestrator.service"

    def run(**over):
        (tmp_path / "calls.log").unlink(missing_ok=True)
        r = run_role(tmp_path, ROLE, "main", {**v, **over}, env=SECRETS)
        assert r.returncode == 0, r.stdout + r.stderr
        return r, [
            c
            for c in calls(tmp_path)
            if c.split()[0] in ("start", "restart", "reload", "enable", "daemon-reload")
        ]

    r, c = run()  # first: reload systemd, enable, start
    assert c == ["daemon-reload", f"enable {unit}", f"start {unit}"] or c == [
        "daemon-reload",
        f"enable {unit}",
        f"start {unit}",
    ], c
    assert stand.reloads == []  # a start loads the profiles itself
    r, c = run()  # converged: nothing moves, and the second run is changed=0
    assert c == [] and "changed=0" in r.stdout, (c, r.stdout)
    r, c = run(orchestration_concurrency=3)  # configuration: restart
    assert c == [f"restart {unit}"], c
    assert stand.reloads == []
    secrets = dict(SECRETS, HNX_SECRET_ORCHESTRATION_STATUS_TOKEN="Z" * 40)
    (tmp_path / "calls.log").unlink()
    r = run_role(tmp_path, ROLE, "main", {**v, "orchestration_concurrency": 3}, env=secrets)
    assert r.returncode == 0, r.stdout + r.stderr
    assert [c for c in calls(tmp_path) if c.split()[0] in ("restart", "reload")] == [
        f"reload {unit}"
    ]
    # a profile added: reloaded through the admin route with the admin token, never a restart
    (tmp_path / "profiles-src" / "agent-c.yaml").write_text(PROFILE.replace("agent-a", "agent-c"))
    (tmp_path / "calls.log").unlink()
    r = run_role(tmp_path, ROLE, "main", {**v, "orchestration_concurrency": 3}, env=secrets)
    assert r.returncode == 0, r.stdout + r.stderr
    assert [c for c in calls(tmp_path) if c.split()[0] in ("restart", "reload", "start")] == []
    assert stand.reloads == [f"Bearer {TOKENS['ADMIN']}"]


def test_start_false_writes_files_and_asks_systemd_nothing(tmp_path, binary):
    r, _ = main(tmp_path, binary, orchestration_systemctl_cli=fake_systemctl(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert calls(tmp_path) == []


# ----------------------------------------------------------------------------- on the real controller


@pytest.fixture
def live(tmp_path, controller_binary):
    """The repository's controller on loopback, on the configuration the role rendered."""
    port = free_port()
    ctl = fake_systemctl(tmp_path)
    (tmp_path / "systemctl.state").write_text("start\nenable\n")  # active and enabled
    v = vars_for(
        tmp_path, controller_binary, ansible_host=LOOP, orchestration_bind=LOOP,
        orchestration_port=port, orchestration_systemctl_cli=ctl,
    )  # fmt: skip
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr  # the real `controller check` passed on the set
    cfg = tmp_path / "etc" / "orchestration" / "controller.yaml"
    log = (tmp_path / "controller.log").open("w")
    proc = subprocess.Popen(
        [str(controller_binary), "serve", "--config", str(cfg)], stdout=log, stderr=log
    )
    try:
        for _ in range(100):
            with contextlib.suppress(OSError):
                socket.create_connection((LOOP, port), timeout=0.2).close()
                break
            if proc.poll() is not None:
                pytest.fail((tmp_path / "controller.log").read_text())
            threading.Event().wait(0.1)
        yield v, proc
    finally:
        proc.terminate()
        proc.wait(timeout=30)
        log.close()


def test_health_runs_a_smoke_job_to_done_on_the_real_controller(tmp_path, live):
    v, _ = live
    r = run_role(tmp_path, ROLE, "health", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    for t in TOKENS.values():
        assert t not in r.stdout


def test_health_fails_on_a_rotated_token_the_host_does_not_hold(tmp_path, live):
    v, _ = live
    rotated = dict(SECRETS, HNX_SECRET_ORCHESTRATION_METRICS_TOKEN="R" * 40)
    r = run_role(tmp_path, ROLE, "health", v, env=rotated)
    assert r.returncode != 0  # the controller refuses the new token before the digest check


def test_health_fails_when_the_unit_is_not_active(tmp_path, live):
    v, _ = live
    (tmp_path / "systemctl.state").write_text("enable\n")
    r = run_role(tmp_path, ROLE, "health", v, env=SECRETS)
    assert r.returncode != 0 and "is-active" in r.stdout + r.stderr


def test_export_backup_and_restore_round_trip_on_the_real_controller(tmp_path, live):
    v, proc = live
    assert (
        run_role(tmp_path, ROLE, "health", v, env=SECRETS).returncode == 0
    )  # one job in the store
    var = tmp_path / "var" / "orchestration"
    for hook in ("export", "backup"):
        r = run_role(tmp_path, ROLE, hook, v, env=SECRETS)
        assert r.returncode == 0, r.stdout + r.stderr
    listing = [
        json.loads(line) for line in (var / "export" / "listing.jsonl").read_text().splitlines()
    ]
    by = {row["key"]: row for row in listing}
    assert by["controller.db"]["tables"]["jobs"] == 1 and by["jobs.jsonl"]["rows"] >= 1
    rows = [json.loads(x) for x in (var / "export" / "jobs.jsonl").read_text().splitlines()]
    (job,) = [x["row"] for x in rows if x["table"] == "jobs"]
    assert job["agent_key"] == "hnx-health" and job["state"] == "done"
    assert (var / "backup-manifest.json").is_file()
    assert sorted(p.name for p in (var / "export").iterdir()) == [
        "controller.db",
        "jobs.jsonl",
        "listing.jsonl",
    ]
    # lose the store, restore it from the export: the job is back, the controller reconciles on start
    proc.terminate()
    proc.wait(timeout=30)
    for p in var.glob("controller.db*"):
        p.unlink()
    r = run_role(
        tmp_path,
        ROLE,
        "restore",
        {**v, "orchestration_restore_source": str(var / "export")},
        env=SECRETS,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    con = sqlite3.connect(var / "controller.db")
    assert con.execute("SELECT COUNT(*) FROM jobs WHERE agent_key = 'hnx-health'").fetchone() == (
        1,
    )
    assert oct((var / "controller.db").stat().st_mode & 0o777) == "0o600"
    assert "stop hnx-orchestrator.service" in calls(tmp_path)


# ----------------------------------------------------------------------------- export, restore, upgrade (no controller)


def make_store(path: Path, jobs: int = 2, *, controller: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    if controller:
        con.execute("CREATE TABLE jobs (run_id TEXT PRIMARY KEY, agent_key TEXT, task BLOB)")
        con.execute("CREATE TABLE event_outbox (seq INTEGER PRIMARY KEY, body TEXT)")
        for i in range(jobs):
            con.execute(
                "INSERT INTO jobs VALUES (?, ?, ?)", (f"run-{i}", "agent-a", bytes([0, 255, i]))
            )
    else:
        con.execute("CREATE TABLE notes (x TEXT)")
    con.commit()
    con.close()


def exported(tmp_path, binary, jobs=2):
    r, v = main(tmp_path, binary)
    assert r.returncode == 0, r.stdout + r.stderr
    var = tmp_path / "var" / "orchestration"
    make_store(var / "controller.db", jobs)
    r = run_role(tmp_path, ROLE, "export", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    return v, var


def test_the_export_holds_every_row_as_jsonl_and_a_listing_with_counts(tmp_path, binary):
    _v, var = exported(tmp_path, binary)
    lines = [json.loads(x) for x in (var / "export" / "jobs.jsonl").read_text().splitlines()]
    assert [x["row"]["run_id"] for x in lines if x["table"] == "jobs"] == ["run-0", "run-1"]
    assert lines[0]["row"]["task"] == {"$b64": base64.b64encode(bytes([0, 255, 0])).decode()}
    listing = {
        json.loads(x)["key"]: json.loads(x)
        for x in (var / "export" / "listing.jsonl").read_text().splitlines()
    }
    assert listing["controller.db"]["tables"] == {"event_outbox": 0, "jobs": 2}
    assert listing["jobs.jsonl"]["rows"] == 2
    assert listing["jobs.jsonl"]["sha256"] == sha(var / "export" / "jobs.jsonl")
    for f in (var / "export").iterdir():
        assert oct(f.stat().st_mode & 0o777) == "0o600"


def test_an_export_of_a_database_that_is_not_a_controller_store_or_is_missing_is_refused(
    tmp_path, binary
):
    r, v = main(tmp_path, binary)
    assert r.returncode == 0
    var = tmp_path / "var" / "orchestration"
    r = run_role(tmp_path, ROLE, "export", v, env=SECRETS)  # no database yet: not an empty export
    assert r.returncode != 0 and "is missing" in r.stdout + r.stderr
    make_store(var / "controller.db", controller=False)
    r = run_role(tmp_path, ROLE, "export", v, env=SECRETS)
    assert r.returncode != 0 and "not a controller database" in r.stdout + r.stderr
    assert not (var / "export" / "listing.jsonl").exists()


def restore(tmp_path, v, src):
    v = {
        **v,
        "orchestration_restore_source": str(src),
        "orchestration_systemctl_cli": fake_systemctl(tmp_path),
    }
    return run_role(tmp_path, ROLE, "restore", v, env=SECRETS)


def test_restore_installs_the_database_and_refuses_what_the_listing_does_not_vouch_for(
    tmp_path, binary
):
    v, var = exported(tmp_path, binary)
    live = var / "controller.db"
    live.unlink()
    r = restore(tmp_path, v, var / "export")
    assert r.returncode == 0, r.stdout + r.stderr
    assert sqlite3.connect(live).execute("SELECT COUNT(*) FROM jobs").fetchone() == (2,)
    # a copy of the export, broken one way at a time: nothing is installed over the live store
    base = tmp_path / "exp"
    for i, break_it in enumerate([
        lambda d: (d / "jobs.jsonl").write_bytes((d / "jobs.jsonl").read_bytes() + b"x"),
        lambda d: (d / "controller.db").write_bytes(
            (d / "controller.db").read_bytes()[:-1]
            + bytes([(d / "controller.db").read_bytes()[-1] ^ 0xFF])
        ),
        lambda d: (d / "stray.txt").write_text("not listed"),
        lambda d: (d / "jobs.jsonl").unlink(),
        lambda d: (d / "listing.jsonl").write_text(
            "\n".join(json.dumps({**json.loads(x), "rows": 99}) if '"rows"' in x else x
                      for x in (d / "listing.jsonl").read_text().splitlines()) + "\n"),
        lambda d: (d / "listing.jsonl").write_text(
            (d / "listing.jsonl").read_text() + json.dumps({"key": "../escape", "size": 0, "sha256": ""}) + "\n"),
    ]):  # fmt: skip
        d = base / str(i)
        d.mkdir(parents=True)
        for f in (var / "export").iterdir():
            (d / f.name).write_bytes(f.read_bytes())
            (d / f.name).chmod(0o600)
        d.chmod(0o700)
        break_it(d)
        before = sha(live)
        r = restore(tmp_path, v, d)
        assert r.returncode != 0 and "restore refused" in r.stdout + r.stderr, (i, r.stdout)
        assert sha(live) == before
    # the live data directory itself is never a source
    r = restore(tmp_path, v, var)
    assert r.returncode != 0 and "restore refused" in r.stdout + r.stderr


def relisted(d):
    """The listing of a copy of the export made to agree with what the files now are (size and
    sha256), so only the checks after the listing's own can refuse it."""
    rows = [json.loads(x) for x in (d / "listing.jsonl").read_text().splitlines()]
    for row in rows:
        row["size"] = (d / row["key"]).stat().st_size
        row["sha256"] = sha(d / row["key"])
    (d / "listing.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_restore_refuses_a_corrupt_database_whose_listing_agrees_with_it(tmp_path, binary):
    v, var = exported(tmp_path, binary)
    d = tmp_path / "corrupt"
    d.mkdir(mode=0o700)
    for f in (var / "export").iterdir():
        (d / f.name).write_bytes(f.read_bytes())
        (d / f.name).chmod(0o600)
    raw = bytearray((d / "controller.db").read_bytes())
    assert len(raw) >= 8192
    raw[4096:] = b"\xff" * (
        len(raw) - 4096
    )  # every page after the schema page: the tables' b-trees
    (d / "controller.db").write_bytes(bytes(raw))
    relisted(d)  # sha256 and size agree: only integrity_check can refuse it
    live = var / "controller.db"
    before = sha(live)
    r = restore(tmp_path, v, d)
    out = r.stdout + r.stderr
    assert r.returncode != 0 and "not a sound controller database" in out, out
    assert sha(live) == before
    assert not (var / ".controller.db.restore").exists()  # no staged copy is left behind


def test_restore_keeps_the_replaced_store_and_refuses_when_one_is_kept(tmp_path, binary):
    v, var = exported(tmp_path, binary)
    live = var / "controller.db"
    old = sha(live)
    (var / "controller.db-wal").write_bytes(b"wal-bytes")
    kept = var / ("controller.db." + time.strftime("%Y%m%d") + ".before-restore")
    r = restore(tmp_path, v, var / "export")
    assert r.returncode == 0, r.stdout + r.stderr
    assert sha(kept) == old
    assert Path(str(kept) + "-wal").read_bytes() == b"wal-bytes"  # moved aside, not deleted
    assert not (var / "controller.db-wal").exists()
    # a second restore the same day refuses (the kept store is never overwritten) and touches nothing
    (var / "controller.db-wal").write_bytes(b"newer-wal")
    now = sha(live)
    r = restore(tmp_path, v, var / "export")
    assert r.returncode != 0 and "already exists" in r.stdout + r.stderr
    assert sha(live) == now and sha(kept) == old
    assert (var / "controller.db-wal").read_bytes() == b"newer-wal"  # the wal survives a refusal


def test_the_backup_manifest_lists_the_data_root_and_not_the_configuration(tmp_path, binary):
    v, var = exported(tmp_path, binary)
    r = run_role(tmp_path, ROLE, "backup", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    manifest = json.loads((var / "backup-manifest.json").read_text())
    assert manifest["paths"] == [str(var)]
    assert str(tmp_path / "etc" / "orchestration") not in json.dumps(manifest)
    assert "secrets" in manifest["note"]


def test_restore_refuses_a_foreign_database_even_with_a_matching_listing(tmp_path, binary):
    v, var = exported(tmp_path, binary)
    d = tmp_path / "foreign"
    d.mkdir(mode=0o700)
    make_store(d / "controller.db", controller=False)
    (d / "jobs.jsonl").write_text("")
    rows = [
        {"key": "controller.db", "size": (d / "controller.db").stat().st_size,
         "sha256": sha(d / "controller.db"), "tables": {"jobs": 0}},
        {"key": "jobs.jsonl", "size": 0, "sha256": sha(d / "jobs.jsonl"), "rows": 0},
    ]  # fmt: skip
    (d / "listing.jsonl").write_text("".join(json.dumps(x) + "\n" for x in rows))
    for f in d.iterdir():
        f.chmod(0o600)
    before = sha(var / "controller.db")
    r = restore(tmp_path, v, d)
    assert r.returncode != 0 and "not a sound controller database" in r.stdout + r.stderr
    assert sha(var / "controller.db") == before
    assert not list(var.glob(".*.restore"))


def test_restore_starts_the_unit_again_whatever_happened_when_asked(tmp_path, binary):
    ctl = fake_systemctl(tmp_path)
    r, v = main(tmp_path, binary, orchestration_systemctl_cli=ctl, orchestration_start=False)
    assert r.returncode == 0
    var = tmp_path / "var" / "orchestration"
    bad = tmp_path / "missing"
    bad.mkdir(mode=0o700)
    v = dict(v, orchestration_start=True)
    r = restore(tmp_path, v, bad)  # refused at the check, before the unit is touched
    assert r.returncode != 0
    assert not any(c.startswith("stop") for c in calls(tmp_path))
    make_store(var / "controller.db")
    assert run_role(tmp_path, ROLE, "export", v, env=SECRETS).returncode == 0
    (var / "export" / "jobs.jsonl").write_text("tampered\n")  # sha256 differs: refused at the check
    r = restore(tmp_path, v, var / "export")
    assert r.returncode != 0 and not any(c.startswith("stop") for c in calls(tmp_path))


def test_upgrade_records_a_bump_to_a_different_binary_and_refuses_the_rest(tmp_path, binary):
    r, v = main(tmp_path, binary)
    assert r.returncode == 0
    new = Path(fake(tmp_path / "next", "import sys\nsys.exit(0)\n"))
    ok = dict(v, orchestration_binary=str(new), orchestration_target_binary_sha256=sha(new))
    r = run_role(tmp_path, ROLE, "upgrade", ok, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    pending = json.loads(
        (tmp_path / "opt" / "hnx-orchestration" / "pending-upgrade.json").read_text()
    )
    assert pending == {"from": v["orchestration_binary_sha256"], "to": sha(new)}
    for over in (
        {"orchestration_target_binary_sha256": v["orchestration_binary_sha256"]},  # not a bump
        {"orchestration_target_binary_sha256": "x" * 64},  # not hex
        {"orchestration_target_binary_sha256": "0" * 64},  # the file does not hash to it
    ):
        r = run_role(tmp_path, ROLE, "upgrade", {**ok, **over}, env=SECRETS)
        assert r.returncode != 0, over


# ----------------------------------------------------------------------------- readiness


def test_readiness_refuses_a_binary_that_is_not_the_pin_and_passes_a_good_set(tmp_path, binary):
    v = vars_for(tmp_path, binary)
    r = run_role(tmp_path, ROLE, "readiness", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    bad = dict(v, orchestration_binary_sha256="0" * 64)
    r = run_role(tmp_path, ROLE, "readiness", bad, env=SECRETS)
    assert r.returncode != 0 and "does not hash" in r.stdout + r.stderr
    gone = dict(v, orchestration_binary=str(tmp_path / "nowhere"))
    r = run_role(tmp_path, ROLE, "readiness", gone, env=SECRETS)
    assert r.returncode != 0
    r = run_role(tmp_path, ROLE, "readiness", v, env={})  # no secrets at all
    assert r.returncode != 0
    assert not (tmp_path / "etc").exists()
