# SPDX-License-Identifier: Apache-2.0
"""docker_engine: Docker Engine from the vendor's signed apt repository, pinned and held, with a
daemon.json checked by dockerd before it goes live.

The install path needs the vendor repository and root, so it is proven by its shape here (every
pin installed in one transaction and held after) and on a real guest; input validation, the
platform check, the daemon.json path (stage, validate, install, owed restart) and the health and
readiness hooks run end to end on localhost against fake ``dockerd``/``docker``/``systemctl``/
``dpkg-query`` commands.  The signing-key check runs with the other vendor-key roles
(``test_product_roles.py`` KEY_CASES).  Every refusal is shown failing on a bad input and passing
on a good one."""

import json
import re

import pytest
import yaml
from rolerun import ANSIBLE, calls, fake, first_run, logging_fake, run_cases, run_role

pytestmark = pytest.mark.requires_tool("ansible-playbook")
ROLE = "docker_engine"
DEFAULTS = yaml.safe_load((ANSIBLE / "roles" / ROLE / "defaults" / "main.yml").read_text())
FIXED = yaml.safe_load((ANSIBLE / "roles" / ROLE / "vars" / "main.yml").read_text())
CHANGED_0 = re.compile(r"localhost\s*:\s*ok=\d+\s+changed=0\s")


def base(**kw):
    return {"docker_engine_log_max_size": "10m", **kw}


# ---------------------------------------------------------------- inputs
def test_the_pins_are_the_defaults_and_every_package_follows_one():
    assert (DEFAULTS["docker_engine_version"], DEFAULTS["docker_engine_containerd_version"],
            DEFAULTS["docker_engine_buildx_version"], DEFAULTS["docker_engine_compose_version"]) == (
        "29.9.2", "2.4.2", "0.38.1", "5.6.1")  # fmt: skip
    pkgs = {p["name"]: p["version"] for p in FIXED["docker_engine_packages"]}
    assert pkgs == {
        "docker-ce": "5:{{ docker_engine_version }}-*",
        "docker-ce-cli": "5:{{ docker_engine_version }}-*",
        "containerd.io": "{{ docker_engine_containerd_version }}-*",
        "docker-buildx-plugin": "{{ docker_engine_buildx_version }}-*",
        "docker-compose-plugin": "{{ docker_engine_compose_version }}-*",
    }


@first_run(lambda tmp: {"role": ROLE, "tasks_from": "validate", "extra_vars": base()})
def test_good_inputs_pass(first):
    r, _ = first
    assert r.returncode == 0, r.stdout + r.stderr


OVERRIDDEN = base(
    docker_engine_version="29.10.0",
    docker_engine_compose_version="5.7.1",
    docker_engine_log_max_size="1g",
    docker_engine_log_max_file=100,
)


@first_run(lambda tmp: {"role": ROLE, "tasks_from": "validate", "extra_vars": OVERRIDDEN})
def test_the_pins_are_overridable(first):
    r, _ = first
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    "over",
    [
        {"docker_engine_version": "29.9"},
        {"docker_engine_version": "29.9.2\nPackage: evil"},
        {"docker_engine_containerd_version": "2.4.2-1"},
        {"docker_engine_buildx_version": "latest"},
        {"docker_engine_compose_version": "*"},
        {"docker_engine_repository": "http://mirror.example.internal/linux"},
        {"docker_engine_repository": "https://mirror.example.internal/linux debian main"},
        {"docker_engine_key_fingerprints": []},
        {"docker_engine_key_fingerprints": ["8D81803C0EBFCD88"]},
        {"docker_engine_key_fingerprints": ["9dc858229fc7dd38854ae2d88d81803c0ebfcd88"]},
        {"docker_engine_log_max_size": "10"},
        {"docker_engine_log_max_size": "0m"},
        {"docker_engine_log_max_size": "10mb"},
        {"docker_engine_log_max_file": 0},
        {"docker_engine_log_max_file": 101},
    ],
)
@first_run(lambda tmp, over: {"role": ROLE, "tasks_from": "validate", "extra_vars": base(**over)})
def test_bad_inputs_are_refused(first, over):
    r, _ = first
    assert r.returncode != 0, over
    assert "docker_engine: versions x.y.z" in r.stdout


@first_run(lambda tmp: {"role": ROLE, "tasks_from": "main", "extra_vars": {}})
def test_the_log_bound_is_required(first):
    r, _ = first
    assert r.returncode != 0 and "docker_engine_log_max_size" in r.stdout + r.stderr


@pytest.mark.parametrize(
    ("distribution", "release", "ok"),
    [("Debian", "trixie", True), ("Ubuntu", "noble", True), ("Fedora", "43", False),
     ("Debian", "trixie/../x", False), ("Debian", "trixie main", False)],
)  # fmt: skip
@first_run(
    lambda tmp, distribution, release, ok: {
        "role": ROLE,
        "tasks_from": "platform",
        "extra_vars": base(docker_engine_distribution=distribution, docker_engine_release=release),
    }
)
def test_debian_and_ubuntu_only(first, distribution, release, ok):
    r, _ = first
    assert (r.returncode == 0) is ok, r.stdout


# ---------------------------------------------------------------- the pinned, held install
def test_every_pin_is_installed_in_one_transaction_and_held_after():
    """The engine depends on the matching CLI and containerd, so all five install together; they
    are dpkg-held, so the bump path (a new pin, re-run main) must be allowed to move them, and the
    holds are set again after."""
    tasks = yaml.safe_load((ANSIBLE / "roles" / ROLE / "tasks" / "main.yml").read_text())
    (i,) = [n for n, t in enumerate(tasks) if "ansible.builtin.apt" in t
            and "docker_engine_packages" in str(t["ansible.builtin.apt"].get("name"))]  # fmt: skip
    install = tasks[i]["ansible.builtin.apt"]
    assert install["allow_change_held_packages"] is True
    (h,) = [n for n, t in enumerate(tasks) if "ansible.builtin.dpkg_selections" in t]
    assert h > i
    hold = tasks[h]
    assert hold["ansible.builtin.dpkg_selections"] == {
        "name": "{{ item.name }}",
        "selection": "hold",
    }
    assert hold["loop"] == "{{ docker_engine_packages }}"
    (src,) = [t["ansible.builtin.deb822_repository"] for t in tasks
              if "ansible.builtin.deb822_repository" in t]  # fmt: skip
    assert src["signed_by"] == "{{ docker_engine_keyring }}"
    assert src["uris"] == "{{ docker_engine_apt_uri }}"
    # the key is checked before the repository that trusts it is added
    keys = [
        n
        for n, t in enumerate(tasks)
        if t.get("ansible.builtin.include_tasks") == "signing_key.yml"
    ]
    repo = [n for n, t in enumerate(tasks) if "ansible.builtin.deb822_repository" in t]
    assert keys and repo and keys[0] < repo[0] < i


# ---------------------------------------------------------------- daemon.json
def config_vars(tmp, **kw):
    return base(
        docker_engine_config_file=str(tmp / "etc" / "docker" / "daemon.json"),
        docker_engine_state_dir=str(tmp / "state"),
        docker_engine_daemon_cli=logging_fake(tmp, "dockerd"),
        docker_engine_systemctl_cli=logging_fake(tmp, "systemctl"),
        **kw,
    )


def _first(tmp):
    v = config_vars(tmp)
    return {"role": ROLE, "tasks_from": "config", "extra_vars": v, "setup": {"v": v}}


@first_run(_first)
def test_daemon_json_is_validated_installed_restarted_once_and_a_rerun_changes_nothing(first):
    r, tmp = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    live = tmp / "etc" / "docker" / "daemon.json"
    assert json.loads(live.read_text()) == {
        "log-driver": "json-file",
        "log-opts": {"max-size": "10m", "max-file": "3"},
    }
    staged = str(tmp / "etc" / "docker" / ".homelabnext-staged.json")
    assert calls(tmp) == [f"dockerd --validate --config-file {staged}", "systemctl restart docker"]
    assert not (tmp / "state" / "restart-pending").exists()
    again = run_role(tmp, ROLE, "config", v)
    assert again.returncode == 0 and CHANGED_0.search(again.stdout), again.stdout
    assert len(calls(tmp)) == 2  # neither validated nor restarted again


def _first(tmp):
    v = config_vars(tmp)
    live = tmp / "etc" / "docker" / "daemon.json"
    live.parent.mkdir(parents=True)
    live.write_text('{"log-driver": "local"}\n')
    (tmp / "dockerd.fails").touch()
    return {"role": ROLE, "tasks_from": "config", "extra_vars": v, "setup": {"live": live}}


@first_run(_first)
def test_a_daemon_json_dockerd_refuses_never_goes_live(first):
    r, tmp = first
    assert r.returncode != 0
    assert first.setup["live"].read_text() == '{"log-driver": "local"}\n'
    assert [c.split()[0] for c in calls(tmp)] == ["dockerd"]  # no restart
    assert not (tmp / "state" / "restart-pending").exists()


def _first(tmp):
    v = config_vars(tmp, docker_engine_restart=False)
    return {"role": ROLE, "tasks_from": "config", "extra_vars": v, "setup": {"v": v}}


@first_run(_first)
def test_an_owed_restart_survives_until_one_succeeds(first):
    r, tmp = first
    v = first.setup["v"]
    pending = tmp / "state" / "restart-pending"
    assert r.returncode == 0, r.stdout + r.stderr
    assert pending.exists() and not [c for c in calls(tmp) if c.startswith("systemctl")]
    (tmp / "systemctl.fails").touch()
    failed = run_role(tmp, ROLE, "config", {**v, "docker_engine_restart": True})
    assert failed.returncode != 0 and pending.exists()
    (tmp / "systemctl.fails").unlink()
    ok = run_role(tmp, ROLE, "config", {**v, "docker_engine_restart": True})
    assert ok.returncode == 0, ok.stdout
    assert not pending.exists()
    assert calls(tmp).count("systemctl restart docker") == 2  # the failed one, then the good one


# ---------------------------------------------------------------- health and readiness
GOOD_INFO = {"ServerVersion": "29.9.2", "LoggingDriver": "json-file"}
GOOD_DPKG = [
    "docker-ce 5:29.9.2-1~debian.13~trixie hi ",
    "docker-ce-cli 5:29.9.2-1~debian.13~trixie hi ",
    "containerd.io 2.4.2-1~debian.13~trixie hi ",
    "docker-buildx-plugin 0.38.1-1~debian.13~trixie hi ",
    "docker-compose-plugin 5.6.1-1~debian.13~trixie hi ",
]


def _swap(lines, old, new):
    return [line.replace(old, new) for line in lines]


HEALTH_CASES = {
    # case: (unit state, docker info (None: the daemon is down), compose version, dpkg lines, message)
    "healthy": ("active", GOOD_INFO, "v5.6.1", GOOD_DPKG, None),
    "unit inactive": ("inactive", GOOD_INFO, "5.6.1", GOOD_DPKG, "is inactive"),
    "daemon down": ("active", None, "5.6.1", GOOD_DPKG, "docker info exited 1"),
    "engine off its pin": ("active", {**GOOD_INFO, "ServerVersion": "29.9.3"}, "5.6.1", GOOD_DPKG, "engine 29.9.3"),
    "logs not bounded by json-file": ("active", {**GOOD_INFO, "LoggingDriver": "journald"}, "5.6.1", GOOD_DPKG, "logging driver journald"),
    "compose off its pin": ("active", GOOD_INFO, "5.7.1", GOOD_DPKG, "compose 5.7.1"),
    "containerd off its pin": ("active", GOOD_INFO, "5.6.1", _swap(GOOD_DPKG, "containerd.io 2.4.2", "containerd.io 2.4.20"), "containerd.io"),
    "a package not held": ("active", GOOD_INFO, "5.6.1", _swap(GOOD_DPKG, "0.38.1-1~debian.13~trixie hi ", "0.38.1-1~debian.13~trixie ii "), "docker-buildx-plugin"),
    "a package missing": ("active", GOOD_INFO, "5.6.1", GOOD_DPKG[:-1], "docker-compose-plugin"),
    "the CLI off the engine's pin": ("active", GOOD_INFO, "5.6.1", _swap(GOOD_DPKG, "docker-ce-cli 5:29.9.2", "docker-ce-cli 5:29.9.1"), "docker-ce-cli"),
    "held but only unpacked": ("active", GOOD_INFO, "5.6.1", _swap(GOOD_DPKG, "2.4.2-1~debian.13~trixie hi ", "2.4.2-1~debian.13~trixie hU "), "containerd.io"),
    "a restart still owed": ("active", GOOD_INFO, "5.6.1", GOOD_DPKG, "a restart is owed", True),
}  # fmt: skip


def health_fakes(tmp, i, unit, info, compose, dpkg, pending=False):
    d = tmp / f"case{i}"
    (d / "state").mkdir(parents=True)
    if pending:
        (d / "state" / "restart-pending").write_text("owed\n")
    out = json.dumps(info) if info is not None else json.dumps({"ServerErrors": ["Cannot connect"]})
    docker = fake(d / "docker", (
        "import sys\na = sys.argv[1:]\n"
        f"if a[:1] == ['info']:\n    print({out!r})\n    sys.exit({0 if info is not None else 1})\n"
        f"if a[:2] == ['compose', 'version']:\n    print({compose!r})\n"
    ))  # fmt: skip
    systemctl = fake(
        d / "systemctl", f"import sys\nprint({unit!r})\nsys.exit({0 if unit == 'active' else 3})\n"
    )
    dpkg_query = fake(d / "dpkg-query", f"print({chr(10).join(dpkg)!r})\n")
    return {"docker_engine_cli": docker, "docker_engine_systemctl_cli": systemctl,
            "docker_engine_dpkg_query_cli": dpkg_query, "docker_engine_state_dir": str(d / "state")}  # fmt: skip


def _first(tmp):
    overrides = [
        health_fakes(tmp, i, *case[:4], *case[5:]) for i, case in enumerate(HEALTH_CASES.values())
    ]
    return {"runner": run_cases, "role": ROLE, "tasks_from": "health", "base_vars": {},
            "overrides": overrides}  # fmt: skip


@first_run(_first)
def test_health_needs_the_engine_ready_at_its_pins_with_bounded_logs_and_held_packages(first):
    results, _ = first
    for (name, case), (failed, got) in zip(HEALTH_CASES.items(), results, strict=True):
        msg = case[4]  # (a sixth item: a restart is owed)
        assert failed is (msg is not None), (name, got)
        assert msg is None or msg in got, (name, got)


def _first(tmp):
    good = health_fakes(tmp, 0, "active", GOOD_INFO, "5.6.1", GOOD_DPKG)
    down = health_fakes(tmp, 1, "active", None, "5.6.1", GOOD_DPKG)
    off = health_fakes(tmp, 2, "failed", GOOD_INFO, "5.6.1", GOOD_DPKG)
    for o in (good, down, off):
        del o["docker_engine_dpkg_query_cli"]
    return {"runner": run_cases, "role": ROLE, "tasks_from": "readiness", "base_vars": {},
            "overrides": [good, down, off]}  # fmt: skip


@first_run(_first)
def test_readiness_needs_the_unit_active_and_the_daemon_answering(first):
    results, _ = first
    assert [failed for failed, _ in results] == [False, True, True], results


# ---------------------------------------------------------------- the other hooks
def _first(tmp):
    return {
        "role": ROLE,
        "tasks_from": "upgrade",
        "extra_vars": {"docker_engine_target_version": "29.10.0"},
    }


@first_run(_first)
def test_upgrade_takes_a_newer_version_only(first):
    ok, tmp = first
    assert ok.returncode == 0, ok.stdout
    for bad in ("29.9.2", "29.9.1", "29.10", "29.10.0-rc.1"):
        r = run_role(tmp, ROLE, "upgrade", {"docker_engine_target_version": bad})
        assert r.returncode != 0, bad


@pytest.mark.parametrize("hook", ["backup", "restore", "export"])
@first_run(lambda tmp, hook: {"role": ROLE, "tasks_from": hook, "extra_vars": {}})
def test_the_data_hooks_say_there_is_nothing_of_the_engines_own(first, hook):
    r, _ = first
    assert r.returncode == 0 and CHANGED_0.search(r.stdout), r.stdout


# ---------------------------------------------------------------- the signing key, run twice
def _first(tmp):
    from test_product_roles import key_setup

    v, ring, served = key_setup(tmp, ROLE)
    return {"role": ROLE, "tasks_from": "signing_key", "extra_vars": v,
            "setup": {"v": v, "ring": ring, "served": served}}  # fmt: skip


@pytest.mark.requires_tool("gpg")
@first_run(_first)
def test_a_second_signing_key_run_changes_nothing(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert first.setup["ring"].read_bytes() == first.setup["served"]
    again = run_role(tmp, ROLE, "signing_key", first.setup["v"])
    assert again.returncode == 0 and CHANGED_0.search(again.stdout), again.stdout


def _first(tmp):
    """A listing whose pub record carries no fpr line right after it (the pattern cannot read
    that key's fingerprint) is refused, not read as "only the pinned key"."""
    from test_product_roles import key_setup

    v, ring, _ = key_setup(tmp, ROLE)
    pin = v["docker_engine_key_fingerprints"][0]
    fake(tmp / "gpg", (
        "import sys\n"
        f"print('pub:-:255:22:AAAA:1:::::::scSC:::::ed25519:::0:')\nprint('fpr:::::::::{pin}:')\n"
        "print('pub:-:255:22:BBBB:1:::::::scSC:::::ed25519:::0:')\nprint('uid:-::::1::X::Other::::::::::0:')\n"
    ))  # fmt: skip
    return {"role": ROLE, "tasks_from": "signing_key", "extra_vars": v,
            "env": {"PATH": f"{tmp}:" + __import__("os").environ["PATH"]},
            "setup": {"ring": ring}}  # fmt: skip


@pytest.mark.requires_tool("gpg")
@first_run(_first)
def test_a_primary_key_whose_fingerprint_is_not_read_is_refused(first):
    r, _ = first
    assert r.returncode != 0 and "not the pinned" in r.stdout, r.stdout
    assert not first.setup["ring"].exists()


def test_the_docker_commands_reach_this_hosts_daemon_whatever_the_environment_says():
    """health and readiness pin DOCKER_HOST and DOCKER_CONFIG, so a DOCKER_HOST, a context or a
    CLI plugin from the account's environment cannot answer for another engine."""
    for hook in ("health", "readiness"):
        (block,) = yaml.safe_load((ANSIBLE / "roles" / ROLE / "tasks" / f"{hook}.yml").read_text())
        assert block["environment"] == {
            "DOCKER_HOST": "unix:///run/docker.sock",
            "DOCKER_CONFIG": "{{ docker_engine_state_dir }}/cli-config",
        }, hook
