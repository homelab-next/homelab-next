# SPDX-License-Identifier: Apache-2.0
"""Role ``prometheus`` (modules/prometheus/roles/prometheus), run on localhost (CI is unprivileged,
nothing is started): the steps main does before the container.

* Its settings are refused when they could widen the listener, change the hnx command or break a
  rule: an address that is not the guest's IPv4, a bad retention, a threshold out of range.
* An unset ``secret:`` reference is refused by name, before anything is written; a token that is
  not a token is refused; so is a scrape credential that is not one line.
* The target lists it installs are exactly the generator's for the lab's registry (a service row
  with a metrics block is a job, every registry host is a host-exporter target, an excluded host
  is not); the scrape credential a row names is written from the store, owner-group readable, and
  removed again when the registry stops naming it; a second run is ``changed=0``.
* The configuration it renders passes the product's own ``promtool check config`` and the four
  default rules pass ``promtool test rules`` against series that should and should not fire them
  (docker, as the lab's other container tests: skipped where there is none).
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from rolerun import _invocation, run_role

from homelabnext.generators import generate
from homelabnext.registry import load
from homelabnext.registry.model import secret_env_name
from tests.suite_policy import require_tool

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "prometheus"
ROLE = str(MODULE / "roles" / "prometheus")
REGISTRY = ROOT / "examples" / "services.yml"
USER = pwd.getpwuid(os.getuid()).pw_name
GUEST = str(load(REGISTRY).hosts["mon-core"].address)  # the example lab's monitoring host
TOKEN = "tk_fakefakefakefakefakefakefake0"
SCRAPE_PASSWORD = "scrape-password-fake"
_ROWS = yaml.safe_load(REGISTRY.read_text())["services"]
# the example row whose metrics endpoint needs a credential: its secret reference, the variable the
# store delivers it in, and the file the generated job reads it from
AUTH_ROW = next(n for n, r in _ROWS.items() if "auth" in (r.get("metrics") or {}))
SCRAPE_REF = _ROWS[AUTH_ROW]["metrics"]["auth"]["secret"]
SCRAPE_ENV = secret_env_name(SCRAPE_REF)
SCRAPE_FILE = "/".join(["scrape-credentials", SCRAPE_REF.removeprefix("secret:") + ".credentials"])
SECRETS = {
    "PYTHONPATH": str(ROOT),  # the checkout's homelabnext, when it is not installed
    "HNX_SECRET_PROMETHEUS_NOTIFY_TOKEN": TOKEN,
    SCRAPE_ENV: SCRAPE_PASSWORD,
}
IMAGE = yaml.safe_load((MODULE / "roles" / "prometheus" / "defaults" / "main.yml").read_text())[
    "prometheus_image"
]
RENDER = ["validate", "app", "generate", "credentials", "dirs", "render"]
HOSTS = sorted(load(REGISTRY).hosts)


def pvars(tmp_path: Path, **kw) -> dict:
    v = {
        "prometheus_logical_id": "metrics",
        "ansible_host": GUEST,
        "prometheus_dir": str(tmp_path / "app"),
        "prometheus_data_root": str(tmp_path / "data"),
        "prometheus_state_dir": str(tmp_path / "state"),
        "prometheus_owner": USER,
        "prometheus_uid": os.getuid(),
        "prometheus_gid": os.getgid(),
        "prometheus_registry": str(REGISTRY),
        "prometheus_node_exporter_port": 9100,
        "prometheus_hnx_cli": [sys.executable, "-m", "homelabnext.cli"],
        "prometheus_start": False,
        "prometheus_validate_with_docker": False,
    }
    v.update(kw)
    return v


def run_steps(tmp_path: Path, steps: list[str], extra: dict, env: dict | None = None):
    """Several task files of the role in one play, in order (rolerun runs one)."""
    cmd, run_env = _invocation(tmp_path, ROLE, steps[0], extra, env)
    play = yaml.safe_load((tmp_path / "play.yml").read_text())
    play[0]["tasks"] = [
        {"ansible.builtin.include_role": {"name": ROLE, "tasks_from": s}} for s in steps
    ]
    (tmp_path / "play.yml").write_text(yaml.safe_dump(play))
    return subprocess.run(cmd, capture_output=True, text=True, env=run_env, cwd=tmp_path)


def render(tmp_path: Path, **kw):
    return run_steps(tmp_path, RENDER, pvars(tmp_path, **kw), SECRETS)


# ----------------------------------------------------------------------------- settings


@pytest.mark.parametrize(
    "over",
    [
        {"prometheus_bind": "0.0.0.0"},
        {"prometheus_bind": "metrics.example.internal"},
        {"prometheus_port": 0},
        {"prometheus_node_exporter_port": 70000},
        {"prometheus_retention_time": "30 days"},
        {"prometheus_retention_time": "0d"},
        {"prometheus_retention_size": "lots"},
        {"prometheus_scrape_interval": "1h"},
        {"prometheus_alert_disk_used_percent": 100},
        {"prometheus_alert_memory_available_percent": 0},
        {"prometheus_alert_target_down_for": "10 minutes"},
        {"prometheus_hnx_cli": ["/bin/sh", "-c", "true"]},
        {"prometheus_registry": "relative/services.yml"},
        {"prometheus_node_exporter_exclude": ["Not A Host"]},
        {"prometheus_notify_auth_ref": "not-a-ref"},
        {"prometheus_alert_interval_seconds": 45},
        {"prometheus_uid": 10},
        {"prometheus_data_root": "/var/lib/../etc"},
    ],
    ids=lambda o: next(iter(o)) + "=" + str(next(iter(o.values()))),
)
def test_a_setting_that_could_widen_or_break_the_service_is_refused(tmp_path, over):
    r = run_steps(tmp_path, ["validate"], pvars(tmp_path, **over), SECRETS)
    assert r.returncode != 0, r.stdout
    assert "prometheus: a registry id" in r.stdout, r.stdout


def test_main_renders_nothing_for_a_refused_setting(tmp_path):
    r = run_role(tmp_path, ROLE, "main", pvars(tmp_path, prometheus_bind="0.0.0.0"), env=SECRETS)
    assert r.returncode != 0
    assert not (tmp_path / "data").exists()


# ----------------------------------------------------------------------------- secrets


def test_an_unset_secret_reference_is_refused_by_name_before_anything_is_written(tmp_path):
    env = {k: v for k, v in SECRETS.items() if "NOTIFY" not in k}
    r = run_steps(tmp_path, RENDER, pvars(tmp_path), env)
    assert r.returncode != 0
    assert "secret:prometheus/notify-token" in r.stdout + r.stderr
    assert not (tmp_path / "data").exists()


def test_an_unset_scrape_credential_is_refused_by_name(tmp_path):
    env = {k: v for k, v in SECRETS.items() if k != SCRAPE_ENV}
    r = run_steps(tmp_path, RENDER, pvars(tmp_path), env)
    assert r.returncode != 0
    assert SCRAPE_REF in r.stdout + r.stderr
    assert not (tmp_path / "data").exists()


@pytest.mark.parametrize(
    "bad", ["short", "has space in it", "two\nlines-of-token"], ids=["short", "space", "lines"]
)
def test_a_token_that_is_not_a_token_is_refused(tmp_path, bad):
    env = {**SECRETS, "HNX_SECRET_PROMETHEUS_NOTIFY_TOKEN": bad}
    r = run_steps(tmp_path, RENDER, pvars(tmp_path), env)
    assert r.returncode != 0 and "must be a publish token" in r.stdout, r.stdout
    assert not (tmp_path / "data").exists()


def test_a_scrape_credential_of_two_lines_is_refused_without_its_value(tmp_path):
    env = {**SECRETS, SCRAPE_ENV: "line-one\nline-two"}
    r = run_steps(tmp_path, RENDER, pvars(tmp_path), env)
    assert r.returncode != 0
    assert SCRAPE_REF in r.stdout
    assert "line-one" not in r.stdout + r.stderr


# ----------------------------------------------------------------------------- the render


def test_the_installed_target_lists_are_the_generators_for_this_registry(tmp_path):
    r = render(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    gen = generate(load(REGISTRY), ["prometheus"], {"node_targets": {"port": 9100}})["prometheus"]
    out = tmp_path / "data" / "config" / "generated"
    assert (out / "scrape_configs.yml").read_text() == gen["prometheus/scrape_configs.yml"]
    assert (out / "node_targets.yml").read_text() == gen["prometheus/node_targets.yml"]
    nodes = yaml.safe_load((out / "node_targets.yml").read_text())
    assert [n["labels"]["host"] for n in nodes] == HOSTS
    jobs = {
        j["job_name"]
        for j in yaml.safe_load((out / "scrape_configs.yml").read_text())["scrape_configs"]
    }
    assert {"metrics", AUTH_ROW} <= jobs  # a job per row with a metrics block


def test_an_excluded_host_is_not_a_target(tmp_path):
    r = render(tmp_path, prometheus_node_exporter_exclude=[HOSTS[0]])
    assert r.returncode == 0, r.stdout + r.stderr
    nodes = yaml.safe_load((tmp_path / "data/config/generated/node_targets.yml").read_text())
    assert HOSTS[0] not in [n["labels"]["host"] for n in nodes] and len(nodes) == len(HOSTS) - 1


def test_a_host_the_registry_lacks_cannot_be_excluded(tmp_path):
    r = render(tmp_path, prometheus_node_exporter_exclude=["old-lab-host"])
    assert r.returncode != 0 and "names no registry host" in r.stdout + r.stderr


def test_the_configuration_carries_the_retention_and_the_generated_lists(tmp_path):
    r = render(tmp_path, prometheus_retention_time="45d", prometheus_retention_size="20GB")
    assert r.returncode == 0, r.stdout + r.stderr
    cfg = yaml.safe_load((tmp_path / "data/config/prometheus.yml").read_text())
    assert cfg["storage"]["tsdb"]["retention"] == {"time": "45d", "size": "20GB"}
    assert cfg["scrape_config_files"] == ["/etc/prometheus/generated/scrape_configs.yml"]
    node = next(j for j in cfg["scrape_configs"] if j["job_name"] == "node")
    assert node["file_sd_configs"] == [{"files": ["/etc/prometheus/generated/node_targets.yml"]}]
    assert cfg["rule_files"] == ["/etc/prometheus/rules.yml"]


def test_the_default_retention_is_thirty_days_without_a_size_cap(tmp_path):
    assert render(tmp_path).returncode == 0
    cfg = yaml.safe_load((tmp_path / "data/config/prometheus.yml").read_text())
    assert cfg["storage"]["tsdb"]["retention"] == {"time": "30d"}


def test_the_four_default_rules_use_the_settings(tmp_path):
    r = render(
        tmp_path,
        prometheus_alert_disk_used_percent=85,
        prometheus_alert_memory_available_percent=15,
        prometheus_alert_target_down_for="20m",
    )
    assert r.returncode == 0, r.stdout + r.stderr
    rules = yaml.safe_load((tmp_path / "data/config/rules.yml").read_text())
    by = {x["alert"]: x for g in rules["groups"] for x in g["rules"]}
    assert sorted(by) == ["DiskAlmostFull", "FilesystemReadOnly", "MemoryPressure", "TargetDown"]
    assert by["TargetDown"]["for"] == "20m" and by["TargetDown"]["expr"] == "up == 0"
    assert "> 85" in by["DiskAlmostFull"]["expr"]
    assert "< 15" in by["MemoryPressure"]["expr"]
    assert by["FilesystemReadOnly"]["expr"] == "node_filesystem_readonly == 1"
    assert "{{ $labels.instance }}" in by["MemoryPressure"]["annotations"]["summary"]


def test_the_scrape_credential_is_written_group_readable_and_removed_when_unnamed(tmp_path):
    r = render(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    cred = tmp_path / "data" / SCRAPE_FILE
    assert cred.read_text() == SCRAPE_PASSWORD + "\n"
    assert oct(cred.stat().st_mode & 0o777) == "0o640"
    # the registry stops naming it: the file goes, and so does nothing else
    doc = yaml.safe_load(REGISTRY.read_text())
    del doc["services"][AUTH_ROW]["metrics"]["auth"]
    reg = tmp_path / "services.yml"
    reg.write_text(yaml.safe_dump(doc))
    r = run_steps(tmp_path, RENDER, pvars(tmp_path, prometheus_registry=str(reg)), SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not cred.exists()
    assert (tmp_path / "data/config/prometheus.yml").exists()


def test_a_second_run_changes_nothing(tmp_path):
    assert render(tmp_path).returncode == 0
    again = render(tmp_path)
    assert again.returncode == 0, again.stdout + again.stderr
    assert "changed=0" in again.stdout, again.stdout


# ----------------------------------------------------------------------------- the product's own checks


def _promtool(tmp_path: Path, *args: str, mounts: dict[Path, str]):
    docker = require_tool("docker")
    cmd = [docker, "run", "--rm", "--entrypoint", "promtool"]
    for src, dst in mounts.items():
        cmd += ["-v", f"{src}:{dst}:ro"]
    return subprocess.run([*cmd, IMAGE, *args], capture_output=True, text=True, timeout=300)


def test_the_rendered_configuration_passes_promtool(tmp_path):
    require_tool("docker")
    assert render(tmp_path).returncode == 0
    data = tmp_path / "data"
    for p in data.rglob("*"):
        p.chmod(0o755 if p.is_dir() else 0o644)  # the container's promtool runs as another user
    data.chmod(0o755)
    r = _promtool(
        tmp_path,
        "check", "config", "/etc/prometheus/prometheus.yml",
        mounts={data / "config": "/etc/prometheus",
                data / "scrape-credentials": "/etc/hnx/scrape-credentials"},
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SUCCESS" in r.stdout


RULE_TESTS = """\
rule_files: [/etc/prometheus/rules.yml]
evaluation_interval: 1m
tests:
  - name: a target that is down for the whole window fires; one that came back does not
    interval: 1m
    input_series:
      - {series: 'up{job="node", instance="a"}', values: '0x15'}
      - {series: 'up{job="node", instance="b"}', values: '0x5 1x10'}
    alert_rule_test:
      - eval_time: 12m
        alertname: TargetDown
        exp_alerts:
          - exp_labels: {severity: critical, job: node, instance: a}
            exp_annotations: {summary: "node target a has been unreachable"}
  - name: a disk over the threshold fires, one under it does not
    interval: 1m
    input_series:
      - {series: 'node_filesystem_size_bytes{instance="a", mountpoint="/"}', values: '100x20'}
      - {series: 'node_filesystem_avail_bytes{instance="a", mountpoint="/"}', values: '5x20'}
      - {series: 'node_filesystem_size_bytes{instance="b", mountpoint="/"}', values: '100x20'}
      - {series: 'node_filesystem_avail_bytes{instance="b", mountpoint="/"}', values: '50x20'}
    alert_rule_test:
      - eval_time: 15m
        alertname: DiskAlmostFull
        exp_alerts:
          - exp_labels: {severity: warning, instance: a, mountpoint: "/"}
            exp_annotations: {summary: "a / is over 90% full"}
  - name: a read-only filesystem fires
    interval: 1m
    input_series:
      - {series: 'node_filesystem_readonly{instance="a", mountpoint="/data"}', values: '1x10'}
      - {series: 'node_filesystem_readonly{instance="b", mountpoint="/"}', values: '0x10'}
    alert_rule_test:
      - eval_time: 5m
        alertname: FilesystemReadOnly
        exp_alerts:
          - exp_labels: {severity: critical, instance: a, mountpoint: "/data"}
            exp_annotations: {summary: "a /data is mounted read-only"}
  - name: a host short of memory fires, one with enough does not
    interval: 1m
    input_series:
      - {series: 'node_memory_MemTotal_bytes{instance="a"}', values: '1000x20'}
      - {series: 'node_memory_MemAvailable_bytes{instance="a"}', values: '50x20'}
      - {series: 'node_memory_MemTotal_bytes{instance="b"}', values: '1000x20'}
      - {series: 'node_memory_MemAvailable_bytes{instance="b"}', values: '500x20'}
    alert_rule_test:
      - eval_time: 15m
        alertname: MemoryPressure
        exp_alerts:
          - exp_labels: {severity: warning, instance: a}
            exp_annotations: {summary: "a has under 10% of its memory available"}
"""


def test_the_default_rules_fire_on_what_they_should_and_not_on_what_they_should_not(tmp_path):
    require_tool("docker")
    assert render(tmp_path).returncode == 0
    work = tmp_path / "rules"
    work.mkdir()
    shutil.copy(tmp_path / "data/config/rules.yml", work / "rules.yml")
    (work / "tests.yml").write_text(RULE_TESTS)
    for p in (work, work / "rules.yml", work / "tests.yml"):
        p.chmod(0o755 if p.is_dir() else 0o644)
    r = _promtool(
        tmp_path, "test", "rules", "/etc/prometheus/tests.yml", mounts={work: "/etc/prometheus"}
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SUCCESS" in r.stdout
