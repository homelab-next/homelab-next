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


NETMASK = ".".join(["255", "255", "255", "0"])  # a /24


def net(a, b, c, d, prefix=24):
    """A CIDR built from its octets, so no address literal sits in a test."""
    return f"{ipaddress.IPv4Address((a << 24) | (b << 16) | (c << 8) | d)}/{prefix}"


SUBNET = net(10, 231, 77, 0)  # a free private /24 stands in for the site's own
SELF = "localhost"  # the container itself
SELF_PORT = 9090  # the port the service listens on inside it


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
        "prometheus_network_subnet": SUBNET,
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
        {"prometheus_alert_schedule": "*-*-* *:*:00/5 UTC"},
        {"prometheus_alert_readonly_ignore": '/boot"} or vector(1) #'},
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
    # byte-identical but for the one job the role points at the container itself (next tests)
    mine = yaml.safe_load((out / "scrape_configs.yml").read_text())["scrape_configs"]
    theirs = yaml.safe_load(gen["prometheus/scrape_configs.yml"])["scrape_configs"]
    assert [j for j in mine if j["job_name"] != "metrics"] == [
        j for j in theirs if j["job_name"] != "metrics"
    ]
    assert (out / "scrape_configs.yml").read_text().startswith("#")  # the header survives
    assert (out / "node_targets.yml").read_text() == gen["prometheus/node_targets.yml"]
    nodes = yaml.safe_load((out / "node_targets.yml").read_text())
    assert [n["labels"]["host"] for n in nodes] == HOSTS
    jobs = {
        j["job_name"]
        for j in yaml.safe_load((out / "scrape_configs.yml").read_text())["scrape_configs"]
    }
    assert {"metrics", AUTH_ROW} <= jobs  # a job per row with a metrics block


def _jobs(tmp_path: Path) -> dict:
    cfg = yaml.safe_load((tmp_path / "data/config/generated/scrape_configs.yml").read_text())
    return {j["job_name"]: j for j in cfg["scrape_configs"]}


def test_the_service_scrapes_itself_inside_its_container_with_its_instance_name_kept(tmp_path):
    """A container reaching the guest's own address arrives on the guest's INPUT chain, which has
    no rule for it (a live 'context deadline exceeded'): the self job targets localhost in the
    container, and the instance label stays the registry's address so series do not change."""
    r = render(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    gen = generate(load(REGISTRY), ["prometheus"], {"node_targets": {"port": 9100}})["prometheus"]
    orig = {
        j["job_name"]: j
        for j in yaml.safe_load(gen["prometheus/scrape_configs.yml"])["scrape_configs"]
    }["metrics"]
    own = _jobs(tmp_path)["metrics"]
    (sc,) = own["static_configs"]
    assert sc["targets"] == [f"{SELF}:{SELF_PORT}"]
    assert sc["labels"] == {
        **orig["static_configs"][0]["labels"],
        "instance": orig["static_configs"][0]["targets"][0],
    }
    assert {k: v for k, v in own.items() if k != "static_configs"} == {
        k: v for k, v in orig.items() if k != "static_configs"
    }


def _selfscrape(tmp_path: Path, text: str):
    """The self-scrape rewrite alone, on crafted generator output; returns (result, output text)."""
    cmd, run_env = _invocation(
        tmp_path, ROLE, "selfscrape", pvars(tmp_path) | {"crafted_text": text}, SECRETS
    )
    play = yaml.safe_load((tmp_path / "play.yml").read_text())
    play[0]["tasks"] = [
        # set_fact, as generate.yml does (an extra var could not be overridden by the rewrite)
        {"ansible.builtin.set_fact": {"prometheus_scrape_text": "{{ crafted_text }}"}},
        {"ansible.builtin.include_role": {"name": ROLE, "tasks_from": "selfscrape"}},
        {
            "ansible.builtin.copy": {
                "content": "{{ prometheus_scrape_text }}",
                "dest": str(tmp_path / "out.yml"),
            }
        },
    ]
    (tmp_path / "play.yml").write_text(yaml.safe_dump(play))
    r = subprocess.run(cmd, capture_output=True, text=True, env=run_env, cwd=tmp_path)
    out = tmp_path / "out.yml"
    return r, out.read_text() if out.exists() else None


def _job(name, service, targets=("a:1",), scheme=None, static=True):
    j = {"job_name": name, "metrics_path": "/metrics"}
    if scheme:
        j["scheme"] = scheme
    if static:
        j["static_configs"] = [{"targets": list(targets), "labels": {"service": service}}]
    return j


def _text(*jobs):
    return "# Managed header\n" + yaml.safe_dump({"scrape_configs": list(jobs)})


def test_the_generators_text_is_kept_byte_for_byte_when_no_job_is_the_services_own(tmp_path):
    text = _text(_job("a", "other"), _job("b", "another", scheme="https"))
    r, out = _selfscrape(tmp_path, text)
    assert r.returncode == 0, r.stdout + r.stderr
    assert out == text


def test_a_job_without_static_configs_is_kept_and_does_not_break_the_rewrite(tmp_path):
    r, out = _selfscrape(
        tmp_path, _text(_job("odd", "x", static=False), _job("metrics", "metrics", ("h:9090",)))
    )
    assert r.returncode == 0, r.stdout + r.stderr
    jobs = {j["job_name"]: j for j in yaml.safe_load(out)["scrape_configs"]}
    assert "static_configs" not in jobs["odd"]
    (sc,) = jobs["metrics"]["static_configs"]
    assert sc["targets"] == [f"{SELF}:{SELF_PORT}"] and sc["labels"]["instance"] == "h:9090"
    assert out.startswith("# Managed header\n")


def test_the_services_own_https_job_is_left_alone(tmp_path):
    text = _text(_job("metrics", "metrics", ("h:9090",), scheme="https"))
    r, out = _selfscrape(tmp_path, text)
    assert r.returncode == 0, r.stdout + r.stderr
    assert out == text


@pytest.mark.parametrize("targets", [(), ("h:1", "h:2")])
def test_the_services_own_job_of_an_unexpected_shape_is_refused_clearly(tmp_path, targets):
    r, _ = _selfscrape(tmp_path, _text(_job("metrics", "metrics", targets)))
    assert r.returncode != 0
    assert "exactly one" in r.stdout + r.stderr


def test_the_self_job_follows_the_container_port_not_the_published_one(tmp_path):
    assert render(tmp_path, prometheus_port=9191).returncode == 0
    assert _jobs(tmp_path)["metrics"]["static_configs"][0]["targets"] == [f"{SELF}:{SELF_PORT}"]


def test_the_own_host_exporter_target_is_unchanged(tmp_path):
    """Its address is the host's, reached through the pinned subnet's firewall rule, not a rewrite."""
    assert render(tmp_path).returncode == 0
    nodes = yaml.safe_load((tmp_path / "data/config/generated/node_targets.yml").read_text())
    assert f"{GUEST}:9100" in [x for n in nodes for x in n["targets"]]


def test_the_pinned_subnet_is_in_the_compose_file_main_produces(tmp_path):
    """main runs compose_app for real (nothing started); the example registry has no notify service,
    so the run stops at the alert forwarder's first task, after the compose file is written."""
    r = run_role(
        tmp_path,
        ROLE,
        "main",
        pvars(tmp_path, prometheus_unit_dir=str(tmp_path / "units")),
        env=SECRETS,
    )
    assert "Resolve the notify endpoint" in r.stdout + r.stderr, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert doc["networks"] == {"default": {"ipam": {"config": [{"subnet": SUBNET}]}}}


SUBNET_REFUSED = {
    "empty": "",
    "no prefix": net(10, 231, 77, 0).split("/")[0],
    "prefix too short": net(10, 0, 0, 0, 8),
    "prefix too long": net(10, 231, 77, 0, 30),
    "not an address": "x/24",
    "loopback": net(127, 0, 0, 0, 16),
    "link-local": net(169, 254, 0, 0, 16),
    "multicast": net(224, 0, 0, 0, 16),
    "unspecified": net(0, 0, 0, 0, 16),
    "public": net(8, 8, 0, 0, 16),
    "the whole LAN range": net(
        192, 168, 0, 0, 16
    ),  # fine as a range, refused when it holds the guest
    "host bits set": net(10, 0, 0, 5),
}


@pytest.mark.parametrize("bad", list(SUBNET_REFUSED.values()), ids=list(SUBNET_REFUSED))
def test_a_network_subnet_that_is_not_a_free_private_network_is_refused(tmp_path, bad):
    extra = {}
    if bad == net(192, 168, 0, 0, 16):  # the guest sits inside it
        extra = {
            "ansible_host": str(ipaddress.IPv4Address((192 << 24) | (168 << 16) | (1 << 8) | 20)),
            "ansible_default_ipv4": {
                "network": str(ipaddress.IPv4Address((192 << 24) | (168 << 16) | (1 << 8))),
                "netmask": NETMASK,
            },
        }
    r = run_steps(
        tmp_path, ["validate"], pvars(tmp_path, prometheus_network_subnet=bad, **extra), SECRETS
    )
    assert r.returncode != 0, r.stdout
    assert "network_subnet" in r.stdout + r.stderr


def test_the_guests_own_address_inside_the_subnet_is_refused(tmp_path):
    inside = str(ipaddress.IPv4Address((10 << 24) | (231 << 16) | (77 << 8) | 9))
    r = run_steps(tmp_path, ["validate"], pvars(tmp_path, ansible_host=inside), SECRETS)
    assert r.returncode != 0 and "must not contain the guest" in r.stdout + r.stderr


def test_a_free_private_subnet_beside_the_guest_is_accepted(tmp_path):
    r = run_steps(tmp_path, ["validate"], pvars(tmp_path), SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_network_subnet_has_no_default(tmp_path):
    v = pvars(tmp_path)
    del v["prometheus_network_subnet"]
    r = run_steps(tmp_path, ["validate"], v, SECRETS)
    assert r.returncode != 0 and "network_subnet" in r.stdout + r.stderr


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
    assert sorted(by) == [
        "DiskAlmostFull", "FilesystemReadOnly", "MemoryPressure", "NoTargets", "TargetDown",
        "Watchdog",
    ]  # fmt: skip
    assert by["TargetDown"]["for"] == "20m" and by["TargetDown"]["expr"] == "up == 0"
    assert "> 85" in by["DiskAlmostFull"]["expr"]
    assert "< 15" in by["MemoryPressure"]["expr"]
    assert by["FilesystemReadOnly"]["expr"] == "node_filesystem_readonly == 1"
    assert "{{ $labels.instance }}" in by["MemoryPressure"]["annotations"]["summary"]


def test_a_deliberate_read_only_mount_can_be_left_out_of_the_rule(tmp_path):
    r = render(tmp_path, prometheus_alert_readonly_ignore="/boot/efi|/mnt/media")
    assert r.returncode == 0, r.stdout + r.stderr
    rules = yaml.safe_load((tmp_path / "data/config/rules.yml").read_text())
    by = {x["alert"]: x for g in rules["groups"] for x in g["rules"]}
    assert (
        by["FilesystemReadOnly"]["expr"]
        == 'node_filesystem_readonly{mountpoint!~"/boot/efi|/mnt/media"} == 1'
    )


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
  - name: an empty host target list fires, a scraped one does not
    interval: 1m
    input_series:
      - {series: 'up{job="other", instance="a"}', values: '1x20'}
    alert_rule_test:
      - eval_time: 15m
        alertname: NoTargets
        exp_alerts:
          - exp_labels: {severity: critical, job: node}
            exp_annotations: {summary: "no host target is being scraped: the generated target list is empty or was not loaded"}
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


# ----------------------------------------------------------------------------- the forwarder's record


def _record(tmp_path: Path, finished: str | None):
    d = tmp_path / "last-run"
    d.mkdir(exist_ok=True)
    rec = {"job": "timer:prometheus/alerts", "finished_at": finished, "running": finished is None}
    (d / "timer%3Aprometheus%2Falerts.json").write_text(json.dumps(rec))
    return d


def _forwarder(tmp_path: Path, d: Path):
    return run_role(tmp_path, ROLE, "forwarder", {"prometheus_last_run_dir": str(d)})


def _ago(seconds: int) -> str:
    """The host's own clock, as the role's check reads it."""
    out = subprocess.run(
        ["date", "-u", "-d", f"{seconds} seconds ago", "+%Y-%m-%dT%H:%M:%SZ"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    return out.stdout.strip()


def test_health_passes_when_the_forwarder_finished_lately(tmp_path):
    r = _forwarder(tmp_path, _record(tmp_path, _ago(30)))
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_forwarder_that_cannot_write_its_record_fails_health_visibly(tmp_path):
    """The unit ignores a failed last-run write (the - prefix), so a timer that runs but cannot
    write (ProtectSystem=strict without the directory) has no record: health must say so."""
    d = tmp_path / "last-run"
    d.mkdir()
    r = _forwarder(tmp_path, d)
    assert r.returncode != 0
    assert "no fresh last-run record" in r.stdout and "ReadWritePaths" in r.stdout


@pytest.mark.parametrize("finished", [None, "garbage"], ids=["never-finished", "malformed"])
def test_an_unfinished_or_malformed_record_fails_health(tmp_path, finished):
    r = _forwarder(tmp_path, _record(tmp_path, finished))
    assert r.returncode != 0 and "no fresh last-run record" in r.stdout


def test_a_stale_record_fails_health(tmp_path):
    r = _forwarder(tmp_path, _record(tmp_path, _ago(3600)))
    assert r.returncode != 0 and "no fresh last-run record" in r.stdout


# ----------------------------------------------------------------------------- the dead-man heartbeat


def test_the_watchdog_rule_always_fires_and_carries_no_severity_that_pages(tmp_path):
    assert render(tmp_path).returncode == 0
    rules = yaml.safe_load((tmp_path / "data/config/rules.yml").read_text())
    by = {x["alert"]: x for g in rules["groups"] for x in g["rules"]}
    assert by["Watchdog"]["expr"] == "vector(1)" and "for" not in by["Watchdog"]
    assert by["Watchdog"]["labels"]["severity"] == "none"


def _placement(tmp_path, notify_host=None):
    """A registry with both rows (the module's metrics row and the notify row) and the notify row
    on ``notify_host`` (None: as the example has it, on the same host as the metrics row)."""
    doc = yaml.safe_load(REGISTRY.read_text())
    if notify_host:
        doc["services"]["notify"]["host"] = notify_host
    path = tmp_path / "registry.yml"
    path.write_text(yaml.safe_dump(doc))
    return path


GETENT = """import json, sys
names = json.load(open(NAMES))
addrs = names.get(sys.argv[2])
if addrs is None:
    sys.exit(2)
for a in addrs:
    print(a + "      STREAM " + sys.argv[2])
"""
ELSEWHERE = str(load(REGISTRY).hosts["lake-core"].address)  # another host of the example lab


def _alerts(tmp_path, registry, resolves=None, **kw):
    """``resolves``: what the fake getent answers by name (default: the notify alias resolves to an
    address that is not this guest's)."""
    from rolerun import fake

    names = tmp_path / "names.json"
    names.write_text(
        json.dumps(
            resolves if resolves is not None else {"notify.svc.example.internal": [ELSEWHERE]}
        )
    )
    kw.setdefault(
        "prometheus_getent_cli",
        fake(tmp_path / "getent", GETENT.replace("NAMES", repr(str(names)))),
    )
    extra = pvars(
        tmp_path,
        prometheus_unit_dir=str(tmp_path / "units"),
        prometheus_notify_allow_plain_http=True,
        prometheus_notify_auth_file=str(tmp_path / "auth" / "token"),
        prometheus_notify_test_on_change=False,
        **kw,
    )
    extra["hnx_registry_file"] = str(registry)
    return run_role(tmp_path, ROLE, "alerts", extra, env=SECRETS, check=True)


def _outcome(out, task):
    """How the named task ended in the play's output: ok, skipping, fatal (or None: not reached)."""
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("TASK [") and task in line:
            for nxt in lines[i + 1 :]:
                if nxt.strip():
                    return nxt.split(":")[0].strip() if not nxt.startswith("[ERROR]") else "fatal"
    return None


def test_a_heartbeat_receiver_on_the_metrics_guest_is_refused(tmp_path):
    """The notify service on the metrics guest is watched by the thing it watches (LL-571)."""
    r = _alerts(tmp_path, _placement(tmp_path))
    out = r.stdout + r.stderr
    assert r.returncode != 0 and "runs on this" in out and "LL-571" in out
    assert not (tmp_path / "state").exists()  # nothing was written before the refusal


ALIAS = "notify.svc.example.internal"


@pytest.mark.parametrize(
    "answer",
    [[GUEST], ["::1"], [__import__("socket").gethostbyname("localhost")], [ELSEWHERE, GUEST]],
    ids=["an alias of this guest", "loopback v6", "loopback v4", "one of several is this guest"],
)
def test_a_receiver_that_resolves_to_this_guest_is_refused_whatever_the_registry_says(
    tmp_path, answer
):
    r = _alerts(tmp_path, _placement(tmp_path, "lake-core"), resolves={ALIAS: answer})
    out = r.stdout + r.stderr
    assert r.returncode != 0 and "runs on this" in out and "resolves to" in out


def test_a_receiver_that_does_not_resolve_is_refused_unless_accepted(tmp_path):
    reg = _placement(tmp_path, "lake-core")
    r = _alerts(tmp_path, reg, resolves={})
    assert r.returncode != 0 and "does not resolve" in r.stdout + r.stderr
    ok = _alerts(tmp_path, reg, resolves={}, prometheus_heartbeat_allow_unresolved=True)
    assert _outcome(ok.stdout + ok.stderr, "Refuse a receiver that does not resolve") == "skipping"


def test_the_refusal_is_lifted_by_turning_the_heartbeat_off(tmp_path):
    r = _alerts(tmp_path, _placement(tmp_path), prometheus_heartbeat_topic="")
    out = r.stdout + r.stderr
    assert _outcome(out, "Refuse a heartbeat receiver") == "skipping", out


def test_a_receiver_on_another_host_passes_the_placement_check(tmp_path):
    r = _alerts(tmp_path, _placement(tmp_path, "lake-core"))
    out = r.stdout + r.stderr
    assert _outcome(out, "Refuse a heartbeat receiver") == "ok", out


@pytest.mark.parametrize(
    "over",
    [
        {"prometheus_heartbeat_topic": "has space"},
        {"prometheus_heartbeat_topic": "homelabnext-alerts"},  # the alert topic itself
        {"prometheus_heartbeat_every_minutes": 0},
        {"prometheus_heartbeat_every_minutes": 61},
    ],
)
def test_a_malformed_heartbeat_setting_is_refused(tmp_path, over):
    r = render(tmp_path, **over)
    assert r.returncode != 0 and "prometheus: a registry id" in r.stdout + r.stderr
