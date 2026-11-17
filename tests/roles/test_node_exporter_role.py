# SPDX-License-Identifier: Apache-2.0
"""The host-metrics role ``node_exporter`` (control metrics-agent, applied per guest).

Its ``config`` hook runs here on localhost against a fake systemctl (the package install is a
distribution package, not run); ``health`` runs against a loopback stand-in for the exporter; and
``validate`` refuses every input that could widen the listener or add an argument."""

from __future__ import annotations

import http.server
import socket
import threading

import pytest
from rolerun import calls, first_run, logging_fake, run_cases, run_role

pytestmark = pytest.mark.requires_tool("ansible-playbook")

LOOPBACK = socket.gethostbyname("localhost")  # the loopback address, by name
GUEST = LOOPBACK  # any guest address will do for the arguments
FAMILIES = [
    "node_filesystem_avail_bytes",
    "node_filesystem_size_bytes",
    "node_filesystem_readonly",
    "node_memory_MemAvailable_bytes",
    "node_memory_MemTotal_bytes",
]


def _vars(tmp_path, **kw):
    d = {
        "node_exporter_bind": GUEST,
        "node_exporter_port": 9100,
        "node_exporter_defaults_file": str(tmp_path / "prometheus-node-exporter"),
        "node_exporter_systemctl_cli": logging_fake(tmp_path, "systemctl"),
        "node_exporter_state_dir": str(tmp_path / "state"),
    }
    d.update(kw)
    return d


def _first(tmp_path):
    v = _vars(tmp_path)
    return {"role": "node_exporter", "tasks_from": "config", "extra_vars": v, "setup": {"v": v}}


@first_run(_first)
def test_the_arguments_bind_the_guest_address_only_and_restart_once(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "prometheus-node-exporter").read_text()
    assert f"--web.listen-address={GUEST}:9100" in text
    assert "0.0.0.0" not in text and "--no-collector.textfile" in text
    assert calls(tmp_path) == ["systemctl restart prometheus-node-exporter"]
    assert not (tmp_path / "state" / "restart-pending").exists()
    again = run_role(tmp_path, "node_exporter", "config", v)
    assert again.returncode == 0 and len(calls(tmp_path)) == 1  # unchanged: no restart


def _first(tmp_path):
    v = _vars(tmp_path)
    (tmp_path / "systemctl.fails").touch()
    return {"role": "node_exporter", "tasks_from": "config", "extra_vars": v, "setup": {"v": v}}


@first_run(_first)
def test_a_failed_restart_stays_owed_until_it_succeeds(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode != 0
    assert (tmp_path / "state" / "restart-pending").exists()
    (tmp_path / "systemctl.fails").unlink()
    assert run_role(tmp_path, "node_exporter", "config", v).returncode == 0
    assert calls(tmp_path)[-1] == "systemctl restart prometheus-node-exporter"
    assert not (tmp_path / "state" / "restart-pending").exists()


def _first(tmp_path):
    return {
        "runner": run_cases,
        "role": "node_exporter",
        "tasks_from": "config",
        "base_vars": _vars(tmp_path),
        "overrides": [
            {"node_exporter_bind": "0.0.0.0"},
            {"node_exporter_bind": "node-1.example.internal"},
            {"node_exporter_port": 0},
            {"node_exporter_port": 70000},
            {"node_exporter_fs_types_exclude": "^(tmp)$ --collector.textfile"},
            {"node_exporter_fs_types_exclude": "tmpfs"},
            {"node_exporter_defaults_file": "/etc/../default/x"},
            {"node_exporter_service": "x; reboot"},
        ],
    }


@first_run(_first)
def test_inputs_that_could_widen_the_listener_or_add_an_argument_are_refused(first):
    results, tmp_path = first
    assert all(f and "node_exporter: the guest's own IPv4" in m for f, m in results), results
    assert not (tmp_path / "prometheus-node-exporter").exists()


class _Exporter(http.server.BaseHTTPRequestHandler):
    families = FAMILIES

    def do_GET(self):
        body = "".join(f"# TYPE {f} gauge\n{f} 1\n" for f in self.families).encode()
        self.send_response(200 if self.path == "/metrics" else 404)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(families):
    handler = type("H", (_Exporter,), {"families": families})
    srv = http.server.HTTPServer((LOOPBACK, 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.mark.parametrize(
    "families, ok",
    [(FAMILIES, True), (FAMILIES[:-1], False), ([], False)],
    ids=["all", "no-memtotal", "empty"],
)
def test_health_wants_the_families_the_alert_rules_read(tmp_path, families, ok):
    srv = _serve(families)
    try:
        v = _vars(tmp_path, node_exporter_bind=LOOPBACK, node_exporter_port=srv.server_port)
        r = run_role(tmp_path, "node_exporter", "health", v)
    finally:
        srv.shutdown()
    assert (r.returncode == 0) is ok, r.stdout + r.stderr
    if not ok:
        assert "lacks a metric family" in r.stdout + r.stderr


def test_health_fails_when_nothing_listens(tmp_path):
    v = _vars(
        tmp_path, node_exporter_bind=LOOPBACK, node_exporter_port=1, node_exporter_health_timeout=2
    )
    assert run_role(tmp_path, "node_exporter", "health", v).returncode != 0


def test_the_package_is_installed_without_recommends():
    """Debian's recommends pull ipmitool and openipmi onto every guest, and openipmi fails each boot without IPMI."""
    import pathlib

    import yaml

    tasks = yaml.safe_load(
        (pathlib.Path(__file__).resolve().parents[2] / "ansible/roles/node_exporter/tasks/main.yml").read_text()
    )
    apt = [t["ansible.builtin.apt"] for t in tasks if "ansible.builtin.apt" in t]
    assert apt, "the role installs the package with ansible.builtin.apt"
    assert all(a.get("install_recommends") is False for a in apt)
