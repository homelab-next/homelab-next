# SPDX-License-Identifier: Apache-2.0
"""The metrics provider module, ``modules/prometheus`` (modules/prometheus/README.md).

* The public tree loads clean; ``roles/`` holds only the contributed role; the image pin is the
  product's version; the slot is provisional (no contract yet) with the shared-adapter style
  client that reads the standard query, alert, rule and target endpoints.
* The row is internal: no public hostname, so the edge renders no site for it, and no login of its
  own (``auth: none``: the network is the control); the manifest declares no egress.
* A fictional overlay that places it on a guest (every other required core slot an incumbent)
  passes ``hnx modules check --overlay`` and renders a play on ``mod_prometheus_server`` with the
  role and its readiness preflight; a row that differs, a guest without the ``base`` baseline and a
  metrics slot answered by both the module and an incumbent are refused.
* The adapter reads a stand-in for the service's API and refuses what is not success.
* role_lint passes the role and the lifecycle playbooks.
"""

from __future__ import annotations

import copy
import http.server
import ipaddress
import json
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml

from homelabnext.conform.adapters import metrics as adapter
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.generators import generate
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld
from homelabnext.registry import load as load_registry
from tests.modules.play_vars import without_footprint

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "prometheus"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
LOOPBACK = socket.gethostbyname("localhost")  # the loopback address, by name
REQUIRED = sorted(
    s for s, d in ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"].items()
    if d.get("required_in_core")
)  # fmt: skip


class _NoAliases(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(doc) -> str:
    return yaml.dump(doc, Dumper=_NoAliases, sort_keys=False)


def bound_row() -> dict:
    """The module's row as the overlay copies it: the instance's name, the guest as host and the
    product's version."""
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["metrics"]
    version = str(ld.load_yaml(MODULE / "module.yml")["product"]["version"])
    return {**copy.deepcopy(row), "host": "mon-1", "version": version}


def overlay(tmp: Path) -> Path:
    """A fictional overlay adopting the module: the example registry with the bound row in place
    of the example's own, one guest, and a selection placing the module on it with every other
    required core slot an incumbent."""
    lab = tmp / "lab"
    (lab / "guests").mkdir(parents=True)
    reg = ld.load_yaml(ROOT / "examples" / "services.yml")
    guest = str(ipaddress.ip_address(reg["hosts"]["mon-core"]["address"]) + 100)  # a free neighbour
    reg["hosts"]["mon-1"] = {"address": guest, "zone": "mgmt", "role": "monitoring"}
    reg["services"]["metrics"] = bound_row()
    hosts = {"agent-runtime": "runtime-core", "backup": "secrets-core", "broker": "idp-core",
             "edge": "edge-core", "records": "lake-core"}  # fmt: skip
    for i, (slot, host) in enumerate(sorted(hosts.items())):
        reg["services"][f"{slot}-incumbent"] = {
            "capability": slot, "impl": "example", "host": host, "protocol": "tcp",
            "port": 7001 + i, "health": {"kind": "none"}, "owner": "platform-team",
            "version": "1.0", "tls": "none",
        }  # fmt: skip
    (lab / "services.yml").write_text(_dump(reg))
    shutil.copy(FIXTURES / "guests" / "_baselines.yml", lab / "guests" / "_baselines.yml")
    (lab / "guests" / "mon-1.yml").write_text(
        "# SPDX-License-Identifier: Apache-2.0\n"
        "id: guest:mon-1\nkind: vm\nprovisioning: terraform\nstatus: planned\n"
        "placement: {node: hv-01, vmid: 242, vmid_scheme: freeform}\n"
        "resources:\n  cpu: {cores: 2}\n  memory: {size_mb: 4096}\n"
        "  disks: [{name: rootfs, size_gb: 64, pool: fast}]\n"
        "image: {logical: debian-13-cloudinit, kind: template-clone, os_type: linux-6}\n"
        "cloudinit: {user: ansible, ssh_authorized_keys: [operator]}\n"
        f"network: {{zone: mgmt, ip: {guest}}}\n"
        "capability: cap:metrics\nbackup: {policy: none}\n"
        "owners: {primary: platform-team}\nbaseline: {names: [base]}\n"
    )
    rows = {n: r["capability"] for n, r in reg["services"].items()}
    incumbents = {
        slot: {"service": next(n for n, c in rows.items() if c == slot), "why": "fictional"}
        for slot in REQUIRED
    }
    sel = {
        "profile": "metrics-pilot",
        "hosts": {"mon": {"guest": "guest:mon-1"}},
        "slots": {"metrics": [{"provider": "prometheus", "instance": "metrics",
                               "placement": {"server": "mon"}}]},
        "incumbents": incumbents,
    }  # fmt: skip
    (lab / "modules.yml").write_text(_dump(sel))
    return tmp


def _args(ov: Path) -> list[str]:
    return ["--root", str(ROOT), "--overlay", str(ov),
            "--keyring", str(ROOT / "examples" / "keyring" / "keyring.json"),
            "--mcp-catalog", str(ROOT / "examples" / "mcp")]  # fmt: skip


def _check(ov: Path, capsys) -> tuple[int, str]:
    code = mcli.main(["check", *_args(ov)])
    return code, capsys.readouterr().out


# ----------------------------------------------------------------------------- the public tree


def test_the_public_tree_loads_clean(capsys):
    code = mcli.main(["check", "--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0, out
    public = sum(1 for p in (ROOT / "modules").iterdir() if (p / "module.yml").is_file())
    assert out.rstrip().endswith(f"{public} module(s), 0 problem(s)")


def test_roles_holds_only_the_contributed_role():
    assert sorted(p.name for p in (MODULE / "roles").iterdir()) == ["prometheus"]
    assert not any(p.is_symlink() for p in MODULE.rglob("*"))
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert [c["file"] for c in manifest["contributes"]["roles"]] == ["roles/prometheus"]


def test_the_manifest_has_no_egress_and_the_row_no_public_route_and_no_login():
    manifest = ld.load_yaml(MODULE / "module.yml")
    assert manifest["egress"] == "none"
    row = ld.load_yaml(MODULE / "registry" / "services.yml")["services"]["metrics"]
    assert "public_hostname" not in row and "edge_tls" not in row
    assert row["auth"] == "none" and row["tls"] == "none"
    assert row["metrics"] == {"path": "/metrics"} and row["upstreams"] == ["notify"]
    assert "version" not in row  # a provider's row takes product.version


def test_the_slot_is_provisional_and_the_adapter_is_a_shared_one():
    slot = ld.load_yaml(MODULE / "module.yml")["provides"]["slots"]["metrics"]
    assert (
        slot["provisional"] is True
        and slot["adapter"] == "homelabnext.conform.adapters.metrics:make"
    )
    registry = ld.load_yaml(ROOT / "examples" / "modules" / "slots.yml")["slots"]
    assert registry["metrics"]["contract"] is None and not registry["metrics"].get(
        "required_in_core"
    )


def test_the_image_pin_is_the_product_version_and_a_digest():
    defaults = ld.load_yaml(MODULE / "roles" / "prometheus" / "defaults" / "main.yml")
    version = ld.load_yaml(MODULE / "module.yml")["product"]["version"]
    image = defaults["prometheus_image"]
    assert image.split("@")[0].endswith(":v" + version)
    assert image.split("@")[1].startswith("sha256:") and len(image.split("@")[1]) == 71
    assert defaults["prometheus_retention_time"] == "30d"


def test_the_lifecycle_playbooks_target_the_module_group():
    for name in ("install", "upgrade", "remove"):
        plays = yaml.safe_load((MODULE / "playbooks" / f"{name}.yml").read_text())
        assert [p["hosts"] for p in plays] == ["mod_prometheus_server"]


def test_the_module_ships_its_alert_script_with_a_catalogued_header():
    text = (MODULE / "roles/prometheus/templates/alert-notify.py.j2").read_text()
    assert "#   id: prometheus-alert-notify\n" in text
    assert "#   trigger: [timer:prometheus/alerts, role:prometheus]\n" in text


# ----------------------------------------------------------------------------- the generated targets


def test_a_registry_with_this_modules_row_gets_a_job_for_it_and_a_target_per_host():
    reg = load_registry(ROOT / "examples" / "services.yml")
    out = generate(reg, ["prometheus"], {"node_targets": {"port": 9100}})["prometheus"]
    jobs = yaml.safe_load(out["prometheus/scrape_configs.yml"])["scrape_configs"]
    assert "metrics" in {j["job_name"] for j in jobs}
    nodes = yaml.safe_load(out["prometheus/node_targets.yml"])
    assert len(nodes) == len(reg.hosts)


# ----------------------------------------------------------------------------- an overlay


def test_an_overlay_placing_the_module_on_a_guest_checks_clean_and_renders(tmp_path, capsys):
    ov = overlay(tmp_path / "ov")
    code, out = _check(ov, capsys)
    assert code == 0, out
    assert " 0 problem(s)" in out.rstrip().splitlines()[-1]
    dest = tmp_path / "out"
    code = mcli.main(["render", *_args(ov), "--out", str(dest)])
    out = capsys.readouterr().out
    assert code == 0, out
    books = yaml.safe_load((dest / "modules.yml").read_text())
    plays = [p for p in books if p["hosts"] == "mod_prometheus_server"]
    assert len(plays) == 1 and plays[0]["become"] is True
    assert plays[0]["roles"][0]["role"].endswith("modules/prometheus/roles/prometheus")
    assert plays[0]["pre_tasks"][0]["ansible.builtin.include_role"]["tasks_from"] == "readiness"
    assert without_footprint(plays[0]["vars"]) == {
        "hnx_module_slice": "hnx-prometheus-server.slice"
    }
    assert (dest / "limits" / "mon" / "hnx-prometheus-server.slice").is_file()


def test_a_registry_row_that_differs_is_named(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["metrics"]["port"] = 8080
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1
    assert "registry: services.metrics.port: prometheus (instance metrics) contributes 9090" in out


def test_a_row_that_gains_a_public_route_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    reg = ld.load_yaml(ov / "lab" / "services.yml")
    reg["services"]["metrics"]["public_hostname"] = "metrics.example.internal"
    (ov / "lab" / "services.yml").write_text(_dump(reg))
    code, out = _check(ov, capsys)
    assert code == 1 and "public_hostname" in out, out


def test_a_guest_without_the_base_baseline_is_refused(tmp_path, capsys):
    ov = overlay(tmp_path)
    g = ov / "lab" / "guests" / "mon-1.yml"
    g.write_text(g.read_text().replace("names: [base]", "names: []"))
    code, out = _check(ov, capsys)
    assert code == 1 and "base" in out, out


def test_metrics_cannot_be_both_the_module_and_an_incumbent(tmp_path, capsys):
    ov = overlay(tmp_path)
    sel = ld.load_yaml(ov / "lab" / "modules.yml")
    sel["incumbents"]["metrics"] = {"service": "metrics", "why": "both"}
    (ov / "lab" / "modules.yml").write_text(_dump(sel))
    code, out = _check(ov, capsys)
    assert code == 1 and "incumbents.metrics: the slot is also selected under slots" in out, out


# ----------------------------------------------------------------------------- the adapter


class _Quick(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def _service(answers: dict, status=200):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?")[0]
            body = json.dumps(answers.get(path, {"status": "error"})).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = _Quick((LOOPBACK, 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


ANSWERS = {
    "/api/v1/query": {"status": "success", "data": {"resultType": "vector", "result": [
        {"metric": {"job": "node"}, "value": [1, "1"]}]}},
    "/api/v1/alerts": {"status": "success", "data": {"alerts": [{"state": "firing"}]}},
    "/api/v1/rules": {"status": "success", "data": {"groups": [
        {"rules": [{"name": "TargetDown"}, {"name": "DiskAlmostFull"}]}]}},
    "/api/v1/targets": {"status": "success", "data": {"activeTargets": [{"health": "up"}]}},
}  # fmt: skip


def test_the_adapter_reads_the_four_endpoints(monkeypatch):
    srv = _service(ANSWERS)
    try:
        monkeypatch.setenv("HNX_ENDPOINT_METRICS", f"http://{LOOPBACK}:{srv.server_port}")
        target = adapter.make()
        assert target.query("up")[0]["metric"] == {"job": "node"}
        assert target.alerts() == [{"state": "firing"}]
        assert target.rule_names() == ["TargetDown", "DiskAlmostFull"]
        assert target.targets() == [{"health": "up"}]
    finally:
        srv.shutdown()


def test_the_adapter_refuses_what_is_not_success_and_what_is_not_http(monkeypatch):
    srv = _service({}, status=200)
    try:
        monkeypatch.setenv("HNX_ENDPOINT_METRICS", f"http://{LOOPBACK}:{srv.server_port}")
        with pytest.raises(adapter.MetricsError, match="did not answer success"):
            adapter.make().alerts()
    finally:
        srv.shutdown()
    srv = _service({}, status=503)
    try:
        monkeypatch.setenv("HNX_ENDPOINT_METRICS", f"http://{LOOPBACK}:{srv.server_port}")
        with pytest.raises(adapter.MetricsError, match="HTTP 503"):
            adapter.make().targets()
    finally:
        srv.shutdown()
    with pytest.raises(ValueError):
        adapter.MetricsTarget("ftp://example.internal")


def test_the_adapter_has_no_default_endpoint_and_no_unknown_setting(monkeypatch):
    monkeypatch.delenv("HNX_ENDPOINT_METRICS", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_METRICS"):
        adapter.make()
    monkeypatch.setenv("HNX_ENDPOINT_METRICS", f"http://{LOOPBACK}:9")
    with pytest.raises(ValueError, match="unknown setting"):
        adapter.make(token="x")


# ----------------------------------------------------------------------------- lint


def test_role_lint_passes_the_role_and_the_lifecycle_playbooks():
    lint = [sys.executable, str(ROOT / "tools" / "role_lint.py")]
    r = subprocess.run(
        [*lint, str(MODULE / "roles" / "prometheus")], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
    books = sorted(str(p) for p in (MODULE / "playbooks").glob("*.yml"))
    inv = str(ROOT / "ansible" / "inventory" / "example" / "hosts.yml")
    r = subprocess.run([*lint, "--playbook", *books, "--inventory", inv],
                       capture_output=True, text=True)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
