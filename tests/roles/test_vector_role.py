# SPDX-License-Identifier: Apache-2.0
"""Role ``vector`` (modules/vector/roles/vector), run on localhost against fakes (CI is
unprivileged): main renders the two-container compose project, the aggregator's configuration, the
code the sidecar runs (the core's label rules as verbatim copies), the rendered label tables and the
listener certificate, with the credentials only in the env_file and the key file, and a second run is
``changed=0``; malformed inputs, credentials and tables are refused before anything is written; export
writes an object-tree of the checkpoints with a sha256 listing and restore refuses a tampered one;
upgrade refuses an unpinned or foreign target and records a pinned one."""

from __future__ import annotations

import json
import os
import pwd
import stat
import sys
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

from homelabnext import tlp
from homelabnext.logpipeline import table_doc
from homelabnext.logpipeline import tlp_labels as tl
from tests.modules.vector_addrs import GUEST_ADDR, MODEL, ROUTER_ADDR, STORE_ADDR

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "vector"
ROLE = str(MODULE / "roles" / "vector")
USER = pwd.getpwuid(os.getuid()).pw_name
GUEST = GUEST_ADDR
STORE = f"http://{STORE_ADDR}:3900"

# built at run time from short pieces: nothing here may read as a key to a secret scanner
KEY_ID = "GK" + "0123456789abcdef01234567"
SIGNING = "ab" * 32
CERT = "\n".join(["-----BEGIN " + "CERTIFICATE-----", "AAAA", "-----END " + "CERTIFICATE-----"])
PEM_KEY = "\n".join(["-----BEGIN " + "PRIVATE KEY-----", "BBBB", "-----END " + "PRIVATE KEY-----"])
SECRETS = {
    "HNX_SECRET_VECTOR_S3_ACCESS_KEY": KEY_ID,
    "HNX_SECRET_VECTOR_S3_SECRET_KEY": SIGNING,
    "HNX_SECRET_VECTOR_TLS_CERT": CERT,
    "HNX_SECRET_VECTOR_TLS_KEY": PEM_KEY,
}


def vector_vars(tmp_path: Path, **kw) -> dict:
    tables = tmp_path / "rendered"
    tables.mkdir(exist_ok=True)
    (tables / "runtime-labels.json").write_text(
        json.dumps(table_doc([(MODEL, "model", "guest:infer-core", "cap:inference")]))
    )
    (tables / "tlp-sources.json").write_text(
        json.dumps(tl.table_doc([("vector/siem-alerts", tlp.Label.AMBER, False)]))
    )
    logs = tmp_path / "siem-logs"
    logs.mkdir(exist_ok=True)
    v = {
        "vector_logical_id": "log-pipeline",
        "ansible_host": GUEST,
        "vector_dir": str(tmp_path / "app"),
        "vector_data_root": str(tmp_path / "data"),
        "vector_export_dir": str(tmp_path / "export"),
        "vector_owner": USER,
        "vector_uid": os.getuid(),
        "vector_gid": os.getgid(),
        "vector_siem_logs_dir": str(logs),
        "vector_s3_url": STORE,
        "vector_s3_region": "region-a",
        "vector_runtime_labels_src": str(tables / "runtime-labels.json"),
        "vector_tlp_sources_src": str(tables / "tlp-sources.json"),
        "vector_trusted_recorders": [ROUTER_ADDR],
        "vector_detection_ids": {"5712": "det:ssh-auth-failure-burst"},
        "vector_start": False,
        "vector_textfile_dir": "",  # the liveness timer writes outside the sandbox: tested statically
        "vector_validate_with_docker": False,
    }
    v.update(kw)
    return v


def _first_main_renders_the_project_and_everything_the_sidecar_runs(tmp_path):
    v = vector_vars(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_renders_the_project_and_everything_the_sidecar_runs)
def test_main_renders_the_project_and_everything_the_sidecar_runs(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    data = tmp_path / "data"
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert set(doc["services"]) == {"vector", "sidecar"}
    agg, side = doc["services"]["vector"], doc["services"]["sidecar"]
    for svc in (agg, side):
        assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
        assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
        assert svc["read_only"] is True and "@sha256:" in svc["image"]
    assert agg["ports"] == [f"{GUEST}:514:5514/udp", f"{GUEST}:6514:6514", f"{GUEST}:6000:6000"]
    assert "ports" not in side  # the sidecar listens on a socket, never a port
    assert f"{v['vector_siem_logs_dir']}:/var/siem-logs:ro" in agg["volumes"]  # read-only
    assert all(
        ":ro" in x for x in side["volumes"] if "/run/hnx" not in x
    )  # it changes none of its inputs
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    for secret in (KEY_ID, SIGNING, PEM_KEY):
        assert secret not in text and secret not in r.stdout
    env = (tmp_path / "app" / "secrets" / "vector.env").read_text()
    assert KEY_ID in env and SIGNING in env and "PRIVATE" not in env
    assert oct((tmp_path / "app" / "secrets" / "vector.env").stat().st_mode & 0o777) == "0o600"
    # the key is a file the container reads, not an environment variable, and is not world readable
    key = data / "tls" / "key.pem"
    assert key.read_text().strip() == PEM_KEY and not key.stat().st_mode & stat.S_IRWXO
    # the aggregator's configuration is the template's, with the real settings in it
    cfg = yaml.safe_load((data / "config" / "vector.yaml").read_text())
    assert (
        cfg["sinks"]["stage"]["endpoint"] == STORE and cfg["sinks"]["stage"]["region"] == "region-a"
    )
    assert not (data / "config" / "vector.yaml.candidate").exists()
    # the label rules are the core's own files, byte for byte, and nothing else is in the layout
    for rel in yaml.safe_load((MODULE / "roles/vector/vars/main.yml").read_text())[
        "vector_lib_files"
    ]:
        assert (data / "lib" / "homelabnext" / rel).read_bytes() == (
            ROOT / "homelabnext" / rel
        ).read_bytes()
    assert sorted(p.name for p in (data / "lib" / "homelabnext").iterdir()) == [
        "__init__.py",
        "logpipeline",
        "tlp.py",
    ]
    for name in ("__init__.py", "log_pipeline.py", "ocsf.py", "sidecar.py"):
        src = MODULE / "roles" / "vector" / "files" / "hnx_modules" / "vector" / name
        assert (data / "code" / "hnx_modules" / "vector" / name).read_bytes() == src.read_bytes()
    # the tables are the rendered files, and the routes are the configuration's
    for name in ("runtime-labels.json", "tlp-sources.json"):
        assert (data / "tables" / name).read_bytes() == (tmp_path / "rendered" / name).read_bytes()
    enrich = json.loads((data / "tables" / "enrich.json").read_text())
    assert enrich["routes"]["vector/syslog-udp"] == {
        "kind": "syslog",
        "observe": "recorded",
        "trusted": [ROUTER_ADDR],
    }
    assert enrich["routes"]["vector/siem-alerts"] == {"kind": "siem", "observe": "agent"}
    assert enrich["detection_ids"] == {"5712": "det:ssh-auth-failure-burst"}
    # ownership: the containers' user owns what it writes, root's files are group readable only
    assert oct((data / "state").stat().st_mode & 0o777) == "0o700"
    assert oct((data / "run").stat().st_mode & 0o777) == "0o700"
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": vector_vars(tmp_path, **over),
        "env": {**SECRETS, **env},
    }


@pytest.mark.parametrize(
    "over, env",
    [
        ({"vector_image": "docker.io/timberio/vector:latest"}, {}),
        ({"vector_sidecar_image": "docker.io/library/python:3"}, {}),
        ({"ansible_host": "0.0.0.0"}, {}),
        ({"ansible_host": "pipeline.example.internal"}, {}),
        ({"vector_siem_syslog_port": 514}, {}),  # the manager's input is not the listener's port
        ({"vector_siem_syslog_protocol": "icmp"}, {}),
        ({"vector_uid": 0}, {}),
        ({"vector_data_root": "/var/lib/../etc"}, {}),
        ({"vector_siem_logs_dir": ""}, {}),
        ({"vector_s3_region": ""}, {}),
        ({"vector_route_siem_alerts": "no-slash"}, {}),
        ({"vector_route_siem_alerts": "vector/syslog-udp"}, {}),  # two inputs, one route
        ({"vector_detection_ids": {"1": "det:Bad Id"}}, {}),
        ({"vector_s3_prefix": "no-trailing-slash"}, {}),
        ({"vector_runtime_labels_src": ""}, {}),
        (
            {"vector_tls_cert_ref": "secret:vector/s3-access-key"},
            {},
        ),  # not four distinct references
        ({"vector_sensor_tls": False, "vector_sensor_ca_ref": "secret:vector/sensor-ca"}, {}),
        ({}, {"HNX_SECRET_VECTOR_S3_ACCESS_KEY": "short-id"}),
        ({}, {"HNX_SECRET_VECTOR_S3_SECRET_KEY": "not-hex"}),
        ({}, {"HNX_SECRET_VECTOR_TLS_CERT": "not a certificate"}),
        ({}, {"HNX_SECRET_VECTOR_TLS_KEY": "not a key"}),
    ],
)
@first_run(_first_main_refuses_bad_inputs_and_credentials)
def test_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert not (tmp_path / "data" / "tls" / "key.pem").exists()
    assert KEY_ID not in r.stdout and SIGNING not in r.stdout


def _first_a_table_of_the_wrong_schema_is_refused_before_anything_is_written(tmp_path):
    v = vector_vars(tmp_path)
    Path(v["vector_runtime_labels_src"]).write_text(Path(v["vector_tlp_sources_src"]).read_text())
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS}


@first_run(_first_a_table_of_the_wrong_schema_is_refused_before_anything_is_written)
def test_a_table_of_the_wrong_schema_is_refused_before_anything_is_written(first):
    r, tmp_path = first
    assert r.returncode != 0 and "not the schema the sidecar loads" in r.stdout
    assert not (tmp_path / "data" / "tables").exists()


def _first_export_writes_an_object_tree_and_restore_checks_it(tmp_path):
    v = vector_vars(tmp_path, vector_start=True)
    for comp, body in (("siem_alerts", '{"a": 1}'), ("siem_archives", '{"b": 2}')):
        d = tmp_path / "data" / "state" / comp
        d.mkdir(parents=True)
        (d / "checkpoints.json").write_text(body)
    (tmp_path / "data" / "state" / "buffer" / "v2").mkdir(parents=True)
    (tmp_path / "data" / "state" / "buffer" / "v2" / "buffer.db").write_text("not exported")
    return {"role": ROLE, "tasks_from": "export", "extra_vars": v, "setup": {"v": v}}


@first_run(_first_export_writes_an_object_tree_and_restore_checks_it)
def test_export_writes_an_object_tree_and_restore_checks_it(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    export = tmp_path / "export"
    listing = [json.loads(x) for x in (export / "listing.jsonl").read_text().splitlines()]
    assert [x["key"] for x in listing] == ["siem_alerts.json", "siem_archives.json"]  # no buffer
    assert sorted(p.name for p in (export / "checkpoints").iterdir()) == [
        "siem_alerts.json",
        "siem_archives.json",
    ]
    log = tmp_path / "docker.log"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake(
        bindir / "docker",
        f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n",
    )
    env = {"PATH": f"{bindir}:{os.environ['PATH']}"}
    # restore from a copy: checked, the containers stopped and started around the copy
    for comp in ("siem_alerts", "siem_archives"):
        (tmp_path / "data" / "state" / comp / "checkpoints.json").write_text("{}")
    ok = run_role(tmp_path, ROLE, "restore", {**v, "vector_restore_source": str(export)}, env=env)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    calls = log.read_text().splitlines()
    assert calls[0].endswith(" stop") and calls[-1].endswith(" start")
    got = tmp_path / "data" / "state" / "siem_alerts" / "checkpoints.json"
    assert got.read_text() == '{"a": 1}' and oct(got.stat().st_mode & 0o777) == "0o600"
    # a tampered file, or a name that is not a plain checkpoint, is refused before anything changes
    log.unlink()
    (export / "checkpoints" / "siem_alerts.json").write_text('{"a": 2}')
    bad = run_role(tmp_path, ROLE, "restore", {**v, "vector_restore_source": str(export)}, env=env)
    assert bad.returncode != 0 and "is missing or is not what the export lists" in bad.stdout
    assert not log.exists()
    (export / "listing.jsonl").write_text(
        json.dumps({"key": "../escape.json", "size": 1, "sha256": "0" * 64}) + "\n"
    )
    bad = run_role(tmp_path, ROLE, "restore", {**v, "vector_restore_source": str(export)}, env=env)
    assert bad.returncode != 0 and "not a plain checkpoint file" in bad.stdout and not log.exists()


def _first_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one(tmp_path):
    v = vector_vars(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one)
def test_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0, first_result.stdout
    bad = run_role(
        tmp_path, ROLE, "upgrade", {**v, "vector_target_image": "docker.io/timberio/vector:9"}
    )
    assert bad.returncode != 0
    other = "docker.io/someone/vector:9.9.9@sha256:" + "a" * 64  # another repository
    assert run_role(tmp_path, ROLE, "upgrade", {**v, "vector_target_image": other}).returncode != 0
    target = "docker.io/timberio/vector:9.9.9-debian@sha256:" + "a" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "vector_target_image": target})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending == {"service": "vector", "tag": "9.9.9-debian", "digest": "sha256:" + "a" * 64}


# ----------------------------------------------------------------------------- stale socket, liveness


def _liveness():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "vector_liveness", MODULE / "roles/vector/files/hnx_modules/vector/liveness.py"
    )
    mod = importlib.util.module_from_spec(spec)
    keep, sys.dont_write_bytecode = sys.dont_write_bytecode, True  # no __pycache__ in the role tree
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = keep
    return mod


def _first_main_for_the_socket(tmp_path):
    v = vector_vars(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_for_the_socket)
def test_the_aggregator_removes_only_its_own_stale_listener_socket_at_every_start(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    agg, side = doc["services"]["vector"], doc["services"]["sidecar"]
    ep = agg["entrypoint"]
    assert ep[:2] == ["/bin/sh", "-c"] and "rm -f --" in ep[2] and "exec /usr/bin/vector" in ep[2]
    assert ep[-1] == "/run/hnx/out.sock"  # the one path, and no glob, no directory
    assert "*" not in " ".join(ep) and agg["command"] == ["--config", "/etc/vector/vector.yaml"]
    assert "entrypoint" not in side


def test_the_liveness_metrics_name_a_dead_container_a_stale_status_and_the_rows_moved():
    mod = _liveness()
    up = {"running": True, "healthy": True, "restarts": 0}
    states = {"vector": {"running": True, "healthy": False, "restarts": 212}, "sidecar": up}
    status = {
        "time": 940.0,
        "listening": True,
        "errors": {},
        "counters": {"vector/siem-archives": {"in": 3, "rows": 7, "unlabelled": 0}},
    }
    text = mod.render(states, status, 1000.0)
    assert 'vector_pipeline_container_restarts{service="vector"} 212' in text
    assert 'vector_pipeline_container_healthy{service="vector"} 0' in text
    assert 'vector_pipeline_container_running{service="sidecar"} 1' in text
    assert (
        "vector_pipeline_status_age_seconds 60" in text
        and "vector_pipeline_status_present 1" in text
    )
    assert 'vector_pipeline_rows_total{route="vector/siem-archives"} 7' in text
    assert "vector_pipeline_check_timestamp_seconds 1000" in text
    missing = mod.render(states, None, 1000.0)
    assert "vector_pipeline_status_present 0" in missing
    assert f"vector_pipeline_status_age_seconds {mod.ABSENT_AGE}" in missing
    assert "vector_pipeline_rows_total{" not in missing  # no counter is invented


def test_the_liveness_writer_reads_the_status_and_refuses_an_unsafe_output(tmp_path):
    mod = _liveness()
    f = tmp_path / "status.json"
    assert mod.read_status(f) is None  # missing
    f.write_text("not json")
    assert mod.read_status(f) is None
    f.write_text("[1]")
    assert mod.read_status(f) is None
    f.write_text('{"time": 5}')
    assert mod.read_status(f) == {"time": 5}
    out = tmp_path / "text" / "vector_pipeline.prom"
    out.parent.mkdir()
    mod.write_atomic(out, "a 1\n")
    assert out.read_text() == "a 1\n" and not list(out.parent.glob(".hnx-liveness-*"))
    assert (out.stat().st_mode & 0o777) == 0o600  # never group- or world-readable
    with pytest.raises(ValueError):
        mod.write_atomic(Path("/x.prom"), "a 1\n")
    with pytest.raises(ValueError):
        mod.write_atomic(out.with_suffix(".txt"), "a 1\n")


def test_the_timer_is_wired_to_the_textfile_dir_and_off_when_it_is_empty():
    role = MODULE / "roles" / "vector"
    assert "vector_textfile_dir | length > 0" in (role / "tasks/main.yml").read_text()
    unit = (role / "templates/hnx-vector-liveness.service.j2").read_text()
    assert "vector_textfile_dir" in unit and "run/status.json" in unit
    d = yaml.safe_load((role / "defaults/main.yml").read_text())
    assert d["vector_textfile_dir"].startswith("/")
    assert "vector_textfile_dir" in (role / "tasks/validate.yml").read_text()
