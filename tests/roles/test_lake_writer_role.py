# SPDX-License-Identifier: Apache-2.0
"""Role ``lake_writer`` (modules/lake-writer/roles/lake_writer), run on localhost against fakes (CI is
unprivileged): main installs the script, the module's schemas, the environment (no secret in it), the
root-only logins file and the template units, and a second run is ``changed=0``; the soc namespace is
derived and cannot be overridden; malformed inputs and credentials are refused by name before anything is
written; ensure-tables runs the script with the soc namespace and every login in the environment;
health passes and fails on its conditions; export writes the state beside and renames it into place;
restore refuses a bad source and replaces the checkpoints."""

from __future__ import annotations

import grp
import json
import os
import pwd
import sys
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "lake-writer" / "roles" / "lake_writer")
P = "lake_writer_"
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
LOGIN = "q" * 24
S3_ID = "i" * 20
S3_KEY = "k" * 24
SECRETS = {
    "HNX_SECRET_LAKE_WRITER_LAKE_PASSWORD": LOGIN,
    "HNX_SECRET_LAKE_WRITER_S3_ACCESS_KEY": S3_ID,
    "HNX_SECRET_LAKE_WRITER_S3_SECRET_KEY": S3_KEY,
}
TABLES = [
    "authentication",
    "compliance_finding",
    "detection_finding",
    "dns_activity",
    "file_activity",
    "http_activity",
    "network_activity",
    "process_activity",
    "raw_archive",
    "vulnerability_finding",
]


def pv(tmp_path: Path, **kw) -> dict:
    v = {
        "logical_id": "writer",
        "lake_user": "writer",
        "lake_warehouse": "wh",
        "s3_region": "region-example-1",
        "lake_query_url": "https://lake-query.example.internal",
        "lake_catalog_url": "https://lake-catalog.example.internal",
        "object_store_url": "https://object-store.example.internal",
        "config_dir": str(tmp_path / "etc"),
        "data_root": str(tmp_path / "data"),
        "bin_dir": str(tmp_path / "bin"),
        "unit_dir": str(tmp_path / "units"),
        "last_run_dir": str(tmp_path / "last-run"),
        "last_run_group": GROUP,
        "last_run_writer": str(tmp_path / "bin" / "hnx-last-run"),
        "owner": USER,
        "owner_group": GROUP,
        "user": USER,
        "group": GROUP,
        "manage_accounts": False,
        "start": False,
        "ensure_tables": False,
        "systemctl_cli": str(tmp_path / "fakebin" / "systemctl"),
    }
    v.update(kw)
    return {P + k: x for k, x in v.items()}


def _fakes(tmp_path: Path, active: bool = True) -> dict:
    """A systemctl, and a stand-in for the runtime interpreter that records its arguments and the
    HNX_LW_* environment, and fails ``schema-check`` / ``status`` while ``<name>.fails`` exists."""
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    fake(
        bindir / "systemctl",
        f"import sys\nok = {active}\nsys.stdout.write('active\\n' if ok else 'inactive\\n')\n"
        "sys.exit(0 if ok else 3)\n",
    )
    body = (
        "import json, os, sys\n"
        f"d = {str(tmp_path)!r}\n"
        "args = sys.argv[1:]\n"
        "name = next(a for a in args if a in ('ensure-tables', 'schema-check', 'status'))\n"
        "open(d + '/calls.log', 'a').write(name + ' ' + ' '.join(args) + '\\n')\n"
        "env = {k: v for k, v in os.environ.items() if k.startswith(('HNX_LW_', 'HNX_ENDPOINT_', 'HNX_SECRET_'))}\n"
        "open(d + '/env-' + name + '.json', 'w').write(json.dumps(env))\n"
        "if os.path.exists(d + '/' + name + '.fails'):\n"
        "    sys.stderr.write(name + ' found a problem\\n')\n"
        "    sys.exit(1)\n"
    )
    fake(bindir / "runtime-python", body)
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def run(tmp_path, tasks_from, extra=None, env=None, active=True, **over):
    over.setdefault("runtime_python", str(tmp_path / "fakebin" / "runtime-python"))
    v = {**pv(tmp_path, **over), **(extra or {})}
    fakes = _fakes(tmp_path, active)
    return run_role(tmp_path, ROLE, tasks_from, v, env={**SECRETS, **fakes, **(env or {})})


def installed(tmp_path: Path, **over):
    (tmp_path / "units").mkdir(exist_ok=True)
    r = run(tmp_path, "main", **over)
    assert r.returncode == 0, r.stdout + r.stderr
    return r


def test_main_installs_the_writer_with_no_secret_in_any_world_readable_file(tmp_path):
    r = installed(tmp_path)
    out = r.stdout + r.stderr
    env = (tmp_path / "etc" / "lake-writer.env").read_text()
    assert "HNX_LW_NAMESPACE=soc" in env and f"HNX_LW_TABLES={','.join(TABLES)}" in env
    assert "HNX_LW_STAGING_BUCKET=soc-staging" in env
    assert "HNX_LW_STAGING_PREFIX=lake-writer/staging/" in env
    assert "HNX_LW_LAKE_CREDENTIAL=secret:lake-writer/lake-password" in env
    assert "HNX_ENDPOINT_LAKE_QUERY=https://lake-query.example.internal" in env
    assert "HNX_ENDPOINT_OBJECT_STORE=https://object-store.example.internal" in env
    assert "CATALOG_CREDENTIAL" not in env  # none asked for
    assert "HNX_LW_S3_ALLOW_PLAINTEXT=false" in env  # https only unless the site says so
    for secret in (LOGIN, S3_ID, S3_KEY):
        assert secret not in env and secret not in out
    logins = tmp_path / "etc" / "credentials" / "logins.env"
    assert oct(logins.stat().st_mode & 0o777) == "0o600"
    text = logins.read_text()
    assert f"HNX_SECRET_LAKE_WRITER_LAKE_PASSWORD={LOGIN}" in text
    assert f"HNX_LW_S3_ACCESS_KEY={S3_ID}" in text and f"HNX_LW_S3_SECRET_KEY={S3_KEY}" in text
    script = tmp_path / "bin" / "hnx-lake-writer"
    assert oct(script.stat().st_mode & 0o777) == "0o755"
    schemas = sorted(p.name for p in (tmp_path / "etc" / "schemas").iterdir())
    assert schemas == [
        "compliance_finding.v1.json",
        "file_activity.v1.json",
        "http_activity.v1.json",
        "process_activity.v1.json",
        "raw_archive.v1.json",
    ]
    service = (tmp_path / "units" / "hnx-writer@.service").read_text()
    assert "commit --table %i" in service and "NoNewPrivileges=yes" in service
    assert (
        f"EnvironmentFile={logins}" in service
        and f"ReadWritePaths={tmp_path}/data/state" in service
    )
    timer = (tmp_path / "units" / "hnx-writer@.timer").read_text()
    assert "OnCalendar=*-*-* *:0/10:00 UTC" in timer and "Unit=hnx-writer@%i.service" in timer
    assert "OnBootSec=" not in timer and "OnUnitActiveSec=" not in timer
    assert oct((tmp_path / "data" / "state").stat().st_mode & 0o777) == "0o700"


def test_a_second_run_changes_nothing(tmp_path):
    installed(tmp_path)
    again = run(tmp_path, "main")
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_ensure_tables_runs_the_script_with_the_soc_namespace_and_every_login(tmp_path):
    (tmp_path / "units").mkdir()
    r = run(tmp_path, "main", ensure_tables=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert len((tmp_path / "calls.log").read_text().splitlines()) == 1
    env = json.loads((tmp_path / "env-ensure-tables.json").read_text())
    assert env["HNX_LW_NAMESPACE"] == "soc" and env["HNX_LW_TABLES"] == ",".join(TABLES)
    assert env["HNX_LW_LAKE_CREDENTIAL"] == "secret:lake-writer/lake-password"
    assert env["HNX_SECRET_LAKE_WRITER_LAKE_PASSWORD"] == LOGIN
    assert env["HNX_LW_S3_ACCESS_KEY"] == S3_ID and env["HNX_LW_S3_SECRET_KEY"] == S3_KEY
    assert LOGIN not in r.stdout + r.stderr  # the task is no_log


@pytest.mark.parametrize(
    "over",
    [
        {"namespace": "cti"},  # an extra variable outranks the derived one: validate still refuses
        {"namespace": "ocsf"},
        {"tables": ["dns_activity", "cti_events"]},
        {"tables": ["dns_activity", "dns_activity"]},
        {"lake_query_url": "http://lake-query.example.internal"},
        # a plain-http catalog is refused when a catalog token would go to it
        {
            "lake_catalog_url": "http://lake-catalog.example.internal",
            "catalog_bearer_ref": "secret:lake-writer/catalog-token",
        },
        {"lake_query_url": "", "lake_query_id": ""},
        {"staging_prefix": "../x/"},
        {"s3_id_ref": "secret:lake-writer/s3-secret-key"},
        {"max_attempts": 0},
        {"data_root": "/var/lib/../etc"},
    ],
)
def test_main_refuses_a_bad_input_and_writes_nothing(tmp_path, over):
    (tmp_path / "units").mkdir()
    r = run(tmp_path, "main", **over)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "etc").exists() and not (tmp_path / "bin").exists()
    assert not (tmp_path / "calls.log").exists()


@pytest.mark.parametrize(
    "name, value",
    [
        ("HNX_SECRET_LAKE_WRITER_LAKE_PASSWORD", "short"),
        ("HNX_SECRET_LAKE_WRITER_S3_ACCESS_KEY", "x"),
        ("HNX_SECRET_LAKE_WRITER_S3_SECRET_KEY", "k" * 200),
    ],
)
def test_main_refuses_a_bad_secret_naming_it_and_never_printing_it(tmp_path, name, value):
    (tmp_path / "units").mkdir()
    r = run(tmp_path, "main", env={name: value})
    assert r.returncode != 0
    assert not (tmp_path / "etc").exists()
    assert "lake-writer: a secret is missing or malformed" in r.stdout + r.stderr
    for secret in (LOGIN, S3_ID, S3_KEY):
        assert secret not in r.stdout + r.stderr


def test_a_catalog_bearer_and_a_ca_are_written_only_when_named(tmp_path):
    (tmp_path / "units").mkdir()
    cert = "-----BEGIN " + "CERTIFICATE-----\n" + "x" * 20 + "\n-----END " + "CERTIFICATE-----"
    r = run(
        tmp_path,
        "main",
        catalog_bearer_ref="secret:lake-writer/catalog-token",
        lake_ca_ref="secret:lake-writer/ca",
        env={
            "HNX_SECRET_LAKE_WRITER_CATALOG_TOKEN": "b" * 24,
            "HNX_SECRET_LAKE_WRITER_CA": cert,
        },
    )
    assert r.returncode == 0, r.stdout + r.stderr
    env = (tmp_path / "etc" / "lake-writer.env").read_text()
    assert "HNX_LW_CATALOG_CREDENTIAL=secret:lake-writer/catalog-token" in env
    assert f"HNX_LW_LAKE_CA_FILE={tmp_path}/etc/lake-ca.pem" in env and "b" * 24 not in env
    assert (
        "HNX_SECRET_LAKE_WRITER_CATALOG_TOKEN=" + "b" * 24
        in (tmp_path / "etc" / "credentials" / "logins.env").read_text()
    )
    assert (tmp_path / "etc" / "lake-ca.pem").read_text().count("BEGIN CERTIFICATE") == 1


def test_health_passes_when_everything_is_there_and_judges_the_tables(tmp_path):
    installed(tmp_path)
    ok = run(tmp_path, "health")
    assert ok.returncode == 0, ok.stdout + ok.stderr
    calls = (tmp_path / "calls.log").read_text()
    assert "schema-check" in calls and "status --max-pending 500 --max-age-s 2400" in calls
    env = json.loads((tmp_path / "env-status.json").read_text())
    assert env["HNX_LW_NAMESPACE"] == "soc"


@pytest.mark.parametrize("what", ["timer", "script", "logins", "schema", "status"])
def test_health_fails_on_an_inactive_timer_a_missing_file_a_bad_table_and_a_bad_run(tmp_path, what):
    installed(tmp_path)
    if what == "script":
        (tmp_path / "bin" / "hnx-lake-writer").unlink()
    if what == "logins":
        (tmp_path / "etc" / "credentials" / "logins.env").unlink()
    if what in ("schema", "status"):
        (tmp_path / f"{'schema-check' if what == 'schema' else 'status'}.fails").write_text("")
    bad = run(tmp_path, "health", active=what != "timer")
    assert bad.returncode != 0
    assert "lake-writer:" in bad.stdout + bad.stderr


def test_readiness_names_a_runtime_that_cannot_import_the_lake_clients(tmp_path):
    (tmp_path / "units").mkdir()
    r = run(tmp_path, "readiness", runtime_python=sys.executable + "-missing")
    assert r.returncode != 0


def test_export_writes_the_state_into_place(tmp_path):
    installed(tmp_path)
    state = tmp_path / "data" / "state" / "dns_activity"
    state.mkdir(parents=True)
    ck = {"schema_version": 1, "data": {"lake-writer/dns_activity": {"batch_id": "b1"}}}
    (state / "checkpoint.json").write_text(json.dumps(ck))
    r = run(tmp_path, "export")
    assert r.returncode == 0, r.stdout + r.stderr
    exports = [p for p in (tmp_path / "data" / "export").iterdir() if not p.name.startswith(".")]
    assert len(exports) == 1
    assert json.loads((exports[0] / "state" / "dns_activity" / "checkpoint.json").read_text()) == ck
    assert not [p for p in (tmp_path / "data" / "export").iterdir() if p.name.endswith(".incoming")]


def test_restore_replaces_the_checkpoints_and_refuses_a_bad_source(tmp_path):
    installed(tmp_path)
    live = tmp_path / "data" / "state" / "dns_activity"
    live.mkdir(parents=True)
    (live / "checkpoint.json").write_text(json.dumps({"schema_version": 1, "data": {"old": 1}}))
    src = tmp_path / "src" / "x"
    (src / "state" / "dns_activity").mkdir(parents=True)
    newer = {"schema_version": 1, "data": {"new": 2}}
    (src / "state" / "dns_activity" / "checkpoint.json").write_text(json.dumps(newer))
    r = run(tmp_path, "restore", extra={P + "restore_source": str(src)})
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((live / "checkpoint.json").read_text()) == newer
    (src / "state" / "dns_activity" / "checkpoint.json").write_text('{"nope": 1}')
    bad = run(tmp_path, "restore", extra={P + "restore_source": str(src)})
    assert bad.returncode != 0 and json.loads((live / "checkpoint.json").read_text()) == newer
    inside = run(
        tmp_path, "restore", extra={P + "restore_source": str(tmp_path / "data" / "state")}
    )
    assert inside.returncode != 0
    assert "outside the live state directory" in inside.stdout + inside.stderr


def test_the_defaults_hold_no_address_and_no_secret_value():
    d = yaml.safe_load((Path(ROLE) / "defaults" / "main.yml").read_text())
    assert all(str(v).startswith("secret:") for k, v in d.items() if k.endswith("_ref") and v)
    text = (Path(ROLE) / "defaults" / "main.yml").read_text()
    assert "192.168" not in text and "gluck" not in text
