# SPDX-License-Identifier: Apache-2.0
"""Role ``intel_ingest`` (modules/intel-ingest/roles/intel_ingest), run on localhost against fakes (CI is
unprivileged): main installs the script, the CA bundle, the environment (no secret in it), the
root-only logins file and the units, and a second run is ``changed=0``; a state seed is checked and
installed create-only; malformed inputs and credentials are refused by name before anything is
written; health passes and fails on its conditions; export writes the state beside and renames it
into place, refuses a bad state; restore refuses a bad source and replaces the state."""

from __future__ import annotations

import grp
import json
import os
import pwd
import sys
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "intel-ingest" / "roles" / "intel_ingest")
P = "intel_ingest_"
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
KEY = "a" * 20 + "7" * 20  # 40 letters and digits, built here
LOGIN = "q" * 24
CA = "-----BEGIN " + "CERTIFICATE-----\n" + "x" * 20 + "\n-----END " + "CERTIFICATE-----"
GRAPH_CA = CA.replace("x" * 20, "y" * 20)
SECRETS = {
    "HNX_SECRET_INTEL_INGEST_THREAT_INTEL_KEY": KEY,
    "HNX_SECRET_INTEL_INGEST_GRAPH_LOGIN": LOGIN,
    "HNX_SECRET_INTEL_INGEST_CA": CA,
    "HNX_SECRET_INTEL_INGEST_GRAPH_CA": GRAPH_CA,
}
STATE = {
    "domain": {"watermark_id": 0, "in_progress": {"page": 24, "newest_id": 5763486}},
    "md5": {"watermark_id": 40962715, "in_progress": None},
    "ip-src": 6051196,  # the legacy flat shape the script still reads
}


def pv(tmp_path: Path, **kw) -> dict:
    v = {
        "logical_id": "ingest",
        "threat_intel_url": "https://threat-intel.example.internal",
        "graph_url": "https://graph.example.internal",
        "config_dir": str(tmp_path / "etc"),
        "data_root": str(tmp_path / "data"),
        "bin_dir": str(tmp_path / "bin"),
        "unit_dir": str(tmp_path / "units"),
        "owner": USER,
        "owner_group": GROUP,
        "user": USER,
        "group": GROUP,
        "manage_accounts": False,
        "start": False,
    }
    v.update(kw)
    return {P + k: x for k, x in v.items()}


def _seed(tmp_path: Path, doc=STATE, name="seed.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    return path


def _first_main_installs_the_job_with_no_secret_in_any_world_readable_file(tmp_path):
    v = pv(tmp_path, state_seed_file=str(_seed(tmp_path)))
    (tmp_path / "units").mkdir()
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_installs_the_job_with_no_secret_in_any_world_readable_file)
def test_main_installs_the_job_with_no_secret_in_any_world_readable_file(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    env = (tmp_path / "etc" / "intel-ingest.env").read_text()
    assert "INGEST_SOURCE_URL=https://threat-intel.example.internal" in env
    assert "INGEST_GRAPH_URL=https://graph.example.internal" in env
    assert f"INGEST_STATE_FILE={tmp_path}/data/state/state.json" in env
    assert f"INGEST_CA_FILE={tmp_path}/etc/ca-bundle.pem" in env
    assert "INGEST_TLS_PINS" not in env
    for secret in (KEY, LOGIN):
        assert secret not in env and secret not in r.stdout + r.stderr
    logins = tmp_path / "etc" / "credentials" / "login.env"
    assert oct(logins.stat().st_mode & 0o777) == "0o600"
    assert f"INGEST_SOURCE_KEY={KEY}" in logins.read_text()
    assert f"INGEST_GRAPH_PASSWORD={LOGIN}" in logins.read_text()
    assert (tmp_path / "etc" / "ca-bundle.pem").read_text().count("BEGIN CERTIFICATE") == 2
    script = tmp_path / "bin" / "hnx-intel-ingest"
    assert oct(script.stat().st_mode & 0o777) == "0o755"
    service = (tmp_path / "units" / "hnx-ingest.service").read_text()
    assert "SuccessExitStatus=2" in service and "KillSignal=SIGTERM" in service
    assert "NoNewPrivileges=yes" in service and "CapabilityBoundingSet=\n" in service
    assert f"ReadWritePaths={tmp_path}/data/state" in service
    assert f"EnvironmentFile={logins}" in service
    timer = (tmp_path / "units" / "hnx-ingest.timer").read_text()
    assert "OnCalendar=*-*-* 13:00:00 UTC" in timer and "Persistent=true" in timer
    assert "OnBootSec=" not in timer and "OnUnitActiveSec=" not in timer
    # the seed became the state, as it was
    state = tmp_path / "data" / "state" / "state.json"
    assert json.loads(state.read_text()) == STATE
    assert oct(state.stat().st_mode & 0o777) == "0o600"


def test_a_second_run_changes_nothing_and_a_seed_never_replaces_a_live_state(tmp_path):
    (tmp_path / "units").mkdir()
    v = pv(tmp_path, state_seed_file=str(_seed(tmp_path)))
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    state = tmp_path / "data" / "state" / "state.json"
    live = {"md5": {"watermark_id": 41000000, "in_progress": None}}
    state.write_text(json.dumps(live))  # the job moved on
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    assert json.loads(state.read_text()) == live


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"not-a-type": 1},
        {"md5": "high"},
        {"md5": -1},
        {"md5": {"watermark_id": -5, "in_progress": None}},
        {"md5": {"watermark_id": 1, "in_progress": {"page": 0, "newest_id": 3}}},
        {"md5": {"watermark_id": 1, "in_progress": "page 3"}},
        {"md5": {"watermark_id": 1, "in_progress": {"page": 2, "newest_id": -1}}},
    ],
)
def test_a_seed_that_is_not_this_modules_form_is_refused_and_installs_nothing(tmp_path, doc):
    (tmp_path / "units").mkdir()
    v = pv(tmp_path, state_seed_file=str(_seed(tmp_path, doc)))
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "data" / "state" / "state.json").exists()
    assert "intel-ingest: the state is not this module's form" in r.stdout + r.stderr


def _first_main_refuses_a_bad_input(tmp_path, over, env):
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": pv(tmp_path, **over),
        "env": {**SECRETS, **env},
    }


@pytest.mark.parametrize(
    "over, env",
    [
        ({"threat_intel_url": "http://threat-intel.example.internal"}, {}),
        ({"graph_url": "http://graph.example.internal"}, {}),
        ({"logical_id": "Ingest"}, {}),
        ({"graph_ca_ref": ""}, {}),  # no CA for the graph store
        ({"threat_intel_ca_ref": ""}, {}),
        ({"threat_intel_key_ref": "secret:intel-ingest/graph-login"}, {}),
        ({"max_runtime_s": 5}, {}),
        ({"oncalendar": "x"}, {}),
        ({"data_root": "/var/lib/../etc"}, {}),
        ({"state_seed_file": "relative.json"}, {}),
        ({}, {"HNX_SECRET_INTEL_INGEST_THREAT_INTEL_KEY": "short"}),
        ({}, {"HNX_SECRET_INTEL_INGEST_GRAPH_LOGIN": "has a space in it 0123456"}),
        ({}, {"HNX_SECRET_INTEL_INGEST_GRAPH_LOGIN": KEY}),  # the same value as the key
        ({}, {"HNX_SECRET_INTEL_INGEST_CA": "not a certificate"}),
        ({}, {"HNX_SECRET_INTEL_INGEST_GRAPH_CA": "not a certificate"}),
    ],
)  # fmt: skip
@first_run(_first_main_refuses_a_bad_input)
def test_main_refuses_a_bad_input_and_writes_nothing(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "etc").exists() and not (tmp_path / "bin").exists()
    for secret in (KEY, LOGIN):
        assert secret not in r.stdout + r.stderr


def _first_main_refuses_an_unset_secret_naming_it(tmp_path, name, ref):
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": pv(tmp_path),
        "env": {**SECRETS, f"HNX_SECRET_INTEL_INGEST_{name}": ""},
    }


@pytest.mark.parametrize(
    "name, ref",
    [
        ("THREAT_INTEL_KEY", "threat-intel-key"),
        ("GRAPH_LOGIN", "graph-login"),
        ("CA", "ca"),
        ("GRAPH_CA", "graph-ca"),
    ],
)
@first_run(_first_main_refuses_an_unset_secret_naming_it)
def test_main_refuses_an_unset_secret_naming_the_reference(first, name, ref):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert "intel-ingest/" + ref in r.stdout + r.stderr
    assert not (tmp_path / "etc").exists()


# ----------------------------------------------------------------------------- hooks


def _systemctl(tmp_path: Path, active: bool = True) -> dict:
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    code = "import sys\nok = {}\nsys.stdout.write('active\\n' if ok else 'inactive\\n')\nsys.exit(0 if ok else 3)\n"
    fake(bindir / "systemctl", code.format(active))
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _installed(tmp_path: Path, **kw) -> dict:
    (tmp_path / "units").mkdir(exist_ok=True)
    v = pv(tmp_path, systemctl_cli=str(tmp_path / "fakebin" / "systemctl"), **kw)
    (tmp_path / "fakebin").mkdir(exist_ok=True)
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    return v


def test_health_passes_when_everything_is_there_and_the_timer_is_active(tmp_path):
    v = _installed(tmp_path, state_seed_file=str(_seed(tmp_path)))
    env = {**SECRETS, **_systemctl(tmp_path)}
    ok = run_role(tmp_path, ROLE, "health", v, env=env)
    assert ok.returncode == 0, ok.stdout + ok.stderr


@pytest.mark.parametrize("what", ["timer", "script", "logins", "state"])
def test_health_fails_on_an_inactive_timer_a_missing_file_and_a_bad_state(tmp_path, what):
    v = _installed(tmp_path, state_seed_file=str(_seed(tmp_path)))
    env = {**SECRETS, **_systemctl(tmp_path, active=what != "timer")}
    if what == "script":
        (tmp_path / "bin" / "hnx-intel-ingest").unlink()
    if what == "logins":
        (tmp_path / "etc" / "credentials" / "login.env").unlink()
    if what == "state":
        (tmp_path / "data" / "state" / "state.json").write_text('{"not-a-type": 1}')
    bad = run_role(tmp_path, ROLE, "health", v, env=env)
    assert bad.returncode != 0
    assert "intel-ingest:" in bad.stdout + bad.stderr


def test_export_writes_the_state_into_place_and_refuses_a_bad_one(tmp_path):
    v = _installed(tmp_path, state_seed_file=str(_seed(tmp_path)))
    r = run_role(tmp_path, ROLE, "export", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    exports = [p for p in (tmp_path / "data" / "export").iterdir() if not p.name.startswith(".")]
    assert len(exports) == 1
    assert json.loads((exports[0] / "state.json").read_text()) == STATE
    assert not [p for p in (tmp_path / "data" / "export").iterdir() if p.name.endswith(".incoming")]
    (tmp_path / "data" / "state" / "state.json").write_text("{}")
    bad = run_role(tmp_path, ROLE, "export", v, env=SECRETS)
    assert bad.returncode != 0 and "not this module's form" in bad.stdout + bad.stderr


def test_restore_replaces_the_state_and_refuses_a_bad_source(tmp_path):
    v = _installed(tmp_path, state_seed_file=str(_seed(tmp_path)))
    src = tmp_path / "src" / "x"
    src.mkdir(parents=True)
    newer = {"md5": {"watermark_id": 41000000, "in_progress": None}}
    (src / "state.json").write_text(json.dumps(newer))
    r = run_role(tmp_path, ROLE, "restore", {**v, P + "restore_source": str(src)}, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((tmp_path / "data" / "state" / "state.json").read_text()) == newer
    (src / "state.json").write_text('{"nope": 1}')
    bad = run_role(tmp_path, ROLE, "restore", {**v, P + "restore_source": str(src)}, env=SECRETS)
    assert bad.returncode != 0
    assert json.loads((tmp_path / "data" / "state" / "state.json").read_text()) == newer
    inside = run_role(
        tmp_path, ROLE, "restore",
        {**v, P + "restore_source": str(tmp_path / "data" / "state")}, env=SECRETS,
    )  # fmt: skip
    assert (
        inside.returncode != 0
        and "outside the live state directory" in inside.stdout + inside.stderr
    )


def test_the_defaults_hold_no_address_and_no_secret_value():
    d = yaml.safe_load((Path(ROLE) / "defaults" / "main.yml").read_text())
    assert all(str(v).startswith("secret:") for k, v in d.items() if k.endswith("_ref") and v)
    text = (Path(ROLE) / "defaults" / "main.yml").read_text()
    assert "192.168" not in text and "gluck" not in text and sys.version_info >= (3, 9)
