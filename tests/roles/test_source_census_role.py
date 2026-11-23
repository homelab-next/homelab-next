# SPDX-License-Identifier: Apache-2.0
"""Role ``source_census`` (modules/source-census/roles/source_census), run on localhost against
fakes (CI is unprivileged): bad settings are refused before anything is written, the credentials
are written by name as 0600 files, the settings hold no secret and load into the census, and the
state hooks never forget what was already paged."""

from __future__ import annotations

import json
import os
import pwd
import stat
from pathlib import Path

import pytest
import yaml
from rolerun import run_role

from homelabnext.lake import cli as census_cli
from homelabnext.lake.census import config_from

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "source-census" / "roles" / "source_census")
USER = pwd.getpwuid(os.getuid()).pw_name
PASSWORD = "pw" * 4
TOKEN = "tk" * 4


def role_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "source_census_logical_id": "source-census",
        "source_census_lake_domain": "lab.example.internal",
        "source_census_lake_warehouse": "wh",
        "source_census_lake_catalog": "cat",
        "source_census_user": USER,
        "source_census_group": USER,
        "source_census_root": str(tmp_path / "var"),
        "source_census_config_dir": str(tmp_path / "etc"),
        "source_census_export_dir": str(tmp_path / "export"),
        "source_census_root_owner": USER,
        "source_census_hnx_bin": str(tmp_path / "bin" / "hnx"),
    }
    v.update(kw)
    return v


ENV = {
    "HNX_SECRET_SOURCE_CENSUS_READER_PASSWORD": PASSWORD,
    "HNX_SECRET_SOURCE_CENSUS_NOTIFY_TOKEN": TOKEN,
}


class Converged:
    """The state of a converge: the last hook's result (stdout and stderr of both, for a no_log check)."""

    def __init__(self, results):
        self.results = results
        self.returncode = next((r.returncode for r in results if r.returncode), 0)
        self.stdout = "".join(r.stdout for r in results)
        self.stderr = "".join(r.stderr for r in results)


def converge(tmp_path: Path, **kw):
    """The role's main without ``dirs.yml`` (a system user and group need root, and CI has none):
    the directories are made here, then the credentials and the settings hooks of main run."""
    for d, mode in (("var/state", 0o750), ("etc/credentials", 0o700)):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
        (tmp_path / d).chmod(mode)
    v = role_vars(tmp_path, **kw)
    return Converged(
        [run_role(tmp_path, ROLE, hook, v, env=ENV) for hook in ("credentials", "config")]
    )


def test_validate_passes_for_the_defaults(tmp_path):
    r = run_role(tmp_path, ROLE, "validate", role_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr


GOOD_EXPECTED = {
    "name": "Edge",
    "match": {"location": {"suffix": "/access.log"}},
    "cadence_hours": 1,
}
GOOD_ACK = {"name": "Edge", "owner": "o", "reason": "r", "expires": "2030-01-02"}


@pytest.mark.parametrize(
    "over",
    [
        {"source_census_lake_domain": "Not A Domain"},
        {"source_census_lake_warehouse": ""},
        {"source_census_lake_catalog": "bad catalog"},
        {"source_census_table": 'raw"; drop'},
        {"source_census_source_columns": []},
        {"source_census_source_columns": ["ok", "not ok"]},
        {"source_census_source_columns": "source"},
        {"source_census_window_days": 1},
        {"source_census_multiple": 0.5},
        {"source_census_floor_hours": 0},
        {"source_census_learning_min_arrivals": 0},
        {"source_census_dark_hours": 0},
        {"source_census_dark_tables": ["bad name"]},
        {"source_census_expected": [{"name": "x"}]},
        {"source_census_expected": [GOOD_EXPECTED, GOOD_EXPECTED]},
        {"source_census_acknowledged": [{"owner": "o", "reason": "r"}]},
        {"source_census_acknowledged": [{**GOOD_ACK, "expires": "someday"}]},
        {"source_census_acknowledged": [{k: v for k, v in GOOD_ACK.items() if k != "owner"}]},
        {"source_census_acknowledged": [{k: v for k, v in GOOD_ACK.items() if k != "expires"}]},
        {"source_census_notify_ceiling": "purple"},
        {"source_census_notify_topic": "has space"},
        {"source_census_reader_cred": "a-value-not-a-reference"},
        {"source_census_notify_cred": "secret:Bad Name"},
        {"source_census_hnx_bin": "bin/hnx"},
        {"source_census_root": "/var/lib/../etc"},
        {"source_census_lake_ca_file": "relative/ca.pem"},
    ],
)
def test_validate_refuses_what_cannot_be_honoured(tmp_path, over):
    r = run_role(tmp_path, ROLE, "validate", {**role_vars(tmp_path), **over})
    assert r.returncode != 0, r.stdout


def test_validate_accepts_declared_sources_and_acknowledgements(tmp_path):
    v = role_vars(
        tmp_path,
        source_census_expected=[GOOD_EXPECTED],
        source_census_acknowledged=[GOOD_ACK],
        source_census_notify_ceiling="amber+strict",
    )
    r = run_role(tmp_path, ROLE, "validate", v)
    assert r.returncode == 0, r.stdout + r.stderr


def test_converge_writes_0600_credentials_by_name_and_settings_without_a_secret(tmp_path):
    r = converge(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    creds = tmp_path / "etc" / "credentials"
    assert sorted(p.name for p in creds.iterdir()) == ["notify-token", "reader-password"]
    for p in creds.iterdir():
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert (creds / "reader-password").read_text().strip() == PASSWORD
    cfg_text = (tmp_path / "etc" / "census.yml").read_text()
    assert PASSWORD not in cfg_text and TOKEN not in cfg_text
    assert PASSWORD not in r.stdout + r.stderr  # no_log: a value never reaches the output


def test_the_rendered_settings_load_into_the_census(tmp_path):
    over = {
        "source_census_expected": [GOOD_EXPECTED],
        "source_census_acknowledged": [GOOD_ACK],
        "source_census_dark_tables": ["raw_archive", "detections"],
    }
    r = converge(tmp_path, **over)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "etc" / "census.yml").read_text())
    cfg = config_from(doc["census"])  # the very loader the command uses
    assert cfg.table == "raw_archive" and cfg.window_days == 8 and cfg.multiple == 3.0
    assert cfg.expected[0].match == {"location": {"suffix": "/access.log"}}
    assert str(cfg.acknowledged[0].expires) == "2030-01-02"
    assert doc["dark"] == {"tables": ["raw_archive", "detections"], "hours": 24.0}
    assert doc["lake"]["credential_file"] == str(
        tmp_path / "etc" / "credentials" / "reader-password"
    )
    assert doc["notify"]["ceiling"] == "red" and doc["state"] == str(
        tmp_path / "var" / "state" / "state.json"
    )
    # the command's own loader accepts the file as written
    assert census_cli._load(str(tmp_path / "etc" / "census.yml"))["lake"]["namespace"] == "soc"


def test_the_dark_tables_default_to_the_census_table(tmp_path):
    assert converge(tmp_path, source_census_table="events_raw").returncode == 0
    doc = yaml.safe_load((tmp_path / "etc" / "census.yml").read_text())
    assert doc["dark"]["tables"] == ["events_raw"]


def test_converge_is_idempotent(tmp_path):
    assert converge(tmp_path).returncode == 0
    r = converge(tmp_path)
    assert r.returncode == 0 and r.stdout.count("changed=0") == 2, r.stdout


def test_main_runs_validate_then_dirs_then_credentials_then_settings():
    steps = yaml.safe_load((Path(ROLE) / "tasks" / "main.yml").read_text())
    assert [t["ansible.builtin.include_tasks"] for t in steps] == [
        "validate.yml", "dirs.yml", "credentials.yml", "config.yml",
    ]  # fmt: skip


def test_the_state_is_the_service_users_alone_and_the_credentials_are_private():
    dirs = (Path(ROLE) / "tasks" / "dirs.yml").read_text()
    assert "shell: /usr/sbin/nologin" in dirs and "system: true" in dirs
    modes = {i["path"]: i["mode"] for i in yaml.safe_load(dirs)[2]["loop"]}
    assert modes["{{ source_census_state_dir }}"] == "0750"
    assert modes["{{ source_census_cred_dir }}"] == "0700"


def test_health_needs_the_credentials_at_0600(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "hnx").write_text("#!/bin/sh\nexit 0\n")
    (fake / "hnx").chmod(0o755)
    assert converge(tmp_path).returncode == 0
    ok = run_role(tmp_path, ROLE, "health", role_vars(tmp_path))
    assert ok.returncode == 0, ok.stdout + ok.stderr
    (tmp_path / "etc" / "credentials" / "reader-password").chmod(0o644)
    bad = run_role(tmp_path, ROLE, "health", role_vars(tmp_path))
    assert bad.returncode != 0 and "is not 0600" in bad.stdout + bad.stderr


def test_readiness_needs_the_runtime_with_the_census_and_every_credential(tmp_path):
    v = role_vars(tmp_path)
    missing = run_role(tmp_path, ROLE, "readiness", v, env=ENV)
    assert missing.returncode != 0 and "hnx_runtime" in missing.stdout + missing.stderr
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "hnx").write_text("#!/bin/sh\nexit 3\n")
    (fake / "hnx").chmod(0o755)
    broken = run_role(tmp_path, ROLE, "readiness", v, env=ENV)
    assert broken.returncode != 0 and "does not carry the census" in broken.stdout + broken.stderr
    (fake / "hnx").write_text("#!/bin/sh\nexit 0\n")
    assert run_role(tmp_path, ROLE, "readiness", v, env=ENV).returncode == 0
    no_token = {k: val for k, val in ENV.items() if "NOTIFY" not in k}
    unset = run_role(tmp_path, ROLE, "readiness", v, env=no_token)
    assert (
        unset.returncode != 0 and "secret:source-census/notify-token" in unset.stdout + unset.stderr
    )


def test_export_restore_round_trip_and_restore_never_overwrites_a_flagged_set(tmp_path):
    v = role_vars(tmp_path)
    assert converge(tmp_path).returncode == 0
    state = tmp_path / "var" / "state" / "state.json"
    state.write_text(json.dumps({"flagged": ["source:a"]}))
    assert run_role(tmp_path, ROLE, "export", v).returncode == 0
    exported = tmp_path / "export"
    assert (exported / "state.json").read_text() == state.read_text()
    assert (exported / "state.sha256").read_text().endswith("  state.json\n")
    # a live state that holds a flagged set is never overwritten
    r = run_role(tmp_path, ROLE, "restore", {**v, "source_census_restore_source": str(exported)})
    assert r.returncode != 0 and "would page it again" in r.stdout + r.stderr
    state.write_text(json.dumps({"flagged": []}))
    r = run_role(tmp_path, ROLE, "restore", {**v, "source_census_restore_source": str(exported)})
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(state.read_text())["flagged"] == ["source:a"]


def test_restore_refuses_a_state_that_does_not_match_its_hash(tmp_path):
    v = role_vars(tmp_path)
    assert converge(tmp_path).returncode == 0
    src = tmp_path / "src"
    src.mkdir()
    (src / "state.json").write_text("{}")
    (src / "state.sha256").write_text("0" * 64 + "  state.json\n")
    r = run_role(tmp_path, ROLE, "restore", {**v, "source_census_restore_source": str(src)})
    assert r.returncode != 0 and "does not match its sha256" in r.stdout + r.stderr


def test_backup_declares_the_state_and_no_credential(tmp_path):
    assert converge(tmp_path).returncode == 0
    r = run_role(tmp_path, ROLE, "backup", role_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    manifest = json.loads((tmp_path / "var" / "state" / "backup-manifest.json").read_text())
    assert manifest["paths"] == [str(tmp_path / "var" / "state")]
    assert "credential" in manifest["note"] and PASSWORD not in json.dumps(manifest)


def test_upgrade_records_the_release(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "hnx").write_text('#!/bin/sh\n[ "$1" = "--version" ] && echo "hnx 9.9.9"\nexit 0\n')
    (fake / "hnx").chmod(0o755)
    assert converge(tmp_path).returncode == 0
    r = run_role(tmp_path, ROLE, "upgrade", role_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((tmp_path / "var" / "state" / "release.json").read_text()) == {
        "runtime": "hnx 9.9.9"
    }
