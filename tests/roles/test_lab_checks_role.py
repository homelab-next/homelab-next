# SPDX-License-Identifier: Apache-2.0
"""Role ``lab_checks`` (modules/lab-checks/roles/lab_checks), run on localhost against a fake ``hnx`` (CI is
unprivileged): main installs the probe and the pager, the register (validated on the host first), the pager's
configuration, the root-only token and the units, and a second run is ``changed=0``; a register that does not
validate is refused before it replaces the live one; malformed inputs are refused by name before anything is
written; health passes only with the timer armed and a recent results document."""

from __future__ import annotations

import grp
import json
import os
import pwd
from pathlib import Path
from urllib.parse import urlsplit

from rolerun import fake, first_run, last_run_vars, run_cases, run_role

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "lab-checks" / "roles" / "lab_checks")
P = "lab_checks_"
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
TOKEN = "tk" + "-" + "t" * 20  # built here, never a literal that looks like a key
SECRETS = {"HNX_SECRET_LAB_CHECKS_NOTIFY_TOKEN": TOKEN}
CERT = "-----BEGIN " + "CERTIFICATE-----\n" + "x" * 20 + "\n-----END " + "CERTIFICATE-----"
REGISTER = """\
pillars:
- {letter: N, title: Lab}
criteria:
- id: N-01
  owner: lab-checks
  statement: A criterion that always holds.
  evidence: auto
  observable: echo fine
  expected: fine
  remediation: nothing to do, it always holds
"""


def _env(tmp_path: Path) -> dict:
    (tmp_path / "bin").mkdir(exist_ok=True)
    (tmp_path / "units").mkdir(exist_ok=True)
    hnx = fake(
        tmp_path / "bin" / "hnx-fake",
        "import os, runpy, sys\n"
        f"os.environ['PYTHONPATH'] = {str(ROOT)!r}\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "sys.argv = ['hnx'] + sys.argv[1:]\n"
        "from homelabnext.cli import main\nsys.exit(main())\n",
    )
    (tmp_path / "registry.yml").write_text(
        "services:\n  notify:\n    host: notify.example.internal\n    port: 80\n    scheme: http\n"
    )
    reg = tmp_path / "invariants.src.yml"
    reg.write_text(REGISTER)
    v = {
        "logical_id": "checks",
        "register_src": str(reg),
        "notify_allow_plain_http": True,
        "hnx_bin": hnx,
        "config_dir": str(tmp_path / "etc"),
        "data_root": str(tmp_path / "data"),
        "bin_dir": str(tmp_path / "bin"),
        "unit_dir": str(tmp_path / "units"),
        "owner": USER,
        "owner_group": GROUP,
        "start": False,
    }
    out = {P + k: x for k, x in v.items()}
    out.update(last_run_vars(tmp_path, "lab_checks"))
    out["hnx_registry_file"] = str(tmp_path / "registry.yml")
    return out


def _first_main(tmp_path):
    v = _env(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


def _first_main_with_ca(tmp_path):
    v = {**_env(tmp_path), P + "ca_ref": "secret:lab-checks/ca"}
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": v,
        "env": {**SECRETS, "HNX_SECRET_LAB_CHECKS_CA": CERT},
        "setup": {"v": v},
    }


@first_run(_first_main)
def test_main_installs_the_checks_with_the_token_only_in_the_root_only_file(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert TOKEN not in r.stdout + r.stderr
    etc = tmp_path / "etc"
    assert (etc / "credentials" / "notify-token").read_text().strip() == TOKEN
    assert oct((etc / "credentials" / "notify-token").stat().st_mode & 0o777) == "0o400"
    cfg = (etc / "notify.json").read_text()
    doc = json.loads(cfg)
    assert TOKEN not in cfg and doc["topic"] == "lab-checks"
    url = urlsplit(doc["url"])
    assert (url.scheme, url.hostname, url.port) == ("http", "notify.example.internal", 80)
    assert (etc / "invariants.yml").read_text() == REGISTER
    assert (
        not list(etc.glob("*.incoming"))
        and not (tmp_path / "data" / "state" / ".validate.json").exists()
    )
    for name in ("hnx-lab-probe", "hnx-lab-notify"):
        assert oct((tmp_path / "bin" / name).stat().st_mode & 0o777) == "0o755"
    service = (tmp_path / "units" / "hnx-checks.service").read_text()
    assert (
        f"invariants run {etc}/invariants.yml" in service and "SuccessExitStatus=1 100" in service
    )
    assert f"--state {tmp_path}/data/state/checks.hourly.json" in service
    assert "--notify-ceiling red" in service
    assert (
        f"Environment=PATH={tmp_path}/bin:" in service
    )  # the probes are found by their short names
    timer = (tmp_path / "units" / "hnx-checks.timer").read_text()
    assert "OnCalendar=*-*-* *:07:00 UTC" in timer and "OnBootSec=" not in timer


@first_run(_first_main)
def test_a_second_run_changes_nothing(first):
    first_r, tmp_path = first
    v = first.setup["v"]
    assert first_r.returncode == 0
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


@first_run(_first_main)
def test_a_register_that_does_not_validate_is_refused_and_the_live_one_stays(first):
    first_r, tmp_path = first
    v = first.setup["v"]
    assert first_r.returncode == 0
    Path(v[P + "register_src"]).write_text(
        REGISTER.replace("remediation: nothing to do, it always holds", "")
    )
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode != 0
    assert (tmp_path / "etc" / "invariants.yml").read_text() == REGISTER


def test_bad_inputs_and_a_bad_token_are_refused_before_anything_is_written(tmp_path):
    bad = [
        {P + "logical_id": "Bad Name"},
        {P + "oncalendar": "hourly"},
        {P + "notify_ceiling": "purple"},
    ]
    results = run_cases(tmp_path, ROLE, "main", _env(tmp_path), bad, env=SECRETS)
    assert len(results) == 3
    for failed, message in results:
        assert failed and "lab-checks: an input is invalid" in message
    r = run_role(
        tmp_path, ROLE, "main", _env(tmp_path), env={"HNX_SECRET_LAB_CHECKS_NOTIFY_TOKEN": "x y"}
    )
    assert r.returncode != 0 and "missing or malformed" in r.stdout + r.stderr
    assert not (tmp_path / "etc" / "invariants.yml").exists()


@first_run(_first_main)
def test_health_needs_the_files_an_armed_timer_and_a_recent_results_document(first):
    first_r, tmp_path = first
    v = first.setup["v"]
    assert first_r.returncode == 0
    sysd = fake(
        tmp_path / "bin" / "systemctl",
        "import sys\nsys.exit(int(open(sys.argv[0] + '.rc').read()))\n",
    )
    Path(sysd + ".rc").write_text("0")
    v[P + "systemctl_cli"] = sysd
    res = tmp_path / "data" / "results" / "checks.hourly.json"
    r = run_role(tmp_path, ROLE, "health", v, env=SECRETS)
    assert r.returncode != 0 and "no results document" in r.stdout + r.stderr  # never ran
    res.write_text("{}")
    r = run_role(tmp_path, ROLE, "health", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    old = res.stat().st_mtime - 30000
    os.utime(res, (old, old))
    assert (
        run_role(tmp_path, ROLE, "health", v, env=SECRETS).returncode != 0
    )  # stale: the timer stopped firing
    os.utime(res)
    Path(sysd + ".rc").write_text("3")  # the timer is not active
    r = run_role(tmp_path, ROLE, "health", v, env=SECRETS)
    assert r.returncode != 0 and "is not active" in r.stdout + r.stderr
    (tmp_path / "etc" / "invariants.yml").unlink()
    Path(sysd + ".rc").write_text("0")
    r = run_role(tmp_path, ROLE, "health", v, env=SECRETS)
    assert r.returncode != 0 and "missing" in r.stdout + r.stderr


@first_run(_first_main)
def test_the_export_writes_the_documents_beside_and_renames_into_place(first):
    first_r, tmp_path = first
    v = first.setup["v"]
    assert first_r.returncode == 0
    (tmp_path / "data" / "results" / "checks.hourly.json").write_text('{"results": {}}')
    (tmp_path / "data" / "state" / "checks.hourly.json").write_text('{"N-01": "pass"}')
    r = run_role(tmp_path, ROLE, "export", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    (exp,) = (tmp_path / "data" / "export").iterdir()
    assert not exp.name.startswith(".")
    assert sorted(p.name for p in exp.iterdir()) == ["results.json", "state.json"]
    assert (exp / "state.json").read_text() == '{"N-01": "pass"}'
    # restore puts the paging state back
    (tmp_path / "data" / "state" / "checks.hourly.json").write_text("{}")
    r = run_role(tmp_path, ROLE, "restore", {**v, P + "restore_source": str(exp)}, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (
        tmp_path / "data" / "state" / "checks.hourly.json"
    ).read_text().strip() == '{"N-01": "pass"}'
    bad = run_role(tmp_path, ROLE, "restore", {**v, P + "restore_source": ""}, env=SECRETS)
    assert bad.returncode != 0


@first_run(_first_main_with_ca)
def test_the_ca_is_written_only_when_named_and_must_be_a_certificate(first):
    r, tmp_path = first
    v = first.setup["v"]
    cert = CERT
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "etc" / "ca.pem").read_text().strip() == cert
    assert oct((tmp_path / "etc" / "ca.pem").stat().st_mode & 0o777) == "0o644"
    again = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, "HNX_SECRET_LAB_CHECKS_CA": cert})
    assert "changed=0" in again.stdout, again.stdout
    bad = run_role(
        tmp_path, ROLE, "main", v, env={**SECRETS, "HNX_SECRET_LAB_CHECKS_CA": "not a cert"}
    )
    assert bad.returncode != 0 and "not a PEM certificate" in bad.stdout + bad.stderr
