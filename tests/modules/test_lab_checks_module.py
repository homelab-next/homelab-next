# SPDX-License-Identifier: Apache-2.0
"""The ``lab-checks`` feature module's manifest and public tree: it names the notify slot and one secret by
reference, declares no egress and no lab value, its timer is a calendar, and its role passes the role lint."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "lab-checks"
ROLE = MODULE / "roles" / "lab_checks"


def _manifest() -> dict:
    return yaml.safe_load((MODULE / "module.yml").read_text())


def test_the_manifest_is_a_feature_that_requires_notify_and_the_secret_store():
    m = _manifest()
    assert m["kind"] == "feature" and m["id"] == "lab-checks"
    assert {c["cap"] for c in m["requires"]["capabilities"]} == {"cap:secrets", "cap:notify"}
    assert m["egress"] == "none"
    assert [h["role"] for h in m["requires"]["hosts"]] == ["runner"]
    pair = m["contributes"]["notify_pairs"][0]
    assert pair["problem"] == "Invariant newly broken" and pair["recovery"] == "Invariant recovered"


@pytest.mark.static
def test_the_one_secret_default_is_a_reference_the_role_defaults_agree_with():
    m = _manifest()
    cfgs = list(m["config"].values())
    assert {c["type"] for c in cfgs} == {"secret"}
    assert all(c["default"].split("/")[0] == "secret:lab-checks" for c in cfgs)
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    # the publish token's reference has a default; the CA's is empty (optional) and the manifest names its default
    assert defaults["lab_checks_notify_publisher_ref"] == m["config"]["notify_token"]["default"]
    assert defaults["lab_checks_ca_ref"] == "" and m["config"]["ca"]["overlay"] == "optional"
    # the unit names the hnx path literally (the scripts catalog resolves the exec); the role checks the same one
    unit = (ROLE / "templates" / "lab-checks.service.j2").read_text()
    path = yaml.safe_load((ROLE / "vars" / "main.yml").read_text())["lab_checks_hnx_bin"]
    assert f"ExecStart={path} invariants run" in unit


@pytest.mark.static
def test_the_defaults_hold_no_address_and_the_timer_is_a_calendar_never_an_interval():
    text = (ROLE / "defaults" / "main.yml").read_text()
    assert "192.168" not in text and "gluck" not in text
    defaults = yaml.safe_load(text)
    assert defaults["lab_checks_oncalendar"].endswith(" UTC")
    timer = (ROLE / "templates" / "lab-checks.timer.j2").read_text()
    assert "OnCalendar=" in timer and "OnBootSec=" not in timer and "OnUnitActiveSec=" not in timer


@pytest.mark.static
def test_the_unit_accepts_a_red_run_and_a_run_that_could_not_measure():
    # the runner exits 1 (a criterion failed) or 100 (one could not be measured): the page is the signal
    service = (ROLE / "templates" / "lab-checks.service.j2").read_text()
    assert "SuccessExitStatus=1 100" in service
    assert "--state " in service and "--notify-cmd " in service and "--notify-ceiling " in service
    assert (
        "NoNewPrivileges=yes" in service and "CapabilityBoundingSet=CAP_DAC_READ_SEARCH" in service
    )


def test_role_lint_passes_the_role():
    r = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "role_lint.py"), str(ROLE)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.static
def test_the_role_installs_the_state_tool_beside_the_wrapper_for_the_sites_checks():
    role = ROOT / "modules" / "cti-pipeline" / "roles" / "cti_pipeline"
    config = (role / "tasks" / "config.yml").read_text()
    assert "src: cti_state.py" in config and 'dest: "{{ cti_pipeline_state_tool }}"' in config
    vars_ = (role / "vars" / "main.yml").read_text()
    assert 'cti_pipeline_state_tool: "{{ cti_pipeline_install_dir }}/bin/hnx-cti-state"' in vars_


@pytest.mark.static
def test_the_results_reader_is_off_by_default_and_restricted_to_printing_the_published_copy():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    assert defaults["lab_checks_results_readers"] == []
    vars_ = yaml.safe_load((ROLE / "vars" / "main.yml").read_text())
    options = vars_["lab_checks_reader_options"]
    assert options.startswith('restrict,command="/bin/cat {{ lab_checks_reader_file }}"')
    reader = (ROLE / "tasks" / "reader.yml").read_text()
    assert 'password: "!"' in reader and "{{ lab_checks_reader_options }} {{ key }}" in reader
    # every task of the reader is conditional on reader keys: no account, no copy without them
    tasks = yaml.safe_load(reader)
    assert all("lab_checks_results_readers | length > 0" in t["when"] for t in tasks)


@pytest.mark.static
def test_the_unit_publishes_the_readers_copy_by_rename_only_with_reader_keys():
    service = (ROLE / "templates" / "lab-checks.service.j2").read_text()
    block = service.split("{% if lab_checks_results_readers | length > 0 %}")[1].split(
        "{% endif %}"
    )[0]
    install, rename = [ln for ln in block.splitlines() if ln.startswith("ExecStartPost=")]
    assert (
        "-m 0640" in install and "-g {{ lab_checks_reader_user }}" in install and ".tmp" in install
    )
    assert rename.startswith("ExecStartPost=+/usr/bin/mv -f ") and rename.endswith(
        "{{ lab_checks_reader_file }}"
    )
    # the data root (results and paging state) stays root's: the reader only ever sees the copy
    dirs = (ROLE / "tasks" / "dirs.yml").read_text()
    assert "lab_checks_reader_user" not in dirs


# ----------------------------------------------------------------------------- the results' readers
def _defaults() -> dict:
    return yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())


def _other_group() -> str:
    """An existing group that is not the test user's primary one (its name only)."""
    import grp
    import os

    return next(g.gr_name for g in grp.getgrall() if g.gr_gid not in (0, os.getgid()))


def _dirs_check(tmp_path: Path, group: str) -> dict[str, dict]:
    """The role's dirs.yml in check mode (nothing changes), as the test user: each task's
    planned result by name (``diff`` before/after of the results directory and document)."""
    import grp
    import json
    import os
    import pwd

    data = tmp_path / "data"
    (data / "results").mkdir(parents=True)
    (data / "results" / "lab-checks.hourly.json").write_text("{}")
    os.chmod(data / "results" / "lab-checks.hourly.json", 0o600)
    me, mygroup = pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name
    pvars = yaml.safe_load((ROLE / "vars" / "main.yml").read_text()) | {
        "lab_checks_logical_id": "lab-checks",
        "lab_checks_owner": me,
        "lab_checks_owner_group": mygroup,
        "lab_checks_results_group": group,
        "lab_checks_bin_dir": str(tmp_path / "bin"),
        "lab_checks_config_dir": str(tmp_path / "etc"),
        "lab_checks_data_root": str(data),
    }
    tasks = yaml.safe_load((ROLE / "tasks" / "dirs.yml").read_text())
    names = [t["name"] for t in tasks]
    for i, t in enumerate(tasks):  # each task's result, kept for the dump below
        t.setdefault("register", f"_r{i}")
    out_file = tmp_path / "results.json"
    regs = [t["register"] for t in tasks]
    dump = (
        "{{ {"
        + ", ".join(f"{n!r}: {r}" for n, r in zip(names, regs, strict=True))
        + "} | to_json }}"
    )
    tasks.append({"name": "dump", "check_mode": False,
                  "ansible.builtin.copy": {"dest": str(out_file), "content": dump}})  # fmt: skip
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False,
             "vars": pvars, "tasks": tasks}]  # fmt: skip
    (tmp_path / "p.yml").write_text(yaml.safe_dump(play))
    r = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "--check", "--diff", str(tmp_path / "p.yml")],
        capture_output=True, text=True, cwd=tmp_path, check=False,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr
    return json.loads(out_file.read_text())


@pytest.mark.static
def test_by_default_the_results_stay_roots_alone():
    assert _defaults()["lab_checks_results_group"] == ""
    unit = (ROLE / "templates" / "lab-checks.service.j2").read_text()
    assert "UMask={{ '0027' if lab_checks_results_group else '0077' }}" in unit


@pytest.mark.requires_tool("ansible-playbook")
def test_the_default_leaves_the_results_document_owner_only(tmp_path):
    got = _dirs_check(tmp_path, "")
    assert got["Create the results readers' group (opt-in)"].get("skipped") is True
    assert (
        got["The results document is readable by exactly the opted-in group"].get("changed")
        is False
    )


@pytest.mark.requires_tool("ansible-playbook")
def test_an_opted_in_group_may_read_the_results_document_and_nothing_else(tmp_path):
    import grp

    group = _other_group()
    gid = grp.getgrnam(group).gr_gid
    got = _dirs_check(tmp_path, group)
    doc = got["The results document is readable by exactly the opted-in group"]
    assert doc["changed"] is True
    after = doc["diff"]["after"]
    assert after["mode"] == "0640" and after["group"] == gid
    dirs = {r["item"]["path"]: r for r in got["Create the directories"]["results"]}
    res = dirs[str(tmp_path / "data" / "results")]
    assert res["diff"]["after"]["mode"] == "02750" and res["diff"]["after"]["group"] == gid
    # the state, the credentials and the data root keep their owner's group
    for path, r in dirs.items():
        if not path.endswith("/results"):
            assert r["item"].get("group") is None, path


@pytest.mark.requires_tool("ansible-playbook")
@pytest.mark.parametrize("group", ["root", "Bad Group", "1x" * 20])
def test_the_results_group_is_never_root_and_is_a_group_name(tmp_path, group):
    import os

    v = _defaults() | yaml.safe_load((ROLE / "vars" / "main.yml").read_text())
    v |= {"lab_checks_logical_id": "lab-checks", "lab_checks_register_src": "/x/invariants.yml",
          "lab_checks_results_group": group}  # fmt: skip
    tasks = yaml.safe_load((ROLE / "tasks" / "validate.yml").read_text())
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False,
             "vars": v, "tasks": tasks}]  # fmt: skip
    (tmp_path / "p.yml").write_text(yaml.safe_dump(play))
    r = subprocess.run(["ansible-playbook", "-i", "localhost,", str(tmp_path / "p.yml")],
                       capture_output=True, text=True, cwd=tmp_path, env=dict(os.environ), check=False)  # fmt: skip
    assert r.returncode != 0
    v["lab_checks_results_group"] = "hnx-lab-results"
    (tmp_path / "p.yml").write_text(yaml.safe_dump([dict(play[0], vars=v)]))
    r = subprocess.run(["ansible-playbook", "-i", "localhost,", str(tmp_path / "p.yml")],
                       capture_output=True, text=True, cwd=tmp_path, check=False)  # fmt: skip
    assert r.returncode == 0, r.stdout
