# SPDX-License-Identifier: Apache-2.0
"""The status hub's pull helper (role status_hub, files/hnx-hub-pull.py; ADR-0049 decision 7): it dials
each producer with a pinned host key and no remote command, files a JSON object at the dest the hub's own
configuration names (never one the stream supplies), by rename and group-readable, and leaves the previous
file as it was when the stream fails, is not a JSON object, is too large or the dest escapes the root."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible/roles/status_hub"
SCRIPT = ROLE / "files/hnx-hub-pull.py"
spec = importlib.util.spec_from_file_location("hnx_hub_pull", SCRIPT)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def _fake_ssh(tmp_path: Path, body: str, rc: int = 0) -> Path:
    """A stand-in for ssh: records its argv, prints ``body`` and exits ``rc``."""
    out = tmp_path / "payload"
    out.write_text(body)
    argv_log = tmp_path / "argv.json"
    script = tmp_path / "ssh"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"open({str(argv_log)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
        f"sys.stdout.write(open({str(out)!r}).read())\n"
        f"sys.exit({rc})\n"
    )
    script.chmod(0o755)
    return script


def _cfg(tmp_path: Path, ssh: Path, **entry) -> Path:
    root = tmp_path / "files"
    root.mkdir(exist_ok=True)
    e = {
        "name": "lab-checks",
        "address": "producer",
        "user": "reader",
        "dest": "invariants/results.json",
    }
    e.update(entry)
    cfg = {
        "key_file": str(tmp_path / "id_pull"),
        "known_hosts": str(tmp_path / "known_hosts"),
        "root": str(root),
        "group": None,
        "ssh": str(ssh),
        "entries": [e],
    }
    path = tmp_path / "pulls.json"
    path.write_text(json.dumps(cfg))
    return path


DOC = json.dumps({"schema": "x", "results": {"N-01": {"status": "pass"}}})


def test_a_json_object_is_filed_at_the_configured_dest_group_readable(tmp_path):
    cfg = _cfg(tmp_path, _fake_ssh(tmp_path, DOC))
    assert helper.main(["hnx-hub-pull", "--config", str(cfg)]) == 0
    out = tmp_path / "files/invariants/results.json"
    assert json.loads(out.read_text())["results"]["N-01"]["status"] == "pass"
    assert stat.S_IMODE(out.stat().st_mode) == 0o640
    assert not [p for p in out.parent.iterdir() if p.name.startswith(".pull-")]


def test_the_client_pins_the_host_key_and_sends_no_command(tmp_path):
    cfg = _cfg(tmp_path, _fake_ssh(tmp_path, DOC))
    helper.main(["hnx-hub-pull", "--config", str(cfg)])
    argv = json.loads((tmp_path / "argv.json").read_text())
    assert (
        "StrictHostKeyChecking=yes" in argv
        and "BatchMode=yes" in argv
        and "IdentitiesOnly=yes" in argv
    )
    assert f"UserKnownHostsFile={tmp_path / 'known_hosts'}" in argv
    # the destination is last, after `--`: nothing follows it, so the forced command decides what runs
    assert argv[-2:] == ["--", "producer"]


@pytest.mark.parametrize(
    ("body", "rc"),
    [("not json", 0), ("[1, 2]", 0), ("{}", 0), (DOC, 255)],
    ids=["not-json", "not-an-object", "empty-object", "ssh-failed"],
)
def test_a_bad_stream_leaves_the_previous_file_as_it_was(tmp_path, body, rc):
    cfg = _cfg(tmp_path, _fake_ssh(tmp_path, body, rc))
    prev = tmp_path / "files/invariants"
    prev.mkdir(parents=True)
    (prev / "results.json").write_text('{"previous": true}')
    assert helper.main(["hnx-hub-pull", "--config", str(cfg)]) == 1
    assert json.loads((prev / "results.json").read_text()) == {"previous": True}
    assert not [p for p in prev.iterdir() if p.name.startswith(".pull-")]


def test_a_stream_over_the_cap_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "MAX_BYTES", 10)
    cfg = _cfg(tmp_path, _fake_ssh(tmp_path, DOC))
    assert helper.main(["hnx-hub-pull", "--config", str(cfg)]) == 1
    assert not (tmp_path / "files/invariants/results.json").exists()


@pytest.mark.parametrize(
    "dest",
    [
        "../escape.json",
        "invariants/../../x.json",
        "/abs.json",
        "a/./b.json",
        "results.txt",
        "Upper.json",
    ],
)
def test_a_dest_outside_the_root_or_not_a_plain_json_path_is_a_configuration_error(tmp_path, dest):
    cfg = _cfg(tmp_path, _fake_ssh(tmp_path, DOC), dest=dest)
    assert helper.main(["hnx-hub-pull", "--config", str(cfg)]) == 2
    assert not (tmp_path / "escape.json").exists() and not (tmp_path / "x.json").exists()


def test_a_symlinked_dest_directory_that_leaves_the_root_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    cfg = _cfg(tmp_path, _fake_ssh(tmp_path, DOC))
    os.symlink(outside, tmp_path / "files/invariants")
    assert helper.main(["hnx-hub-pull", "--config", str(cfg)]) == 2
    assert list(outside.iterdir()) == []


def test_the_role_wires_the_timer_as_a_calendar_and_keeps_the_key_out_of_the_environment():
    defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
    assert defaults["status_hub_pulls"] == [] and defaults["status_hub_pull_key_ref"] == ""
    assert defaults["status_hub_pulls_oncalendar"].endswith(" UTC")
    timer = (ROLE / "templates/hnx-hub-pull.timer.j2").read_text()
    assert "OnCalendar=" in timer and "OnBootSec=" not in timer and "OnUnitActiveSec=" not in timer
    service = (ROLE / "templates/hnx-hub-pull.service.j2").read_text()
    assert (
        "ExecStart=/usr/bin/python3 -I /usr/local/libexec/hnx-hub/hnx-hub-pull --config" in service
    )
    assert (
        "ReadWritePaths={{ status_hub_root_dir }}" in service and "EnvironmentFile" not in service
    )
    tasks = (ROLE / "tasks/pulls.yml").read_text()
    assert 'mode: "0600"' in tasks and "no_log: true" in tasks
    validate = (ROLE / "tasks/validate.yml").read_text()
    assert "status_hub_pull_key_ref not in status_hub_secret_refs" in validate
