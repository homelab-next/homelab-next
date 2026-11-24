# SPDX-License-Identifier: Apache-2.0
"""Role agent_rehome: move an agent enrolled with another manager to the registry's manager (fake
service-manager and enrolment commands record their argv; the secret comes from the environment)."""

import grp
import os
from pathlib import Path

import pytest
from rolerun import calls, logging_fake, run_role

pytestmark = pytest.mark.requires_tool("ansible-playbook")
ENV = {"HNX_SECRET_SIEM_ENROLLMENT_PASSWORD": "new-enrolment-pass"}


def _agent(tmp_path: Path, address: str):
    etc = tmp_path / "agent" / "etc"
    etc.mkdir(parents=True)
    (etc / "agent.conf").write_text(
        f"<cfg><client><server><address>{address}</address><port>1514</port></server>"
        "</client></cfg>\n"
    )
    (etc / "client.keys").write_text("001 old-host any oldkey\n")
    (etc / "authd.pass").write_text("old-pass\n")
    v = {
        "agent_rehome_manager_id": "siem",
        "agent_rehome_enrollment_ref": "secret:siem/enrollment-password",
        "agent_rehome_enrollment_port": 1515,
        "agent_rehome_config_file": str(etc / "agent.conf"),
        "agent_rehome_key_file": str(etc / "client.keys"),
        "agent_rehome_password_file": str(etc / "authd.pass"),
        "agent_rehome_service": "endpoint-agent",
        "agent_rehome_stamp": "20261124",
        "agent_rehome_config_group": grp.getgrgid(os.getgid()).gr_name,
        "agent_rehome_systemctl_cli": logging_fake(tmp_path, "systemctl"),
        "agent_rehome_auth_cli": logging_fake(tmp_path, "agent-auth"),
    }
    return etc, v


def test_an_agent_enrolled_elsewhere_is_moved(tmp_path):
    etc, v = _agent(tmp_path, "old.example.internal")
    r = run_role(tmp_path, "agent_rehome", "main", v, env=ENV)
    assert r.returncode == 0, r.stdout + r.stderr
    conf = (etc / "agent.conf").read_text()
    assert "<address>siem-01.example.internal</address>" in conf
    assert "old.example.internal" not in conf
    assert (etc / "client.keys").read_text() == ""
    assert (etc / "authd.pass").read_text() == "new-enrolment-pass"
    for f in ("agent.conf", "client.keys", "authd.pass"):  # the rollback copies
        assert (etc / f"{f}.pre-rehome-20261124").exists()
    assert "old.example.internal" in (etc / "agent.conf.pre-rehome-20261124").read_text()
    log = [line.split()[0:3] for line in calls(tmp_path)]
    assert log == [["systemctl", "stop", "endpoint-agent"],
                   ["agent-auth", "-m", "siem-01.example.internal"],
                   ["systemctl", "start", "endpoint-agent"]]  # fmt: skip
    assert "new-enrolment-pass" not in r.stdout + r.stderr  # the password is never printed
    assert all("new-enrolment-pass" not in c for c in calls(tmp_path))  # nor an argument


def test_an_agent_already_on_the_manager_is_left_alone(tmp_path):
    etc, v = _agent(tmp_path, "siem-01.example.internal")
    r = run_role(tmp_path, "agent_rehome", "main", v, env=ENV)
    assert r.returncode == 0, r.stdout + r.stderr
    assert calls(tmp_path) == []
    assert (etc / "client.keys").read_text() == "001 old-host any oldkey\n"
    assert not list(etc.glob("*.pre-rehome-*"))
