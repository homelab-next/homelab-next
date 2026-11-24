# SPDX-License-Identifier: Apache-2.0
"""The endpoint-agent module: the clients dial the PUBLISHED frontend port (not the
container's), and an
enrolment counts only when the server itself sees the client (a client writes its identity file
before it ever reaches a server)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SERVERS = ROOT.glob("modules/*/roles/*_server/files/hnx_*.py")
(SERVER,) = (f for f in SERVERS if "def seen_problems" in f.read_text())
ROLE = SERVER.parents[1].name  # the server role's name, which prefixes its variables
PREFIX = ROLE.removesuffix("_server")
ROLES = SERVER.parents[2]
SPEC = importlib.util.spec_from_file_location("hnx_endpoint_agent", SERVER)
vr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vr)

TEXT = "{{ " + PREFIX + "_server_client_config_text }}"
NOW = 1_800_000_000.0
CID = "C.0123456789abcdef"


def _row(cid, age_s):
    return {"client_id": cid, "last_seen_at": int((NOW - age_s) * 1e6)}


def test_a_client_the_server_saw_lately_passes():
    assert vr.seen_problems([_row(CID, 10)], NOW, 300, CID) == []


@pytest.mark.parametrize(
    ("rows", "needle"),
    [
        ([], "never enrolled"),
        ([_row("C.ffffffffffffffff", 1)], "never enrolled"),
        ([_row(CID, 3600)], "not seen"),
    ],
)
def test_a_client_the_server_does_not_list_or_saw_long_ago_fails(rows, needle):
    (p,) = vr.seen_problems(rows, NOW, 300, CID)
    assert needle in p


def test_the_fleet_check_counts_fresh_enrolled_clients():
    rows = [_row(CID, 10), _row("C.ffffffffffffffff", 99999)]
    assert vr.fleet_problems(rows, NOW, 900, 1) == []
    (p,) = vr.fleet_problems(rows, NOW, 900, 2)
    assert "1 fresh of 2" in p
    (p,) = vr.fleet_problems([], NOW, 900, 1)  # an empty fleet never reads green
    assert "0 fresh of 0" in p


def test_the_client_id_argument_is_checked_before_any_query():
    assert vr.CLIENT_ID.fullmatch(CID)
    assert not vr.CLIENT_ID.fullmatch("C.0123') OR 1=1 --")


@pytest.mark.requires_tool("ansible-playbook")
@pytest.mark.parametrize(("published", "container"), [(8001, 8000), (8000, 8000)])
def test_the_client_configuration_dials_the_published_port(tmp_path, published, container):
    tasks = yaml.safe_load((ROLES / ROLE / "tasks/client_config.yml").read_text())
    (rewrite,) = [t for t in tasks if "ansible.builtin.set_fact" in t]
    (check,) = [t for t in tasks if "ansible.builtin.assert" in t]
    host = "sensor.example.internal"
    printed = (
        f"Client:\n  server_urls:\n  - wss://{host}:{container}/\n  - https://{host}:{container}/\n"
        "  ca_certificate: -----BEGIN CERTIFICATE-----\n"
    )
    play = [{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {f"{PREFIX}_server_frontend_hostname": host,
                 f"{PREFIX}_server_container_frontend_port": container,
                 f"{PREFIX}_server_frontend_port": published,
                 f"{PREFIX}_server_client_config": {"stdout": printed}},
        "tasks": [rewrite, {"ansible.builtin.assert": check["ansible.builtin.assert"]},
                  {"ansible.builtin.copy": {"content": TEXT,
                                            "dest": str(tmp_path / "out.yaml")}}],
    }]  # fmt: skip
    (tmp_path / "p.yml").write_text(yaml.safe_dump(play))
    r = subprocess.run(["ansible-playbook", "-i", "localhost,", str(tmp_path / "p.yml")],
                       capture_output=True, text=True, cwd=tmp_path)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    urls = yaml.safe_load((tmp_path / "out.yaml").read_text())["Client"]["server_urls"]
    assert urls == [f"wss://{host}:{published}/", f"https://{host}:{published}/"]
    assert json.dumps(urls).count(f":{container}/") == (2 if published == container else 0)
