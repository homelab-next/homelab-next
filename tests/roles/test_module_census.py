# SPDX-License-Identifier: Apache-2.0
"""Role module_census (docs/modules.md, "What the loader checks"): each host's enabled and active
fleet units, its notifier owners' pairs records and its installed MCP client configurations,
read-only, and on a broker host the agents its broker serves, written on the controller, where ``hnx modules gather`` reads them.  systemctl and hnx are stand-ins here; the
play runs on localhost, which is then both the host and the controller."""

from __future__ import annotations

import json
import os
import shutil

import pytest
from rolerun import LOGGER, calls, fake, first_run, run_cases

from homelabnext.modules import census
from homelabnext.notify import record as nr
from homelabnext.notify.record import PairsRecord

needs_ansible = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)

ENABLED = (
    "hnx-external-collector-pull.service enabled enabled\n"
    "hnx-external-collector-pull.timer enabled -\n"
    "hnx-lake-compact.timer enabled\n"
    "hnx-page@.service enabled disabled\n"
)
ACTIVE = (
    "hnx-external-collector-pull.timer loaded active waiting Pull the collector\n"
    "hnx-stray.service loaded active running Started outside any unit file\n"
)


def _systemctl(tmp_path) -> str:
    """A stand-in systemctl that logs its arguments and answers each query in its own shape."""
    out = f"sys.stdout.write({ENABLED!r} if sys.argv[1] == 'list-unit-files' else {ACTIVE!r})"
    body = (
        LOGGER.replace("LOG", repr(str(tmp_path / "calls.log")))
        .replace("NAME", repr("systemctl"))
        .replace("FAIL", repr(str(tmp_path / "systemctl.fails")))
        .replace("OUT", out)
    )
    return fake(tmp_path / "systemctl", body)


PAIR = {"problem": "UPS on battery", "recovery": "UPS back on line power"}
MCP_JSON = json.dumps({"mcpServers": {"hnx-broker": {"type": "stdio", "command": "hnx"}}})
AGENTS = "core-staff-scorecard\nexternal-collector-analyst\n"


def _hnx(tmp_path) -> str:
    """A stand-in hnx whose broker answers the operator's agents (and logs the call); it fails
    unless it was reached through become as root (the stand-in sudo below says so)."""
    out = (
        "if os.environ.get('HNX_TEST_BECOME_USER') != 'root':\n"
        "    sys.exit('hnx broker agents: not run as root')\n"
        f"sys.stdout.write({AGENTS!r})"
    )
    body = (
        LOGGER.replace("LOG", repr(str(tmp_path / "calls.log")))
        .replace("NAME", repr("hnx"))
        .replace("FAIL", repr(str(tmp_path / "hnx.fails")))
        .replace("OUT", out)
    )
    return fake(tmp_path / "hnx", body)


# A stand-in sudo (become_exe): it logs the user it was asked to become, says so to what it runs,
# and runs it as this user; a task that does not become never reaches it.
SUDO = r"""
import os, sys
args, user, i = sys.argv[1:], None, 0
while i < len(args) and args[i].startswith("-"):
    if args[i] == "-u":
        user = args[i + 1]
        i += 1
    i += 1
open(LOG, "a").write("sudo -u " + str(user) + "\n")
os.environ["HNX_TEST_BECOME_USER"] = str(user)
os.execvp(args[i], args[i:])
"""


# ansible skips become when it already runs as the user asked for (root, on a box that runs the
# tests as root): allowing the same user keeps the stand-in sudo in the path either way
BECOME_ENV = {"ANSIBLE_BECOME_ALLOW_SAME_USER": "True"}


def _sudo(tmp_path) -> str:
    return fake(tmp_path / "sudo", SUDO.replace("LOG", repr(str(tmp_path / "calls.log"))))


def _first(tmp_path):
    out = tmp_path / "census"
    out.mkdir()
    pairs = tmp_path / "pairs"
    pairs.mkdir(mode=0o700)
    os.chmod(pairs, 0o700)
    # this process writes it, so the record's process is running while the role reads it
    PairsRecord(pairs, "broker").write({PAIR["problem"]: (PAIR["recovery"], None)})
    # an installed MCP client configuration, and one the host lists that is absent
    agent = tmp_path / "agent"
    agent.mkdir(mode=0o700)
    os.chmod(agent, 0o700)
    (agent / ".mcp.json").write_text(MCP_JSON)
    os.chmod(agent / ".mcp.json", 0o600)
    v = {
        "module_census_dir": str(out),
        "module_census_systemctl_cli": _systemctl(tmp_path),
        "module_census_pairs_dir": str(pairs),  # broker's record present, status's absent
        # this host runs the broker: the census asks it for the agents it serves
        "module_census_broker_socket": "/run/hnx-broker/broker.sock",
        "module_census_hnx_cli": _hnx(tmp_path),
        # the broker task becomes root (the identity the broker's manifest lists as operator)
        "ansible_become_exe": _sudo(tmp_path),
        "module_census_mcp_configs": [
            {"path": str(agent / ".mcp.json"), "client": "claude-code"},
            {"path": str(agent / "absent.yaml"), "client": "hermes"},
        ],
    }
    return {
        "role": "module_census",
        "tasks_from": "main",
        "extra_vars": v,
        "env": BECOME_ENV,
        "setup": {"v": v},
    }


@needs_ansible
@first_run(_first)
def test_module_census_writes_each_hosts_answer_and_gather_reads_it(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    # three read-only queries, by argument vector: the pattern reaches systemctl unexpanded,
    # and the broker host's broker is asked for its agents over its socket, as root (the one
    # task that becomes)
    assert calls(tmp_path) == [
        "systemctl list-unit-files --no-legend --plain --no-pager --type=service,timer "
        "--state=enabled hnx-*",
        "systemctl list-units --no-legend --plain --no-pager --type=service,timer "
        "--state=active hnx-*",
        "sudo -u root",
        "hnx broker agents --socket /run/hnx-broker/broker.sock",
    ]
    out = tmp_path / "census"
    assert json.loads((out / "_hosts.json").read_text()) == ["localhost"]
    answer = json.loads((out / "localhost.json").read_text())
    text = (tmp_path / "pairs" / "broker" / "pairs.json").read_text()
    started = nr.parse_record(text, "broker").started
    assert answer == {
        "host": "localhost",
        "enabled": ENABLED.splitlines(),
        "active": ACTIVE.splitlines(),
        "pairs": {
            "boot_id": nr.boot_id(),
            "now": answer["pairs"]["now"],
            "records": {"broker": {"text": text, "pid_started": started}, "status": None},
        },
        "agents": AGENTS.splitlines(),
        "mcp": [
            {
                "path": v["module_census_mcp_configs"][0]["path"],
                "client": "claude-code",
                "text": MCP_JSON,
            },
            {"path": v["module_census_mcp_configs"][1]["path"], "client": "hermes", "text": None},
        ],
    }
    inventory, notes = census.gather(out)
    assert inventory == {
        "schema_version": "1.0",
        "units": ["external-collector-pull", "lake-compact", "stray"],
        "agents": ["core-staff-scorecard", "external-collector-analyst"],
        "mcp_servers": ["hnx-broker"],
        "not_gathered": ["rows", "tables"],
        "notify_pairs": [PAIR],
    }
    assert any("template unit" in n for n in notes)

    # refused before anything is listed: a relative or missing directory; and a systemctl that
    # fails, or exits 1 while printing (only an empty "nothing matched" may exit 1)
    failing = fake(tmp_path / "systemctl-fails", "import sys\nsys.exit(2)\n")
    noisy = fake(
        tmp_path / "systemctl-noisy",
        "import sys\nprint('hnx-x.service enabled')\nsys.exit(1)\n",
    )
    # nothing matches: list-unit-files exits 1 and list-units 0, both printing nothing
    empty = fake(
        tmp_path / "systemctl-empty",
        "import sys\nsys.exit(1 if sys.argv[1] == 'list-unit-files' else 0)\n",
    )
    # list-units has no "nothing matched" exit: a failure there fails the census
    active_fails = fake(
        tmp_path / "systemctl-active-fails",
        "import sys\nsys.exit(1 if sys.argv[1] == 'list-units' else 0)\n",
    )

    # a record is read only as a small regular file, never through a link, in a directory no
    # one else may write; a FIFO never blocks the read
    def plain(name, owner):  # its owner's only
        d = tmp_path / name
        (d / owner).mkdir(parents=True)
        for x in (d, d / owner):
            os.chmod(x, 0o700)
        return d

    linked = plain("linked-pairs", "broker")
    (linked / "broker" / "pairs.json").symlink_to(tmp_path / "pairs" / "broker" / "pairs.json")
    big = plain("big-pairs", "status")
    (big / "status" / "pairs.json").write_text(" " * (256 * 1024 + 1))
    fifo = plain("fifo-pairs", "status")
    os.mkfifo(fifo / "status" / "pairs.json")
    via = tmp_path / "via"
    via.symlink_to(tmp_path / "pairs")
    # an MCP client configuration is an absolute plain path of a known client, read never
    # through a link
    (tmp_path / "agent" / "link.json").symlink_to(tmp_path / "agent" / ".mcp.json")
    results = run_cases(
        tmp_path,
        "module_census",
        "main",
        v,
        [
            {"module_census_pairs_dir": "relative/pairs"},
            {"module_census_pairs_dir": str(linked)},
            {"module_census_pairs_dir": str(big)},
            {"module_census_pairs_dir": str(fifo)},
            {"module_census_pairs_dir": str(via)},
            {"module_census_dir": "relative/census"},
            {"module_census_dir": str(tmp_path / "absent")},
            {"module_census_systemctl_cli": failing},
            {"module_census_systemctl_cli": noisy},
            {"module_census_systemctl_cli": empty},
            {"module_census_systemctl_cli": active_fails},
            # a host name names the host's answer file: never a path
            {"inventory_hostname": "../x"},
            {"inventory_hostname": "a/b"},
            {"inventory_hostname": ".hidden"},
            # the broker's socket is a plain path under /run/ and hnx an absolute plain path (it
            # runs as root); a broker that does not answer fails the census
            {"module_census_broker_socket": "run/broker.sock"},
            {"module_census_broker_socket": "/run/../etc/broker.sock"},
            {"module_census_broker_socket": "/tmp/broker.sock"},
            {"module_census_hnx_cli": "hnx; true"},
            {"module_census_hnx_cli": "hnx"},
            {"module_census_hnx_cli": "-hnx"},
            {"module_census_hnx_cli": fake(tmp_path / "hnx-fails", "import sys\nsys.exit(1)\n")},
            {"module_census_mcp_configs": [{"path": "agent/.mcp.json", "client": "claude-code"}]},
            {"module_census_mcp_configs": [{"path": "/srv/a.json", "client": "other"}]},
            {"module_census_mcp_configs": ["/srv/a.json"]},
            {
                "module_census_mcp_configs": [
                    {"path": str(tmp_path / "agent" / "link.json"), "client": "generic"}
                ]
            },
        ],
        env=BECOME_ENV,
    )
    assert results[0][0] and "the notify pairs directory an absolute" in results[0][1]
    for failed, said in results[1:4]:
        assert failed and "is not a regular file of at most 262144 bytes" in said, results
    assert results[4][0] and "reached without a link" in results[4][1], results
    results = results[5:]
    assert results[0][0] and "module_census: the census directory is an absolute" in results[0][1]
    assert results[1][0] and "is not a directory on the controller" in results[1][1]
    assert results[2][0] and results[3][0], results
    assert results[4] == (False, ""), results
    assert results[5][0], results
    for failed, said in results[6:9]:
        assert failed and "the host name a plain name" in said, results
    for failed, said in results[9:15]:
        assert failed and "the broker socket empty or a path under /run/" in said, results
    assert results[15][0], results
    for failed, said in results[16:18]:
        assert failed and "each MCP client configuration {path, client}" in said, results
    # an entry that is not a mapping: the role's argument spec refuses it first
    assert results[18][0] and "module_census_mcp_configs" in results[18][1], results
    assert results[19][0] and "is not a regular file of at most 1048576 bytes" in results[19][1]


def test_the_record_reader_refuses_a_directory_its_group_or_others_may_write(monkeypatch):
    # the reader's own mode rule, on reported modes: no real directory is made writable by
    # others (the playbook cases above cover links, size and the FIFO)
    import importlib.util
    import sys
    import types

    # the reader imports only AnsibleModule, which main() alone uses: a stand-in keeps this test
    # free of an Ansible install (the repository's own ansible/ directory is not the package)
    for name in ("ansible", "ansible.module_utils", "ansible.module_utils.basic"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    sys.modules["ansible.module_utils.basic"].AnsibleModule = object
    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "ansible",
        "roles",
        "module_census",
        "library",
        "notify_pairs_records.py",
    )
    spec = importlib.util.spec_from_file_location("notify_pairs_records", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for mode, refused in ((0o40700, False), (0o40755, False), (0o40775, True), (0o40757, True)):
        monkeypatch.setattr(mod.os, "fstat", lambda fd, m=mode: types.SimpleNamespace(st_mode=m))
        if refused:
            with pytest.raises(mod.Refused, match="is writable by its group or others"):
                mod.guarded(3, "/x")
        else:
            mod.guarded(3, "/x")
