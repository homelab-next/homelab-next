# SPDX-License-Identifier: Apache-2.0
"""Role module_census (docs/modules.md, "What the loader checks"): each host's enabled and active
fleet units, its notifier owners' pairs records and its installed MCP client configurations,
read-only, on a broker host the agents its broker serves and on a lake catalog host the tables its
catalog lists, written on the controller, where ``hnx modules gather`` reads them.  systemctl and hnx are stand-ins here; the
play runs on localhost, which is then both the host and the controller."""

from __future__ import annotations

import json
import os
import shutil

import pytest
from rolerun import LOGGER, calls, fake, first_run, logging_fake, run_cases

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
#: a value in a configuration's env block: it never leaves the host (only names do)
MCP_SECRET = "s3cr3t-census-token-0002"
MCP_JSON = json.dumps(
    {"mcpServers": {"hnx-broker": {"type": "stdio", "command": "hnx", "env": {"T": MCP_SECRET}}}}
)
AGENTS = "core-staff-scorecard\nexternal-collector-analyst\n"
#: what hnx modules catalog-tables prints on the catalog host: names only
TABLES_FOUND = {"tables": ["lab_own.x", "ocsf.authentication"], "left_out": 1}
CATALOG = "http://127.0.0.1:8181"  # no-raw-endpoint: allow loopback, a stand-in answers
NAMED = "http://localhost:8181"  # no-raw-endpoint: allow refused, a name not an IP literal
OFF_HOST = "http://192.0.2.8:8181"  # no-raw-endpoint: allow RFC 5737, refused off loopback


def _hnx(tmp_path) -> str:
    """A stand-in hnx whose broker answers the operator's agents and whose catalog listing
    answers the tables (and logs each call); each fails unless it was reached through become as
    root (the stand-in sudo below says so)."""
    out = (
        "if os.environ.get('HNX_TEST_BECOME_USER') != 'root':\n"
        "    sys.exit('hnx: not run as root')\n"
        f"sys.stdout.write({AGENTS!r} if sys.argv[1] == 'broker' else {json.dumps(TABLES_FOUND)!r})"
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


#: the kernel's socket tables, as a host shows them (``/proc/net``): a TCP port listening (8443,
#: on every address, and 9000, on IPv6), a TCP connection (not a service), a bound UDP port
#: (53) and a connected UDP socket (a client's); the address fields are the kernel's hex
_HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"
TABLES = {
    "tcp": _HEAD
    + "   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0\n"
    + "   1: 00000000:A3F2 00000000:01BB 01 00000000:00000000 00:00000000 00000000 0\n",
    "tcp6": _HEAD
    + "   0: 00000000000000000000000000000000:2328 00000000000000000000000000000000:0000 0A 0\n",
    "udp": _HEAD
    + "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 0\n"
    + "   1: 00000000:D431 00000000:0035 01 00000000:00000000 00:00000000 00000000 0\n",
}


def _tables(tmp_path) -> str:
    d = tmp_path / "net"
    d.mkdir()
    for name, text in TABLES.items():  # no udp6: IPv6 off for UDP reads as no table, not a failure
        (d / name).write_text(text)
    return str(d)


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
        "module_census_socket_tables": _tables(tmp_path),
        # this host runs the broker: the census asks it for the agents it serves
        "module_census_broker_socket": "/run/hnx-broker/broker.sock",
        "module_census_hnx_cli": _hnx(tmp_path),
        # the broker task becomes root (the identity the broker's manifest lists as operator)
        "ansible_become_exe": _sudo(tmp_path),
        # this host runs the lake catalog, whose token is root's: the listing task becomes root
        "module_census_catalog_url": CATALOG,
        "module_census_catalog_warehouse": "lab",
        "module_census_catalog_token_file": "/etc/hnx/catalog.token",
        "module_census_mcp_configs": [
            {"path": str(agent / ".mcp.json"), "client": "claude-code"},
            {"path": str(agent / "hermes" / "config.yaml"), "client": "hermes"},
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
        "sudo -u root",
        f"hnx modules catalog-tables --url {CATALOG} --warehouse lab --api-root /catalog "
        "--token-file /etc/hnx/catalog.token",
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
        "listening": ["tcp/8443", "tcp/9000", "udp/53"],
        "agents": AGENTS.splitlines(),
        "mcp": [
            {
                "path": v["module_census_mcp_configs"][0]["path"],
                "client": "claude-code",
                "present": True,
                "servers": ["hnx-broker"],
            },
            {
                "path": v["module_census_mcp_configs"][1]["path"],
                "client": "hermes",
                "present": False,
                "servers": [],
            },
        ],
        "tables": TABLES_FOUND,
    }
    # a configuration is parsed on the host: no value of its env block reaches the answer, nor
    # anything the run printed
    assert MCP_SECRET not in (out / "localhost.json").read_text()
    assert MCP_SECRET not in r.stdout + r.stderr
    inventory, notes = census.gather(out)
    assert inventory == {
        "schema_version": "1.0",
        "units": ["external-collector-pull", "lake-compact", "stray"],
        "agents": ["core-staff-scorecard", "external-collector-analyst"],
        "mcp_servers": ["hnx-broker"],
        "tables": ["table:lab_own.x", "table:ocsf.authentication"],
        "not_gathered": ["rows"],
        "notify_pairs": [PAIR],
        "listening": [{"host": "localhost", "sockets": ["tcp/8443", "tcp/9000", "udp/53"]}],
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
    (tmp_path / "agent" / "link.mcp.json").symlink_to(tmp_path / "agent" / ".mcp.json")
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
                    {"path": str(tmp_path / "agent" / "link.mcp.json"), "client": "generic"}
                ]
            },
            # a file not named as its client's configuration is never opened
            {"module_census_mcp_configs": [{"path": "/etc/shadow", "client": "claude-code"}]},
            # the catalog is listed from its own host: a loopback IP literal, and plain values
            {"module_census_catalog_url": NAMED},
            {"module_census_catalog_url": OFF_HOST},
            {"module_census_catalog_url": CATALOG + "/catalog"},
            {"module_census_catalog_warehouse": ""},
            {"module_census_catalog_warehouse": "--url=x"},
            {"module_census_catalog_api_root": "/../x"},
            {"module_census_catalog_token_file": "etc/token"},
            # no token file: the listing does not become root (the stand-in refuses it then)
            {"module_census_catalog_token_file": ""},
            # a listing that is not JSON fails the census
            {"module_census_hnx_cli": logging_fake(tmp_path, "hnx-prints", "lab_own.x\n")},
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
    assert results[20][0] and "is not named as a claude-code configuration" in results[20][1]
    for failed, said in results[21:28]:
        assert failed and "the lake catalog empty or http(s)://<loopback IP>" in said, results
    said = "module_census: the lake catalog was not listed: hnx: not run as root"
    assert results[28] == (True, said), results
    assert results[29][0], results


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


def _socket_module(monkeypatch):
    """The role's listening_sockets module, loaded with a stand-in for AnsibleModule (only main()
    uses it; the repository's own ansible/ directory is not the package)."""
    import importlib.util
    import sys
    import types

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
        "listening_sockets.py",
    )
    spec = importlib.util.spec_from_file_location("listening_sockets", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_socket_reader_takes_listening_tcp_and_bound_udp_only(tmp_path, monkeypatch):
    mod = _socket_module(monkeypatch)
    root = _tables(tmp_path)
    # a connection and a connected UDP socket are clients, not services
    assert mod.sockets(root) == ["tcp/8443", "tcp/9000", "udp/53"]
    # no IPv4 TCP table is a failure; an oversized table is refused, never cut short
    (tmp_path / "net" / "tcp").unlink()
    with pytest.raises(mod.Refused, match="cannot be read"):
        mod.sockets(root)
    (tmp_path / "net" / "tcp").write_text(TABLES["tcp"])
    monkeypatch.setattr(mod, "MAX_BYTES", 16)
    with pytest.raises(mod.Refused, match="is over 16 bytes"):
        mod.sockets(root)


#: IPv4 loopback and a documentation address, built from integers (no address literal)
_LOOPBACK4, _DOC4 = 0x7F000001, 0xC000020A


def _kernel_hex(address) -> str:
    """An address (text or ``ipaddress`` object) as the kernel writes it in its socket tables:
    32-bit words in host order."""
    import ipaddress
    import sys

    packed = ipaddress.ip_address(address).packed
    return "".join(
        int.from_bytes(packed[i : i + 4], "big").to_bytes(4, sys.byteorder).hex().upper()
        for i in range(0, len(packed), 4)
    )


def test_a_socket_bound_only_to_loopback_is_marked_and_a_bad_line_skipped(tmp_path, monkeypatch):
    import ipaddress

    mod = _socket_module(monkeypatch)
    d = tmp_path / "net"
    d.mkdir()
    any4, any6 = _kernel_hex("0.0.0.0"), _kernel_hex("::")

    def line(local, port, state="0A", remote=None):
        return f"   0: {local}:{port:04X} {remote or local}:0000 {state} 0 0 0\n"

    (d / "tcp").write_text(
        _HEAD
        + line(_kernel_hex(ipaddress.IPv4Address(_LOOPBACK4)), 631)  # loopback only
        + line(_kernel_hex(ipaddress.IPv4Address(_DOC4)), 8443)  # one of the host's addresses
        + line(any4, 22)
        + "   0: ZZZZZZZZ:0050 00000000:0000 0A 0\n"  # not the kernel's hex: skipped
        + "   0: 00000000:50 00000000:0000 0A 0\n"  # a short port: skipped
        + line(any4, 0)  # port 0: no service
    )
    (d / "tcp6").write_text(
        _HEAD
        + line(_kernel_hex("::1"), 5432)
        + line(_kernel_hex(ipaddress.IPv6Address((0xFFFF << 32) | _LOOPBACK4)), 6379)  # mapped
        + line(any6, 22)
    )
    assert mod.sockets(str(d)) == [
        "tcp/22",
        "tcp/631@lo",
        "tcp/5432@lo",
        "tcp/6379@lo",
        "tcp/8443",
    ]
    # more sockets than the census takes fails, never cut short
    monkeypatch.setattr(mod, "MAX_SOCKETS", 4)
    with pytest.raises(mod.Refused, match="holds 5 sockets, over the 4 the census takes"):
        mod.sockets(str(d))
