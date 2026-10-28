# SPDX-License-Identifier: Apache-2.0
"""The census role's MCP client configuration reader (``library/mcp_client_configs.py``), on its
own: no symbolic link at any step, no file or directory someone else's or its group or others may
write, a small regular file with one link, named as its client's configuration, or nothing; parsed
strictly on the host, and only the server names it registers returned, never its text.  No real
path is made writable by anyone but its owner: the mode and owner rules are judged on reported
values."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import census

PATH = (
    Path(__file__).resolve().parents[2]
    / "ansible"
    / "roles"
    / "module_census"
    / "library"
    / "mcp_client_configs.py"
)


@pytest.fixture
def mod(monkeypatch):
    # the reader imports only AnsibleModule, which main() alone uses: a stand-in keeps this test
    # free of an Ansible install (the repository's own ansible/ directory is not the package)
    for name in ("ansible", "ansible.module_utils", "ansible.module_utils.basic"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    sys.modules["ansible.module_utils.basic"].AnsibleModule = object
    spec = importlib.util.spec_from_file_location("mcp_client_configs", PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def home(tmp_path: Path) -> Path:
    d = tmp_path / "agent"
    d.mkdir()
    for x in (tmp_path, d):
        os.chmod(x, 0o700)
    return d


def test_a_configuration_is_read_whole(mod, tmp_path):
    f = home(tmp_path) / ".mcp.json"
    f.write_text('{"mcpServers": {}}')
    os.chmod(f, 0o600)
    assert mod.read_one(str(f), 1024) == '{"mcpServers": {}}'


def test_an_absent_file_or_directory_is_nothing(mod, tmp_path):
    d = home(tmp_path)
    assert mod.read_one(str(d / "absent.json"), 1024) is None
    assert mod.read_one(str(d / "no" / "such.json"), 1024) is None


def test_a_link_at_any_step_is_refused(mod, tmp_path):
    d = home(tmp_path)
    real = d / "real.json"
    real.write_text("{}")
    os.chmod(real, 0o600)
    (d / "link.json").symlink_to(real)
    with pytest.raises(mod.Refused, match="not a regular file"):
        mod.read_one(str(d / "link.json"), 1024)
    (tmp_path / "via").symlink_to(d)
    with pytest.raises(mod.Refused, match="reached without a link"):
        mod.read_one(str(tmp_path / "via" / "real.json"), 1024)


def test_a_fifo_or_an_oversized_file_is_refused_without_blocking(mod, tmp_path):
    d = home(tmp_path)
    os.mkfifo(d / "fifo.json", 0o600)
    with pytest.raises(mod.Refused, match="not a regular file of at most 8 bytes"):
        mod.read_one(str(d / "fifo.json"), 8)
    big = d / "big.json"
    big.write_text("x" * 9)
    os.chmod(big, 0o600)
    with pytest.raises(mod.Refused, match="not a regular file of at most 8 bytes"):
        mod.read_one(str(big), 8)
    exact = d / "exact.json"
    exact.write_text("x" * 8)
    os.chmod(exact, 0o600)
    assert mod.read_one(str(exact), 8) == "x" * 8


@pytest.mark.parametrize(
    ("mode", "uid", "directory", "refused"),
    [
        (0o40700, 1000, True, False),
        (0o40755, 1000, True, False),
        (0o40775, 1000, True, True),  # its group may write
        (0o40757, 1000, True, True),  # others may write
        (0o41777, 0, True, False),  # /tmp: root's, sticky
        (0o41777, 1000, True, True),  # sticky but someone else's
        (0o100644, 1000, False, False),
        (0o100664, 1000, False, True),
        (0o101666, 0, False, True),  # a sticky file is no sticky directory
    ],
)
def test_the_mode_rule_refuses_group_or_other_write(mod, mode, uid, directory, refused):
    assert mod.open_to_others(mode, uid, directory) is refused


def test_a_directory_its_group_or_others_may_write_is_refused(mod, tmp_path, monkeypatch):
    f = home(tmp_path) / ".mcp.json"
    f.write_text("{}")
    os.chmod(f, 0o600)
    real = os.fstat
    loose = os.stat(tmp_path / "agent").st_ino

    def reported(fd):
        st = real(fd)
        if st.st_ino == loose:
            return types.SimpleNamespace(
                st_mode=st.st_mode | 0o020, st_ino=st.st_ino, st_uid=st.st_uid
            )
        return st

    monkeypatch.setattr(mod.os, "fstat", reported)
    with pytest.raises(mod.Refused, match="agent is writable by its group or others"):
        mod.read_one(str(f), 1024)


@pytest.mark.parametrize(
    ("path", "plain"),
    [
        ("/var/lib/agent/.mcp.json", True),
        ("/etc/hermes/primary.yaml", True),
        ("relative/.mcp.json", False),
        ("/var/lib/../etc/x.json", False),
        ("/var/lib/./x.json", False),
        ("/var//x.json", False),
        ("/var/x y.json", False),
    ],
)
def test_a_path_is_absolute_and_plain(mod, path, plain):
    assert bool(mod.PATH_RE.fullmatch(path)) is plain


def test_a_hard_link_is_refused(mod, tmp_path):
    d = home(tmp_path)
    f = d / ".mcp.json"
    f.write_text("{}")
    os.chmod(f, 0o600)
    os.link(f, d / "other.mcp.json")
    with pytest.raises(mod.Refused, match="has more than one link"):
        mod.read_one(str(f), 1024)


@pytest.mark.parametrize("target", ["dir", "file"])
def test_a_file_or_directory_someone_else_owns_is_refused(mod, tmp_path, monkeypatch, target):
    # benign modes, someone else's: what is reached through it could be theirs to change
    f = home(tmp_path) / ".mcp.json"
    f.write_text("{}")
    os.chmod(f, 0o600)
    real = os.fstat
    other = os.stat(tmp_path / "agent" if target == "dir" else f).st_ino

    def reported(fd):
        st = real(fd)
        if st.st_ino == other:
            return types.SimpleNamespace(
                st_mode=st.st_mode, st_ino=st.st_ino, st_uid=os.geteuid() + 4242, st_nlink=1
            )
        return st

    monkeypatch.setattr(mod.os, "fstat", reported)
    shown = "agent" if target == "dir" else ".mcp.json"
    with pytest.raises(mod.Refused, match=f"{shown} is neither root's nor this user's"):
        mod.read_one(str(f), 1024)


@pytest.mark.parametrize(
    ("client", "name", "named"),
    [
        ("claude-code", ".mcp.json", True),
        ("claude-code", "broker-agent.mcp.json", True),
        ("claude-code", "mcp.json", False),
        ("generic", "mcp.json", True),
        ("generic", ".mcp.json", True),
        ("generic", "hosts.mcp.json", True),
        ("hermes", "config.yaml", True),
        ("hermes", "mcp.yaml", False),
        ("claude-code", "shadow", False),
        ("claude-code", "server.key", False),
        ("generic", "credentials", False),
        ("hermes", "config.yaml.bak", False),
    ],
)
def test_a_file_is_read_only_under_its_clients_name(mod, client, name, named):
    assert bool(mod.BASENAMES[client].fullmatch(name)) is named


def test_a_sensitive_file_is_refused_before_it_is_opened(mod, monkeypatch):
    monkeypatch.setattr(mod, "read_one", lambda *a: pytest.fail("opened"))
    for path, client in (("/etc/shadow", "claude-code"), ("/srv/agent/token.json", "generic")):
        with pytest.raises(mod.Refused, match="is not named as a"):
            mod.read_names(path, client, 1024)
    with pytest.raises(mod.Refused, match="is no known client"):
        mod.read_names("/srv/.mcp.json", ["claude-code"], 1024)


SECRET = "s3cr3t-token-value-0001"


def test_only_the_names_leave_the_host_never_a_secret(mod, tmp_path):
    d = home(tmp_path)
    f = d / ".mcp.json"
    servers = {
        "hnx-broker": {"type": "stdio", "command": "hnx", "env": {"API_TOKEN": SECRET}},
        "notes-a-real": {"type": "http", "url": "https://notes.example", "headers": {"x": SECRET}},
    }
    f.write_text(json.dumps({"mcpServers": servers}))
    os.chmod(f, 0o600)
    got = mod.read_names(str(f), "claude-code", 1024)
    assert got == {
        "path": str(f),
        "client": "claude-code",
        "present": True,
        "servers": ["hnx-broker", "notes-a-real"],
    }
    assert SECRET not in json.dumps(got)
    absent = mod.read_names(str(d / "gone.mcp.json"), "generic", 1024)
    assert absent["present"] is False and absent["servers"] == []
    # and what the host sends is what the controller accepts
    assert census.parse_mcp([got, absent], "h")[0] == {"hnx-broker", "notes-a-real"}


@pytest.mark.parametrize(
    ("client", "text", "why"),
    [
        ("claude-code", "{not json", "does not parse"),
        ("claude-code", '{"mcpServers": {"a": 1, "a": 2}}', "does not parse"),
        ("claude-code", '{"mcpServers": {"a": NaN}}', "does not parse"),
        ("claude-code", '{"mcpServers": {"a": Infinity}}', "does not parse"),
        ("generic", "[]", "is not a generic configuration"),
        ("claude-code", '{"mcpServers": []}', "mcpServers is not a mapping"),
        ("claude-code", '{"mcpServers": {"Upper": {}}}', "a server name is not an inventory name"),
        ("claude-code", '{"mcpServers": {"snake_case": {}}}', "not an inventory name"),
        ("claude-code", "[" * 100000 + "]" * 100000, "does not parse"),
        ("hermes", "mcp_servers: &a {x: 1}\nmore: *a\n", "does not parse"),
        ("hermes", "mcp_servers: {a: 1, a: 2}\n", "does not parse"),
        ("hermes", "mcp_servers: [a]\n", "mcp_servers is not a mapping"),
        # a complex key (a sequence as a mapping key) cannot be hashed: a refusal, not a crash
        ("hermes", "mcp_servers:\n  ? [secret-a, secret-b]\n  : 1\n", "does not parse"),
    ],
)
def test_a_configuration_is_parsed_strictly(mod, client, text, why):
    with pytest.raises(mod.Refused, match=why) as err:
        mod.server_names(text, client, "/p")
    # a message names the path and a reason, never the text
    assert str(err.value).startswith("/p") and "NaN" not in str(err.value)
    assert "secret" not in str(err.value)


def test_too_many_servers_are_refused(mod):
    text = json.dumps({"mcpServers": {f"s{i}": {} for i in range(mod.MAX_SERVERS + 1)}})
    with pytest.raises(mod.Refused, match="registers more than"):
        mod.server_names(text, "claude-code", "/p")


def test_a_hermes_file_parses_where_pyyaml_is_installed(mod):
    text = yaml.safe_dump({"model": "x", "mcp_servers": {"notes-a-real": {"command": "hnx"}}})
    assert mod.server_names(text, "hermes", "/p") == ["notes-a-real"]


def test_without_pyyaml_a_hermes_file_fails_closed(mod, monkeypatch):
    monkeypatch.setattr(mod, "_yaml_loader", lambda: (None, None))
    with pytest.raises(mod.Refused, match="PyYAML is not installed on this host"):
        mod.server_names("mcp_servers: {}\n", "hermes", "/p")
    # a JSON client needs only the standard library
    assert mod.server_names('{"mcpServers": {"a": {}}}', "claude-code", "/p") == ["a"]


def test_the_role_module_and_census_name_the_same_clients(mod):
    roles = PATH.parents[1]
    listed = yaml.safe_load((roles / "vars" / "main.yml").read_text())["module_census_mcp_clients"]
    assert sorted(listed) == sorted(census.MCP_CLIENTS) == sorted(mod.BASENAMES)
    assert mod.SERVERS_KEY == census.MCP_CLIENTS
    assert mod.NAME_RE.pattern == census.NAME_RE.pattern
