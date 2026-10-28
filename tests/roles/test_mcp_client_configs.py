# SPDX-License-Identifier: Apache-2.0
"""The census role's MCP client configuration reader (``library/mcp_client_configs.py``), on its
own: no symbolic link at any step, no directory its group or others may write, a small regular
file or nothing.  No real path is made writable by anyone but its owner: the mode rule is judged on
reported modes."""

from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest

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
