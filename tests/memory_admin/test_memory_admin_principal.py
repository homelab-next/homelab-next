# SPDX-License-Identifier: Apache-2.0
"""``MemoryAdmin`` is out of the agent's reach (ADR-0037 decision 12, amended 2026-11-06): nothing
in ``homelabnext.agent``, ``homelabnext.broker`` or ``homelabnext.orchestration`` imports it, and
its ``OperatorPrincipal`` comes only from the invoking OS user, checked against a root-owned
operators file that refuses the uids the agent runtime and the broker run as.  The boundary is
the uid and file ownership: a principal is re-checked against the process's uids on every call.
The store-side retraction tests are in ``tests/agent/test_agent_memory_retraction.py``.

CI does not run as root, so these tests let the test's own uid stand in for root's ownership and
check directories only up to ``tmp_path`` (``_ROOT_OWNERS``, ``_TRUST_ABOVE``)."""

import ast
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest

from homelabnext.memory_admin import MemoryAdminError, OperatorPrincipal, principal
from homelabnext.memory_admin.principal import (
    OperatorsUnreadable,
    invoking_operator,
    load_operators,
    require_operator,
)

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_UID, BROKER_UID = 4242, 4343


@pytest.fixture(autouse=True)
def trusted(tmp_path, monkeypatch):
    monkeypatch.setattr(principal, "_TRUST_ABOVE", tmp_path)
    monkeypatch.setattr(principal, "_ROOT_OWNERS", frozenset({0, os.getuid()}))


def operators_file(directory, users=None, name="memory-operators.json", **extra):
    """An operators file in ``directory`` listing ``users`` (by default the invoking user)."""
    me = pwd.getpwuid(os.getuid()).pw_name
    doc = {
        "operators": users or [me],
        "agent_runtime": [{"uid": RUNTIME_UID}],
        "broker": [{"uid": BROKER_UID}],
        **extra,
    }
    path = directory / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    path.chmod(0o644)
    return path


def test_an_operator_principal_is_sealed_and_re_checked(tmp_path, monkeypatch):
    op = invoking_operator(load_operators(operators_file(tmp_path)))
    assert require_operator(op) is op and op.user == pwd.getpwuid(os.getuid()).pw_name
    with pytest.raises(TypeError, match="built only by the hnx agent memory command"):
        OperatorPrincipal("root", 0, "x")
    with pytest.raises(TypeError, match="sealed"):
        type("Sub", (OperatorPrincipal,), {})
    with pytest.raises(AttributeError):
        op.user = "someone"  # type: ignore[misc]
    for by in ("root", {"user": "root"}, None, 0):
        with pytest.raises(TypeError, match="OperatorPrincipal"):
            require_operator(by)
    # a forged principal (the seal is no defence against code that reads it) does not act from a
    # process with other uids, or one whose uid is refused
    forged = OperatorPrincipal("root", 0, "x", principal._SEALED, refused={RUNTIME_UID})
    if os.getuid() != 0:
        with pytest.raises(MemoryAdminError, match="not this process's operator"):
            require_operator(forged)
    monkeypatch.setattr(os, "getuid", lambda: RUNTIME_UID)
    monkeypatch.setattr(os, "geteuid", lambda: RUNTIME_UID)
    with pytest.raises(MemoryAdminError, match="not this process's operator"):
        require_operator(op)
    runtime = OperatorPrincipal("x", RUNTIME_UID, "x", principal._SEALED, refused={RUNTIME_UID})
    with pytest.raises(MemoryAdminError, match="not this process's operator"):
        require_operator(runtime)


def test_sudo_user_is_recorded_as_advisory(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDO_USER", "alice")
    op = invoking_operator(load_operators(operators_file(tmp_path)))
    assert op.by_sudo == "alice"


_RUNTIME = ("homelabnext/agent", "homelabnext/broker", "homelabnext/orchestration")


def _module_of(path: Path) -> list[str]:
    rel = path.relative_to(ROOT).with_suffix("")
    parts = list(rel.parts)
    return parts[:-1] if parts[-1] == "__init__" else parts


def imported(path: Path, text: str | None = None) -> list[tuple[int, str]]:
    """``(line, module)`` of every module ``path`` imports, relative imports resolved against
    its package, each ``from X import name`` also as ``X.name``, and constant names passed to
    ``importlib.import_module`` or ``__import__``."""
    here = _module_of(path)
    package = here if path.name == "__init__.py" else here[:-1]
    out: list[tuple[int, str]] = []
    source = path.read_text(encoding="utf-8") if text is None else text
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            out += [(node.lineno, a.name) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = package[: len(package) - node.level + 1] if node.level else []
            mod = ".".join([*base, *(node.module.split(".") if node.module else [])])
            out.append((node.lineno, mod))
            out += [(node.lineno, f"{mod}.{a.name}") for a in node.names]
        elif isinstance(node, ast.Call):
            name = getattr(node.func, "attr", getattr(node.func, "id", ""))
            if name in ("import_module", "__import__"):
                out += [
                    (node.lineno, a.value)
                    for a in node.args
                    if isinstance(a, ast.Constant) and isinstance(a.value, str)
                ]
    return out


def _hits(path: Path, text: str | None = None) -> list[str]:
    return [f"{path}:{n}" for n, m in imported(path, text) if "memory_admin" in m.split(".")]


@pytest.mark.parametrize(
    "spelling",
    [
        "from ..memory_admin import admin",
        "from homelabnext import memory_admin",
        "from .. import memory_admin",
        "import homelabnext.memory_admin.admin",
        "importlib.import_module('homelabnext.memory_admin')",
    ],
)
def test_the_import_check_sees_every_spelling(spelling):
    """The reviewer's three spellings (and two more): a relative import is resolved against the
    file's package, and each imported name is checked as ``module.name``."""
    # read as if it lived in homelabnext/agent/, without writing anything there
    assert _hits(ROOT / "homelabnext/agent/_probe.py", spelling), spelling
    assert not _hits(ROOT / "homelabnext/agent/_probe.py", "from .memory import fold")


def test_no_runtime_module_imports_the_memory_admin():
    found, seen = [], 0
    for base in _RUNTIME:
        for path in sorted((ROOT / base).rglob("*.py")):
            seen += 1
            found += _hits(path)
    assert seen > 40 and found == []


def test_importing_the_runtime_leaves_the_memory_admin_out_of_sys_modules():
    code = (
        "import sys, homelabnext.agent, homelabnext.broker, homelabnext.orchestration\n"
        "import homelabnext.agent.memory, homelabnext.agent.pack, homelabnext.broker.service\n"
        "print(sorted(m for m in sys.modules if 'memory_admin' in m))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "[]", out.stdout


def test_no_broker_handler_names_the_memory_admin():
    handlers = [p for p in (ROOT / "examples").rglob("handlers/*") if p.is_file()]
    assert handlers and all(b"memory_admin" not in p.read_bytes() for p in handlers)


def test_the_runtime_and_broker_uids_and_non_operators_are_refused(tmp_path, monkeypatch):
    me = pwd.getpwuid(os.getuid()).pw_name
    config = load_operators(operators_file(tmp_path))
    assert config.refused == {RUNTIME_UID, BROKER_UID} and config.operators == {me}
    assert config.refusing([7777]).refused == {RUNTIME_UID, BROKER_UID, 7777}
    for uid_ in (RUNTIME_UID, BROKER_UID):
        monkeypatch.setattr(os, "geteuid", lambda u=uid_: u)
        with pytest.raises(MemoryAdminError, match="agent runtime or the broker runs as"):
            invoking_operator(config)
    monkeypatch.undo()
    monkeypatch.setattr(principal, "_TRUST_ABOVE", tmp_path)
    monkeypatch.setattr(principal, "_ROOT_OWNERS", frozenset({0, os.getuid()}))
    with pytest.raises(MemoryAdminError, match="owns the memory state file"):
        invoking_operator(config.refusing([os.getuid()]))
    other = tmp_path / "o"
    other.mkdir(mode=0o755)
    with pytest.raises(MemoryAdminError, match="not in the operators list"):
        invoking_operator(load_operators(operators_file(other, users=["someone-else"])))
    with pytest.raises(TypeError):
        invoking_operator({"operators": [me], "refused": []})  # a mapping is not a config


def test_the_operators_file_is_trusted_only_through_root_ownership(tmp_path, monkeypatch):
    path = operators_file(tmp_path)
    path.chmod(0o666)
    with pytest.raises(MemoryAdminError, match="writable by its group or others"):
        load_operators(path)
    path.chmod(0o644)
    tmp_path.chmod(0o777)  # a directory above it the runtime could write
    with pytest.raises(MemoryAdminError, match="writable by its group or others"):
        load_operators(path)
    tmp_path.chmod(0o755)
    monkeypatch.setattr(principal, "_ROOT_OWNERS", frozenset({0}))
    if os.getuid() != 0:  # owned by the (non-root) invoking user: not root's
        with pytest.raises(MemoryAdminError, match="not root"):
            load_operators(path)
    monkeypatch.setattr(principal, "_ROOT_OWNERS", frozenset({0, os.getuid()}))
    monkeypatch.setenv("SUDO_UID", str(os.stat(path).st_uid or 1))
    if os.stat(path).st_uid:
        with pytest.raises(MemoryAdminError, match="owned by the invoking user"):
            load_operators(path)
    monkeypatch.delenv("SUDO_UID")
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OperatorsUnreadable, match="cannot open"):  # O_NOFOLLOW
        load_operators(link)
    with pytest.raises(OperatorsUnreadable, match="cannot open"):
        load_operators(tmp_path / "missing.json")
    (tmp_path / "bad.yml").write_text("operators: [", encoding="utf-8")
    with pytest.raises(OperatorsUnreadable, match="cannot parse"):
        load_operators(tmp_path / "bad.yml")
    for doc, words in (
        ({"operators": ["a"], "broker": [{"uid": 1}]}, "no agent runtime user"),
        ({"operators": ["a"], "agent_runtime": [{"uid": 1}]}, "broker must list"),
        ({"operators": [], "agent_runtime": [{"uid": 1}], "broker": [{"uid": 2}]}, "non-empty"),
        ({"operators": ["a"], "agent_runtime": [{"uid": 1}], "broker": [{"uid": 2}],
          "state": "x"}, "unknown keys"),
        ({"operators": ["a"], "agent_runtime": [{"uid": True}], "broker": [{"uid": 2}]},
         r"agent_runtime\[0\]: expected"),  # a bool is no uid
    ):  # fmt: skip
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(MemoryAdminError, match=words):
            load_operators(bad)


def test_every_broker_peer_is_refused_as_a_runtime_user(tmp_path):
    (tmp_path / "broker.json").write_text(
        json.dumps({
            "callers": [{"uid": 5151, "profile": "profile:reader"}],
            "approval_relays": [{"uid": 5252, "issuer": "x"}],
            "operators": [{"uid": 5353}],
            "codemode": {"runners": [{"uid": 5454}], "sandboxes": [{"uid": 5555}]},
        }),
        encoding="utf-8",
    )  # fmt: skip
    (tmp_path / "broker.json").chmod(0o644)
    path = operators_file(tmp_path, agent_runtime=None, broker_manifest="broker.json")
    assert load_operators(path).refused == {5151, 5252, 5353, 5454, 5555, BROKER_UID}
