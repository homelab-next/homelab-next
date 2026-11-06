# SPDX-License-Identifier: Apache-2.0
"""``MemoryAdmin`` is out of the agent's reach (ADR-0037 decision 12): nothing in
``homelabnext.agent``, ``homelabnext.broker`` or ``homelabnext.orchestration`` imports it, and its
``OperatorPrincipal`` comes only from the invoking OS user, checked against a reviewed operators
file that refuses the uids the agent runtime and the broker run as.  The store-side retraction
tests are in ``tests/agent/test_agent_memory_retraction.py``."""

import ast
import json
import os
import pwd
from pathlib import Path

import pytest

from homelabnext.memory_admin import MemoryAdminError, OperatorPrincipal
from homelabnext.memory_admin.principal import invoking_operator, load_operators, require_operator

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_UID, BROKER_UID = 4242, 4343


def operators_file(directory, users=None, **extra):
    """An operators file in ``directory`` listing ``users`` (by default the invoking user)."""
    me = pwd.getpwuid(os.getuid()).pw_name
    doc = {
        "operators": users or [me],
        "agent_runtime": [{"uid": RUNTIME_UID}],
        "broker": [{"uid": BROKER_UID}],
        **extra,
    }
    path = directory / "memory-operators.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    path.chmod(0o644)
    return path


def test_an_operator_principal_is_sealed(tmp_path):
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


_RUNTIME = ("homelabnext/agent", "homelabnext/broker", "homelabnext/orchestration")


def test_no_runtime_module_imports_the_memory_admin():
    """The import graph: nothing in homelabnext.agent, homelabnext.broker or
    homelabnext.orchestration imports homelabnext.memory_admin, statically or by name."""
    found = []
    seen = 0
    for base in _RUNTIME:
        for path in sorted((ROOT / base).rglob("*.py")):
            seen += 1
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                mods: list[str] = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    # a relative import cannot leave its package, so it never reaches it
                    mods = [node.module or ""] if not node.level else []
                elif isinstance(node, ast.Call):  # importlib.import_module("..."), __import__
                    consts = [a for a in node.args if isinstance(a, ast.Constant)]
                    mods = [a.value for a in consts if isinstance(a.value, str)]
                    name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                    if name not in ("import_module", "__import__"):
                        mods = []
                if any("memory_admin" in m for m in mods):
                    found.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert seen > 40 and found == []


def test_the_runtime_and_broker_uids_and_non_operators_are_refused(tmp_path, monkeypatch):
    me = pwd.getpwuid(os.getuid()).pw_name
    config = load_operators(operators_file(tmp_path))
    assert config.refused == {RUNTIME_UID, BROKER_UID} and config.operators == {me}
    for uid_ in (RUNTIME_UID, BROKER_UID):
        monkeypatch.setattr(os, "geteuid", lambda u=uid_: u)
        with pytest.raises(MemoryAdminError, match="agent runtime or the broker runs as"):
            invoking_operator(config)
    monkeypatch.undo()
    other = tmp_path / "o"
    other.mkdir()
    with pytest.raises(MemoryAdminError, match="not in the operators list"):
        invoking_operator(load_operators(operators_file(other, users=["someone-else"])))
    with pytest.raises(TypeError):
        invoking_operator({"operators": [me], "refused": []})  # a mapping is not a config


def test_the_operators_file_must_be_one_the_runtime_cannot_write(tmp_path):
    path = operators_file(tmp_path)
    path.chmod(0o666)
    with pytest.raises(MemoryAdminError, match="writable by its group or others"):
        load_operators(path)
    path.chmod(0o644)
    owned = operators_file(
        tmp_path, users=["someone-else"], agent_runtime=[{"uid": os.stat(path).st_uid}]
    )
    with pytest.raises(MemoryAdminError, match="owned by uid"):
        load_operators(owned)
    for doc, words in (
        ({"operators": ["a"], "broker": [{"uid": 1}]}, "no agent runtime user"),
        ({"operators": ["a"], "agent_runtime": [{"uid": 1}]}, "broker must list"),
        ({"operators": [], "agent_runtime": [{"uid": 1}], "broker": [{"uid": 2}]}, "non-empty"),
        ({"operators": ["a"], "agent_runtime": [{"uid": 1}], "broker": [{"uid": 2}],
          "state": "x"}, "unknown keys"),
    ):  # fmt: skip
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(MemoryAdminError, match=words):
            load_operators(bad)


def test_the_broker_manifests_callers_are_refused_as_runtime_users(tmp_path):
    (tmp_path / "broker.json").write_text(
        json.dumps({"callers": [{"uid": 5151, "profile": "profile:reader"}]}), encoding="utf-8"
    )
    path = tmp_path / "ops.json"
    me = pwd.getpwuid(os.getuid()).pw_name
    path.write_text(json.dumps({"operators": [me], "broker": [{"uid": 4343}],
                                "broker_manifest": "broker.json"}), encoding="utf-8")  # fmt: skip
    assert load_operators(path).refused == {5151, 4343}
