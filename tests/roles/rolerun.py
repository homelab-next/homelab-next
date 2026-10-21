# SPDX-License-Identifier: Apache-2.0
"""Run one hook of a role on localhost, and write fake vendor commands (shared by the role tests)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"


def run_role(tmp_path, role, tasks_from, extra_vars, env=None, verbose=False):
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "tasks": [{"ansible.builtin.include_role": {"name": role, "tasks_from": tasks_from}}],
        }
    ]
    pb = tmp_path / "play.yml"
    pb.write_text(yaml.safe_dump(play))
    ev = tmp_path / "vars.json"
    ev.write_text(
        json.dumps(
            {
                "hnx_registry_file": str(ANSIBLE / "inventory/example/registry.yml"),
                "ansible_python_interpreter": sys.executable,
                **extra_vars,
            }
        )
    )
    run_env = dict(
        os.environ,
        ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
        ANSIBLE_ERROR_ON_UNDEFINED_VARS="True",
        ANSIBLE_LOCALHOST_WARNING="False",
        ANSIBLE_HOME=str(tmp_path / ".ansible"),
        ANSIBLE_NOCOLOR="1",
        **(env or {}),
    )
    cmd = ["ansible-playbook", "-i", "localhost,", "-e", f"@{ev}", str(pb)]
    if verbose:
        cmd.append("-v")
    return subprocess.run(cmd, capture_output=True, text=True, env=run_env, cwd=tmp_path)


def fake(path: Path, body: str) -> str:
    """An executable Python script at ``path`` (a stand-in for a vendor command)."""
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


LOGGER = r"""
import os, sys
open(LOG, "a").write(NAME + " " + " ".join(sys.argv[1:]) + "\n")
OUT
sys.exit(1 if os.path.exists(FAIL) else 0)
"""


def logging_fake(tmp_path: Path, name: str, out: str = "") -> str:
    """A fake ``name`` that appends ``<name> <args>`` to ``calls.log``, prints ``out`` and fails
    while ``<name>.fails`` exists."""
    body = (
        LOGGER.replace("LOG", repr(str(tmp_path / "calls.log")))
        .replace("NAME", repr(name))
        .replace("FAIL", repr(str(tmp_path / f"{name}.fails")))
        .replace("OUT", f"sys.stdout.write({out!r})")
    )
    return fake(tmp_path / name, body)


def calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls.log"
    return log.read_text().splitlines() if log.exists() else []


def run_cases(tmp_path, role, tasks_from, base_vars, overrides, env=None):
    """Run one hook once per override in a single ansible-playbook process (one ``block`` with a
    ``rescue`` per case, so a failing case does not stop the others).  Returns, per override,
    ``(failed, message)``: whether the hook failed for that case, and its failure message."""
    tasks = []
    for i, over in enumerate(overrides):
        tasks.append(
            {
                "block": [
                    {
                        "ansible.builtin.include_role": {"name": role, "tasks_from": tasks_from},
                        "vars": over,
                    },
                    {"ansible.builtin.set_fact": {f"hnx_case_{i}": {"failed": False, "msg": ""}}},
                ],
                "rescue": [
                    {
                        "ansible.builtin.set_fact": {
                            f"hnx_case_{i}": {
                                "failed": True,
                                "msg": "{{ ansible_failed_result.msg | default('') | string }}",
                            }
                        }
                    }
                ],
            }
        )
    names = [f"hnx_case_{i}" for i in range(len(overrides))]
    tasks.append(
        {
            "ansible.builtin.copy": {
                "dest": str(tmp_path / "cases.json"),
                "content": "{{ [" + ", ".join(names) + "] | to_json }}",
                "mode": "0600",
            }
        }
    )
    # the shared values are play variables: a case's task variables take precedence over them
    # (extra variables would override every case)
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars": base_vars,
            "tasks": tasks,
        }
    ]
    pb = tmp_path / "cases.yml"
    pb.write_text(yaml.safe_dump(play))
    ev = tmp_path / "vars.json"
    ev.write_text(
        json.dumps(
            {
                "hnx_registry_file": str(ANSIBLE / "inventory/example/registry.yml"),
                "ansible_python_interpreter": sys.executable,
            }
        )
    )
    run_env = dict(
        os.environ,
        ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
        ANSIBLE_ERROR_ON_UNDEFINED_VARS="True",
        ANSIBLE_LOCALHOST_WARNING="False",
        ANSIBLE_HOME=str(tmp_path / ".ansible"),
        ANSIBLE_NOCOLOR="1",
        **(env or {}),
    )
    r = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", f"@{ev}", str(pb)],
        capture_output=True, text=True, env=run_env, cwd=tmp_path,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    return [(c["failed"], c["msg"]) for c in json.loads((tmp_path / "cases.json").read_text())]
