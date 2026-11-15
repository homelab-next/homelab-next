# SPDX-License-Identifier: Apache-2.0
"""Read-only probes that an assert decides on must run under ``ansible-playbook --check``.

Under --check a command task is skipped, so its registered result is empty (rc unset, stdout ''),
and the assert after it fails on a healthy host ("docker_engine: unit docker is unknown ...").  A
probe that registers a result and changes nothing (``changed_when: false``) therefore carries
``check_mode: false``, on the task or on an enclosing block.  Checked statically for every role's
health and readiness hook, and for the version probes in a role's main.yml."""

import pathlib

import pytest
import yaml

ROLES = pathlib.Path(__file__).resolve().parents[2] / "ansible" / "roles"
# a role's main.yml holds a version probe too when a task there asks the binary "for its version"
VERSION_PROBES = [p for p in ROLES.glob("*/tasks/main.yml") if "for its version" in p.read_text()]
FILES = sorted(
    [*ROLES.glob("*/tasks/health.yml"), *ROLES.glob("*/tasks/readiness.yml"), *VERSION_PROBES]
)
COMMANDS = {"ansible.builtin.command", "ansible.builtin.shell", "command", "shell"}


def _probes(tasks, inherited=None):
    """Yield (name, effective check_mode) for each registered read-only command task."""
    for task in tasks or []:
        effective = task.get("check_mode", inherited)
        if COMMANDS & task.keys() and "register" in task and task.get("changed_when") is False:
            yield task.get("name", "?"), effective
        for key in ("block", "rescue", "always"):
            yield from _probes(task.get(key), effective)


@pytest.mark.parametrize("path", FILES, ids=lambda p: f"{p.parent.parent.name}/{p.name}")
def test_every_registered_read_only_command_runs_in_check_mode(path):
    tasks = yaml.safe_load(path.read_text())
    bad = [name for name, mode in _probes(tasks) if mode is not False]
    assert not bad, f"{path.relative_to(ROLES)}: add `check_mode: false` to {bad}"


def test_the_docker_engine_readiness_probes_are_found():
    names = [
        n
        for n, _ in _probes(
            yaml.safe_load((ROLES / "docker_engine/tasks/readiness.yml").read_text())
        )
    ]
    assert len(names) == 2, names


def test_a_version_probe_in_a_main_tasks_file_is_found():
    assert VERSION_PROBES
