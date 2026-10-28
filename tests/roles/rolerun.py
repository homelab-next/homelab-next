# SPDX-License-Identifier: Apache-2.0
"""Run one hook of a role on localhost, and write fake vendor commands (shared by the role tests)."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"


def _invocation(tmp_path, role, tasks_from, extra_vars, env=None, verbose=False):
    """The ``ansible-playbook`` command (and its environment) that runs one hook of a role."""
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
    return cmd, run_env


def run_role(tmp_path, role, tasks_from, extra_vars, env=None, verbose=False):
    cmd, run_env = _invocation(tmp_path, role, tasks_from, extra_vars, env, verbose)
    return subprocess.run(cmd, capture_output=True, text=True, env=run_env, cwd=tmp_path)


def first_run(case):
    """Mark a test whose first role run needs nothing from any other test, so it can run beside
    the others.  ``case(tmp, **params)`` sets up what that run needs under a fresh directory
    ``tmp`` (fake commands, files) and returns run_role's keyword arguments, or another runner's
    under ``runner`` (``run_cases``, or a module's own run_role), plus, under ``setup``, values
    the test reads back.  The test takes the ``first`` fixture, ``(result, tmp)`` with
    ``.vars`` and ``.setup``, in place of its own first run and ``tmp_path``.

    The first test of a module to ask starts the first runs of every marked test of that module
    this session will run, one ``ansible-playbook`` per CPU at a time (``prefetch_first_runs``).
    Each is the very command the test ran itself, in its own directory, so it sees the same
    result, sooner: the role tests spend their time waiting on ``ansible-playbook`` (about 0.85 s
    to start, 0.3 s a module task), one process at a time, on runners with idle CPUs."""

    def mark(fn):
        fn.hnx_first_run = case
        return fn

    return mark


class FirstRun(tuple):
    """A prefetched first run: ``(result, tmp)``, with the run's extra variables as ``.vars``."""

    vars: dict
    setup: dict
    error: Exception | None


_FIRST_RUNS: dict[str, FirstRun] = {}


def _run_one(job):
    """One prefetched run: ``(result, None)``, or ``(None, exception)`` for its own test to raise."""
    _, tmp, spec = job
    spec = dict(spec)
    spec.pop("setup", None)
    try:
        return spec.pop("runner", run_role)(tmp, **spec), None
    except Exception as e:  # handed to the test it belongs to
        return None, e


MAX_WORKERS = 8  # first runs started at once: enough for CI's runners, gentle on a large box


def workers(env=None, cpus=None) -> int:
    """How many first runs start at once: ``HNX_ROLERUN_WORKERS`` (a positive integer of up to
    four digits, any size the operator asks for: only the default is capped) when it is set, else
    the CPUs this process may use, at most :data:`MAX_WORKERS`."""
    env = os.environ if env is None else env
    raw = env.get("HNX_ROLERUN_WORKERS")
    if raw is not None:
        if not re.fullmatch(r"[1-9][0-9]{0,3}", raw.strip()):
            raise ValueError(f"HNX_ROLERUN_WORKERS is a positive integer, not {raw!r}")
        return int(raw)
    cpus = len(os.sched_getaffinity(0)) if cpus is None else cpus
    return max(1, min(cpus, MAX_WORKERS))


def _raise(e):
    def runner(_tmp):
        raise e

    return runner


def _will_run(item) -> bool:
    """Not skipped by a mark (a skip, or a skipif whose condition is already a true value)."""
    if item.get_closest_marker("skip"):
        return False
    return not any(m.args and m.args[0] is True for m in item.iter_markers("skipif"))


def prefetch_first_runs(request, tmp_path_factory):
    """The ``first`` fixture: this test's first run (see ``first_run``), with the first runs of
    every other marked test of its module that this session will run started alongside it."""
    node = request.node
    if node.nodeid not in _FIRST_RUNS:
        todo = []
        for item in node.session.items:
            case = getattr(getattr(item, "function", None), "hnx_first_run", None)
            if (case is None or item.module is not node.module or item.nodeid in _FIRST_RUNS
                    or not (item is node or _will_run(item))):  # fmt: skip
                continue
            # named as tmp_path names a test's directory (30 characters: gpg's agent socket
            # path under it must stay short)
            tmp = tmp_path_factory.mktemp(re.sub(r"[\W]", "_", item.name)[:30], numbered=True)
            params = getattr(getattr(item, "callspec", None), "params", {})
            try:
                todo.append((item.nodeid, tmp, case(tmp, **params)))
            except Exception as e:  # a bad setup fails its own test only
                todo.append((item.nodeid, tmp, {"runner": _raise(e)}))
        with ThreadPoolExecutor(max_workers=workers()) as pool:
            done = list(pool.map(_run_one, todo))
        for (nid, tmp, spec), (r, err) in zip(todo, done, strict=True):
            _FIRST_RUNS[nid] = FirstRun((r, tmp))
            _FIRST_RUNS[nid].vars = spec.get("extra_vars", spec.get("base_vars"))
            _FIRST_RUNS[nid].setup = spec.get("setup", {})
            _FIRST_RUNS[nid].error = err
    run = _FIRST_RUNS.pop(node.nodeid)
    if run.error is not None:  # raised by this test's own run (run_cases asserts), not another's
        raise run.error
    return run


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


def last_run_vars(tmp_path: Path, role: str) -> dict[str, str]:
    """A timer role's last-run inputs (role last_run) pointed into ``tmp_path``: the writer at
    ``bin/hnx-last-run``, the records under ``last-run/``, readable by the test user's own group
    (the only group an unprivileged run may give a file)."""
    import grp

    return {
        f"{role}_last_run_dir": str(tmp_path / "last-run"),
        f"{role}_last_run_group": grp.getgrgid(os.getgid()).gr_name,
        f"{role}_last_run_writer": str(tmp_path / "bin" / "hnx-last-run"),
    }


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
