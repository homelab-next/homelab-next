# SPDX-License-Identifier: Apache-2.0
"""Exec handlers: pinned digest, argv only, params on stdin, scrubbed env, secrets by name,
timeout and output caps.  Each refusal is shown failing on the bad input and passing on the good."""

from __future__ import annotations

import errno
import json
import os
import subprocess
import time

import pytest

from homelabnext.broker import execute as execute_mod
from homelabnext.broker.execute import (
    ExecError,
    env_secret_resolver,
    file_digest,
    run_handler,
)

SECRET = "fake-secret-value-7c2e"


def _handler(tmp_path, body, name="h.sh"):
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)
    return p


def _run(tmp_path, path, digest=None, **kw):
    rd = tmp_path / f"run-{len(list(tmp_path.glob('run-*')))}"
    rd.mkdir()
    kw.setdefault("params", {})
    kw.setdefault("timeout_s", 10)
    return run_handler(path, digest or file_digest(path), run_dir=rd, **kw), rd


def test_params_arrive_on_stdin_and_argv_is_fixed(tmp_path):
    h = _handler(tmp_path, 'printf "%s|" "$@"; cat\n')
    res, rd = _run(tmp_path, h, params={"name": "; rm -rf /"}, argv=["--mode", "a b"])
    assert res.exit_code == 0 and not res.timed_out
    args, stdin = res.stdout.decode().split("|", 2)[:2], res.stdout.decode().rsplit("|", 1)[1]
    assert args == ["--mode", "a b"]
    assert json.loads(stdin) == {"name": "; rm -rf /"}
    assert (rd / "stdout").read_bytes() == res.stdout


def test_digest_mismatch_refuses_before_anything_runs(tmp_path):
    marker = tmp_path / "ran"
    h = _handler(tmp_path, f"touch {marker}\n")
    good = file_digest(h)
    h.write_text(h.read_text() + "# tampered\n")
    with pytest.raises(ExecError) as info:
        _run(tmp_path, h, digest=good)
    assert info.value.reason == "handler-digest-mismatch" and info.value.outcome == "denied"
    assert not marker.exists()
    _run(tmp_path, h)  # the current digest runs
    assert marker.exists()


def test_symlinked_handler_is_refused(tmp_path):
    real = _handler(tmp_path, "true\n")
    link = tmp_path / "link.sh"
    os.symlink(real, link)
    with pytest.raises(ExecError) as info:
        _run(tmp_path, link, digest=file_digest(real))
    assert info.value.reason == "handler-path-escape"


def test_missing_handler_is_refused(tmp_path):
    with pytest.raises(ExecError) as info:
        _run(tmp_path, tmp_path / "nope.sh", digest="sha256:" + "0" * 64)
    assert info.value.reason == "handler-missing"


def test_environment_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_PARENT_ONLY", "fake-leak")
    h = _handler(tmp_path, "env\n")
    res, rd = _run(tmp_path, h, env={"HNX_BROKER_ACTION": "x.y"})
    env = dict(line.split("=", 1) for line in res.stdout.decode().splitlines() if "=" in line)
    assert "FAKE_PARENT_ONLY" not in env
    assert env["PATH"] == "/usr/local/bin:/usr/bin:/bin"
    assert env["HOME"] == str(rd) and env["HNX_BROKER_ACTION"] == "x.y"


def test_secrets_by_name_reach_only_the_handler_and_are_redacted_from_output(tmp_path):
    h = _handler(tmp_path, 'echo "token=$DEMO_TOKEN"; echo "$DEMO_TOKEN" >&2\n')
    res, rd = _run(tmp_path, h, secrets=["DEMO_TOKEN"], resolve_secret={"DEMO_TOKEN": SECRET}.get)
    assert res.stdout == b"token=<redacted>\n" and res.stderr == b"<redacted>\n"
    for f in rd.iterdir():
        if f.is_file() and f.name != "handler.sh":
            assert SECRET.encode() not in f.read_bytes(), f.name
    with pytest.raises(ExecError) as info:
        _run(tmp_path, h, secrets=["MISSING"], resolve_secret={}.__getitem__)
    assert info.value.reason == "secret-unavailable" and SECRET not in str(info.value)


def test_env_secret_resolver_reads_the_brokers_prefixed_variable():
    resolve = env_secret_resolver({"HNX_BROKER_SECRET_DEMO": "fake-v", "DEMO": "fake-wrong"})
    assert resolve("DEMO") == "fake-v"
    with pytest.raises(KeyError):
        resolve("OTHER")


def test_timeout_kills_the_handler(tmp_path):
    h = _handler(tmp_path, "sleep 30\n")
    res, _ = _run(tmp_path, h, timeout_s=1)
    assert res.timed_out and res.exit_code != 0
    quick = _handler(tmp_path, "true\n", "q.sh")
    assert not _run(tmp_path, quick, timeout_s=1)[0].timed_out


def test_output_is_capped(tmp_path):
    h = _handler(tmp_path, "head -c 200000 /dev/zero | tr '\\0' a; head -c 5000 /dev/zero >&2\n")
    res, rd = _run(tmp_path, h, max_output=1000)
    assert len(res.stdout) == 1000 and res.stdout_truncated
    assert len(res.stderr) == 1000 and res.stderr_truncated
    assert (rd / "stdout").stat().st_size == 1000
    small, _ = _run(tmp_path, _handler(tmp_path, "echo hi\n", "s.sh"), max_output=1000)
    assert not small.stdout_truncated


def test_unexecutable_handler_is_a_spawn_failure(tmp_path):
    p = tmp_path / "data.bin"
    p.write_bytes(b"\x00\x01not a program")
    with pytest.raises(ExecError) as info:
        _run(tmp_path, p)
    assert info.value.reason == "handler-spawn-failed"


# -- review regressions: the process group, redaction at the cap, close-on-exec ------------


def _unreaped(pid: int) -> bool:
    """True while ``pid`` is still our child: running, or a zombie nobody has reaped."""
    try:
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return False
    return True


@pytest.mark.parametrize("body", ["true\n", "sleep 30\n"])
def test_the_process_group_is_killed_before_the_handler_is_reaped(tmp_path, monkeypatch, body):
    seen = []
    real = os.killpg

    def killpg(pgid, sig):
        seen.append(_unreaped(pgid))  # the leader still pins its pgid: it cannot be reused
        real(pgid, sig)

    monkeypatch.setattr(execute_mod.os, "killpg", killpg)
    res = _run(tmp_path, _handler(tmp_path, body), timeout_s=1)[0]
    assert seen == [True]
    assert res.timed_out is (body != "true\n")


def test_leftover_children_are_still_killed(tmp_path):
    marker = tmp_path / "late"
    _run(tmp_path, _handler(tmp_path, f"(sleep 1; touch {marker}) &\nexit 0\n"))
    time.sleep(1.5)
    assert not marker.exists()


def test_a_secret_cut_at_the_cap_leaves_no_prefix(tmp_path):
    secret = "fake-secret-value-0f3c9d"
    h = _handler(tmp_path, 'printf "%s" "$(head -c 95 /dev/zero | tr "\\0" a)$DEMO"\n')
    res, _ = _run(
        tmp_path, h, secrets=["DEMO"], resolve_secret={"DEMO": secret}.get, max_output=100
    )
    assert res.stdout_truncated
    text = res.stdout.decode()
    assert not any(text.endswith(secret[:n]) for n in range(1, len(secret) + 1)), text
    assert text.startswith("a" * 95)


def test_the_handler_copy_is_close_on_exec_and_a_busy_text_file_is_retried(tmp_path, monkeypatch):
    real_open, real_popen = os.open, subprocess.Popen
    flags, calls = [], []

    def spy_open(path, fl, *a, **k):
        if str(path).endswith("handler.sh"):
            flags.append(fl)
        return real_open(path, fl, *a, **k)

    def busy_once(*a, **k):
        calls.append(1)
        if len(calls) == 1:  # another thread's fork still held the copy open for write
            raise OSError(errno.ETXTBSY, "Text file busy")
        return real_popen(*a, **k)

    monkeypatch.setattr(execute_mod.os, "open", spy_open)
    monkeypatch.setattr(execute_mod.subprocess, "Popen", busy_once)
    res, _ = _run(tmp_path, _handler(tmp_path, "echo hi\n"))
    assert res.exit_code == 0 and res.stdout == b"hi\n" and len(calls) == 2
    assert flags and all(f & os.O_CLOEXEC for f in flags)
