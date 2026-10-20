# SPDX-License-Identifier: Apache-2.0
"""Exec handlers: pinned digest, argv only, params on stdin, scrubbed env, secrets by name,
timeout and output caps.  Each refusal is shown failing on the bad input and passing on the good."""

from __future__ import annotations

import json
import os

import pytest

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
