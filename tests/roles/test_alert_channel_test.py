# SPDX-License-Identifier: Apache-2.0
"""LL-567: an alerting control deployed green whose channel could never deliver, found only by
faking a pending reboot.  The scripts that alert through the notify slot (needrestart's check and
pending-reboot check, lynis's package integrity sweep) now have a ``--test`` mode that sends one
low-priority message through the very code path a real alert takes; the role runs it once at
deploy when the channel changed and fails the play with the script's error; every real send
records its outcome and the role's health hook fails when the last attempt failed.

The scripts are rendered with test values (plain Jinja2) and run as subprocesses against loopback
endpoints; the deploy and health tests run the roles' own task files on localhost."""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest
from rolerun import run_role

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[2]
LOOPBACK = ".".join(["127", "0", "0", "1"])
TOKEN = "tk-test-not-a-secret"
TEMPLATES = {
    "needrestart": ("needrestart", "ansible/roles/needrestart/templates/needrestart-check.py.j2", "send-status.json"),
    "needrestart-reboot": ("needrestart", "ansible/roles/needrestart/templates/reboot-check.py.j2", "reboot-send-status.json"),
    "lynis": ("lynis", "ansible/roles/lynis/templates/dpkg-verify.py.j2", "send-status.json"),
}  # fmt: skip


class _Quick(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Notify:
    """A loopback notify endpoint: records (method, path, headers, body); answers `code`."""

    def __init__(self, code=200, headers=None):
        self.seen, self.code, self.extra = [], code, headers or {}
        me = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                me.seen.append(
                    (self.command, self.path, dict(self.headers), self.rfile.read(n).decode())
                )
                self.send_response(me.code)
                for k, v in me.extra.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = _Quick((LOOPBACK, 0), H)
        self.url = f"http://{LOOPBACK}:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, args=(0.02,), daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def notify():
    made = []

    def make(**kw):
        made.append(Notify(**kw))
        return made[-1]

    yield make
    for n in made:
        n.close()


@pytest.fixture(autouse=True)
def no_env_proxy(monkeypatch):
    for name in (
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(urllib.request, "_opener", None)


def render(tmp_path, key, url, mode="notify"):
    """The script rendered for `url`; returns (script path, state dir)."""
    prefix, template, _ = TEMPLATES[key]
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    env.filters["to_json"] = json.dumps
    env.filters["bool"] = lambda v: v is True or str(v).lower() in ("yes", "true", "1", "on")
    token = tmp_path / "token"
    token.write_text(TOKEN + "\n")
    state = tmp_path / "state"
    common = {
        "state_dir": str(state), "notify_url": url, "notify_topic": "topic", "notify_priority": 3,
        "notify_auth_file": str(token), "notify_auth_ref": "secret:notify-token",
        "sendmail_cli": "/bin/false", "mail_to": "root",
    }  # fmt: skip
    extra = {
        "needrestart": {
            "cli": "/bin/false", "mode": mode, "alert_kernel": False,
            "reboot_required_file": "/nonexistent", "busctl_cli": "/bin/false", "shutdown_cli": "/bin/false",
        },
        "lynis": {
            "dpkg_cli": "/bin/false", "debsums_cli": "/bin/false", "notify_mode": mode,
            "dpkg_verify_include_conffiles": False, "dpkg_verify_allow": [], "dpkg_cfg_files": [],
        },
    }[prefix]  # fmt: skip
    values = {f"{prefix}_{k}": v for k, v in {**common, **extra}.items()}
    script = tmp_path / f"{key}.py"
    script.write_text(env.from_string((ROOT / template).read_text()).render(values))
    return script, state


def run_test_mode(script):
    return subprocess.run(
        [sys.executable, str(script), "--test"], capture_output=True, text=True, timeout=60
    )


def status(state, key):
    return json.loads((state / TEMPLATES[key][2]).read_text())


@pytest.mark.parametrize("key", sorted(TEMPLATES))
def test_test_mode_sends_one_low_priority_message_through_the_real_path(tmp_path, notify, key):
    n = notify()
    script, state = render(tmp_path, key, n.url)
    r = run_test_mode(script)
    assert r.returncode == 0, r.stderr
    ((method, path, headers, body),) = n.seen
    prefix = TEMPLATES[key][0]
    want = f"{prefix} channel test from {os.uname().nodename}"
    assert (method, path, body) == ("POST", "/topic", want)
    assert headers["Priority"] == "1" and headers["Authorization"] == "Bearer " + TOKEN
    assert want in headers["Title"] and TOKEN not in r.stdout + r.stderr
    doc = status(state, key)
    assert doc["ok"] is True and doc["error"] == "" and doc["time"].endswith("Z")


@pytest.mark.parametrize("key", sorted(TEMPLATES))
@pytest.mark.parametrize(
    ("code", "headers", "shown"),
    [
        (500, {}, "HTTP 500"),
        (401, {}, "HTTP 401"),
        (302, {"Location": "http://other.example.internal/x"}, "HTTP 302"),
    ],
)
def test_test_mode_fails_on_a_non_2xx_answer_and_never_prints_the_token(
    tmp_path, notify, key, code, headers, shown
):
    n = notify(code=code, headers=headers)
    script, state = render(tmp_path, key, n.url)
    r = run_test_mode(script)
    assert r.returncode == 1
    assert "channel test failed" in r.stderr and shown in r.stderr
    assert TOKEN not in r.stdout + r.stderr + (state / TEMPLATES[key][2]).read_text()
    doc = status(state, key)
    assert doc["ok"] is False and shown in doc["error"]


@pytest.mark.parametrize("key", sorted(TEMPLATES))
def test_test_mode_fails_when_nothing_listens(tmp_path, key):
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        port = s.getsockname()[1]
    script, state = render(tmp_path, key, f"http://{LOOPBACK}:{port}")
    r = run_test_mode(script)
    assert r.returncode == 1 and "channel test failed" in r.stderr
    assert TOKEN not in r.stdout + r.stderr
    assert status(state, key)["ok"] is False


@pytest.mark.parametrize("key", sorted(TEMPLATES))
def test_test_mode_with_no_channel_has_nothing_to_test(tmp_path, notify, key):
    n = notify()
    script, state = render(tmp_path, key, n.url, mode="none")
    r = run_test_mode(script)
    assert r.returncode == 0 and "nothing to test" in r.stdout
    assert n.seen == [] and not state.exists()


@pytest.mark.parametrize("key", sorted(TEMPLATES))
def test_every_real_send_records_its_outcome_and_a_later_success_clears_it(tmp_path, notify, key):
    n = notify(code=503)
    script, state = render(tmp_path, key, n.url)
    spec = importlib.util.spec_from_file_location(f"alert_{key}", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    with pytest.raises(Exception, match="503"):
        mod.send("t", "b")
    assert status(state, key)["ok"] is False
    n.code = 200
    mod.send("t", "b")
    assert status(state, key) | {"time": ""} == {"time": "", "ok": True, "error": ""}
    assert "[token]" in mod.describe(ValueError(f"bad {TOKEN} here")) and TOKEN not in mod.describe(
        ValueError(TOKEN)
    )


# ---------------------------------------------------------------- the roles: deploy and health
def registry(tmp_path, url):
    from urllib.parse import urlsplit

    u = urlsplit(url)
    reg = tmp_path / "registry.yml"
    reg.write_text(
        f"services:\n  notify:\n    host: {u.hostname}\n    port: {u.port}\n    scheme: {u.scheme}\n"
    )
    return str(reg)


def needrestart_vars(tmp_path, url, **kw):
    sysd = tmp_path / "systemctl"
    sysd.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(0)\n")
    sysd.chmod(0o755)
    perl = tmp_path / "perl"
    perl.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(0)\n")
    perl.chmod(0o755)
    (tmp_path / "units").mkdir(exist_ok=True)
    import grp

    return {
        "needrestart_notify": "notify",
        "hnx_registry_file": registry(tmp_path, url),
        "needrestart_systemctl_cli": str(sysd),
        "needrestart_perl_cli": str(perl),
        "needrestart_cli": "/bin/true",
        "needrestart_dropin": str(tmp_path / "50-homelabnext.conf"),
        "needrestart_aliases_file": str(tmp_path / "aliases"),
        "needrestart_unit_dir": str(tmp_path / "units"),
        "needrestart_state_dir": str(tmp_path / "state"),
        "needrestart_script": str(tmp_path / "bin" / "needrestart-check"),
        "needrestart_reboot_script": str(tmp_path / "bin" / "needrestart-reboot-check"),
        "needrestart_last_run_dir": str(tmp_path / "last-run"),
        "needrestart_last_run_group": grp.getgrgid(os.getgid()).gr_name,
        "needrestart_last_run_writer": str(tmp_path / "bin" / "hnx-last-run"),
        **kw,
    }


def test_needrestart_tests_the_channel_at_deploy_only_when_it_changed(tmp_path, notify):
    n = notify()
    v = needrestart_vars(tmp_path, n.url)
    r = run_role(tmp_path, "needrestart", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert [b for *_, b in n.seen] == [f"needrestart channel test from {os.uname().nodename}"]
    assert run_role(tmp_path, "needrestart", "config", v).returncode == 0
    assert len(n.seen) == 1, "an unchanged channel was tested again"
    r = run_role(
        tmp_path, "needrestart", "config", {**v, "needrestart_notify_topic": "other-topic"}
    )
    assert r.returncode == 0 and [p for _, p, *_ in n.seen] == [
        "/homelabnext-restarts",
        "/other-topic",
    ]
    off = {
        **v,
        "needrestart_notify_topic": "third-topic",
        "needrestart_notify_test_on_change": False,
    }
    assert run_role(tmp_path, "needrestart", "config", off).returncode == 0
    assert len(n.seen) == 2, "the opt-out still tested"


def test_needrestart_deploy_skips_the_test_in_check_mode(tmp_path, notify):
    n = notify()
    v = needrestart_vars(tmp_path, n.url)
    r = run_role(tmp_path, "needrestart", "config", v, check=True)
    assert n.seen == [], r.stdout


def test_needrestart_deploy_fails_with_the_scripts_error_until_the_channel_delivers(
    tmp_path, notify
):
    n = notify(code=500)
    v = needrestart_vars(tmp_path, n.url)
    r = run_role(tmp_path, "needrestart", "config", v)
    assert (
        r.returncode != 0
        and "did not deliver its test message" in r.stdout
        and "HTTP 500" in r.stdout
    )
    again = run_role(tmp_path, "needrestart", "config", v)
    assert again.returncode != 0, "a failed test was remembered as passed"
    n.code = 200
    assert run_role(tmp_path, "needrestart", "config", v).returncode == 0
    assert len(n.seen) == 3


def test_needrestart_tests_the_pending_reboot_check_on_its_own_when_it_is_installed(
    tmp_path, notify
):
    n = notify()
    v = needrestart_vars(tmp_path, n.url, needrestart_alert_reboot=True)
    r = run_role(tmp_path, "needrestart", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(n.seen) == 2  # the check and the pending-reboot check, each through its own script
    assert (tmp_path / "state" / "reboot-channel-test.sha256").exists()
    assert run_role(tmp_path, "needrestart", "config", v).returncode == 0
    assert len(n.seen) == 2


def test_needrestart_health_fails_when_the_last_send_failed(tmp_path, notify):
    n = notify()
    v = needrestart_vars(tmp_path, n.url, needrestart_alert_reboot=True)
    state = tmp_path / "state"
    state.mkdir()
    (state / "state.json").write_text("{}")
    (state / "reboot-state.json").write_text("{}")
    assert (
        run_role(tmp_path, "needrestart", "health", v).returncode == 0
    )  # never sent: nothing owed
    (state / "send-status.json").write_text(json.dumps({"ok": True, "error": "", "time": "t"}))
    assert run_role(tmp_path, "needrestart", "health", v).returncode == 0
    (state / "send-status.json").write_text(
        json.dumps({"ok": False, "error": "HTTP 500 from the notify endpoint", "time": "t"})
    )
    r = run_role(tmp_path, "needrestart", "health", v)
    assert r.returncode != 0 and "HTTP 500 from the notify endpoint" in r.stdout
    (state / "send-status.json").write_text(json.dumps({"ok": True, "error": "", "time": "t"}))
    (state / "reboot-send-status.json").write_text(
        json.dumps({"ok": False, "error": "refused", "time": "t"})
    )
    r = run_role(tmp_path, "needrestart", "health", v)
    assert r.returncode != 0 and "pending-reboot alert could not be sent" in r.stdout


def lynis_vars(tmp_path, url, **kw):
    import grp

    sysd = tmp_path / "systemctl"
    sysd.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(0)\n")
    sysd.chmod(0o755)
    (tmp_path / "units").mkdir(exist_ok=True)
    return {
        "lynis_min_hardening_index": 60,
        "lynis_dpkg_verify": True,
        "lynis_notify": "notify",
        "hnx_registry_file": registry(tmp_path, url),
        "lynis_unit_dir": str(tmp_path / "units"),
        "lynis_script": str(tmp_path / "bin" / "scan"),
        "lynis_verify_script": str(tmp_path / "bin" / "dpkg-verify"),
        "lynis_state_dir": str(tmp_path / "state"),
        "lynis_systemctl_cli": str(sysd),
        "lynis_last_run_dir": str(tmp_path / "last-run"),
        "lynis_last_run_group": grp.getgrgid(os.getgid()).gr_name,
        "lynis_last_run_writer": str(tmp_path / "bin" / "hnx-last-run"),
        **kw,
    }


def test_lynis_tests_the_channel_at_deploy_only_when_it_changed(tmp_path, notify):
    n = notify()
    v = lynis_vars(tmp_path, n.url)
    r = run_role(tmp_path, "lynis", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert [b for *_, b in n.seen] == [f"lynis channel test from {os.uname().nodename}"]
    assert run_role(tmp_path, "lynis", "config", v).returncode == 0 and len(n.seen) == 1
    assert (
        run_role(tmp_path, "lynis", "config", {**v, "lynis_notify_topic": "other"}).returncode == 0
    )
    assert [p for _, p, *_ in n.seen] == ["/homelabnext-integrity", "/other"]
    off = {**v, "lynis_notify_topic": "third", "lynis_notify_test_on_change": False}
    assert run_role(tmp_path, "lynis", "config", off).returncode == 0 and len(n.seen) == 2
    assert n.seen and run_role(tmp_path, "lynis", "config", v, check=True).returncode == 0
    assert len(n.seen) == 2


def test_lynis_deploy_fails_with_the_scripts_error(tmp_path, notify):
    n = notify(code=403)
    r = run_role(tmp_path, "lynis", "config", lynis_vars(tmp_path, n.url))
    assert (
        r.returncode != 0
        and "did not deliver its test message" in r.stdout
        and "HTTP 403" in r.stdout
    )


def test_lynis_health_fails_when_the_last_send_failed(tmp_path, notify):
    n = notify()
    v = lynis_vars(tmp_path, n.url)
    state = tmp_path / "state"
    state.mkdir()
    (state / "last-run").write_text("0\n")
    (state / "report.dat").write_text("hardening_index=90\n")
    (state / "dpkg-verify.json").write_text(
        json.dumps({"findings": [], "accepted": [], "conffiles_skipped": 0})
    )
    assert run_role(tmp_path, "lynis", "health", v).returncode == 0, "baseline health must pass"
    (state / "send-status.json").write_text(
        json.dumps({"ok": False, "error": "HTTP 500 from the notify endpoint", "time": "t"})
    )
    r = run_role(tmp_path, "lynis", "health", v)
    assert r.returncode != 0 and "the last alert could not be sent" in r.stdout
    (state / "send-status.json").write_text(json.dumps({"ok": True, "error": "", "time": "t"}))
    assert run_role(tmp_path, "lynis", "health", v).returncode == 0
