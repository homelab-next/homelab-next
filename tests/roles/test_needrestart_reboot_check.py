# SPDX-License-Identifier: Apache-2.0
"""``needrestart-reboot-check`` (role needrestart, ``alert_reboot``): a pending reboot on a host that
never reboots by itself reaches the operator once per change and once when it clears (LL-564).  The
script is rendered with test values (plain Jinja2, no playbook run) and run as a subprocess against
stub ``needrestart``, ``busctl`` and ``shutdown`` commands, a reboot-required file in a temp
directory and a loopback notify endpoint, so the state file carries from one run to the next."""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "ansible/roles/needrestart/templates/reboot-check.py.j2"
LOOPBACK = ".".join(["127", "0", "0", "1"])
TOKEN = "tk-test-not-a-secret"
BATCH = "NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.1.0-25\nNEEDRESTART-KEXP: 6.1.0-25\nNEEDRESTART-KSTA: 1\n"
NO_SHUTDOWN = '(st) "" 0\n'


class _Quick(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Notify:
    """A loopback ntfy: records (path, headers, body) of each POST; answers `code`."""

    def __init__(self):
        self.seen, self.code = [], 200
        seen, me = self.seen, self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                seen.append((self.path, dict(self.headers), self.rfile.read(n).decode()))
                self.send_response(me.code)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = _Quick((LOOPBACK, 0), H)
        self.url = f"http://{LOOPBACK}:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, args=(0.02,), daemon=True).start()

    def titles(self):
        return [h["Title"] for _, h, _ in self.seen]


class Host:
    """The stubs and files the script reads, and how to run it."""

    def __init__(self, tmp_path, url, mode="notify"):
        self.t = tmp_path
        self.reboot_file = tmp_path / "reboot-required"
        self.nr_out = tmp_path / "nr.out"
        self.nr_rc = tmp_path / "nr.rc"
        self.bus_out = tmp_path / "bus.out"
        self.bus_rc = tmp_path / "bus.rc"
        self.show_out = tmp_path / "show.out"
        self.mail = tmp_path / "mail.log"
        self.nr_out.write_text(BATCH)
        self.bus_out.write_text(NO_SHUTDOWN)
        self.show_out.write_text("")
        for name, out, rc in (("needrestart", self.nr_out, self.nr_rc),
                              ("busctl", self.bus_out, self.bus_rc),
                              ("shutdown", self.show_out, tmp_path / "show.rc")):  # fmt: skip
            self.stub(name, out, rc)
        sendmail = tmp_path / "sendmail"
        sendmail.write_text(
            f"#!{sys.executable}\nimport sys\nopen({str(self.mail)!r}, 'a').write(sys.stdin.read() + '\\0')\n"
        )
        sendmail.chmod(sendmail.stat().st_mode | stat.S_IXUSR)
        token = tmp_path / "token"
        token.write_text(TOKEN + "\n")
        env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
        env.filters["to_json"] = json.dumps
        values = {
            "needrestart_state_dir": str(tmp_path / "state"),
            "needrestart_reboot_required_file": str(self.reboot_file),
            "needrestart_cli": str(tmp_path / "needrestart"),
            "needrestart_busctl_cli": str(tmp_path / "busctl"),
            "needrestart_shutdown_cli": str(tmp_path / "shutdown"),
            "needrestart_mode": mode,
            "needrestart_notify_url": url,
            "needrestart_notify_topic": "topic",
            "needrestart_notify_priority": 4,
            "needrestart_notify_auth_file": str(token),
            "needrestart_notify_auth_ref": "secret:notify-token",
            "needrestart_sendmail_cli": str(sendmail),
            "needrestart_mail_to": "root",
        }
        self.script = tmp_path / "reboot-check.py"
        self.script.write_text(env.from_string(TEMPLATE.read_text()).render(values))

    def stub(self, name, out, rc):
        p = self.t / name
        p.write_text(
            f"#!{sys.executable}\nimport os, sys\nsys.stdout.write(open({str(out)!r}).read())\n"
            f"rc = {str(rc)!r}\nsys.exit(int(open(rc).read()) if os.path.exists(rc) else 0)\n"
        )
        p.chmod(p.stat().st_mode | stat.S_IXUSR)

    def run(self):
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        return subprocess.run(
            [sys.executable, str(self.script)], capture_output=True, text=True, env=env
        )

    def state(self):
        return json.loads((self.t / "state" / "reboot-state.json").read_text())

    def mails(self):
        return [m for m in self.mail.read_text().split("\0") if m] if self.mail.exists() else []


@pytest.fixture
def notify():
    n = Notify()
    yield n
    n.srv.shutdown()
    n.srv.server_close()


@pytest.fixture
def host(tmp_path, notify):
    return Host(tmp_path, notify.url)


def test_nothing_pending_is_silent_and_owner_only(host, notify):
    assert host.run().returncode == 0 and host.run().returncode == 0
    assert notify.seen == []
    st = host.t / "state" / "reboot-state.json"
    assert oct(st.stat().st_mode & 0o777) == "0o600"
    assert host.state()["alerted"] == []


def test_the_reboot_required_file_alerts_once_then_clears_once(host, notify):
    host.reboot_file.write_text("*** System restart required ***\n")
    (host.t / "reboot-required.pkgs").write_text("linux-image-6.1.0-26-amd64\nlinux-base\n")
    assert host.run().returncode == 0
    assert len(notify.seen) == 1
    path, hdrs, body = notify.seen[0]
    assert path == "/topic"
    assert hdrs["Title"].startswith("reboot required on ")
    assert hdrs["Title"].endswith("the reboot-required file is set")
    assert "Packages asking for it: linux-base, linux-image-6.1.0-26-amd64" in body
    assert hdrs["Authorization"] == "Bearer " + TOKEN and hdrs["Priority"] == "4"
    assert "reboot-required" in hdrs["Tags"] and "never reboot by itself" in body
    # more packages joining the list is the same state: not posted again
    (host.t / "reboot-required.pkgs").write_text("linux-image-6.1.0-26-amd64\nlinux-base\nlibc6\n")
    # more packages joining the list is the same state: not posted again
    (host.t / "reboot-required.pkgs").write_text("linux-image-6.1.0-26-amd64\nlinux-base\nlibc6\n")
    for _ in range(3):  # the same state is never posted twice
        assert host.run().returncode == 0
    assert len(notify.seen) == 1
    host.reboot_file.unlink()
    assert host.run().returncode == 0
    assert notify.titles()[-1].startswith("reboot cleared on ") and len(notify.seen) == 2
    assert host.run().returncode == 0 and len(notify.seen) == 2  # and not "cleared" twice


def test_a_pending_kernel_or_microcode_update_alerts_and_services_are_only_named(host, notify):
    host.nr_out.write_text(
        BATCH.replace("KSTA: 1", "KSTA: 3").replace("KEXP: 6.1.0-25", "KEXP: 6.1.0-26")
        + "NEEDRESTART-UCSTA: 2\nNEEDRESTART-SVC: ssh.service\n"
    )
    assert host.run().returncode == 0
    (_, hdrs, body), = notify.seen  # fmt: skip
    assert "a newer kernel waits (6.1.0-26; running 6.1.0-25)" in hdrs["Title"]
    assert "a microcode update waits" in hdrs["Title"]
    assert "ssh.service" in body and "ssh.service" not in hdrs["Title"]
    # a service alone is not a reboot (the other check alerts on it)
    host.nr_out.write_text(BATCH + "NEEDRESTART-SVC: ssh.service\n")
    assert host.run().returncode == 0
    assert notify.titles()[-1].startswith("reboot cleared")


def test_a_reboot_logind_holds_alerts_and_a_poweroff_does_not(host, notify):
    host.bus_out.write_text('(st) "reboot" 1731558600000000\n')
    assert host.run().returncode == 0
    assert "a reboot is scheduled for 2024-11-14 04:30:00 UTC" in notify.titles()[0]
    assert host.run().returncode == 0 and len(notify.seen) == 1
    host.bus_out.write_text('(st) "poweroff" 1731558600000000\n')
    assert host.run().returncode == 0
    assert notify.titles()[-1].startswith("reboot cleared")
    host.bus_out.write_text('(st) "reboot" 18446744073709551615\n')  # a time that means "unknown"
    assert host.run().returncode == 0
    assert "scheduled for an unknown time" in notify.titles()[-1]


def test_shutdown_show_answers_where_busctl_does_not(host, notify):
    host.bus_rc.write_text("1")
    host.bus_out.write_text("")
    host.show_out.write_text(
        "Reboot scheduled for Thu 2026-11-12 04:30:00 UTC, use 'shutdown -c' to cancel.\n"
    )
    assert host.run().returncode == 0
    assert "a reboot is scheduled for Thu 2026-11-12 04:30:00 UTC" in notify.titles()[0]


def test_an_unreadable_reader_is_not_a_clear(host, notify):
    host.reboot_file.write_text("")
    assert host.run().returncode == 0 and len(notify.seen) == 1
    host.nr_rc.write_text("2")  # needrestart now fails
    r = host.run()
    assert r.returncode == 1 and "needrestart -b exited 2" in r.stderr
    assert len(notify.seen) == 1  # the reboot-required file still stands: no flapping
    host.reboot_file.unlink()
    assert host.run().returncode == 1 and len(notify.seen) == 1  # cannot be called cleared
    assert host.state()["alerted"]
    host.nr_rc.unlink()
    assert host.run().returncode == 0 and notify.titles()[-1].startswith("reboot cleared")


def test_neither_logind_reader_answering_is_unread_not_clear(host, notify):
    host.bus_rc.write_text("1")
    host.show_rc = host.t / "show.rc"
    host.show_out.write_text("garbled\n")
    r = host.run()
    assert r.returncode == 1 and "could not be read" in r.stderr and notify.seen == []


def test_a_failed_post_stays_owed_and_is_not_repeated_after_it_lands(host, notify):
    host.reboot_file.write_text("")
    notify.code = 500
    assert host.run().returncode == 2 and host.state()["alerted"] == []
    assert host.run().returncode == 2 and len(notify.seen) == 2  # retried
    notify.code = 200
    assert host.run().returncode == 0 and len(notify.seen) == 3
    assert host.run().returncode == 0 and len(notify.seen) == 3


def test_a_changed_reason_alerts_again(host, notify):
    host.reboot_file.write_text("")
    assert host.run().returncode == 0
    host.bus_out.write_text('(st) "reboot" 1731558600000000\n')
    assert host.run().returncode == 0 and len(notify.seen) == 2
    assert "the reboot-required file is set" in notify.titles()[1]
    assert "a reboot is scheduled" in notify.titles()[1]


def test_mail_mode_sends_the_same_text_once(tmp_path):
    h = Host(tmp_path, "", mode="mail")
    h.reboot_file.write_text("")
    assert h.run().returncode == 0 and h.run().returncode == 0
    (mail,) = h.mails()
    assert mail.startswith("To: root\nSubject: reboot required on ")


def test_the_token_never_follows_a_redirect_or_a_proxy(tmp_path):
    other = Notify()
    first = Notify()

    # a 302 to another origin: the redirect target receives nothing, the post fails (owed)
    class R(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            first.seen.append((self.path, dict(self.headers), ""))
            self.send_response(302)
            self.send_header("Location", other.url + "/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    first.srv.shutdown()
    first.srv.server_close()
    first.srv = _Quick((LOOPBACK, 0), R)
    first.url = f"http://{LOOPBACK}:{first.srv.server_port}"
    threading.Thread(target=first.srv.serve_forever, args=(0.02,), daemon=True).start()
    h = Host(tmp_path, first.url)
    h.reboot_file.write_text("")
    r = h.run()
    assert r.returncode == 2 and other.seen == [] and len(first.seen) == 1
    assert TOKEN not in r.stderr
    # an environment proxy is not used
    proxy = Notify()
    env = {**os.environ, "http_proxy": proxy.url, "HTTP_PROXY": proxy.url}
    ok = Notify()
    h2 = Host(tmp_path / "b" if (tmp_path / "b").mkdir() is None else tmp_path, ok.url)
    h2.reboot_file.write_text("")
    r = subprocess.run([sys.executable, str(h2.script)], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and proxy.seen == [] and len(ok.seen) == 1
    for n in (other, first, proxy, ok):
        n.srv.shutdown()
        n.srv.server_close()


def test_a_token_that_is_not_printable_is_refused_without_quoting_it(host, notify):
    (host.t / "token").write_text("bad\x01token\n")
    host.reboot_file.write_text("")
    r = host.run()
    assert r.returncode == 2 and notify.seen == [] and "bad" not in r.stderr
