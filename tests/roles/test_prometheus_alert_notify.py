# SPDX-License-Identifier: Apache-2.0
"""The alert forwarder of the metrics provider (modules/prometheus/roles/prometheus/templates/
alert-notify.py.j2), rendered with test values (plain Jinja2) and run as a subprocess against
loopback stand-ins for the metrics service and the notify service.

* It posts when the SET of firing alerts changes, never for the same set twice, names new and
  resolved alerts, says "cleared" once, ignores pending alerts, and posts a critical alert at
  priority 4.
* A post that fails stays owed (state not advanced) and is retried; a redirect is not followed;
  the token is sent as a Bearer token, only to the configured URL, and is never in any output or
  state file.
* A metrics service that cannot be asked is alerted once after the configured number of runs, not
  every run, and its recovery once.
* ``--test`` sends one low-priority message through the real path; the last send's outcome is
  recorded for the role's health hook.
"""

from __future__ import annotations

import http.server
import json
import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "modules/prometheus/roles/prometheus/templates/alert-notify.py.j2"
LOOPBACK = socket.gethostbyname("localhost")  # the loopback address, by name
TOKEN = "tk_fakefakefakefakefakefakefake0"


class _Quick(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Fake:
    """A loopback server: ``alerts`` (what /api/v1/alerts answers; None: a 503) and ``post``
    (the status of a POST, with optional headers); records every request."""

    def __init__(self, alerts=None, post=200, post_headers=None):
        self.alerts, self.post, self.post_headers = alerts, post, post_headers or {}
        self.seen = []
        me = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                me.seen.append(("GET", self.path, dict(self.headers), ""))
                if me.alerts is None:
                    self.send_response(503)
                    self.end_headers()
                    return
                body = json.dumps({"status": "success", "data": {"alerts": me.alerts}}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                me.seen.append(("POST", self.path, dict(self.headers), self.rfile.read(n).decode()))
                self.send_response(me.post)
                for k, v in me.post_headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = _Quick((LOOPBACK, 0), H)
        threading.Thread(
            target=self.srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()

    @property
    def url(self):
        return f"http://{LOOPBACK}:{self.srv.server_port}"

    @property
    def posts(self):
        return [s for s in self.seen if s[0] == "POST"]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def alert(name, instance="a", severity="warning", state="firing", summary=None):
    return {
        "labels": {"alertname": name, "instance": instance, "severity": severity},
        "annotations": {"summary": summary or f"{name} on {instance}"},
        "state": state,
    }


@pytest.fixture
def env(tmp_path):
    made = []

    def build(metrics, notify, **over):
        token = tmp_path / "token"
        token.write_text(TOKEN + "\n")
        port = metrics.srv.server_port
        values = {
            "prometheus_state_dir": str(tmp_path / "state"),
            "prometheus_bind": LOOPBACK,
            "prometheus_port": port,
            "prometheus_notify_url": notify.url,
            "prometheus_notify_topic": "alerts",
            "prometheus_notify_priority": 3,
            "prometheus_notify_auth_file": str(token),
            "prometheus_logical_id": "metrics",
            "prometheus_unreachable_after_minutes": 3,
            "prometheus_alert_interval_seconds": 60,
            "prometheus_heartbeat_topic": "",
            "prometheus_heartbeat_every_minutes": 5,
        }
        values.update(over)
        e = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
        e.filters["to_json"] = json.dumps
        script = tmp_path / "forwarder.py"
        script.write_text(e.from_string(TEMPLATE.read_text()).render(**values))
        made.append(script)
        return script

    return build


def run(script, *args):
    return subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True)


def state(tmp_path):
    return json.loads((tmp_path / "state" / "alert-state.json").read_text())


@pytest.fixture
def servers():
    made = []

    def make(**kw):
        f = Fake(**kw)
        made.append(f)
        return f

    yield make
    for f in made:
        f.close()


def test_a_firing_alert_is_posted_once_with_the_bearer_token(tmp_path, env, servers):
    metrics, notify = servers(alerts=[alert("DiskAlmostFull")]), servers()
    script = env(metrics, notify)
    r = run(script)
    assert r.returncode == 0, r.stderr
    ((_method, path, headers, body),) = notify.posts
    assert path == "/alerts" and headers["Authorization"] == "Bearer " + TOKEN
    assert headers["Title"] == "1 alert(s) firing on metrics: DiskAlmostFull"
    assert headers["Priority"] == "3" and "FIRING DiskAlmostFull on a" in body
    # the same set: nothing more is posted
    assert run(script).returncode == 0 and len(notify.posts) == 1


def test_a_critical_alert_is_posted_at_priority_four(tmp_path, env, servers):
    metrics = servers(alerts=[alert("TargetDown", severity="critical")])
    notify = servers()
    assert run(env(metrics, notify)).returncode == 0
    assert notify.posts[0][2]["Priority"] == "4"


def test_a_pending_alert_is_not_posted(tmp_path, env, servers):
    metrics, notify = servers(alerts=[alert("TargetDown", state="pending")]), servers()
    assert run(env(metrics, notify)).returncode == 0
    assert notify.posts == []


def test_a_change_names_new_and_resolved_alerts_and_an_empty_set_says_cleared_once(
    tmp_path, env, servers
):
    metrics, notify = servers(alerts=[alert("DiskAlmostFull")]), servers()
    script = env(metrics, notify)
    assert run(script).returncode == 0
    metrics.alerts = [alert("MemoryPressure", instance="b")]
    assert run(script).returncode == 0
    body = notify.posts[1][3]
    assert "FIRING MemoryPressure on b" in body and "RESOLVED DiskAlmostFull on a" in body
    metrics.alerts = []
    assert run(script).returncode == 0
    assert notify.posts[2][2]["Title"] == "alerts cleared on metrics"
    assert run(script).returncode == 0 and len(notify.posts) == 3  # empty and empty: silent


def test_a_failed_post_stays_owed_and_is_retried(tmp_path, env, servers):
    metrics, notify = servers(alerts=[alert("DiskAlmostFull")]), servers(post=503)
    script = env(metrics, notify)
    r = run(script)
    assert r.returncode == 2 and "alert not sent: HTTP 503" in r.stderr
    assert state(tmp_path)["alerted"] == {}  # not advanced
    notify.post = 200
    assert run(script).returncode == 0
    assert len(notify.posts) == 2 and state(tmp_path)["alerted"]


def test_a_redirect_is_not_followed_and_is_a_failed_post(tmp_path, env, servers):
    elsewhere = servers()
    metrics = servers(alerts=[alert("DiskAlmostFull")])
    notify = servers(post=302, post_headers={"Location": elsewhere.url + "/stolen"})
    r = run(env(metrics, notify))
    assert r.returncode == 2
    assert elsewhere.seen == []  # the token never went anywhere else


def test_the_token_is_in_no_output_and_no_state_file(tmp_path, env, servers):
    metrics, notify = servers(alerts=[alert("DiskAlmostFull")]), servers(post=401)
    r = run(env(metrics, notify))
    assert r.returncode == 2
    blob = (
        r.stdout
        + r.stderr
        + "".join(p.read_text() for p in (tmp_path / "state").iterdir() if p.is_file())
    )
    assert TOKEN not in blob
    status = json.loads((tmp_path / "state" / "send-status.json").read_text())
    assert status["ok"] is False and "HTTP 401" in status["error"]


def test_an_unreadable_token_is_a_failed_post_not_a_crash(tmp_path, env, servers):
    metrics, notify = servers(alerts=[alert("DiskAlmostFull")]), servers()
    script = env(metrics, notify, prometheus_notify_auth_file=str(tmp_path / "missing"))
    r = run(script)
    assert r.returncode == 2 and notify.posts == []


def test_the_unreachable_metrics_service_is_alerted_once_and_its_recovery_once(
    tmp_path, env, servers
):
    metrics, notify = servers(alerts=None), servers()
    script = env(metrics, notify)  # 3 minutes at 60 s: three misses
    for expect_posts in (0, 0, 1, 1):
        r = run(script)
        assert r.returncode == 1
        assert len(notify.posts) == expect_posts
    assert notify.posts[0][2]["Title"] == "metrics service unreachable on metrics"
    assert notify.posts[0][2]["Priority"] == "4"
    metrics.alerts = []
    assert run(script).returncode == 0
    assert len(notify.posts) == 2 and "answers again" in notify.posts[1][3]
    assert run(script).returncode == 0 and len(notify.posts) == 2
    assert state(tmp_path)["misses"] == 0


def test_a_blip_shorter_than_the_threshold_posts_nothing(tmp_path, env, servers):
    metrics, notify = servers(alerts=None), servers()
    script = env(metrics, notify)
    assert run(script).returncode == 1
    metrics.alerts = []
    assert run(script).returncode == 0
    assert notify.posts == [] and state(tmp_path)["misses"] == 0


def test_test_mode_sends_one_low_priority_message_and_records_the_outcome(tmp_path, env, servers):
    metrics, notify = servers(alerts=[]), servers()
    script = env(metrics, notify)
    r = run(script, "--test")
    assert r.returncode == 0 and "channel test ok" in r.stdout
    ((_m, _p, h, body),) = notify.posts
    assert h["Priority"] == "1" and "channel test from metrics" in body
    assert json.loads((tmp_path / "state" / "send-status.json").read_text())["ok"] is True
    notify.post = 500
    r = run(script, "--test")
    assert r.returncode == 1 and "HTTP 500" in r.stderr and TOKEN not in r.stderr


def test_hostile_label_text_cannot_inject_into_a_header(tmp_path, env, servers):
    evil = alert("DiskAlmostFull", summary="x\r\nX-Injected: 1\r\n\r\nbody")
    metrics, notify = servers(alerts=[evil]), servers()
    assert run(env(metrics, notify)).returncode == 0
    h = notify.posts[0][2]
    assert "X-Injected" not in h and "\r" not in h["Title"] and "\n" not in h["Title"]


@pytest.mark.static
def test_the_units_run_the_script_report_their_runs_and_tick_on_the_schedule():
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    values = {
        "prometheus_alert_schedule": "*-*-* *:*:00 UTC",
        "prometheus_state_dir": "/var/lib/homelabnext/prometheus",
        "prometheus_alert_interval_seconds": 60,
        "prometheus_last_run_dir": "/var/lib/homelabnext/last-run",
        "prometheus_last_run_group": "root",
    }
    units = TEMPLATE.parent
    service = env.from_string((units / "alerts.service.j2").read_text()).render(**values)
    timer = env.from_string((units / "alerts.timer.j2").read_text()).render(**values)
    assert "ExecStart=/usr/local/libexec/homelabnext/prometheus-alert-notify\n" in service
    assert "--job timer:prometheus/alerts" in service
    assert service.count("hnx-last-run start") == 1 and service.count("hnx-last-run finish") == 1
    rw = next(l for l in service.splitlines() if l.startswith("ReadWritePaths="))
    assert "/var/lib/homelabnext/last-run" in rw and "/var/lib/homelabnext/prometheus" in rw
    assert "OnCalendar=*-*-* *:*:00 UTC\n" in timer and "Persistent=false" in timer


# ----------------------------------------------------------------------------- the dead-man heartbeat


def watchdog():
    return alert("Watchdog", instance="", severity="none")


def beats(notify):
    return [p for p in notify.posts if p[1] == "/beat"]


def test_the_watchdog_is_never_posted_as_an_alert(tmp_path, env, servers):
    metrics, notify = servers(alerts=[watchdog()]), servers()
    assert run(env(metrics, notify)).returncode == 0
    assert notify.posts == []  # the always-firing rule is the proof of life, not an alert


def test_a_heartbeat_is_posted_at_minimum_priority_when_the_watchdog_fires(tmp_path, env, servers):
    metrics, notify = servers(alerts=[watchdog()]), servers()
    r = run(env(metrics, notify, prometheus_heartbeat_topic="beat"))
    assert r.returncode == 0, r.stderr
    ((_m, path, headers, _body),) = notify.posts
    assert path == "/beat" and headers["Priority"] == "1"
    assert headers["Authorization"] == "Bearer " + TOKEN


def test_the_heartbeat_is_paced_not_sent_every_run(tmp_path, env, servers):
    metrics, notify = servers(alerts=[watchdog()]), servers()
    script = env(metrics, notify, prometheus_heartbeat_topic="beat")
    assert run(script).returncode == 0 and run(script).returncode == 0
    assert len(beats(notify)) == 1
    stamp = tmp_path / "state" / "heartbeat.json"
    stamp.write_text(json.dumps({"sent": 0}))  # long ago
    assert run(script).returncode == 0 and len(beats(notify)) == 2


def test_no_heartbeat_without_the_watchdog_or_when_the_metrics_service_is_down(
    tmp_path, env, servers
):
    # rules not loaded: the service answers but the Watchdog is absent -> silence (the watcher pages)
    metrics, notify = servers(alerts=[alert("DiskAlmostFull")]), servers()
    script = env(metrics, notify, prometheus_heartbeat_topic="beat")
    assert run(script).returncode == 0
    assert beats(notify) == []
    metrics.alerts = None  # the service itself is down
    assert run(script).returncode == 1
    assert beats(notify) == []


def test_heartbeat_off_when_the_topic_is_empty(tmp_path, env, servers):
    metrics, notify = servers(alerts=[watchdog()]), servers()
    assert run(env(metrics, notify)).returncode == 0
    assert notify.posts == []


def test_a_failed_heartbeat_is_owed_and_exits_2_without_losing_the_alert_state(
    tmp_path, env, servers
):
    metrics, notify = servers(alerts=[watchdog()]), servers(post=503)
    script = env(metrics, notify, prometheus_heartbeat_topic="beat")
    r = run(script)
    assert r.returncode == 2 and "heartbeat not sent" in r.stderr
    assert TOKEN not in r.stdout + r.stderr
    assert not (tmp_path / "state" / "heartbeat.json").exists()  # owed: tried again next run
    notify.post = 200
    assert run(script).returncode == 0 and (tmp_path / "state" / "heartbeat.json").exists()
