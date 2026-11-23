# SPDX-License-Identifier: Apache-2.0
"""Native detection rules (homelabnext.detections.native): the lint, the ratchet and the engine run."""

from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path

import pytest
import yaml

from homelabnext.detections import cli, native

RULE = """<group name="hnx,">
  <rule id="{n}" level="10"><if_sid>5716</if_sid><description>d</description></rule>
</group>
"""


def tree(tmp: Path, **over) -> Path:
    (tmp / "native" / "rules").mkdir(parents=True)
    (tmp / "native" / "rules" / "ssh-off.xml").write_text(RULE.format(n=900200))
    entry = {"slug": "ssh-off", "det": "det:ssh-off", "kind": "rules", "file": "ssh-off.xml",
             "native_reason": "engine-correlation", "why": "a same-source frequency chain Sigma cannot say",
             "rule_ids": [900200]}  # fmt: skip
    entry.update(over)
    (tmp / "native" / "index.yml").write_text(yaml.dump({"schema": native.SCHEMA, "engine": "e",
                                                         "range": [900000, 919999], "rules": [entry]}))  # fmt: skip
    (tmp / "native" / "native.baseline.json").write_text(
        json.dumps({"count": 1, "stock-override": 0})
    )
    for kind, n in (("must_fire", 1), ("must_not_fire", 2)):
        d = tmp / "fixtures" / "ssh-off" / kind
        d.mkdir(parents=True)
        (d / "a.json").write_text(json.dumps({"event": f"line {n}", "rule_id": 900200}))
    return tmp


def test_a_complete_native_rule_lints_clean(tmp_path):
    assert native.lint_native(tree(tmp_path)) == []
    assert native.lint_native(tmp_path / "nothing") == []  # no native rules: nothing to say


@pytest.mark.parametrize("over,needle", [
    ({"native_reason": "because"}, "native_reason"),
    ({"native_reason": None}, "native_reason"),
    ({"why": "x"}, "why"),
    ({"det": "det:other"}, "det must be"),
    ({"rule_ids": [900201]}, "differ from the ids"),
    ({"native_reason": "stock-override"}, "names the stock rule ids"),
    ({"file": "missing.xml"}, "does not exist"),
])  # fmt: skip
def test_the_lint_refuses(tmp_path, over, needle):
    assert any(needle in p for p in native.lint_native(tree(tmp_path, **over)))


def test_a_number_outside_the_range_or_a_sigma_clash_is_refused(tmp_path):
    t = tree(tmp_path)
    (t / "native" / "rules" / "ssh-off.xml").write_text(RULE.format(n=50))
    assert any("outside" in p for p in native.lint_native(t, set()))
    assert any(
        "also another" in p for p in native.lint_native(tree(tmp_path / "b"), {"det:ssh-off"})
    )


def test_both_fixture_kinds_are_required(tmp_path):
    t = tree(tmp_path)
    for f in (t / "fixtures" / "ssh-off" / "must_not_fire").glob("*.json"):
        f.unlink()
    assert any("no must_not_fire" in p for p in native.lint_native(t))


def test_a_live_proof_replaces_the_fixtures_but_must_say_how_it_is_proven(tmp_path):
    import shutil

    t = tree(tmp_path, proof="live", live_test="touch a watched file on a test guest; the rule's alert appears in alerts.json")
    shutil.rmtree(t / "fixtures")
    assert native.lint_native(t) == []  # no fixtures, and none required
    t2 = tree(tmp_path / "b", proof="live")
    assert any("live_test" in p for p in native.lint_native(t2))
    t3 = tree(tmp_path / "c", proof="soon")
    assert any("proof must be" in p for p in native.lint_native(t3))


def test_a_regex_location_without_pcre2_is_refused(tmp_path):
    t = tree(tmp_path)
    (t / "native" / "rules" / "ssh-off.xml").write_text(
        '<group name="g"><rule id="900200" level="5"><location>/var/log/a\\.log$</location></rule></group>'
    )
    assert any("pcre2" in p for p in native.lint_native(t))
    (t / "native" / "rules" / "ssh-off.xml").write_text(
        '<group name="g"><rule id="900200" level="5"><location type="pcre2">/var/log/a\\.log$</location></rule></group>'
    )
    assert native.lint_native(t) == []


def test_the_ratchet_only_a_reviewed_change_raises(tmp_path):
    t = tree(tmp_path)
    (t / "native" / "native.baseline.json").write_text(
        json.dumps({"count": 0, "stock-override": 0})
    )
    assert any("exceed the baseline" in p for p in native.lint_native(t))
    (t / "native" / "native.baseline.json").unlink()
    assert any("baseline.json is missing" in p for p in native.lint_native(t))


def test_the_engine_run_fails_on_a_missed_must_fire_and_a_fired_must_not_fire(tmp_path):
    t = tree(tmp_path)
    ok, ran = native.run_native(t, lambda fx: 900200 if fx.kind == "must_fire" else None)
    assert ok == [] and ran == 2
    bad, _ = native.run_native(t, lambda fx: None if fx.kind == "must_fire" else 900200)
    assert len(bad) == 2 and "expected rule" in bad[0] and "must not" in bad[1]


def test_native_fixtures_are_not_orphans_to_the_sigma_lint(tmp_path):
    from homelabnext.detections import lint

    t = tree(tmp_path)
    assert not [p for p in lint.lint_rules(t) if "orphan" in p]


class _Api(http.server.BaseHTTPRequestHandler):
    seen: list = []  # noqa: RUF012

    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"jwt-token")

    def do_PUT(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.headers["Authorization"], body))
        rule = {"id": "900200"} if "hit" in body["event"] else {}
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"data": {"token": "sess", "output": {"rule": rule}}}).encode())

    def log_message(self, *a):
        return None


def test_the_manager_tester_authenticates_once_and_reuses_its_session(tmp_path):
    _Api.seen = []
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Api)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    try:
        t = ManagerLogtestFor(srv)
        fx = native.Fixture("s", "must_fire", tmp_path, "a hit", "/x", "syslog", 900200)
        assert t(fx) == 900200
        assert (
            t(native.Fixture("s", "must_not_fire", tmp_path, "nothing", "", "syslog", 900200))
            is None
        )
    finally:
        srv.shutdown()
    assert _Api.seen[0][0] == "Bearer jwt-token" and "token" not in _Api.seen[0][1]
    assert _Api.seen[1][1]["token"] == "sess"


def ManagerLogtestFor(srv):
    return native.ManagerLogtest(f"http://127.0.0.1:{srv.server_address[1]}", "u", "p" * 20, "")


def test_the_cli_lints_and_needs_its_inputs_to_run(tmp_path, capsys, monkeypatch):
    t = tree(tmp_path)
    assert cli.main(["--root", str(t), "lint", "--native"]) == 0
    assert "native lint ok" in capsys.readouterr().out
    monkeypatch.delenv("HNX_MANAGER_API_PASSWORD", raising=False)
    assert cli.main(["--root", str(t), "run", "--native"]) == 2


def test_a_stock_override_may_carry_the_stock_rules_own_number(tmp_path):
    t = tree(tmp_path, native_reason="stock-override", overrides=[1007], rule_ids=[1007])
    (t / "native" / "rules" / "ssh-off.xml").write_text(RULE.format(n=1007))
    (t / "native" / "native.baseline.json").write_text(
        json.dumps({"count": 1, "stock-override": 1})
    )
    assert native.lint_native(t) == []
    other = tree(tmp_path / "b", rule_ids=[1007])
    (other / "native" / "rules" / "ssh-off.xml").write_text(RULE.format(n=1007))
    assert any("outside" in p for p in native.lint_native(other))


class _Limited(http.server.BaseHTTPRequestHandler):
    """Answers 429 (Retry-After optional) to the first `refuse` PUTs, then 200."""

    refuse = 0
    retry_after: str | None = None
    puts = 0

    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"jwt-token")

    def do_PUT(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        type(self).puts += 1
        if type(self).puts <= type(self).refuse:
            self.send_response(429)
            if type(self).retry_after:
                self.send_header("Retry-After", type(self).retry_after)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"data": {"token": "s", "output": {"rule": {"id": "900200"}}}}).encode())

    def log_message(self, *a):
        return None


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    return srv


def _runner(srv, tmp_path, **kw):
    t = native.ManagerLogtest(f"http://127.0.0.1:{srv.server_address[1]}", "u", "p", "", **kw)
    return t, native.Fixture("s", "must_fire", tmp_path, "e", "/x", "syslog", 900200)


def test_the_runner_backs_off_and_retries_on_429_then_gives_up(tmp_path):
    naps: list[float] = []
    _Limited.refuse, _Limited.retry_after, _Limited.puts = 2, None, 0
    srv = _serve(_Limited)
    try:
        t, fx = _runner(srv, tmp_path, sleep=naps.append)
        assert t(fx) == 900200 and _Limited.puts == 3
        assert naps == [2.0, 4.0]  # exponential
        _Limited.refuse, _Limited.retry_after, _Limited.puts = 1, "7", 0
        naps.clear()
        assert t(fx) == 900200 and naps == [7.0]  # Retry-After wins
        _Limited.refuse, _Limited.puts = 99, 0
        t2, fx = _runner(srv, tmp_path, retries=2, sleep=lambda s: None)
        with pytest.raises(RuntimeError, match="429"):
            t2(fx)
        assert _Limited.puts == 3  # the first try and two retries
    finally:
        srv.shutdown()


def test_the_runner_stays_under_its_own_per_minute_budget(tmp_path):
    now = [1000.0]
    naps: list[float] = []

    def sleep(s):
        naps.append(s)
        now[0] += s

    _Limited.refuse, _Limited.puts = 0, 0
    srv = _serve(_Limited)
    try:
        t, fx = _runner(srv, tmp_path, max_per_minute=5, clock=lambda: now[0], sleep=sleep)
        for _ in range(12):  # 1 auth + 12 calls, 5 per minute: it must wait for the window, never 429
            t(fx)
    finally:
        srv.shutdown()
    assert naps and all(0 < n <= 60.01 for n in naps) and _Limited.puts == 12
