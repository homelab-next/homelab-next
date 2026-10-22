# SPDX-License-Identifier: Apache-2.0
"""``poll-nut``: the NUT protocol client and ups.status mapping against recorded upsd 2.8.1
transcripts (a fake upsd on loopback replays them), the sources generated from the site's
``power.ups``, the state-diffed "UPS on battery" notification and the Topology UPS badge."""

from __future__ import annotations

import pytest
import yaml
from fake_upsd import FakeUpsd, load_transcript, self_signed
from status_helpers import ROOT

from homelabnext.notify import FakeSender, Notifier
from homelabnext.registry.model import load
from homelabnext.status import SourceSpec, sources_from_registry
from homelabnext.status.collectors import CollectContext, CollectError
from homelabnext.status.nut import NutCollector, quote, split_words, ups_drafts
from homelabnext.status.power import PowerError, expand, power_state, states
from homelabnext.status.power import load as load_power
from homelabnext.status.scheduler import Scheduler, SourceResult

LAB = ROOT / "examples" / "lab-topology"
SECRET = "fake-nut-password"


def nut_spec(sid="ups", **mapping):
    auth = mapping.pop("auth", None)
    return SourceSpec(
        id=sid,
        kind="poll-nut",
        service="ups-monitor",
        capability="ups-monitor",
        interval_s=30,
        timeout_s=2,
        what="UPS state",
        mapping=mapping,
        auth=auth,
    )


def ctx(url, clock, root=ROOT, secret=SECRET):
    return CollectContext(
        clock=clock, endpoint=lambda svc: url, root=root, secret=lambda ref: secret
    )


def lvars(transcript, ups):
    """``LIST VAR <ups>`` of a transcript as a dict (what the collector parses)."""
    lines = load_transcript(transcript)[f"LIST VAR {ups}"]
    return {w[2]: w[3] for w in map(split_words, lines) if w and w[0] == "VAR"}


def by_item(drafts):
    return {d.item: d for d in drafts}


# ---------------------------------------------------------------- protocol words
def test_words_and_quoting_follow_parseconf():
    assert split_words('VAR ups-a ups.status "OB DISCHRG"') == [
        "VAR",
        "ups-a",
        "ups.status",
        "OB DISCHRG",
    ]
    assert split_words(r'VAR u d "say \"hi\" \\ ok"')[3] == 'say "hi" \\ ok'
    assert split_words('UPS ups-a ""') == ["UPS", "ups-a", ""]
    assert quote("hub-monitor") == "hub-monitor"
    assert split_words(quote('fake pass "x" \\ #')) == ['fake pass "x" \\ #']
    with pytest.raises(ValueError):
        quote("fake\nLOGIN ups-a")  # a password cannot smuggle a second command


# ---------------------------------------------------------------- ups.status mapping
def test_on_line_is_ok_on_battery_is_warn_replace_and_low_battery_are_fail():
    online = by_item(ups_drafts("ups-a", lvars("online", "ups-a"), {}))
    assert online["status"].state == "ok"
    assert online["status"].summary.startswith("OL CHRG: on line power, charging; 92% charge")
    assert (online["battery-charge"].state, online["battery-charge"].value) == ("ok", 92.0)
    assert online["battery-runtime"].state == "ok" and online["load"].state == "ok"

    ob = by_item(ups_drafts("ups-a", lvars("on-battery", "ups-a"), {}))
    assert ob["status"].state == "warn" and ob["status"].flags == ("OB", "DISCHRG")
    assert power_state(ob["status"].flags) == "on-battery"

    rb = by_item(ups_drafts("ups-a", lvars("replace-battery", "ups-a"), {}))
    assert rb["status"].state == "fail" and "replace battery" in rb["status"].summary
    assert power_state(rb["status"].flags) == "ok"  # on line: not an on-battery event

    lb = by_item(ups_drafts("ups-b", lvars("online", "ups-b"), {}))  # OB DISCHRG LB, 14%, 180 s
    assert lb["status"].state == "fail" and power_state(lb["status"].flags) == "low-battery"
    assert lb["battery-charge"].state == "fail"  # at or below 20 (no battery.charge.low)
    assert lb["battery-runtime"].state == "warn"  # 180 s: at or below 600, above 120


def test_unknown_flags_wait_and_no_line_flag_are_never_ok_and_states_override():
    def state(status, **mapping):
        return by_item(ups_drafts("u", {"ups.status": status}, mapping))["status"]

    assert state("CHRG").state == "unknown"  # no line flag: says nothing about power
    assert state("WAIT").state == "unknown"
    s = state("OL NEWFLAG")
    assert s.state == "ok" and "NEWFLAG (not a known flag)" in s.summary
    assert state("OL BYPASS").state == "warn"
    assert state("OL BYPASS", states={"bypass": "fail"}).state == "fail"
    assert state("").state == "unknown" and state("").summary.startswith("NONE:")
    alarm = by_item(ups_drafts("u", {"ups.status": "ALARM OL", "ups.alarm": "Fan failure"}, {}))
    assert alarm["status"].state == "warn" and "alarm: Fan failure" in alarm["status"].summary


def test_limits_use_the_ups_own_low_marks_unless_the_source_sets_them():
    var = {"ups.status": "OB", "battery.charge": "25", "battery.charge.low": "30"}
    assert by_item(ups_drafts("u", var, {}))["battery-charge"].state == "fail"  # its own low
    tuned = {"limits": {"charge": {"fail": 10, "warn": 40}}}
    assert by_item(ups_drafts("u", var, tuned))["battery-charge"].state == "warn"
    load = by_item(ups_drafts("u", {"ups.status": "OL", "ups.load": "97"}, {}))["load"]
    assert load.state == "fail" and "at or above 95%" in load.summary
    bad = by_item(ups_drafts("u", {"ups.status": "OL", "ups.load": "n/a"}, {}))["load"]
    assert bad.state == "unknown" and bad.value is None


# ---------------------------------------------------------------- the collector, against a fake upsd
def test_one_ups_over_the_wire_without_credentials(clock):
    with FakeUpsd("online") as upsd:
        drafts = NutCollector().collect(nut_spec(ups="ups-a", tls="none"), ctx(upsd.url, clock))
    assert by_item(drafts)["status"].state == "ok"
    assert [c for c, _ in upsd.received] == ["LIST VAR ups-a", "LOGOUT"]


def test_every_ups_upsd_lists_is_read_without_mapping_ups(clock):
    with FakeUpsd("online") as upsd:
        drafts = by_item(NutCollector().collect(nut_spec(tls="none"), ctx(upsd.url, clock)))
    assert drafts["ups-a:status"].state == "ok" and drafts["ups-b:status"].state == "fail"
    assert "ups-b:battery-charge" in drafts


def test_a_ups_whose_driver_is_gone_is_unknown_and_a_wrong_name_is_the_source_error(clock):
    with FakeUpsd("errors") as upsd:
        got = NutCollector().collect(nut_spec(ups="ups-a", tls="none"), ctx(upsd.url, clock))
        assert [(d.item, d.state) for d in got] == [("status", "unknown")]
        assert "DRIVER-NOT-CONNECTED" in got[0].summary
        with pytest.raises(CollectError, match="UNKNOWN-UPS"):
            NutCollector().collect(nut_spec(ups="nosuch", tls="none"), ctx(upsd.url, clock))


def test_starttls_is_the_default_and_an_upsd_without_a_certificate_is_an_error(clock):
    auth = {"secret": "secret:nut/monitor-password", "username": "hub-monitor"}
    with (
        FakeUpsd("errors") as upsd,
        pytest.raises(CollectError, match=r"does not offer STARTTLS.*tls: none"),
    ):
        NutCollector().collect(nut_spec(ups="ups-a", auth=auth), ctx(upsd.url, clock))
    assert upsd.received[0][0] == "STARTTLS"
    assert not any(c.startswith("PASSWORD") for c, _ in upsd.received)  # never sent


def test_starttls_verifies_upsd_and_the_password_only_travels_inside_tls(tmp_path, clock):
    made = self_signed(tmp_path)
    if made is None:
        pytest.skip("no openssl command to mint a test certificate")
    server, ca = made
    auth = {"secret": "secret:nut/monitor-password", "username": "hub-monitor"}
    spec = nut_spec(ups="ups-a", auth=auth, ca_file=ca.name)
    with FakeUpsd("tls", "on-battery", tls=server) as upsd:
        drafts = by_item(NutCollector().collect(spec, ctx(upsd.url, clock, root=tmp_path)))
    assert drafts["status"].state == "warn"
    sent = dict(upsd.received)
    assert sent["STARTTLS"] is False and sent[f"PASSWORD {SECRET}"] is True
    assert sent["USERNAME hub-monitor"] is True and sent["LIST VAR ups-a"] is True
    with (
        FakeUpsd("tls", "on-battery", tls=server) as upsd,  # not the CA it was signed by
        pytest.raises(CollectError, match="TLS"),
    ):
        NutCollector().collect(nut_spec(ups="ups-a", auth=auth), ctx(upsd.url, clock))


def test_plaintext_credentials_are_refused_off_loopback_unless_allowed(clock):
    auth = {"secret": "secret:nut/monitor-password", "username": "hub-monitor"}
    far = "tcp://ups-monitor.svc.example.internal:3493"  # no-raw-endpoint: allow resolver output
    with pytest.raises(CollectError, match="refusing to send the NUT password in plaintext"):
        NutCollector().collect(nut_spec(ups="ups-a", tls="none", auth=auth), ctx(far, clock))
    with FakeUpsd("online", "tls") as upsd:  # loopback: allowed, as for the HTTP kinds
        spec = nut_spec(ups="ups-a", tls="none", auth=auth)
        assert NutCollector().collect(spec, ctx(upsd.url, clock))
    assert ("PASSWORD fake-nut-password", False) in upsd.received
    with pytest.raises(CollectError, match="did not resolve"):
        NutCollector().collect(nut_spec(ups="ups-a", auth=auth), ctx(far, clock, secret=None))


def test_a_hung_upsd_is_bounded_by_the_source_timeout(clock):
    with FakeUpsd("online", stall=True) as upsd:
        spec = nut_spec(ups="ups-a", tls="none")
        [res] = Scheduler().run([spec], ctx(upsd.url, clock))
    assert not res.ok and res.error


# ---------------------------------------------------------------- generated from the site
def _lab_specs():
    return sources_from_registry(load(LAB / "services.yml"))


def test_each_site_ups_monitored_by_nut_becomes_a_source_with_what_it_feeds():
    specs = load_power(_lab_specs(), LAB / "site.yml", LAB / "guests")
    nut = [s for s in specs if s.kind == "poll-nut"]
    assert [s.id for s in nut] == ["power-ups-a"]  # ups-b is monitored by snmp
    s = nut[0]
    assert s.mapping["ups"] == "ups-a" and s.auth["username"] == "hub-monitor"
    assert s.power["devices"] == ["edge:cable-modem", "router:harbor-gw", "switch:core-sw"]
    assert "hv-1" in s.power["guests"] and "siem-1" in s.power["guests"]  # VMs inherit hv-1's
    assert "nas-1" not in s.power["guests"]  # nas-1 is on ups-b
    assert s.describe()["ups"] == "ups-a"


def test_without_a_site_the_template_reads_every_ups_and_with_one_named_it_is_kept():
    specs = _lab_specs()
    assert [s.id for s in specs if s.kind == "poll-nut"] == ["power"]
    site = yaml.safe_load((LAB / "site.yml").read_text())
    named = [*specs, nut_spec("ups-a-direct", ups="ups-a")]
    out = {s.id: s for s in expand(named, site)}
    assert "power-ups-a" not in out and out["ups-a-direct"].power["ups"] == "ups-a"
    assert "power" in out  # nothing left to expand: still a source over every UPS


def test_two_templates_or_a_clashing_id_are_refused():
    site = yaml.safe_load((LAB / "site.yml").read_text())
    with pytest.raises(PowerError, match="all read every UPS"):
        expand([*_lab_specs(), nut_spec("other")], site)
    with pytest.raises(PowerError, match="already registered"):
        expand([*_lab_specs(), nut_spec("power-ups-a", ups="elsewhere")], site)


# ---------------------------------------------------------------- the on-battery event
def _result(spec, transcript):
    return SourceResult(spec.id, ups_drafts("ups-a", lvars(transcript, "ups-a"), spec.mapping))


def test_on_battery_pages_once_with_the_guests_on_that_ups_and_recovers_once(make_hub, clock):
    [spec] = [
        s
        for s in load_power(_lab_specs(), LAB / "site.yml", LAB / "guests")
        if s.kind == "poll-nut"
    ]
    hub = make_hub([spec])
    sender = FakeSender()
    notifier = Notifier(sender, hub.store, clock=clock)
    hub.record(_result(spec, "online"))
    assert hub.notify(notifier) == []
    hub.record(_result(spec, "on-battery"))
    assert hub.notify(notifier) == ["status-power/power-ups-a/ups-a"]  # warn alone does not page
    msg = sender.sent[-1]
    assert msg.title == "UPS on battery" and msg.level == "warn"
    assert "router:harbor-gw" in msg.body and "siem-1" in msg.body and "nas-1" not in msg.body
    hub.record(_result(spec, "on-battery"))
    assert hub.notify(notifier) == []  # state-diffed: still on battery is not a second page
    clock.advance(200)  # upsd unreachable mid-outage: stale is held, not a recovery
    assert "status-power/power-ups-a/ups-a" not in hub.notify(notifier)
    hub.record(_result(spec, "online"))
    assert "status-power/power-ups-a/ups-a" in hub.notify(notifier)
    assert sender.titles.count("UPS back on line power") == 1


def test_low_battery_escalates_the_same_key(make_hub, clock):
    spec = nut_spec(ups="ups-b", tls="none")
    hub = make_hub([spec])
    sender = FakeSender()
    notifier = Notifier(sender, hub.store, clock=clock)
    hub.record(SourceResult(spec.id, ups_drafts("ups-b", lvars("online", "ups-b"), {})))
    assert "status-power/ups/ups-b" in hub.notify(notifier)  # beside the fail items' pages
    [msg] = [m for m in sender.sent if m.title == "UPS on battery"]
    assert msg.level == "crit" and "not known (no site model" in msg.body


# ---------------------------------------------------------------- the Topology badge
def test_the_topology_ups_card_shows_its_live_state():
    from homelabnext.status.maps import topology

    doc = {
        "sources": [{"id": "power-ups-a", "ups": "ups-a"}],
        "observations": [
            {
                "source": "power-ups-a",
                "item": "status",
                "state": "warn",
                "summary": "OB DISCHRG: on battery, discharging; 87% charge",
                "flags": ["OB", "DISCHRG"],
                "observed_at": "2026-09-21T13:33:20Z",
            }
        ],
    }
    vm = topology.load(LAB / "guests", LAB / "site.yml", ups_state=states(doc))
    [card] = [c for row in vm["top"] for c in row if c["node"] == "ups:ups-a"]
    assert {"cls": "ups-warn", "text": "on battery"} in card["badges"]
    assert vm["details"]["ups:ups-a"]["power"][0].startswith("live (warn at 2026-09-21")
    plain = topology.load(LAB / "guests", LAB / "site.yml")
    [card] = [c for row in plain["top"] for c in row if c["node"] == "ups:ups-a"]
    assert not any(b["cls"].startswith("ups-") for b in card["badges"])  # no reading, no badge


def test_no_reading_is_held_never_a_recovery(make_hub, clock):
    """A summary that only looks like flags (an uppercase upsname, ``NONE``, ``WAIT``) is no
    reading: it must neither page nor send "back on line power" mid-outage."""
    from homelabnext.status.nut import unreadable

    spec = nut_spec(ups="UPSA", tls="none")
    hub = make_hub([spec])
    sender = FakeSender()
    notifier = Notifier(sender, hub.store, clock=clock)
    key = "status-power/ups/UPSA"

    def reading(*drafts):
        hub.record(SourceResult(spec.id, drafts))
        return [k for k in hub.notify(notifier) if k.startswith("status-power/")]

    assert reading(*ups_drafts("UPSA", {"ups.status": "OB DISCHRG"}, {})) == [key]
    assert reading(unreadable("UPSA", "DATA-STALE")) == []  # the USB driver dropped
    assert reading(unreadable("UPSA", "DRIVER-NOT-CONNECTED")) == []
    assert reading(*ups_drafts("UPSA", {}, {})) == []  # NONE: no ups.status
    assert reading(*ups_drafts("UPSA", {"ups.status": "WAIT"}, {})) == []
    assert reading(*ups_drafts("UPSA", {"ups.status": "CHRG"}, {})) == []  # no line flag
    assert sender.titles.count("UPS back on line power") == 0
    assert reading(*ups_drafts("UPSA", {"ups.status": "OL CHRG"}, {})) == [key]
    assert sender.titles.count("UPS back on line power") == 1
    assert sender.titles.count("UPS on battery") == 1


def test_power_state_needs_a_line_or_battery_flag():
    from homelabnext.status.nut import unreadable

    assert unreadable("UPS1", "DATA-STALE").flags is None  # no reading, whatever its name
    assert power_state(None) is None and power_state(()) is None
    assert power_state(["WAIT"]) is None and power_state(["CHRG", "OFF"]) is None
    assert power_state(["OL"]) == "ok" and power_state(["BYPASS"]) == "ok"
    assert power_state(["OB", "LB"]) == "low-battery"
