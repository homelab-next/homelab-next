# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.logbursts``: error lines clustered in time, bursts collapsed to shapes, and a
verdict that separates a recovered blip from a live fault (ADR-0049 decision 9; the ingest
audit's burst logic, rebuilt generic).

Fixtures are recorded-shape logs under ``fixtures/``; the clock is always passed in.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from homelabnext import logbursts as lb

HERE = Path(__file__).resolve().parent
FX = HERE / "fixtures"
ROOT = HERE.parents[1]
NOW = datetime(2026, 7, 31, 22, 0, 0, tzinfo=UTC)
BENIGN = ROOT / "modules" / "source-census" / "data" / "manager-benign.yml"
SCANNER = {"scanner_address": "scanner-host-7"}


def _assess(name: str, *, benign=(), **kw) -> lb.Assessment:
    raw = (FX / name).read_text().splitlines()
    lines, bad = lb.parse_lines(ln for ln in raw if lb.SEVERITY.search(ln))
    return lb.assess(lines, now=NOW, benign=benign, unparsed=bad, **kw)


def test_fifteen_errors_in_one_38_second_blip_are_recovered():
    a = _assess("blip_recovered.txt")
    assert a.count == 15
    assert len(a.bursts) == 1
    assert a.bursts[0].seconds == 36  # inside one 38 s window
    assert a.verdict == "RECOVERED"
    assert not a.ongoing
    # two distinct shapes (the retried connection error, the re-registration), not fifteen lines
    shapes = a.bursts[0].shapes()
    assert [s.count for s in shapes] == [9, 6]
    text = lb.render(a, now=NOW)
    assert "RECOVERED (no action)" in text
    assert "15 error line(s) in 1 burst(s)" in text
    # one real unmasked example per shape: the shape alone cannot say WHICH agent
    assert "Agent '004' re-registering" in text


def test_key_already_in_use_storm_over_is_a_reconnection_storm_that_recovered():
    a = _assess("keyinuse_storm_recovered.txt")
    assert a.count == 8 and len(a.bursts) == 1
    (shape,) = a.bursts[0].shapes()
    assert shape.count == 8
    assert shape.shape.endswith(
        "agent ID '#'"
    )  # eight agents, one shape: a storm, not eight faults
    assert a.verdict == "RECOVERED"


def test_the_same_storm_still_running_is_ongoing():
    a = _assess("keyinuse_storm_ongoing.txt")
    assert a.verdict == "ONGOING"
    assert a.age is not None and a.age <= lb.QUIET
    assert "ONGOING (needs attention)" in lb.render(a, now=NOW)


def test_a_burst_that_recurs_on_three_days_is_ongoing_not_three_recoveries():
    a = _assess("recurring_three_days.txt", window=timedelta(days=4))
    # every burst stopped long ago, yet the verdict is not RECOVERED
    assert a.age is not None and a.age > lb.QUIET
    assert a.verdict == "ONGOING"
    assert len(a.recurring) == 1 and a.recurring[0][1] == 3
    assert "Recurring" in lb.render(a, now=NOW)


def test_recurrence_needs_the_distinct_days_not_the_line_count():
    lines = [
        lb.Line(
            NOW - timedelta(hours=30 + k),
            "analysisd: ERROR: queue overflow for agent #".replace("#", str(k)),
        )
        for k in range(10)
    ]
    # ten lines, but only on two UTC days
    a = lb.assess(lines, now=NOW, window=timedelta(days=3))
    assert a.verdict == "RECOVERED"
    assert a.recurring == ()


def test_clean_when_no_line_and_not_a_pass_of_anything_else():
    a = lb.assess([], now=NOW)
    assert a.verdict == "CLEAN" and a.bursts == ()
    assert "No error lines" in lb.render(a, now=NOW)


def test_a_gap_wider_than_the_gap_starts_a_new_burst():
    t = NOW - timedelta(hours=6)
    lines = [
        lb.Line(t, "a: ERROR: x 1"),
        lb.Line(t + timedelta(minutes=9), "a: ERROR: x 2"),
        lb.Line(t + timedelta(minutes=30), "a: ERROR: x 3"),
    ]
    assert [len(b.lines) for b in lb.cluster(lines)] == [2, 1]
    assert [len(b.lines) for b in lb.cluster(lines, timedelta(minutes=40))] == [3]


def test_unreadable_timestamps_are_counted_never_dropped_silently():
    lines, bad = lb.parse_lines(
        [
            "not a timestamp ERROR",
            "2026/07/31 10:00:00 a: ERROR: x",
            "",
            "2026/13/45 99:99:99 b: ERROR",
        ]
    )
    assert len(lines) == 1 and bad == 2
    a = lb.assess(lines, now=NOW, unparsed=bad)
    assert "2 line(s) without a readable timestamp" in lb.render(a, now=NOW)


def test_iso_timestamps_and_offsets_are_read_as_utc():
    lines, bad = lb.parse_lines(
        ["2026-07-31T12:00:00Z a: ERROR: z", "2026-07-31 14:00:00+02:00 a: ERROR: z"]
    )
    assert bad == 0 and lines[0].ts == lines[1].ts == datetime(2026, 7, 31, 12, tzinfo=UTC)


def test_the_shape_masks_addresses_ids_and_numbers():
    ip = ".".join(["198", "51", "100", "23"])
    assert (
        lb.shape_of(f"connect from {ip} port 1514 id 0123456789abcdef0123")
        == "connect from <ip> port # id <hex>"
    )
    assert lb.shape_of("uuid 123e4567-e89b-12d3-a456-426614174000 done") == "uuid <uuid> done"


# ------------------------------------------------------------------ the benign list
def test_benign_scan_noise_is_dropped_and_counted():
    benign = lb.load_benign(BENIGN, SCANNER)
    a = _assess("scan_noise_only.txt", benign=benign)
    assert a.verdict == "CLEAN" and a.dropped_benign == 16


def test_benign_scoping_keeps_a_real_error_from_another_source_visible():
    benign = lb.load_benign(BENIGN, SCANNER)
    a = _assess("scan_noise_plus_real.txt", benign=benign)
    assert a.verdict == "ONGOING" and a.count == 1
    assert "other-host-9" in lb.render(a, now=NOW)


@pytest.mark.parametrize(
    "doc, why",
    [
        ({"benign": [{"match": "Too big message size", "reason": ""}]}, "carries a reason"),
        ({"benign": [{"match": "Too big message size", "reason": "   "}]}, "carries a reason"),
        ({"benign": [{"match": "Too big message size"}]}, "exactly the keys"),
        ({"benign": [{"match": "short", "reason": "why"}]}, "shorter than 8"),
        (
            {"benign": [{"match": "from {scanner_address}", "reason": "why"}]},
            "no value for scanner_address",
        ),
        ({"benign": [{"match": "Too big message size", "reason": "a"}] * 2}, "listed twice"),
        ({"benign": "nope"}, "benign:"),
        ([], "benign:"),
    ],
)
def test_a_benign_list_that_is_not_a_reviewed_list_is_refused_whole(doc, why):
    with pytest.raises(lb.BenignError, match=why):
        lb.load_benign(doc, {})


def test_an_unreadable_benign_file_is_refused(tmp_path):
    with pytest.raises(lb.BenignError, match="cannot be read"):
        lb.load_benign(tmp_path / "missing.yml")


# ------------------------------------------------------------------ the command
def _run(capsys, *args, now=NOW):
    code = lb.main(list(args), now=now)
    return code, capsys.readouterr()


def test_cli_exit_codes_follow_the_verdict(capsys):
    code, out = _run(capsys, "--log", str(FX / "blip_recovered.txt"))
    assert code == 0 and "RECOVERED (no action)" in out.out
    code, out = _run(capsys, "--log", str(FX / "keyinuse_storm_ongoing.txt"))
    assert code == 1 and "ONGOING" in out.out


def test_cli_recurrence_reads_every_log_given(capsys):
    code, out = _run(
        capsys, "--log", str(FX / "recurring_three_days.txt"), "--since-hours", "100", "--json"
    )
    assert code == 1
    assert json.loads(out.out)["recurring"][0][1] == 3


def test_cli_benign_list_with_var(capsys):
    args = [
        "--log",
        str(FX / "scan_noise_only.txt"),
        "--benign",
        str(BENIGN),
        "--var",
        "scanner_address=scanner-host-7",
    ]
    code, out = _run(capsys, *args)
    assert code == 0 and "No error lines" in out.out
    # without the variable the list is refused (exit 2), never run as if it hid nothing
    code, out = _run(capsys, "--log", str(FX / "scan_noise_only.txt"), "--benign", str(BENIGN))
    assert code == 2 and "scanner_address" in out.err


def test_cli_unreadable_log_is_could_not_measure_not_a_pass(capsys, tmp_path):
    code, _out = _run(capsys, "--log", str(tmp_path / "absent.txt"))
    assert code == 100


def test_cli_reads_gzip(capsys, tmp_path):
    import gzip

    gz = tmp_path / "old.log.gz"
    gz.write_bytes(gzip.compress((FX / "blip_recovered.txt").read_bytes()))
    code, out = _run(capsys, "--log", str(gz))
    assert code == 0 and "15 error line(s)" in out.out


def test_cli_bad_var(capsys):
    code, _out = _run(capsys, "--log", str(FX / "blip_recovered.txt"), "--var", "novalue")
    assert code == 2
