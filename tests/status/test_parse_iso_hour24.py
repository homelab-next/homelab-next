# SPDX-License-Identifier: Apache-2.0
"""parse_iso gives the same verdict on every Python (3.11-3.14).  3.14's fromisoformat reads hour 24
in every spelling its grammar has and rolls it over to the next day, where 3.11-3.13 refuse it, so
a record's verdict depended on the interpreter.  parse_iso reads an RFC 3339 date-time (or a bare
date) and refuses everything else before fromisoformat sees it, including the forms wider than
RFC 3339 that every Python's fromisoformat reads.  CI runs this on 3.11 and 3.12; run it on 3.14
too."""

import pytest

from homelabnext.status.model import parse_iso

REFUSED = [
    # hour 24, in every spelling some Python's fromisoformat reads
    "2026-01-01T24:00:00Z",
    "2026-01-01T24:00:00+00:00",
    "2026-01-01 24:00:00",
    "2026-01-01t24:00:00",
    "2026-01-01T24",
    "2026-01-01T2400",
    "2026-01-01T24Z",
    "20260101T240000Z",
    "20260101T2400Z",
    "2026-01-01_24:00:00",
    "2026-01-01x24:00:00",
    # wider than RFC 3339 (most of them read by every Python's fromisoformat): parse_iso does not
    "2026-01-01_12:00:00",
    "2026-01-01x12:00:00",
    "2026-01-01T12",
    "2026-01-01T1200",
    "20260101T120000Z",
    "20260101",
    "2026-01-01T12:00:00,5Z",
    "2026-01-01T12:00:00+0000",
    "2026-01-01T12:00:00+00:00:00",
    "2026-01-01T12:00:60Z",
    "2026-01-01T12:00:00Z\n",
    " 2026-01-01T12:00:00Z",
    "2026-01-01T12:00:00+24:00",  # an offset of a day: out of range on every Python
    "\uff12\uff10\uff12\uff16-01-01T12:00:00Z",  # non-ASCII (fullwidth) digits
    "",
]


@pytest.mark.parametrize("text", REFUSED)
def test_refused_on_every_python(text):
    with pytest.raises(ValueError):
        parse_iso(text)


ACCEPTED = {
    "2026-01-01T23:24:00Z": 1767309840.0,
    "2026-01-01T23:24:00+00:00": 1767309840.0,
    "2026-01-01T23:24:00-00:24": 1767311280.0,
    "2026-01-01T23:24:00+05:24": 1767290400.0,
    "2026-01-01T23:24:00": 1767309840.0,  # no offset: UTC
    "2026-01-01 23:24:00": 1767309840.0,
    "2026-01-01t23:24:00z": 1767309840.0,
    "2026-01-01T23:24Z": 1767309840.0,
    "2026-01-01T23:24:00.5Z": 1767309840.5,
    "2026-01-01T23:24:00.123456789Z": 1767309840.123456,
    "2026-01-02T00:00:00Z": 1767312000.0,
    "2026-01-02T00:00:00": 1767312000.0,
    "2026-01-02": 1767312000.0,
}


@pytest.mark.parametrize(("text", "ts"), ACCEPTED.items())
def test_accepted_on_every_python(text, ts):
    assert parse_iso(text) == pytest.approx(ts, abs=1e-6)


def test_a_real_midnight_still_parses():
    assert parse_iso("2026-01-02T00:00:00Z") == parse_iso("2026-01-01T23:59:59Z") + 1
