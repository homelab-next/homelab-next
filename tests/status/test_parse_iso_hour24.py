# SPDX-License-Identifier: Apache-2.0
"""parse_iso refuses hour 24 on every Python: 3.14's fromisoformat rolls ``T24:00`` over to the
next day where 3.11-3.13 refuse it, so a record's verdict depended on the interpreter."""

import pytest

from homelabnext.status.model import parse_iso


@pytest.mark.parametrize(
    "text", ["2026-01-01T24:00:00Z", "2026-01-01T24:00:00+00:00", "2026-01-01 24:00:00"]
)
def test_hour_24_is_refused(text):
    with pytest.raises(ValueError, match="hour 24"):
        parse_iso(text)


def test_a_real_midnight_still_parses():
    assert parse_iso("2026-01-02T00:00:00Z") == parse_iso("2026-01-01T23:59:59Z") + 1
