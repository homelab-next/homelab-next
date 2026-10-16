# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from datetime import date

from cust_helpers import TODAY, load_one, make_doc, write_custom

from homelabnext.customization import build_register, render_register


def items(tmp_path):
    write_custom(tmp_path, "a", make_doc(id="custom:alive", links={"lesson": "LL-900"}))
    write_custom(
        tmp_path,
        "b",
        make_doc(
            id="custom:stale",
            created="2025-01-01",
            review_by="2025-06-01",
            reason="<script>alert(1)</script> padded to be long enough",
        ),
    )
    write_custom(tmp_path, "c", make_doc(id="custom:opt", optional=True))
    return load_one(tmp_path)


def test_html_and_json_are_deterministic_and_escaped(tmp_path):
    cs = items(tmp_path)
    h1, d1 = render_register(cs, TODAY)
    h2, d2 = render_register(list(reversed(cs)), TODAY)
    assert h1 == h2 and d1 == d2
    assert "<script>" not in h1 and "&lt;script&gt;" in h1
    states = {r["id"]: r["state"] for r in d1["customizations"]}
    assert states == {"custom:alive": "active", "custom:opt": "inactive", "custom:stale": "expired"}
    assert d1["summary"]["by_state"] == {"active": 1, "expired": 1, "inactive": 1}
    assert "expired" in h1


def test_enabled_optional_is_active(tmp_path):
    _, d = render_register(items(tmp_path), TODAY, {"custom:opt": []})
    assert {r["id"]: r["state"] for r in d["customizations"]}["custom:opt"] == "active"


def test_build_writes_two_files_and_is_idempotent(tmp_path):
    out = tmp_path / "out"
    paths = build_register(items(tmp_path / "src"), out, TODAY)
    first = [p.read_bytes() for p in paths]
    assert [p.name for p in paths] == ["customizations.html", "customizations.json"]
    assert json.loads(paths[1].read_text())["summary"]["total"] == 3
    build_register(items(tmp_path / "src2"), out, TODAY)
    assert first == [p.read_bytes() for p in paths]


def test_days_left_tracks_injected_date(tmp_path):
    _, d = render_register(items(tmp_path), date(2026, 10, 25))
    assert {r["id"]: r["days_left"] for r in d["customizations"]}["custom:alive"] == 37
