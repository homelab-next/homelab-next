# SPDX-License-Identifier: Apache-2.0
"""``hnx status views check --preview TIER``: an author sees what a tier will be shown, from the
state file, without serving it (the public tier through its release transform)."""

from __future__ import annotations

import json

from status_helpers import REGISTRY, VIEWS

from homelabnext.status.cli import main
from homelabnext.status.views import public_status


def _preview(tmp_path, capsys, tier):
    argv = ["views", "check", str(VIEWS), "--registry", str(REGISTRY)]
    argv += ["--state", str(tmp_path / "state.json"), "--preview", tier]
    rc = main(argv, clock=lambda: 1_700_000_000.0)
    out = capsys.readouterr()
    return rc, out


def test_the_public_preview_is_the_released_status_json(tmp_path, capsys):
    rc, out = _preview(tmp_path, capsys, "private")
    assert rc == 0 and "views: ok" in out.err
    whole = json.loads(out.out)
    rc, out = _preview(tmp_path, capsys, "public")
    assert rc == 0 and "views: ok" in out.err and "views: ok" not in out.out
    shown = json.loads(out.out)
    assert shown == json.loads(json.dumps(public_status(whole, contract=True)))
    assert set(shown) < set(whole), "the release keeps fewer fields than the document has"
    assert not any(m.get("group") == "private" for m in shown["menu"])


def test_an_unknown_tier_is_a_usage_error(tmp_path, capsys):
    assert _preview(tmp_path, capsys, "amber")[0] == 2


def test_without_preview_check_prints_only_its_verdict(capsys):
    assert main(["views", "check", str(VIEWS), "--registry", str(REGISTRY)]) == 0
    assert capsys.readouterr().out.startswith("views: ok")
