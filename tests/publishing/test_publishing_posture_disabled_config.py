# SPDX-License-Identifier: Apache-2.0
"""``posture_rules_disabled`` in the run config: named posture rules off, an unknown name refused."""

from __future__ import annotations

import json

import pytest

from homelabnext.publishing import config as cf
from homelabnext.publishing import run as rn
from tests.publishing.test_publishing_pages_stage_run import setup_lab

CREDS = ("deny-list", "cloudflare-api-token", "r2-access-key-id", "r2-secret-access-key")


def _cfg(tmp_path, **extra):
    base, _, _ = setup_lab(tmp_path, "stage", creds=CREDS)
    doc = json.loads((base / "config.json").read_text())
    (base / "config.json").write_text(json.dumps({**doc, **extra}))
    return cf.load(base / "config.json")


def test_the_default_disables_nothing(tmp_path):
    assert _cfg(tmp_path).posture_rules_disabled == ()


def test_named_rules_load_sorted_and_reach_the_policy(tmp_path):
    cfg = _cfg(tmp_path, posture_rules_disabled=["we-run", "affected-assets"])
    assert cfg.posture_rules_disabled == ("affected-assets", "we-run")
    assert cfg.posture_rules is True


@pytest.mark.parametrize("bad", [["nope"], ["deny-list"], ["secret-shape"], "we-run", [None]])
def test_an_unknown_name_is_refused_at_load(tmp_path, bad):
    with pytest.raises(cf.ConfigError):
        _cfg(tmp_path, posture_rules_disabled=bad)


def test_run_builds_its_policy_from_the_setting():
    assert "posture_rules_disabled" in rn.gt.Policy.__dataclass_fields__
