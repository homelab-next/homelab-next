# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.8 (additive): an egress service's ``tlp_ceiling``, declared once on its
registry row (ADR-0033 decision 6), so the commands that send to it read one declaration instead
of each restating it per invocation; a flag that disagrees with the row is refused."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

from homelabnext import tlp
from homelabnext.notify.ceiling import channel_ceiling
from homelabnext.registry.model import build_registry, schema_problems, semantic_problems

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_27 = json.loads((ROOT / "schemas/_frozen/2.7/platform/service.json").read_text())
FROZEN_28 = json.loads((ROOT / "schemas/_frozen/2.8/platform/service.json").read_text())
FROZEN_29 = json.loads((ROOT / "schemas/_frozen/2.9/platform/service.json").read_text())
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())


def _with_ceiling(label, service="notify"):
    doc = copy.deepcopy(DOC)
    doc["services"][service]["tlp_ceiling"] = label
    return doc


def _problems(doc):
    return schema_problems(doc) + semantic_problems(doc)


def test_version_is_2_8_frozen_and_additive():
    assert FROZEN_28["$id"].endswith("/platform/service/2.8")
    assert sc.is_additive(FROZEN_27, FROZEN_28) == []
    assert sc.is_additive(FROZEN_28, FROZEN_29) == []


def test_tlp_ceiling_validates_in_2_8_only_and_reaches_the_model():
    doc = _with_ceiling("green")
    assert sc.errors_for(CURRENT, doc, REG) == [] and _problems(doc) == []
    assert sc.errors_for(FROZEN_28, doc, REG) == []
    assert sc.errors_for(FROZEN_27, doc, REG) != []
    assert build_registry(doc).by_capability("notify").tlp_ceiling == "green"
    assert build_registry(DOC).by_capability("notify").tlp_ceiling is None


def test_tlp_ceiling_is_a_canonical_label_on_an_egress_row_only():
    assert _problems(_with_ceiling("white"))  # a legacy spelling is not a declaration
    wrong = _problems(_with_ceiling("red", service="metrics"))
    assert any("tlp_ceiling is for an egress capability" in p for p in wrong), wrong


def test_the_row_declares_the_channel_ceiling_and_a_disagreeing_flag_is_refused():
    reg = build_registry(_with_ceiling("green"))
    assert channel_ceiling(None, reg) == tlp.Label.GREEN
    assert channel_ceiling(tlp.Label.GREEN, reg) == tlp.Label.GREEN
    with pytest.raises(ValueError, match="disagrees with the registry's notify row"):
        channel_ceiling(tlp.Label.RED, reg)
    with pytest.raises(ValueError, match="--notify-ceiling"):
        channel_ceiling(None, build_registry(DOC))  # neither declares it: refused, never red
    assert channel_ceiling(tlp.Label.AMBER, build_registry(DOC)) == tlp.Label.AMBER


def test_status_collect_reads_the_row_and_refuses_a_disagreeing_flag(tmp_path, capsys):
    from homelabnext.status.cli import main

    reg = tmp_path / "services.yml"
    reg.write_text(yaml.safe_dump(_with_ceiling("green")))
    base = ["collect", "--registry", str(reg), "--root", str(ROOT), "--notify-topic", "status"]
    base += ["--source", "invariants"]
    bad = tmp_path / "bad.json"
    assert main([*base, "--state", str(bad), "--notify-ceiling", "red"]) == 2
    assert "disagrees" in capsys.readouterr().err and not bad.exists()
    good = tmp_path / "good.json"
    assert main([*base, "--state", str(good)]) == 0  # the row is the declaration


def test_broker_serve_reads_the_row_and_refuses_a_disagreeing_flag(tmp_path, monkeypatch):
    from homelabnext.broker.cli import notifier_from_args

    secure = "https://n.svc.example.internal:8443"  # no-raw-endpoint: allow override syntax
    monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", secure)  # the row's override: no name lookup

    reg = tmp_path / "services.yml"
    reg.write_text(yaml.safe_dump(_with_ceiling("green")))

    def args(ceiling):
        return argparse.Namespace(
            state=str(tmp_path / "state"),
            notify_topic="broker",
            notify_topic_file=None,
            notify_token=None,
            registry=str(reg),
            notify_ceiling=ceiling,
            notify_pairs_dir=None,
        )

    assert notifier_from_args(args(None)).sender.ceiling == tlp.Label.GREEN
    with pytest.raises(ValueError, match="disagrees"):
        notifier_from_args(args(tlp.Label.RED))
