# SPDX-License-Identifier: Apache-2.0
"""The keyring comes from the sources (checklist M-12): generated, and 0 drift from them."""

import copy
import json
import shutil
from pathlib import Path

import pytest
import yaml
from agent_support import library, spec

from homelabnext import cli
from homelabnext.agent import SpecError, build_keyring, compile_profile
from homelabnext.agent.keyring import build_from_sources, drift, render_keyring
from homelabnext.registry import load

REPO = Path(__file__).resolve().parents[2]
SOURCES = REPO / "examples" / "keyring" / "sources.yml"
BROKER = json.loads((REPO / "schemas/broker/examples/manifest.example.json").read_text())


@pytest.fixture(scope="module")
def registry():
    return load(REPO / "examples" / "services.yml")


def test_the_committed_keyring_has_no_drift_from_its_sources(capsys):
    assert cli.main(["agent", "keyring", "check", str(SOURCES)]) == 0
    text, out = build_from_sources(SOURCES)
    assert out.read_text() == text


def test_every_principal_of_every_source_is_in_the_keyring(registry):
    reader = compile_profile(spec(), library())
    doc = build_keyring(registry, [reader], broker=BROKER)
    rows = {r["principal"]: r for r in doc["principals"]}
    assert rows["profile:reader"]["kind"] == "agent"
    assert rows["profile:operator"]["profile"] is None  # granted by the broker, no profile
    assert rows["sso:approver-one"]["grants"][0]["level"] == "privileged"
    assert {f"zone:{z}" for z in registry.zones} <= set(rows)
    grants = {g["resource"]: g for g in rows["profile:reader"]["grants"]}
    assert grants["cap:lake-query"]["endpoint"] == "lake-query.svc.example.internal"
    assert grants["action:service.status"]["level"] == "read"
    denied = {d["resource"] for d in rows["profile:reader"]["denials"]}
    assert {"cap:secrets", "action:host.reboot"} <= denied and not denied & set(grants)


def test_build_is_deterministic(registry):
    a = compile_profile(spec(), library())
    s = spec()
    s["id"] = "profile:second"
    b = compile_profile(s, library())
    assert render_keyring(build_keyring(registry, [a, b])) == render_keyring(
        build_keyring(registry, [b, a])
    )


def test_an_edited_or_duplicated_profile_is_refused(registry):
    p = compile_profile(spec(), library())
    bad = copy.deepcopy(p)
    bad["grants"]["capabilities"].append("cap:secrets")
    with pytest.raises(SpecError, match="digest"):
        build_keyring(registry, [bad])
    with pytest.raises(SpecError, match="twice"):
        build_keyring(registry, [p, p])


@pytest.fixture
def lab(tmp_path):
    shutil.copy(REPO / "examples" / "services.yml", tmp_path / "services.yml")
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "p.json").write_text(json.dumps(compile_profile(spec(), library())))
    (tmp_path / "sources.yml").write_text(
        yaml.safe_dump(
            {"registry": "services.yml", "profiles": ["profiles/*.json"], "out": "keyring.json"}
        )
    )
    assert cli.main(["agent", "keyring", "build", str(tmp_path / "sources.yml")]) == 0
    assert cli.main(["agent", "keyring", "check", str(tmp_path / "sources.yml")]) == 0
    return tmp_path


def test_drift_is_caught_when_a_source_changes(lab, capsys):
    s = spec()
    s["capabilities"] = ["cap:lake-query", "cap:records-propose"]
    s["tier"] = "write"
    (lab / "profiles" / "p.json").write_text(json.dumps(compile_profile(s, library())))
    assert cli.main(["agent", "keyring", "check", str(lab / "sources.yml")]) == 1
    err = capsys.readouterr().err
    assert "principal profile:reader differs" in err and "keyring build" in err


def test_drift_is_caught_when_the_registry_changes(lab, capsys):
    reg = lab / "services.yml"
    reg.write_text(
        reg.read_text().replace("clients: [data, compute]", "clients: [data, compute, edge]", 1)
    )
    assert cli.main(["agent", "keyring", "check", str(lab / "sources.yml")]) == 1
    assert "zone:edge differs" in capsys.readouterr().err


def test_drift_is_caught_when_the_keyring_is_edited_by_hand(lab, capsys):
    kr = lab / "keyring.json"
    doc = json.loads(kr.read_text())
    doc["principals"].append(
        {"principal": "profile:ghost", "kind": "agent", "grants": [], "denials": []}
    )
    kr.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    assert cli.main(["agent", "keyring", "check", str(lab / "sources.yml")]) == 1
    assert "profile:ghost is in the keyring but in no source" in capsys.readouterr().err
    kr.unlink()
    assert drift("{}", None)
    assert cli.main(["agent", "keyring", "check", str(lab / "sources.yml")]) == 1


def test_a_sources_file_naming_nothing_is_refused(tmp_path, capsys):
    (tmp_path / "s.yml").write_text("registry: services.yml\nprofiles: [none.json]\nout: k.json\n")
    shutil.copy(REPO / "examples" / "services.yml", tmp_path / "services.yml")
    assert cli.main(["agent", "keyring", "check", str(tmp_path / "s.yml")]) == 1
    assert "names no file" in capsys.readouterr().err
