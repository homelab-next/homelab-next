# SPDX-License-Identifier: Apache-2.0
"""``hnx workflows validate``: R-01 (packs are code), R-03 (deterministic first), R-07 (fixtures
round-trip) and the deploy pins.  Each rule fails on a mutated copy of a real pack and passes on
the repository."""

import json
import shutil
import subprocess

import pytest
from wf_support import MANIFEST, PACKS, ROOT, manifest, pack, problems, rules, step, universe

from homelabnext.workflows import Universe, check_pack, pack_digest, validate_repo
from homelabnext.workflows.cli import main

ALL = (
    "new-critical-alert",
    "phishing-report",
    "case-opened-notify",
    "proposal-validate",
    "agent-job-retry",
)


# ---------------------------------------------------------------- the repository passes
def test_repository_packs_validate_cleanly():
    rep = validate_repo(root=ROOT)
    assert [str(p) for p in rep.problems] == []
    assert set(ALL) <= set(rep.packs) and set(ALL) <= rep.clean


@pytest.mark.parametrize("name", ALL)
def test_each_pack_is_clean(name):
    assert problems(pack(name)) == []


def test_schema_examples_are_real_packs():
    examples = ROOT / "schemas" / "workflows" / "examples"
    rep = validate_repo([examples], root=ROOT)
    assert [str(p) for p in rep.problems] == []
    assert len(rep.packs) == 2


def test_schema_negatives_fail():
    files = sorted((ROOT / "schemas" / "workflows" / "negative").glob("pack.*"))
    rep = validate_repo(files, root=ROOT)
    rejected = {p.path for p in rep.problems if p.rule == "schema"}
    assert rejected == {f.relative_to(ROOT).as_posix() for f in files}


# ---------------------------------------------------------------- R-01: references resolve
def test_r01_nonexistent_action_fails():
    doc = pack("phishing-report")
    step(doc, "open-case")["action"] = "case.open-everything"
    assert "action" in rules(doc)


def test_r01_action_not_granted_fails():
    doc = pack("new-critical-alert")
    doc["actor"] = "profile:someone-else"
    assert "grant" in rules(doc)


def test_r01_grant_tier_too_low_fails(tmp_path):
    m = manifest()
    m["grants"][0]["max_tier"] = "write"
    (tmp_path / "workflows").mkdir()
    (tmp_path / "workflows" / "broker.manifest.json").write_text(json.dumps(m))
    uni = universe()
    local = Universe(tmp_path, uni.spec_labels, uni.templates)
    found = check_pack(pack("phishing-report"), local)
    assert any(r == "grant" and "above the grant's max_tier write" in d for r, d in found)


def test_r01_missing_manifest_fails():
    doc = pack("case-opened-notify")
    doc["broker_manifest"] = "workflows/no-such.manifest.json"
    assert rules(doc) == {"manifest"}


def test_r01_unknown_event_type_fails():
    doc = pack("case-opened-notify")
    doc["trigger"]["event"] = "homelabnext.case.reopened"
    assert "event-type" in rules(doc)


def test_r01_unknown_decision_spec_fails():
    doc = pack("new-critical-alert")
    step(doc, "classify")["spec"] = "no-such-spec"
    assert "spec" in rules(doc)


def test_r01_unknown_template_fails():
    doc = pack("phishing-report")
    step(doc, "triage")["template"] = "no-such-template"
    assert "template" in rules(doc)


def test_r01_slots_must_match_the_template():
    doc = pack("phishing-report")
    slots = step(doc, "triage")["slots"]
    del slots["email-body"]
    slots["mood"] = "calm"
    found = problems(doc)
    assert any(r == "slot" and "'email-body' is not bound" in d for r, d in found)
    assert any(r == "slot" and "no slot 'mood'" in d for r, d in found)


def test_r01_trusted_slot_bound_to_event_data_fails():
    doc = pack("phishing-report")
    step(doc, "triage")["slots"]["reporter-team"] = "$event.data.title"
    assert any(r == "slot" and "trusted slot" in d for r, d in problems(doc))


def test_r01_reference_to_a_later_step_fails():
    doc = pack("new-critical-alert")
    step(doc, "hosts")["from"] = "$steps.owner.row"
    assert "ref" in rules(doc)


def test_r01_trigger_reads_only_the_event():
    doc = pack("case-opened-notify")
    doc["trigger"]["where"] = [{"ref": "$steps.announce.result", "equals": "executed"}]
    assert "ref" in rules(doc)


def test_r01_duplicate_step_id_fails():
    doc = pack("new-critical-alert")
    step(doc, "page")["id"] = "open-case"
    assert "duplicate" in rules(doc)


def test_r01_schema_violation_is_reported_alone():
    doc = pack("case-opened-notify")
    doc["steps"][0]["kind"] = "shell"
    assert rules(doc) == {"schema"}


def test_r01_untracked_pack_fails_in_git(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "workflows" / "packs").mkdir(parents=True)
    shutil.copy(MANIFEST, tmp_path / "workflows" / "broker.manifest.json")
    shutil.copy(PACKS / "case-opened-notify.yml", tmp_path / "workflows" / "packs" / "p.yml")
    (tmp_path / "notes.yml").write_text("pack: mentioned, trigger and steps too, but no pack\n")
    rep = validate_repo(root=tmp_path)
    assert [(p.path, p.rule) for p in rep.problems] == [("workflows/packs/p.yml", "in-git")]
    assert rep.clean == set()
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    rep = validate_repo(root=tmp_path)
    assert rep.problems == [] and rep.clean == {"case-opened-notify"}


def test_r01_duplicate_pack_name_fails(tmp_path):
    a = tmp_path / "a.yml"
    shutil.copy(PACKS / "case-opened-notify.yml", a)
    shutil.copy(a, tmp_path / "b.yml")
    rep = validate_repo([a, tmp_path / "b.yml"], root=ROOT)
    assert [p.rule for p in rep.problems] == ["duplicate"]


# ---------------------------------------------------------------- R-01: deploy pins
def _deploy(tmp_path, pins):
    import yaml

    f = tmp_path / "deploy.yml"
    f.write_text(yaml.safe_dump({"deploy_id": "lab-workflows", "pins": pins}))
    return f


def test_deploy_pin_must_match_the_pack_digest(tmp_path):
    good = pack_digest(pack("case-opened-notify"))
    files = [PACKS / "case-opened-notify.yml"]
    ok = _deploy(tmp_path, [{"pack": "case-opened-notify", "digest": good}])
    rep = validate_repo(files, root=ROOT, deploy=ok)
    # the temporary deploy file is outside git: that alone is the one problem
    assert [p.detail for p in rep.problems] == ["the deploy manifest is not tracked by git"]
    stale = "sha256:" + "0" * 64
    bad = _deploy(tmp_path, [{"pack": "case-opened-notify", "digest": stale}])
    details = [p.detail for p in validate_repo(files, root=ROOT, deploy=bad).problems]
    assert any("pinned sha256:000" in d for d in details)


def test_deploy_pin_of_a_failing_pack_fails(tmp_path):
    doc = pack("case-opened-notify")
    doc["fixtures"][0]["expect"]["calls"] = []
    import yaml

    f = tmp_path / "p.yml"
    f.write_text(yaml.safe_dump(doc))
    d = _deploy(tmp_path, [{"pack": "case-opened-notify", "digest": pack_digest(doc)}])
    details = [p.detail for p in validate_repo([f], root=ROOT, deploy=d).problems]
    assert "case-opened-notify: pinned, but p.yml does not validate" in "\n".join(
        x.replace(str(tmp_path) + "/", "") for x in details
    )


def test_deploy_unknown_and_twice_pinned(tmp_path):
    good = pack_digest(pack("case-opened-notify"))
    pins = [{"pack": "nope", "digest": good}, *[{"pack": "case-opened-notify", "digest": good}] * 2]
    rep = validate_repo(
        [PACKS / "case-opened-notify.yml"], root=ROOT, deploy=_deploy(tmp_path, pins)
    )
    details = {p.detail for p in rep.problems}
    assert {"nope: no such pack", "case-opened-notify: pinned twice"} <= details


def test_repository_deploy_manifest_pins_every_shipped_pack():
    import yaml

    pins = yaml.safe_load((ROOT / "workflows" / "deploy.yml").read_text())["pins"]
    assert {p["pack"]: p["digest"] for p in pins} == {n: pack_digest(pack(n)) for n in ALL}


def test_pack_digest_ignores_comments_and_key_order():
    doc = pack("case-opened-notify")
    reordered = dict(reversed(list(doc.items())))
    assert pack_digest(reordered) == pack_digest(doc)
    doc["version"] = 2
    assert pack_digest(doc) != pack_digest(reordered)


# ---------------------------------------------------------------- R-03: deterministic first
def test_r03_model_before_enrichment_fails():
    doc = pack("new-critical-alert")
    classify = step(doc, "classify")
    doc["steps"].remove(classify)
    doc["steps"].insert(0, classify)
    found = rules(doc)
    assert "deterministic-first" in found


def test_r03_only_conditional_enrichment_before_the_model_fails():
    doc = pack("phishing-report")
    doc["steps"] = [s for s in doc["steps"] if s["id"] != "iocs"]
    step(doc, "message")["when"] = [{"ref": "$event.data.alert_id", "exists": True}]
    assert "deterministic-first" in rules(doc)


def test_r03_model_reading_only_the_raw_event_fails():
    doc = pack("new-critical-alert")
    step(doc, "classify")["input"] = {"title": "$event.data.title"}
    step(doc, "classify").pop("when")
    assert rules(doc) == {"model-input"}


def test_r03_pack_without_model_needs_no_enrichment():
    assert not any(s["kind"] == "enrich" for s in pack("case-opened-notify")["steps"])
    assert problems(pack("case-opened-notify")) == []


def test_risky_action_params_from_prompt_output_fail():
    doc = pack("phishing-report")
    step(doc, "block")["params"]["domains"] = "$steps.triage.urls"
    assert "risky-params" in rules(doc)


# ---------------------------------------------------------------- R-07: fixtures round-trip
def test_r07_wrong_expected_params_fail():
    doc = pack("new-critical-alert")
    doc["fixtures"][0]["expect"]["calls"][1]["params"]["rota"] = "someone-else"
    found = problems(doc)
    assert [r for r, _ in found] == ["round-trip"]
    assert "call 1" in found[0][1]


def test_r07_missing_and_extra_calls_fail():
    doc = pack("new-critical-alert")
    doc["fixtures"][0]["expect"]["calls"].pop()
    doc["fixtures"][1]["expect"]["calls"].append(dict(doc["fixtures"][0]["expect"]["calls"][0]))
    found = problems(doc)
    assert {r for r, _ in found} == {"round-trip"} and len(found) == 2


def test_r07_trigger_verdict_is_checked():
    doc = pack("new-critical-alert")
    doc["fixtures"][3]["expect"]["triggered"] = True
    assert any("triggered False, expected True" in d for _, d in problems(doc))


def test_r07_model_output_missing_or_stale_fails():
    doc = pack("new-critical-alert")
    del doc["fixtures"][0]["model"]["classify"]
    doc["fixtures"][2]["model"] = {"classify": {"label": "accept"}}
    details = [d for r, d in problems(doc) if r == "fixture"]
    assert any("gives no model output" in d for d in details)
    assert any("no such model step ran" in d for d in details)


def test_r07_label_the_spec_cannot_return_fails():
    doc = pack("new-critical-alert")
    doc["fixtures"][0]["model"]["classify"]["label"] = "page-everyone"
    assert any("not one spec" in d for _, d in problems(doc))


def test_r07_invalid_fixture_event_fails():
    doc = pack("case-opened-notify")
    del doc["fixtures"][0]["event"]["data"]["title"]
    assert rules(doc) == {"fixture"}


def test_r07_stale_approval_fails():
    doc = pack("phishing-report")
    doc["fixtures"][3]["approvals"] = [dict(doc["fixtures"][0]["approvals"][0])]
    assert any("never made" in d for _, d in problems(doc))


# ---------------------------------------------------------------- the command
def test_cli_validate_run_digest(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    assert main(["validate"]) == 0
    assert "5 pack(s), 0 problem(s)" in capsys.readouterr().out
    assert (
        main(
            [
                "run",
                str(PACKS / "phishing-report.yml"),
                "--fixture",
                "phishing-held-without-approval",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert '"result": "held"' in out and '"request_digest": "sha256:' in out
    assert main(["digest", str(PACKS / "case-opened-notify.yml")]) == 0
    assert capsys.readouterr().out.split() == [
        "case-opened-notify",
        pack_digest(pack("case-opened-notify")),
    ]
    import yaml

    bad = pack("phishing-report")
    step(bad, "open-case")["action"] = "case.nope"
    f = tmp_path / "bad.yml"
    f.write_text(yaml.safe_dump(bad))
    assert main(["validate", str(f)]) == 1
    assert "action: steps[3] open-case" in capsys.readouterr().out
    assert main(["validate", str(tmp_path / "missing.yml")]) == 2


def test_hnx_dispatches_workflows(capsys, monkeypatch):
    from homelabnext import cli

    monkeypatch.chdir(ROOT)
    assert cli.main(["workflows", "validate"]) == 0
