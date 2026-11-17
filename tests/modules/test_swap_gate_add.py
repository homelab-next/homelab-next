# SPDX-License-Identifier: Apache-2.0
"""The swap gate (``hnx modules swap-gate --overlay``) over the change that adds an overlay's first
model role: the base holds an empty role table, the store entry and the live report for the
table after (the vetting change); the change adds the role, a decision role, and the record whose
add leg covers it.  The evidence is still the base's, never the change's."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from homelabnext import paths
from homelabnext.golden import pins as gp
from homelabnext.golden.canary import benign_decider, benign_model
from homelabnext.models import store as st
from homelabnext.modules import cli as mcli
from homelabnext.modules import swap as ms
from homelabnext.registry.models import RoleTable

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "schemas/platform/examples/module_swap.inference-add.json"
STORE_FILE = paths.example_file("model-serving", "model_store.json")
STORE = st.load(STORE_FILE)
SHIPPED = RoleTable.load(paths.example_file("model_roles.json"))
(ENTRY,) = (
    e
    for e in STORE.entries.values()
    if e.served_model_name == SHIPPED.get("fast-classifier").bindings[0].model_id
)
LAB_ROLES = "lab/model_roles.json"
LAB_STORE = "lab/model-serving/model_store.json"
LAB_EVALS = "lab/model-evals"
LAB_SWAPS = "lab/swaps"
EMPTY = {"version": 1, "roles": {}}
ADDED = {
    "version": 1,
    "roles": {
        "fast-classifier": {
            "kind": "decision",
            "tier": "fast",
            "bindings": [
                {
                    "backend": "svc:inference",
                    "model_id": ENTRY.served_model_name,
                    "version": ENTRY.revision,
                    "digest": ENTRY.digest,
                }
            ],
        }
    },
}


def _report(doc: dict, mode: str = "live") -> dict:
    return gp.run_eval(
        RoleTable.from_dict(doc),
        gp.DEFAULT_SUITES,
        gp.fake_factory,
        model_name="fake-golden",
        canary_factory=lambda r, b: (benign_model, mode),
        decision_canary_factory=lambda r, b: (benign_decider, mode),
    )


@pytest.fixture(scope="module")
def report() -> dict:
    return _report(ADDED)


def _git(root: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    r = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)
    return r.stdout.decode().strip()


def _write(root: Path, rel: str, doc) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return p


def _overlay(tmp_path: Path, start: dict, end: dict, *reports: dict) -> Path:
    root = tmp_path / "overlay"
    (root / "lab" / "model-serving").mkdir(parents=True)
    _write(root, LAB_ROLES, start)
    shutil.copy(STORE_FILE, root / LAB_STORE)
    for i, r in enumerate(reports):
        _write(root, f"{LAB_EVALS}/candidate-{i}.json", r)
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _write(root, LAB_ROLES, end)
    return root


def _add_record(report: dict) -> dict:
    swap = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    swap["model_roles"][0]["evaluation"]["report"] = gp.report_digest(report)
    return swap


def _gate(root: Path, capsys) -> tuple[int, dict]:
    rc = mcli.main(["swap-gate", "--overlay", str(root), "--base", "HEAD", "--json"])
    return rc, json.loads(capsys.readouterr().out)


def test_the_first_role_lands_with_an_add_record(tmp_path, report, capsys):
    root = _overlay(tmp_path, EMPTY, ADDED, report)
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", _add_record(report))
    rc, out = _gate(root, capsys)
    assert (rc, out["problems"]) == (0, []), out


def test_the_first_role_uncovered_names_the_add_leg(tmp_path, report, capsys):
    root = _overlay(tmp_path, EMPTY, ADDED, report)
    rc, out = _gate(root, capsys)
    (p,) = out["problems"]
    assert rc == 1 and "roles: fast-classifier" in p and "add" in p


def test_a_rebind_record_cannot_land_the_first_role(tmp_path, report, capsys):
    """The rebind gate is unchanged: the record that rebinds cannot cover a new role."""
    root = _overlay(tmp_path, EMPTY, ADDED, report)
    swap = _add_record(report)
    leg = swap["model_roles"][0]
    leg["change"] = "rebind"
    leg["from"] = {"pin": "sha256:" + "0" * 64}
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", swap)
    rc, out = _gate(root, capsys)
    assert rc == 1
    assert any("needs an add leg (change: add), not a rebind" in p for p in out["problems"])


def test_the_live_report_must_be_on_the_base(tmp_path, report, capsys):
    """Vetted in one change, added in a later one: the report in the same change counts for
    nothing."""
    root = _overlay(tmp_path, EMPTY, ADDED)
    _write(root, f"{LAB_EVALS}/candidate.json", report)
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", _add_record(report))
    rc, out = _gate(root, capsys)
    assert rc == 1 and any("is not supplied" in p for p in out["problems"])


def test_a_fake_report_does_not_land_a_role(tmp_path, capsys):
    fake = _report(ADDED, "fake")
    root = _overlay(tmp_path, EMPTY, ADDED, fake)
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", _add_record(fake))
    rc, out = _gate(root, capsys)
    assert rc == 1 and any("a live run is required" in p for p in out["problems"])


def test_the_role_leaves_with_a_remove_record(tmp_path, capsys):
    empty = _report(EMPTY)
    root = _overlay(tmp_path, ADDED, EMPTY, empty)
    swap = _add_record(empty)
    leg = swap["model_roles"][0]
    leg["change"] = "remove"
    leg["from"] = {"pin": ms._pin_of(RoleTable.from_dict(ADDED).get("fast-classifier").bindings[0])}
    del leg["to"]
    del swap["model_role_changes"]  # a removed role brings no field to approve
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", swap)
    rc, out = _gate(root, capsys)
    assert (rc, out["problems"]) == (0, []), out


# ---------------------------------------------------------------- review blockers (#476)


def test_the_gate_requires_the_added_role_be_named(tmp_path, report, capsys):
    root = _overlay(tmp_path, EMPTY, ADDED, report)
    swap = _add_record(report)
    del swap["model_role_changes"]
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", swap)
    rc, out = _gate(root, capsys)
    assert rc == 1
    assert any(
        "mdl:fast-classifier changes bindings[], kind, tier" in p
        or ("mdl:fast-classifier changes" in p and "model_role_changes" in p)
        for p in out["problems"]
    ), out


def _leaves_lab() -> dict:
    doc = json.loads(json.dumps(ADDED))
    doc["roles"]["fast-classifier"]["bindings"][0]["leaves_lab"] = True
    return doc


def test_the_gate_names_an_added_bindings_leaves_lab(tmp_path, capsys):
    """The reviewer's probe: an added binding with leaves_lab lands only named and reviewed."""
    after = _leaves_lab()
    rep = _report(after)
    root = _overlay(tmp_path, EMPTY, after, rep)
    swap = _add_record(rep)
    del swap["model_role_changes"]
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", swap)
    rc, out = _gate(root, capsys)
    assert rc == 1
    assert any("bindings[].leaves_lab" in p and "model_role_changes" in p for p in out["problems"])
    swap["model_role_changes"] = ["mdl:fast-classifier"]
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", swap)
    rc, out = _gate(root, capsys)
    assert (rc, out["problems"]) == (0, []), out


def test_the_gate_names_an_added_roles_fallback(tmp_path, capsys):
    """The reviewer's probe: an added role falling back to a role on another backend."""
    other = {
        "kind": "decision",
        "tier": "fast",
        "bindings": [{**ADDED["roles"]["fast-classifier"]["bindings"][0],
                      "backend": "svc:other-inference"}],
    }  # fmt: skip
    before = {"version": 1, "roles": {"main-reasoner": other}}
    after = json.loads(json.dumps(ADDED))
    after["roles"]["main-reasoner"] = other
    after["roles"]["fast-classifier"]["fallback"] = "mdl:main-reasoner"
    rep = _report(after)
    root = _overlay(tmp_path, before, after, rep)
    swap = _add_record(rep)
    del swap["model_role_changes"]
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", swap)
    rc, out = _gate(root, capsys)
    assert rc == 1
    assert any("mdl:fast-classifier changes" in p and "fallback" in p for p in out["problems"])


def _remove_record(empty: dict) -> dict:
    swap = _add_record(empty)
    leg = swap["model_roles"][0]
    leg["change"] = "remove"
    leg["from"] = {"pin": ms._pin_of(RoleTable.from_dict(ADDED).get("fast-classifier").bindings[0])}
    del leg["to"]
    del swap["model_role_changes"]
    return swap


def test_the_gate_refuses_removing_a_role_a_consumer_still_names(tmp_path, capsys):
    empty = _report(EMPTY)
    root = _overlay(tmp_path, ADDED, EMPTY, empty)
    _write(
        root, "lab/gateway.json", {"keys": [{"name": "triage", "roles": ["mdl:fast-classifier"]}]}
    )
    _write(root, "lab/notes.md", {"text": "mdl:fast-classifier"})  # prose: not a consumer
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", _remove_record(empty))
    rc, out = _gate(root, capsys)
    assert rc == 1
    assert out["problems"] == [
        "mdl:fast-classifier is removed, but lab/gateway.json still names it: remove that "
        "consumer in the same change, or keep the role"
    ]


def test_a_similar_role_name_is_no_consumer(tmp_path, capsys):
    empty = _report(EMPTY)
    root = _overlay(tmp_path, ADDED, EMPTY, empty)
    _write(root, "lab/gateway.json", {"roles": ["mdl:fast-classifier-2"]})
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", _remove_record(empty))
    rc, out = _gate(root, capsys)
    assert (rc, out["problems"]) == (0, []), out


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("lab/golden/decision.yml", "suite: d\nkind: decision\nrole: fast-classifier\n"),
        ("lab/conformance/target.yml", "gateway:\n  checks:\n    model: fast-classifier\n"),
        ("lab/conformance/target.yml", "throttle_model: 'fast-classifier'  # the slow one\n"),
        ("lab/capabilities.yml", "capabilities:\n  - inference\n  - fast-classifier\n"),
        ("lab/templates/gateway.json.j2", '{"keys": [{"roles": ["mdl:fast-classifier"]}]}\n'),
        ("lab/templates/client.yml.j2", "role: {{ 'fast-classifier' }}\nmodel: fast-classifier\n"),
    ],
)
def test_the_gate_finds_a_removed_role_named_bare(tmp_path, capsys, rel, text):
    """The re-review's consumers that name the role without ``mdl:``: a golden suite's role, a
    conformance target's model, capabilities.yml, a template."""
    empty = _report(EMPTY)
    root = _overlay(tmp_path, ADDED, EMPTY, empty)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(text, encoding="utf-8")
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", _remove_record(empty))
    rc, out = _gate(root, capsys)
    assert rc == 1
    assert out["problems"] == [
        f"mdl:fast-classifier is removed, but {rel} still names it: remove that consumer in the "
        "same change, or keep the role"
    ]


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("lab/golden/other.yml", "role: fast-classifier-2\n"),
        ("lab/notes.yml", "note: fast-classifier was removed\n"),
        (
            "lab/list.yml",
            "items:\n  - fast-classifier\n",
        ),  # a list item counts only in capabilities.yml
    ],
)
def test_a_bare_name_elsewhere_is_no_consumer(tmp_path, capsys, rel, text):
    empty = _report(EMPTY)
    root = _overlay(tmp_path, ADDED, EMPTY, empty)
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(text, encoding="utf-8")
    _write(root, f"{LAB_SWAPS}/fast-classifier.json", _remove_record(empty))
    rc, out = _gate(root, capsys)
    assert (rc, out["problems"]) == (0, []), out
