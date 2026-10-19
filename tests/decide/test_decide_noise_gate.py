# SPDX-License-Identifier: Apache-2.0
"""K-08: a noise gate de-escalates only with a deterministic corroboration reference."""

import random

import pytest
from decide_support import fixed, spec

from homelabnext.decide import Cascade, CascadeConfigError, Item, SpecError

GATE = {"deescalate": ["reject"], "corroborators": ["allowlist", "seen-before"]}
ALLOWLIST = {"backup job", "patch window"}


def allowlist(item: Item) -> str | None:
    hit = sorted(k for k in ALLOWLIST if k in item.text)
    return f"entry={hit[0]}" if hit else None


def seen_before(item: Item) -> str | None:
    return item.fields.get("prior_case")


def gate_cascade(label="reject", conf=0.97, **corr):
    s = spec(
        noise_gate=GATE,
        tiers=[{"name": "floor"}, {"name": "small", "model_role": "mdl:a", "min_confidence": 0.9}],
    )
    impls = {"allowlist": allowlist, "seen-before": seen_before, **corr}
    return Cascade(s, {"floor": fixed("floor", None), "small": fixed("small", label, conf)}, None,
                   corroborators=impls)  # fmt: skip


def test_corroborated_deescalation_carries_the_reference():
    d = gate_cascade().decide(Item("a", "nightly backup job failed once"))
    assert (d.verdict, d.tier, d.corroboration) == ("reject", "small", "allowlist:entry=backup job")
    assert d.to_dict()["corroboration"] == "allowlist:entry=backup job"


def test_second_corroborator_is_tried_in_spec_order():
    d = gate_cascade().decide(Item("a", "odd login", fields={"prior_case": "case-0042"}))
    assert d.corroboration == "seen-before:case-0042"


def test_uncorroborated_deescalation_escalates_to_a_human():
    d = gate_cascade().decide(Item("a", "odd login from a new place"))
    assert d.verdict == "human" and d.escalated and d.corroboration is None
    step = d.trace[1]
    assert step.outcome == "uncorroborated" and "no evidence" in step.detail
    assert "corroboration" not in d.to_dict()


def test_a_failing_corroborator_never_corroborates():
    def boom(item):
        raise RuntimeError("index down")

    d = gate_cascade(allowlist=boom).decide(Item("a", "nightly backup job"))
    assert d.verdict == "human" and "RuntimeError" in d.trace[1].detail


def test_escalating_answers_need_no_corroboration():
    d = gate_cascade(label="accept").decide(Item("a", "odd login"))
    assert (d.verdict, d.corroboration) == ("accept", None)


def test_every_deescalation_is_corroborated_and_deterministic():
    rng = random.Random(8)
    words = ["backup job", "patch window", "odd login", "new device", "scan", "beacon"]
    c = gate_cascade()
    for n in range(500):
        fields = {"prior_case": f"case-{n}"} if rng.random() < 0.2 else {}
        item = Item(f"i-{n}", " ".join(rng.sample(words, 2)), fields=fields)
        d = c.decide(item)
        if d.verdict == "reject":
            assert d.corroboration, item
            assert c.decide(item).corroboration == d.corroboration
        else:
            assert d.verdict == "human" and d.corroboration is None


def test_missing_corroborator_implementation_is_a_config_error():
    s = spec(noise_gate=GATE)
    tiers = {
        "floor": fixed("floor", None),
        "small": fixed("small", None),
        "large": fixed("large", None),
    }
    with pytest.raises(CascadeConfigError, match="seen-before"):
        Cascade(s, tiers, corroborators={"allowlist": allowlist})


@pytest.mark.parametrize(
    ("gate", "over", "needle"),
    [
        ({"deescalate": ["reject"], "corroborators": []}, {}, "at least one corroborator"),
        ({"deescalate": ["escalate"], "corroborators": ["x"]}, {}, "deescalate"),
        ({"deescalate": [], "corroborators": ["x"]}, {}, "deescalate"),
        ("yes", {}, "mapping"),
        (GATE, {"safety": True}, "never de-escalates"),
    ],
)
def test_malformed_noise_gates_are_refused(gate, over, needle):
    with pytest.raises(SpecError, match=needle):
        spec(noise_gate=gate, **over)


def test_the_schema_example_noise_gate_parses_and_lints_clean():
    import json
    from pathlib import Path

    from homelabnext.decide import parse_spec
    from homelabnext.decide.lint import lint_doc

    root = Path(__file__).resolve().parents[2]
    doc = json.loads(
        (root / "schemas/registers/examples/decision_spec.noise-gate.json").read_text()
    )
    assert parse_spec(doc).noise_gate.corroborators == ("maintenance-window",)
    assert lint_doc(doc) == []
    neg = root / "schemas/registers/negative/decision_spec.noise-gate-uncorroborated.json"
    assert ("complete", "noise_gate.corroborators must name at least one corroborator") in lint_doc(
        json.loads(neg.read_text())
    )
