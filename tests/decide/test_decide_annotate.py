# SPDX-License-Identifier: Apache-2.0
"""K-13: classifiers never delete data at ingest; results arrive only as annotation columns."""

import copy
import random

import pytest

from homelabnext.decide import FaultyTier
from homelabnext.decide.annotate import AnnotationCollision, annotate, columns, iter_annotate
from homelabnext.decide.evalset import PhraseTier, demo_cascade, generate_gold_set

VALUES = [None, 0, -3, 2.5, True, "", "x", [], [1, "a"], {}, {"k": {"n": None}}]


def random_rows(rng: random.Random, n: int) -> list[dict]:
    texts = [r.item.text for r in generate_gold_set(40, seed=3)]
    rows = []
    for i in range(n):
        row: dict = {}
        for k in rng.sample(
            ["src", "host", "ts", "tags", "raw", "impact", "extra"], rng.randint(0, 5)
        ):
            row[k] = copy.deepcopy(rng.choice(VALUES))
        if rng.random() < 0.9:
            row["text"] = rng.choice([*texts, rng.choice(VALUES)])
        if rng.random() < 0.8:
            row["id"] = rng.choice([f"r-{i}", "", None, i])
        rows.append(row)
    return rows


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_records_in_equal_records_out_and_only_annotation_columns_added(seed):
    rng = random.Random(seed)
    rows = random_rows(rng, 300)
    before = copy.deepcopy(rows)
    out = annotate(rows, demo_cascade())
    assert rows == before  # the input is never mutated
    assert len(out) == len(rows)
    cols = set(columns())
    for src, got in zip(rows, out, strict=True):
        assert {k: got[k] for k in src} == src  # every original column, unchanged
        assert set(got) - set(src) == cols  # and nothing but the annotation columns
        assert list(got)[: len(src)] == list(src)  # original columns first, in order
        assert got["decide_spec"] == "change-review"


def test_unclassifiable_rows_are_kept_and_marked_for_a_human():
    out = annotate([{"id": "a"}, {"id": "b", "text": 42}], demo_cascade())
    assert [r["id"] for r in out] == ["a", "b"]
    assert all(r["decide_verdict"] == "human" and r["decide_error"] for r in out)


def test_faulty_tiers_never_drop_a_record():
    small = FaultyTier(PhraseTier("small", {}), "error")
    rows = [{"id": f"r{i}", "text": r.item.text} for i, r in enumerate(generate_gold_set(50))]
    out = annotate(rows, demo_cascade(small=small))
    assert [r["id"] for r in out] == [r["id"] for r in rows]


def test_a_crashing_cascade_still_emits_the_record():
    class Broken:
        spec = demo_cascade().spec

        def decide(self, item):
            raise RuntimeError("bug")

    out = annotate([{"text": "x"}], Broken())
    assert out[0]["text"] == "x" and out[0]["decide_error"] == "cascade failed: RuntimeError"


def test_an_annotation_column_never_overwrites_input():
    rows = [{"text": "a"}, {"text": "b", "decide_verdict": "mine"}]
    with pytest.raises(AnnotationCollision, match="decide_verdict"):
        annotate(rows, demo_cascade())
    with pytest.raises(AnnotationCollision):
        list(iter_annotate(rows, demo_cascade()))
    out = annotate(rows, demo_cascade(), prefix="k13_")
    assert out[1]["decide_verdict"] == "mine" and "k13_verdict" in out[1]
