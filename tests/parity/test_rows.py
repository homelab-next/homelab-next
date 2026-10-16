# SPDX-License-Identifier: Apache-2.0
import pytest

from homelabnext.parity import RowRules, Sample, Tolerance, diff_rows


def rows(n=5):
    return [{"id": i, "v": float(i), "s": f"x{i}"} for i in range(n)]


def test_identical_unordered():
    a = rows()
    assert diff_rows(a, list(reversed(a)), RowRules(key=("id",))).ok
    assert diff_rows(a, list(reversed(a))).ok


def test_ordering_rule_detects_reorder_only_when_asked():
    a = rows()
    b = list(reversed(a))
    assert diff_rows(a, b, RowRules(key=("id",), ordered=True)).order_violations == 4
    assert diff_rows(a, b, RowRules(ordered=True)).order_violations > 0
    assert diff_rows(a, b, RowRules(key=("id",), order_by=("id",))).ok


def test_missing_extra_and_changed_are_reported():
    a = rows()
    b = rows()
    b.pop()
    b.append({"id": 99, "v": 1.0, "s": "n"})
    b[0]["s"] = "changed"
    d = diff_rows(a, b, RowRules(key=("id",)))
    assert not d.ok
    assert d.only_left_total == 1 and d.only_right_total == 1 and d.changed_total == 1
    assert d.changed[0] == {"key": [0], "column": "s", "left": "x0", "right": "changed"}


def test_float_tolerance_boundary():
    a, b = rows(), rows()
    b[2]["v"] += 0.0005
    assert not diff_rows(a, b, RowRules(key=("id",))).ok
    assert diff_rows(a, b, RowRules(key=("id",), tolerances={"v": Tolerance(abs=0.001)})).ok
    assert not diff_rows(a, b, RowRules(key=("id",), tolerances={"v": Tolerance(abs=0.0001)})).ok
    assert diff_rows(a, b, RowRules(key=("id",), tolerances={"v": Tolerance(rel=0.001)})).ok


def test_timestamp_skew_tolerance_and_normalisation():
    a = [{"id": 1, "t": "2026-03-01T00:00:00Z"}]
    same = [{"id": 1, "t": "2026-03-01 00:00:00+00:00"}]
    skew = [{"id": 1, "t": "2026-03-01T00:00:02Z"}]
    assert diff_rows(a, same, RowRules(key=("id",))).ok
    assert not diff_rows(a, skew, RowRules(key=("id",))).ok
    assert diff_rows(a, skew, RowRules(key=("id",), tolerances={"t": Tolerance(seconds=3)})).ok


def test_null_equals_missing_by_default():
    assert diff_rows([{"id": 1, "x": None}], [{"id": 1}], RowRules(key=("id",))).ok
    d = diff_rows(
        [{"id": 1, "x": None}], [{"id": 1}], RowRules(key=("id",), nulls_as_missing=False)
    )
    assert not d.ok


def test_column_drift_reported():
    d = diff_rows([{"id": 1, "a": 1}], [{"id": 1, "a": 1, "b": 2}], RowRules(key=("id",)))
    assert d.columns_only_right == ["b"] and not d.ok


def test_ignore_columns():
    assert diff_rows(
        [{"id": 1, "n": 1}], [{"id": 1, "n": 2}], RowRules(key=("id",), ignore={"n"})
    ).ok


def test_duplicate_keys_counted():
    d = diff_rows([{"id": 1}, {"id": 1}], [{"id": 1}], RowRules(key=("id",)))
    assert d.only_left_total == 1


def test_bool_is_not_number():
    assert not diff_rows([{"id": 1, "f": True}], [{"id": 1, "f": 1}], RowRules(key=("id",))).ok


def test_sample_is_deterministic_and_same_rows_both_sides():
    a = rows(400)
    b = rows(400)
    rules = RowRules(key=("id",), sample=Sample(0.25))
    d = diff_rows(a, b, rules)
    assert d.ok and d.sampled and 40 < d.left_count < 160 and d.left_count == d.right_count
    assert diff_rows(a, b, rules).left_count == d.left_count
    b[7]["s"] = "drift"
    b[8]["s"] = "drift"
    kept = [r["id"] for r in a if rules.sample.keep(f"[{r['id']}]")]
    d2 = diff_rows(a, b, rules)
    assert d2.changed_total == len({7, 8} & set(kept))


def test_rules_validation():
    with pytest.raises(ValueError):
        RowRules(tolerances={"v": Tolerance(abs=1)})
    with pytest.raises(ValueError):
        RowRules(sample=Sample(0.5))
    with pytest.raises(ValueError):
        Sample(0)
    with pytest.raises(ValueError):
        Tolerance(abs=-1)
