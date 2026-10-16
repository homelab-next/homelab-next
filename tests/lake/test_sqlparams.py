# SPDX-License-Identifier: Apache-2.0
import pytest

from homelabnext.lake import LakeError
from homelabnext.lake.sqlparams import check_params, named_params, to_dollar, to_qmark


def test_finds_params_but_not_casts_literals_or_comments():
    sql = "SELECT x::int, ':nope', \":nope2\" FROM t -- :c1\n WHERE a = :a /* :c2 */ AND b = :b AND a < :a"
    assert named_params(sql) == ["a", "b"]
    assert to_dollar("SELECT :a, ':a', x::int") == "SELECT $a, ':a', x::int"


def test_qmark_order():
    sql, args = to_qmark("WHERE a = :a AND b = :b AND c = :a", {"a": 1, "b": 2})
    assert sql == "WHERE a = ? AND b = ? AND c = ?" and args == [1, 2, 1]


def test_missing_and_extra_params_refused():
    with pytest.raises(LakeError, match="not supplied"):
        check_params("SELECT :a", {})
    with pytest.raises(LakeError, match="not used"):
        check_params("SELECT 1", {"z": 1})
