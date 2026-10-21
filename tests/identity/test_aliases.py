# SPDX-License-Identifier: Apache-2.0
"""The legacy alias map (homelabnext.identity.aliases): a code resolves to its uid on read, with
a deprecation warning; a uid passes through; anything else is left for the caller to report."""

from __future__ import annotations

import warnings

import pytest

from homelabnext.identity.aliases import (
    AliasMap,
    LegacyRecordCode,
    load_aliases,
    render_aliases,
    resolve,
    resolve_node_id,
)

U1 = "01a15e4e-0000-7000-8000-000000000001"
U2 = "01a15e4e-0000-7000-8000-000000000002"


def test_a_legacy_code_resolves_with_a_deprecation_warning():
    with pytest.warns(LegacyRecordCode, match="LL-001 is a legacy record code"):
        assert resolve("LL-001", {"LL-001": U1}, "an intent") == U1


def test_a_uid_and_an_unknown_code_pass_through_silently():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert resolve(U2, {"LL-001": U1}) == U2
        assert resolve("LL-009", {"LL-001": U1}) == "LL-009"  # unresolved: the caller reports
        assert resolve("M-17", AliasMap({"LL-001": U1})) == "M-17"


def test_a_node_id_resolves_its_body():
    with pytest.warns(LegacyRecordCode):
        assert resolve_node_id("lesson:LL-001", {"LL-001": U1}) == f"lesson:{U1}"
    assert resolve_node_id("svc:secrets", {"LL-001": U1}) == "svc:secrets"


def test_the_map_is_found_in_the_tree_or_beside_a_record_directory(tmp_path):
    (tmp_path / "registers" / "lessons").mkdir(parents=True)
    (tmp_path / "registers" / "aliases.yml").write_text(render_aliases({"LL-001": U1}))
    assert load_aliases(tmp_path / "registers").codes == {"LL-001": U1}
    assert load_aliases(tmp_path / "registers" / "lessons").codes == {"LL-001": U1}
    assert not load_aliases(tmp_path)


@pytest.mark.parametrize(
    "body",
    [
        "aliases_version: 1\n",
        f"aliases:\n  LL-NEW: {U1}\n",  # a placeholder never had an identity to keep
        "aliases:\n  LL-001: 0f6b1c2e-3d4a-4b5c-8d6e-7f8091a2b3c4\n",  # not a UUIDv7
        f"aliases:\n  M-17: {U1}\n",  # not a record code
    ],
)
def test_a_malformed_map_is_refused(tmp_path, body):
    (tmp_path / "aliases.yml").write_text(body)
    with pytest.raises(ValueError):
        load_aliases(tmp_path)


def test_the_rendered_map_is_sorted_by_code_and_number():
    text = render_aliases({"RB-001": U2, "LL-010": U1, "LL-002": U2}, {"LL-002": "a title"})
    lines = [ln.strip() for ln in text.splitlines() if ln.startswith("  ")]
    assert lines == [f"LL-002: {U2}  # a title", f"LL-010: {U1}", f"RB-001: {U2}"]
    assert text.startswith("# SPDX-License-Identifier: Apache-2.0\n")
