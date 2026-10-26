# SPDX-License-Identifier: Apache-2.0
"""Capability reference pages: generated from the code, deterministic, and gated by ``check``."""

from __future__ import annotations

import re
import shutil
import sys
import types
from pathlib import Path

import pytest

from homelabnext.conform.registry import CAPABILITIES
from homelabnext.registry.model import load
from homelabnext.sop import capabilities as caps
from homelabnext.sop.cli import main

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "examples" / "services.yml"
PAGES = ROOT / "docs" / "capabilities"


@pytest.fixture(scope="module")
def reg():
    return load(REGISTRY)


@pytest.fixture(scope="module")
def pages(reg):
    return caps.render_all(ROOT, reg)


@pytest.fixture
def generated(reg, tmp_path):
    caps.generate(tmp_path, ROOT, reg)
    return tmp_path


def test_one_page_per_capability_plus_index(pages):
    assert set(pages) == {f"{c}.md" for c in CAPABILITIES} | {"README.md"}


def test_rendering_is_deterministic(reg, pages, tmp_path):
    assert caps.render_all(ROOT, reg) == pages
    written, removed = caps.generate(tmp_path, ROOT, reg)
    assert len(written) == len(pages) and removed == []
    assert caps.generate(tmp_path, ROOT, reg) == ([], [])  # idempotent: nothing rewritten
    for text in pages.values():  # no run-dependent content
        assert not re.search(r"\b20\d\d-\d\d-\d\d[T ]\d\d:", text)
        assert str(ROOT) not in text


def test_secrets_page_has_signatures_fields_errors_and_checks(pages):
    page = pages["secrets.md"]
    assert page.startswith("---\ntitle: secrets\ntype: capability\n")
    # what it does: the contract module docstring
    assert "no value ever appears in an error message" in page
    # how to use it: every method, with a readable signature, its docstring and what it raises
    assert "def get(path: str, version: int | None = None) -> Secret" in page
    assert "| `version` | `int \\| None` | `None` | positional or keyword |" in page
    assert (
        "Latest (or given) version.  Raises SecretNotFound, also for a version that was never"
        in page
    )
    assert "**Raises:** `SecretNotFound`, `LeaseError`" in page  # lease()
    for op in ("put", "get", "delete", "list", "lease", "lease_valid", "revoke"):
        assert f"#### `SecretStore.{op}`" in page
    # data shapes: field tables and the error hierarchy
    assert "### `Secret` (dataclass, frozen)" in page
    assert "| `version` | `int` | required |  |" in page
    assert "| `SecretNotFound` | `SecretsError` |" in page
    # behaviour: every suite check with its level
    assert "| `errors-never-contain-values` | MUST |" in page
    # implementations: the fake, the real adapter with its target and limits, the services
    assert "`FakeSecretStore` in [`conformance.fakes.secret_store`]" in page
    assert (
        "[`homelabnext.conform.adapters.openbao:make`](../../homelabnext/conform/adapters/openbao.py)"
        in page
    )
    assert "(../../compose/lab-in-a-box/targets/secrets.yml)" in page
    assert "KV v2 keeps `max_versions` versions per path" in page
    assert "[secrets](../systems/secrets.md) ([[systems/secrets\\|secrets]]) | `openbao` |" in page
    # integrating: the factory/target/run pattern
    assert "hnx conform run secrets --target path/to/my-target.yml" in page
    assert "HNX_ENDPOINT_SECRETS" in page


def test_field_notes_features_and_schema_links_come_from_code(pages):
    assert "| `attempt` | `int` | required | 1 on first delivery |" in pages["events.md"]
    # a product feature a check requires is listed for adapters to declare
    assert re.search(r"\| `streaming` \| product feature", pages["inference.md"])
    # schema links only where the code loads one
    assert "(../../schemas/records/note.schema.json)" in pages["records.md"]
    assert "(../../schemas/ocsf/authentication.v1.json)" in pages["lake-query.md"]
    assert "None: no module of this contract" in pages["secrets.md"]
    # re-exported contracts pull in the types they reach (LakeClient -> TableInfo -> Column)
    assert "### `Column` (dataclass, frozen)" in pages["lake-catalog.md"]


def test_index_is_the_tool_choice_matrix(pages):
    index = pages["README.md"]
    row = next(line for line in index.splitlines() if line.startswith("| [secrets]"))
    cells = [c.strip() for c in re.split(r"(?<!\\)\|", row)[1:-1]]
    assert cells[2:5] == ["7", "15", "0"]  # operations, MUST, SHOULD
    assert cells[5] == "`openbao`"
    assert "| [dns](../systems/dns.md)" in index and "no conformance suite" in index


def test_check_passes_on_the_repository(reg):
    rep = caps.check(PAGES, ROOT, reg)
    assert rep.ok(), rep.lines()


def test_check_fails_on_a_stale_page(reg, generated):
    p = generated / "secrets.md"
    p.write_text(p.read_text().replace("| MUST |", "| SHOULD |", 1))
    rep = caps.check(generated, ROOT, reg)
    assert rep.stale == ["secrets.md"] and not rep.ok()
    assert "stale page" in rep.lines()[0]


def test_check_fails_on_a_missing_page(reg, generated):
    (generated / "notify.md").unlink()
    rep = caps.check(generated, ROOT, reg)
    assert rep.missing == ["notify.md"] and not rep.ok()


def test_check_fails_on_an_orphan_page(reg, generated):
    (generated / "ghost.md").write_text("# ghost\n")
    rep = caps.check(generated, ROOT, reg)
    assert rep.orphans == ["ghost.md"] and not rep.ok()
    caps.generate(generated, ROOT, reg)  # generate removes it
    assert caps.check(generated, ROOT, reg).ok()


def test_cli(tmp_path, capsys):
    assert main(["capabilities", "check"]) == 0
    assert main(["capabilities", "check", "--out", str(tmp_path)]) == 1
    assert "missing page: secrets.md" in capsys.readouterr().out
    assert main(["capabilities", "generate", "--out", str(tmp_path)]) == 0
    assert main(["capabilities", "check", "--out", str(tmp_path)]) == 0
    assert main(["capabilities", "bogus"]) == 2
    assert main(["capabilities", "check", "--registry", str(tmp_path / "nope.yml")]) == 2
    capsys.readouterr()


def test_without_a_checkout_it_fails_clearly(tmp_path, monkeypatch, capsys):
    with pytest.raises(caps.NotACheckoutError, match="not a homelabnext source checkout"):
        caps.resolve_root(tmp_path)
    assert main(["capabilities", "check", "--root", str(tmp_path)]) == 2
    assert "conformance/suites" in capsys.readouterr().err
    monkeypatch.setattr(caps.paths, "checkout_root", lambda: None)  # a wheel install
    with pytest.raises(caps.NotACheckoutError, match="the wheel does not carry"):
        caps.resolve_root()


def test_vault_links_resolve():
    """Every wiki-link and relative .md link of the generated pages and the home page resolves."""
    docs = ROOT / "docs"
    files = [
        docs / "README.md",
        *sorted(PAGES.glob("*.md")),
        *sorted((docs / "systems").glob("*.md")),
    ]
    for f in files:
        text = re.sub(r"```.*?```|`[^`\n]*`", "", f.read_text(), flags=re.DOTALL)  # code
        for target in re.findall(r"\[\[([^\]|\\]+)", text):
            if "/" in target:  # path-qualified: exactly that file under the vault root
                assert (docs / f"{target}.md").is_file(), (f, target)
            else:  # bare: Obsidian resolves by file name
                assert any(docs.rglob(f"{target}.md")), (f, target)
        for target in re.findall(r"\]\(([^)#:]+\.md)\)", text):
            assert (f.parent / target).resolve().is_file(), (f, target)


def test_regenerating_into_a_copy_of_the_repo_changes_nothing(reg, tmp_path):
    shutil.copytree(PAGES, tmp_path / "capabilities")
    assert caps.generate(tmp_path / "capabilities", ROOT, reg) == ([], [])


def test_a_foreign_out_directory_is_written_never_pruned(reg, tmp_path):
    """``hnx docs capabilities generate --out docs`` (a copy of it here) deletes nothing."""
    docs = tmp_path / "docs"
    shutil.copytree(ROOT / "docs", docs)
    before = sorted(p.name for p in docs.glob("*.md"))
    written, removed = caps.generate(docs, ROOT, reg)
    assert removed == [] and written
    assert set(before) <= {p.name for p in docs.glob("*.md")}
    assert not (docs / ".hnx-generated").exists()


def test_pages_do_not_depend_on_what_is_imported(reg, pages, monkeypatch, tmp_path):
    """A same-named module imported from another tree (a test, a --root run) changes nothing."""
    foreign = types.ModuleType("conformance.fakes.lake_iceberg")
    foreign.__file__ = str(tmp_path / "elsewhere" / "lake_iceberg.py")
    monkeypatch.setitem(sys.modules, "conformance.fakes.lake_iceberg", foreign)
    assert caps.render_all(ROOT, reg) == pages


def test_every_page_and_the_index_carry_a_valid_derived_summary(pages):
    """ADR-0032 level 0: the front-matter ``summary:`` comes from the contract's purpose line."""
    from homelabnext.context.levels import check_summary, front_matter, summary_of

    for name, text in pages.items():
        fm, _ = front_matter(text)
        assert check_summary(fm["summary"]) is None, name
        assert summary_of(text, name) == (fm["summary"], "generated")
    for c in CAPABILITIES:
        fm, _ = front_matter(pages[f"{c}.md"])
        assert fm["summary"].endswith(".") and fm["title"] == c
    assert front_matter(pages["README.md"])[0]["summary"] == caps.INDEX_SUMMARY


def test_a_long_purpose_is_cut_to_the_summary_limit(reg):
    from dataclasses import replace

    from homelabnext.context.levels import MAX_SUMMARY_CHARS

    c = next(iter(caps.collect(ROOT, reg)))
    long = replace(c, summary="does a thing " * 40)
    s = caps.capability_summary(long)
    assert 0 < len(s) <= MAX_SUMMARY_CHARS
    assert caps.capability_summary(long) == s  # deterministic


def test_a_summary_with_noncharacters_still_parses_in_the_front_matter(reg):
    """U+FFFE and U+FFFF are not valid in a YAML stream: they are escaped, the page keeps its
    front matter and the summary reads back unchanged."""
    from dataclasses import replace

    from homelabnext.context.levels import front_matter

    c = next(iter(caps.collect(ROOT, reg)))
    odd = replace(c, summary="odd ￾ name ￿ here")
    page = caps.render_page(odd, ROOT)
    fm, _ = front_matter(page)
    assert fm is not None and fm["summary"] == caps.capability_summary(odd)
    assert "￾" in fm["summary"] and fm["summary_generated"] is True
    assert fm["title"] == c.name  # the rest of the front matter survived
