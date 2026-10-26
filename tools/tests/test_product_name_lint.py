# SPDX-License-Identifier: Apache-2.0
"""The product-name lint (ADR-0027 rule 1): what it reads, where a name is allowed, what it
skips, and the baseline that only shrinks."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import product_name_lint as pl

PROVIDER = {
    "id": "example-store",
    "kind": "provider",
    "product": {"name": "acme-objects", "display": "Acme Objects", "aliases": ["acmeobj"]},
}


def tree(tmp_path: Path, files: dict[str, str]) -> Path:
    base = {
        "examples/modules/example-store/module.yml": yaml.safe_dump(PROVIDER),
        "examples/modules/example-feature/module.yml": yaml.safe_dump(
            {"id": "f", "kind": "feature"}
        ),
        "tools/product_names.yml": yaml.safe_dump(
            {"products": [{"name": "zorbix", "why": "no provider yet"}], "allow": []}
        ),
        "examples/model_roles.json": json.dumps(
            {"roles": {"main": {"bindings": [{"model_id": "fancy-9b"}]}}}
        ),
    }
    for rel, text in {**base, **files}.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    return tmp_path


def run(root: Path, *args: str) -> int:
    return pl.main([str(root), *args])


def counts(root: Path) -> dict:
    terms, dirs = pl.vocabulary(root, None, root / pl.ROLES)
    globs = [*pl.ALWAYS_ALLOWED, *(d + "/**" for d in dirs), *(g for g, _ in pl.allowlist(root))]
    return {k: dict(v) for k, v in pl.scan(root, terms, globs).items()}


def test_python_strings_and_identifiers_count_but_comments_and_docstrings_do_not(tmp_path):
    root = tree(
        tmp_path,
        {
            "core/a.py": '"""Talks to Acme Objects (a docstring)."""\n'
            "# zorbix in a comment\n"
            "def f():\n"
            '    """zorbix in a function docstring"""\n'
            '    acme_objects_client = "acme-objects"\n'
            '    return ZORBIX_TOKEN, "fancy-9b"\n'
        },
    )
    got = counts(root)["core/a.py"]
    assert got == {"acme-objects": 2, "zorbix": 1, "fancy-9b": 1}


def test_yaml_keys_and_values_count_but_comments_do_not(tmp_path):
    root = tree(
        tmp_path,
        {
            "core/c.yml": "# acme-objects here is a comment\n"
            "acmeobj: 1\n"
            "backend: {enum: [zorbix, other]}\n",
            "core/d.json": json.dumps({"default": "Acme Objects"}),
        },
    )
    got = counts(root)
    assert got["core/c.yml"] == {"acme-objects": 1, "zorbix": 1}
    assert got["core/d.json"] == {"acme-objects": 1}


def test_names_are_bounded_case_insensitive_and_dashes_underscores_alike(tmp_path):
    root = tree(
        tmp_path,
        {
            "core/e.py": 'a = "ACME_OBJECTS_ENDPOINT"\n'
            'b = "acme objects"\n'
            'c = "notacme-objectsx"\n'
            'd = "zorbixes"\n',
        },
    )
    assert counts(root)["core/e.py"] == {"acme-objects": 2}


def test_file_and_directory_names_count(tmp_path):
    root = tree(tmp_path, {"ansible/roles/zorbix/tasks/main.yml": "- x: 1\n"})
    got = counts(root)
    assert got["ansible/roles/zorbix/"] == {"zorbix": 1}


def test_provider_dirs_sites_overlays_and_prose_are_allowed(tmp_path):
    root = tree(
        tmp_path,
        {
            "examples/modules/example-store/adapter.py": 'x = "acme-objects"\n',
            "examples/modules/sites/small.yml": "provider: zorbix\n",
            "examples/private-overlay/lab/x.yml": "zorbix: 1\n",
            "docs/adr/0099-x.md": "We chose zorbix.\n",
            "CHANGELOG.md": "- zorbix\n",
        },
    )
    assert counts(root) == {}


def test_a_feature_module_naming_a_product_is_counted(tmp_path):
    root = tree(tmp_path, {"examples/modules/example-feature/run.py": 'x = "acme-objects"\n'})
    assert counts(root)["examples/modules/example-feature/run.py"] == {"acme-objects": 1}


def test_an_allow_glob_needs_a_reason_and_a_product_a_why(tmp_path):
    root = tree(tmp_path, {})
    (root / pl.VOCABULARY).write_text(yaml.safe_dump({"allow": [{"path": "core/**"}]}))
    assert run(root) == 2
    (root / pl.VOCABULARY).write_text(yaml.safe_dump({"products": [{"name": "zorbix"}]}))
    assert run(root) == 2


def test_the_baseline_fails_on_new_names_and_on_stale_entries_and_only_shrinks(tmp_path, capsys):
    root = tree(tmp_path, {"core/a.py": 'x = "zorbix"\ny = "zorbix"\n'})
    assert run(root, "--init") == 0
    assert run(root, "--init") == 2  # first adoption only
    assert run(root) == 0
    (root / "core/a.py").write_text('x = "zorbix"\ny = "zorbix"\nz = "zorbix"\n')
    assert run(root) == 1
    assert "zorbix x3 (baseline 2)" in capsys.readouterr().out
    assert run(root, "--shrink") == 1  # never while something is new
    (root / "core/a.py").write_text('x = "zorbix"\n')
    assert run(root) == 1
    assert "run --shrink" in capsys.readouterr().out
    assert run(root, "--shrink") == 0
    assert json.loads((root / pl.BASELINE).read_text())["counts"] == {"core/a.py": {"zorbix": 1}}
    (root / "core/a.py").write_text('x = "nothing"\n')
    assert run(root, "--shrink") == 0
    assert json.loads((root / pl.BASELINE).read_text())["counts"] == {}
    assert run(root) == 0


def test_a_malformed_baseline_is_a_usage_error(tmp_path):
    root = tree(tmp_path, {})
    (root / pl.BASELINE).write_text(json.dumps({"version": 1, "counts": {"a": {"x": 0}}}))
    assert run(root) == 2


def test_the_repository_passes_its_own_lint():
    assert run(ROOT) == 0
