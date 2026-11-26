# SPDX-License-Identifier: Apache-2.0
"""The product-name lint (ADR-0027 rule 1): what it reads, where a name is allowed, what it
skips, and the baseline that only shrinks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
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
    vocab = pl.vocabulary(root, None, root / pl.ROLES)
    globs = [*pl.ALWAYS_ALLOWED, *(g for g, _ in pl.allowlist(root))]
    return {k: dict(v) for k, v in pl.scan(root, vocab, globs).items()}


def git(root: Path, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


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


def test_a_provider_dir_names_only_its_own_product(tmp_path):
    root = tree(
        tmp_path,
        {
            "examples/modules/example-store/adapter.py": 'x = "acme-objects"\ny = "zorbix"\n',
            "examples/modules/evil/module.yml": yaml.safe_dump(
                {"id": "evil", "kind": "provider", "product": {"name": "evilco"}}
            ),
            "examples/modules/evil/impl.py": 'x = "zorbix"\ny = "acme-objects"\nz = "evilco"\n',
        },
    )
    got = counts(root)
    assert got["examples/modules/example-store/adapter.py"] == {"zorbix": 1}
    assert got["examples/modules/evil/impl.py"] == {"zorbix": 1, "acme-objects": 1}


def test_a_feature_module_naming_a_product_is_counted(tmp_path):
    root = tree(tmp_path, {"examples/modules/example-feature/run.py": 'x = "acme-objects"\n'})
    assert counts(root)["examples/modules/example-feature/run.py"] == {"acme-objects": 1}


def test_an_allow_glob_needs_a_reason_and_a_product_a_why(tmp_path):
    root = tree(tmp_path, {})
    (root / pl.VOCABULARY).write_text(yaml.safe_dump({"allow": [{"path": "core/**"}]}))
    assert run(root) == 2
    (root / pl.VOCABULARY).write_text(yaml.safe_dump({"products": [{"name": "zorbix"}]}))
    assert run(root) == 2


def test_camel_case_and_digit_seams_count_but_glued_words_do_not(tmp_path):
    root = tree(
        tmp_path,
        {
            "core/f.py": "class ZorbixClient: pass\n"
            "def getZorbix(): pass\n"
            "zorbix2 = AcmeObjectsStore = acmeobjects = 1\n"
            "notzorbix = ZORBIXADDR = 1\n"
        },
    )
    assert counts(root)["core/f.py"] == {"zorbix": 3, "acme-objects": 2}


def test_a_docstring_hides_nothing_beside_it_and_escapes_are_decoded(tmp_path):
    root = tree(
        tmp_path,
        {
            "core/g.py": '"""doc"""; x = "zorbix"\n'
            "def f():\n"
            '    """a docstring"""\n'
            '    return "\\x7aorbix", b"zorbix", "zor\u200bbix", f"{x}-zorbix"\n'
        },
    )
    assert counts(root)["core/g.py"] == {"zorbix": 5}


def test_identifiers_come_from_the_tree_so_every_python_version_counts_alike(tmp_path):
    # tokenize emits the names inside an f-string's braces from 3.12 on and not before
    root = tree(tmp_path, {"core/v.py": 'import zorbix\nx = f"{zorbix.url}"\n'})
    assert counts(root)["core/v.py"] == {"zorbix": 2}


def test_argparse_choices_count(tmp_path):
    root = tree(tmp_path, {"core/cli.py": 'ap.add_argument("--b", choices=["zorbix", "x"])\n'})
    assert counts(root)["core/cli.py"] == {"zorbix": 1}


def test_prose_keys_are_skipped_but_their_siblings_are_not(tmp_path):
    root = tree(
        tmp_path,
        {
            "core/s.json": json.dumps(
                {
                    "description": "backed by zorbix",
                    "properties": {"backend": {"enum": ["zorbix"], "title": "zorbix"}},
                }
            )
        },
    )
    assert counts(root)["core/s.json"] == {"zorbix": 1}


def test_every_text_file_is_read_whatever_its_name_or_encoding(tmp_path):
    root = tree(
        tmp_path,
        {
            "Dockerfile": "FROM zorbix\n# zorbix in a comment\n",
            "core/page.html": "<p>zorbix</p>\n",
            "core/build/m.py": 'x = "zorbix"\n',
            "core/.env.example": "ZORBIX_URL=x\n",
        },
    )
    (root / "core/latin.py").write_bytes(b'# -*- coding: latin-1 -*-\nx = "zorbix \xe9"\n')
    (root / "core/binary.bin").write_bytes(b"\0zorbix")
    got = counts(root)
    for rel in (
        "Dockerfile",
        "core/page.html",
        "core/build/m.py",
        "core/.env.example",
        "core/latin.py",
    ):
        assert got[rel] == {"zorbix": 1}, rel
    assert "core/binary.bin" not in got


def test_an_oversized_file_is_an_error_not_a_skip(tmp_path, monkeypatch):
    root = tree(tmp_path, {"core/big.txt": "x" * 100})
    monkeypatch.setattr(pl, "MAX_BYTES", 10)
    assert run(root) == 2


def test_a_yaml_alias_bomb_is_read_once(tmp_path):
    lines = ["a0: &a0 [zorbix]"]
    lines += [f"a{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 9)}]" for i in range(1, 12)]
    root = tree(tmp_path, {"core/bomb.yml": "\n".join(lines) + "\n"})
    assert counts(root)["core/bomb.yml"] == {"zorbix": 1}


def test_only_tracked_and_unignored_files_are_read_in_a_checkout(tmp_path):
    root = tree(tmp_path, {"core/a.py": 'x = "zorbix"\n', "core/out.log": "zorbix\n"})
    (root / ".gitignore").write_text("*.log\n")
    git(root, "init", "-q")
    assert set(counts(root)) == {"core/a.py"}


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("examples/modules/x/module.yml", "kind: provider\nproduct: zorbix\n"),
        ("examples/modules/x/module.yml", "kind: provider\nproduct: {name: x, aliases: 5}\n"),
        ("examples/modules/x/module.yml", "kind: provider\nproduct: {name: 'Not A Name!'}\n"),
        (pl.BASELINE, "[]"),
        (pl.BASELINE, json.dumps({"version": 1, "counts": {"a": {"x": 0}}})),
        (pl.BASELINE, json.dumps({"version": 1, "counts": {"a": {"x": True}}})),
    ],
)
def test_a_malformed_input_is_a_usage_error(tmp_path, rel, text):
    root = tree(tmp_path, {rel: text})
    assert run(root) == 2


def test_an_internal_failure_is_could_not_measure(tmp_path, monkeypatch):
    root = tree(tmp_path, {})

    def boom(*_a, **_k):
        raise RuntimeError("x")

    monkeypatch.setattr(pl, "scan", boom)
    assert run(root) == 100


def test_the_baseline_fails_on_new_names_and_stale_entries_and_never_grows(tmp_path, capsys):
    root = tree(tmp_path, {"core/a.py": 'x = "zorbix"\ny = "zorbix"\n'})
    assert run(root, "--init") == 0
    assert run(root, "--init") == 2  # first adoption only
    assert run(root) == 0
    (root / "core/a.py").write_text('x = "zorbix"\ny = "zorbix"\nz = "zorbix"\n')
    assert run(root) == 1
    assert "zorbix x3 (baseline 2)" in capsys.readouterr().out
    assert run(root, "--update") == 1  # a total would rise
    (root / "core/a.py").write_text('x = "zorbix"\n')
    assert run(root) == 1
    assert "run --update" in capsys.readouterr().out
    assert run(root, "--update") == 0
    assert json.loads((root / pl.BASELINE).read_text())["counts"] == {"core/a.py": {"zorbix": 1}}
    (root / "core/a.py").rename(root / "core/b.py")  # a move keeps its debt
    assert run(root) == 1
    assert run(root, "--update") == 0
    assert json.loads((root / pl.BASELINE).read_text())["counts"] == {"core/b.py": {"zorbix": 1}}
    (root / "core/b.py").write_text('x = "nothing"\n')
    assert run(root, "--update") == 0
    assert json.loads((root / pl.BASELINE).read_text())["counts"] == {}
    assert run(root) == 0


def test_the_baseline_is_never_written_through_a_link(tmp_path):
    root = tree(tmp_path, {"core/a.py": 'x = "nothing"\n'})
    victim = tmp_path / "victim.json"
    (root / pl.BASELINE).symlink_to(victim)
    assert run(root, "--init") == 2
    assert run(root, "--update") == 2
    assert not victim.exists()


def test_against_the_base_neither_the_baseline_nor_the_vocabulary_may_grow(tmp_path, capsys):
    root = tree(tmp_path, {"core/a.py": 'x = "zorbix"\n'})
    assert run(root, "--init") == 0
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "base")
    assert run(root, "--base", "HEAD") == 0
    (root / "core/a.py").write_text('x = "zorbix"\ny = "zorbix"\n')
    baseline = json.loads((root / pl.BASELINE).read_text())
    baseline["counts"]["core/a.py"]["zorbix"] = 2  # a hand edit that raises the baseline
    (root / pl.BASELINE).write_text(json.dumps(baseline))
    assert run(root) == 0
    assert run(root, "--base", "HEAD") == 1
    assert "the baseline never grows" in capsys.readouterr().out
    git(root, "checkout", "-q", "--", ".")
    (root / pl.VOCABULARY).write_text(yaml.safe_dump({"products": []}))  # un-lint zorbix
    assert run(root, "--base", "HEAD") == 1
    assert "no longer" in capsys.readouterr().out
    assert run(root, "--base", "no-such-rev") == 2


@pytest.mark.parametrize(
    ("rel", "data"),
    [
        ("core/a.yml", b'x: "\\x7aorbix"\n'),  # a YAML escape
        ("core/a.json", b'{"a": "\\u007aorbix"}'),  # a JSON escape
        ("core/a.py", b'x = "zor\\\nbix"\n'),  # a Python line continuation
        ("core/b.yml", b'k: "acme\n  objects"\n'),  # a folded scalar
        ("core/b.py", 'x = "\u0130nfluxdb"\ny = "influxdb"\n'.encode()),  # a dotted capital I
        ("core/c.py", b'x = ("acme-" "objects")\n'),  # implicit concatenation
        ("core/d.py", b'x = f"\\x7aorbix{1}"\n'),  # an escape in an f-string
        ("core/e.yml", b"x: !!set {zorbix}\n"),  # a YAML set
        ("core/f.sh", b"z\0\nzorbix\n"),  # a NUL in a text suffix
        ("core/g.txt", "zorbix\n".encode("utf-16-le")),  # UTF-16 without a BOM
        ("core/h.txt", "zorbix\n".encode("utf-32")),  # UTF-32 with a BOM
        ("core/i.py", b"class ZORBIXClient: pass\n"),  # an upper-case run into a word
        ("core/j.py", b'x = ("zor"  # first half\n     "bix")\n'),  # a comment between halves
        ("core/k.yml", b"k: !!binary em9yYml4\n"),  # a YAML binary
        ("core/l.py", 'x = "zorb\U0001d6a4x"\n'.encode()),  # a mathematical dotless i
    ],
)
def test_what_the_prefilter_and_the_decoders_must_not_miss(tmp_path, rel, data):
    vocab = {"products": [{"name": "zorbix", "why": "x"}, {"name": "influxdb", "why": "x"}]}
    root = tree(tmp_path, {pl.VOCABULARY: yaml.safe_dump(vocab)})
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_bytes(data)
    got = counts(root)
    assert got.get(rel), rel
    assert run(root, "--init") == 0


def test_a_binary_is_skipped_whatever_its_size(tmp_path, monkeypatch):
    root = tree(tmp_path, {})
    (root / "core").mkdir()
    (root / "core/weights.bin").write_bytes(b"\0" * 100 + b"zorbix")
    monkeypatch.setattr(pl, "MAX_BYTES", 10)
    assert pl._file_texts(root / "core/weights.bin", "core/weights.bin") == []
    (root / "core/big.txt").write_text("x" * 100)
    with pytest.raises(pl.LintError, match="over 10 bytes"):
        pl._file_texts(root / "core/big.txt", "core/big.txt")


def test_a_link_into_the_tree_is_read_as_its_target(tmp_path):
    root = tree(tmp_path, {"README.md": "zorbix\n"})
    (root / "core").mkdir()
    (root / "core/cfg.yml").symlink_to("../README.md")
    assert counts(root)["core/cfg.yml"] == {"zorbix": 1}


def test_an_empty_base_and_a_missing_vocabulary_are_usage_errors(tmp_path):
    root = tree(tmp_path, {})
    assert run(root, "--base", "") == 2
    (root / pl.VOCABULARY).unlink()
    assert run(root) == 2


def test_a_subdirectory_of_a_checkout_is_linted_by_git(tmp_path):
    outer = tmp_path / "outer"
    root = tree(
        outer / "sub", {"core/a.py": 'x = "zorbix"\n', "node_modules/b.py": 'x = "zorbix"\n'}
    )
    (outer / ".gitignore").write_text("node_modules/\n")
    git(outer, "init", "-q")
    assert set(counts(root)) == {"core/a.py"}


def test_against_the_base_a_new_path_may_not_take_on_debt_but_a_rename_keeps_its_own(
    tmp_path, capsys
):
    root = tree(tmp_path, {"core/a.py": 'x = "zorbix"\n', "core/b.py": 'x = "acme-objects"\n'})
    assert run(root, "--init") == 0
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "base")
    git(root, "mv", "core/a.py", "core/renamed.py")
    assert run(root, "--update") == 0
    git(root, "add", "-A")
    git(root, "commit", "-qm", "rename")
    assert run(root, "--base", "HEAD^") == 0
    (root / "core/b.py").write_text("x = 1\n")  # cleanup elsewhere does not fund a new file
    (root / "core/new.py").write_text('y = "acme-objects"\n')
    assert run(root, "--update") == 0
    git(root, "add", "-A")
    git(root, "commit", "-qm", "swap")
    assert run(root, "--base", "HEAD^") == 1
    assert "core/new.py: acme-objects 1, 0 at" in capsys.readouterr().out


def test_against_the_base_no_spelling_may_leave_the_vocabulary_silently(tmp_path, capsys):
    vocab = {"products": [{"name": "zorbix", "aliases": ["zbx"], "why": "x"}]}
    root = tree(tmp_path, {pl.VOCABULARY: yaml.safe_dump(vocab)})
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "base")
    vocab["products"][0]["aliases"] = []
    (root / pl.VOCABULARY).write_text(yaml.safe_dump(vocab))
    assert run(root, "--base", "HEAD") == 1
    assert "'zbx' was linted" in capsys.readouterr().out
    (root / "examples/modules/example-store/module.yml").write_text(
        yaml.safe_dump({**PROVIDER, "product": {"name": "acme-objects"}})
    )
    assert run(root, "--base", "HEAD") == 1  # a provider's alias dropped too
    vocab["retired"] = [{"name": "zbx", "reason": "x"}, {"name": "acmeobj", "reason": "x"}]
    (root / pl.VOCABULARY).write_text(yaml.safe_dump(vocab))
    assert run(root, "--base", "HEAD") == 0


def test_a_link_loop_is_not_an_internal_error(tmp_path):
    root = tree(tmp_path, {})
    (root / "core").mkdir()
    (root / "core/a").symlink_to("b")
    (root / "core/b").symlink_to("a")
    assert run(root) == 0


def _committed(root: Path) -> None:
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "base")


def test_against_the_base_a_copy_never_doubles_debt_and_a_split_needs_moved(tmp_path, capsys):
    root = tree(tmp_path, {"core/a.py": 'x = "zorbix"\ny = "zorbix"\n'})
    assert run(root, "--init") == 0
    _committed(root)
    (root / "core/b.py").write_text((root / "core/a.py").read_text())  # a copy
    baseline = json.loads((root / pl.BASELINE).read_text())
    baseline["counts"]["core/b.py"] = {"zorbix": 2}
    (root / pl.BASELINE).write_text(json.dumps(baseline))
    assert run(root, "--base", "HEAD") == 1
    assert "no product's total may rise" in capsys.readouterr().out
    git(root, "checkout", "-q", "--", ".")
    (root / "core/b.py").write_text('y = "zorbix"\n')  # a split: half moves to a new file
    (root / "core/a.py").write_text('x = "zorbix"\n')
    assert run(root, "--update") == 0
    assert run(root, "--base", "HEAD") == 1
    vocab = yaml.safe_load((root / pl.VOCABULARY).read_text())
    vocab["moved"] = [{"from": "core/a.py", "to": "core/b.py", "reason": "split"}]
    (root / pl.VOCABULARY).write_text(yaml.safe_dump(vocab))
    assert run(root, "--base", "HEAD") == 0


def test_against_the_base_from_a_subdirectory_a_dropped_name_is_still_seen(tmp_path, capsys):
    outer = tmp_path / "outer"
    vocab = {"products": [{"name": "zorbix", "why": "x"}, {"name": "kuma", "why": "x"}]}
    root = tree(outer / "sub", {pl.VOCABULARY: yaml.safe_dump(vocab)})
    _committed(outer)
    vocab["products"].pop()
    (root / pl.VOCABULARY).write_text(yaml.safe_dump(vocab))
    assert run(root, "--base", "HEAD") == 1
    assert "'kuma' was linted" in capsys.readouterr().out
    vocab["retired"] = [{"name": "kuma", "reason": "gone"}]
    (root / pl.VOCABULARY).write_text(yaml.safe_dump(vocab))
    assert run(root, "--base", "HEAD") == 0
    assert "'kuma' retired since" in capsys.readouterr().out


@pytest.mark.static
def test_the_repository_passes_its_own_lint():
    assert run(ROOT) == 0


def test_a_products_allow_entry_exempts_only_the_named_product_in_that_file(tmp_path):
    vocab = {
        "products": [{"name": "zorbix", "why": "no provider yet"}, {"name": "quuxd", "why": "x"}],
        "allow": [
            {"path": "stack/*.yml", "products": ["zorbix"], "reason": "the stack runs zorbix"},
            {"path": "whole/*.yml", "reason": "every product is allowed here"},
        ],
    }
    root = tree(
        tmp_path,
        {
            "tools/product_names.yml": yaml.safe_dump(vocab),
            "stack/a.yml": "image: zorbix\nsink: quuxd\n",
            "whole/b.yml": "image: zorbix\nsink: quuxd\n",
        },
    )
    pv = pl.vocabulary(root, None, root / pl.ROLES)
    globs = [*pl.ALWAYS_ALLOWED, *(g for g, _ in pl.allowlist(root))]
    hits = {k: dict(v) for k, v in pl.scan(root, pv, globs, pl.product_allowlist(root)).items()}
    # zorbix is exempt in stack/a.yml, quuxd is still counted there; whole/b.yml is exempt for both
    assert hits == {"stack/a.yml": {"quuxd": 1}}


def test_a_products_allow_entry_needs_a_list_of_names(tmp_path):
    vocab = {"products": [], "allow": [{"path": "x", "reason": "r", "products": "zorbix"}]}
    root = tree(tmp_path, {"tools/product_names.yml": yaml.safe_dump(vocab)})
    with pytest.raises(pl.LintError, match="list of names"):
        pl.allowlist(root)


def _partial_tree(tmp_path, products, baseline=None):
    vocab = {
        "products": [{"name": "zorbix", "why": "new"}, {"name": "quuxd", "why": "old"}],
        "allow": [{"path": "stack/*.yml", "products": products, "reason": "the stack runs it"}],
    }
    files = {"tools/product_names.yml": yaml.safe_dump(vocab), "stack/a.yml": "image: zorbix\n"}
    root = tree(tmp_path, files)
    if baseline is not None:
        (root / pl.BASELINE).write_text(json.dumps({"version": 1, "counts": baseline}))
    return root


def _problems(root):
    vocab = pl.vocabulary(root, None, root / pl.ROLES)
    return pl.partial_problems(
        pl.product_allowlist(root), vocab, pl.load_baseline(root / pl.BASELINE), "the baseline"
    )


def test_a_per_product_exemption_for_a_product_new_to_the_lint_is_accepted(tmp_path):
    root = _partial_tree(tmp_path, ["zorbix"], {"stack/a.yml": {"quuxd": 3}})
    assert _problems(root) == []


def test_a_per_product_exemption_for_an_unknown_product_is_an_error(tmp_path):
    root = _partial_tree(tmp_path, ["nosuchproduct"])
    assert any("'nosuchproduct' is not a known product" in p for p in _problems(root))
    assert run(root) == 1


def test_a_per_product_exemption_cannot_erase_counted_debt(tmp_path):
    # quuxd is already counted in a matching path: exempting it would drop that debt unpaid
    root = _partial_tree(tmp_path, ["quuxd"], {"stack/a.yml": {"quuxd": 3}})
    problems = _problems(root)
    assert len(problems) == 1 and "already has 3 counted in stack/a.yml" in problems[0]
    assert run(root) == 1
    # counted somewhere the glob does not match: fine
    root2 = _partial_tree(tmp_path / "b", ["quuxd"], {"other/x.yml": {"quuxd": 3}})
    assert _problems(root2) == []


def _based(
    tmp_path, then_vocab, then_baseline, now_vocab, now_baseline, allow_products, then_allow=None
):
    """A repo whose base commit has ``then_*`` and whose working tree has ``now_*`` plus an allow
    entry exempting ``allow_products`` in ``stack/*.yml``."""
    products = {"zorbix": {"name": "zorbix", "why": "x"}, "quuxd": {"name": "quuxd", "why": "x"}}
    base_allow = (
        [{"path": "stack/*.yml", "products": then_allow, "reason": "the stack runs it"}]
        if then_allow
        else []
    )
    base_vocab = {"products": [products[p] for p in then_vocab], "allow": base_allow}
    root = tree(
        tmp_path, {"tools/product_names.yml": yaml.safe_dump(base_vocab), "stack/a.yml": "x: 1\n"}
    )
    (root / pl.BASELINE).write_text(json.dumps({"version": 1, "counts": then_baseline}))
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "base")
    now = {
        "products": [products[p] for p in now_vocab],
        "allow": [
            {"path": "stack/*.yml", "products": allow_products, "reason": "the stack runs it"}
        ],
    }
    (root / "tools/product_names.yml").write_text(yaml.safe_dump(now))
    (root / pl.BASELINE).write_text(json.dumps({"version": 1, "counts": now_baseline}))
    return root


def test_a_product_already_linted_at_the_base_cannot_be_exempted_even_with_no_debt(
    tmp_path, capsys
):
    # quuxd was linted at the base and has no count in stack/: not new to the lint, so refused
    root = _based(tmp_path, ["quuxd"], {}, ["quuxd"], {}, ["quuxd"])
    assert run(root, "--base", "HEAD") == 1
    assert "'quuxd' was already linted at the base commit" in capsys.readouterr().out


def test_a_product_new_since_the_base_may_be_exempted(tmp_path):
    root = _based(tmp_path, ["quuxd"], {}, ["quuxd", "zorbix"], {}, ["zorbix"])
    assert run(root, "--base", "HEAD") == 0


def test_debt_at_the_base_that_the_working_baseline_dropped_is_still_refused(tmp_path, capsys):
    # drives against_base: the working baseline has no count (a hand edit), the base still has it
    root = _based(tmp_path, ["zorbix"], {"stack/a.yml": {"zorbix": 4}}, ["zorbix"], {}, ["zorbix"])
    vocab = pl.vocabulary(root, None, root / pl.ROLES)
    problems = pl.against_base(root, "HEAD", pl.load_baseline(root / pl.BASELINE), vocab)
    assert any("already has 4 counted in stack/a.yml in the baseline at" in p for p in problems), (
        problems
    )
    assert run(root, "--base", "HEAD") == 1
    assert "already has 4 counted" in capsys.readouterr().out


def test_an_exemption_identical_at_the_base_is_not_judged_again_once_merged(tmp_path):
    # zorbix was new when the entry was added; after the merge it IS in the base vocabulary
    root = _based(tmp_path, ["zorbix"], {}, ["zorbix"], {}, ["zorbix"], then_allow=["zorbix"])
    assert run(root, "--base", "HEAD") == 0


def test_an_exemption_added_now_for_an_already_linted_product_still_fails(tmp_path, capsys):
    root = _based(tmp_path, ["zorbix", "quuxd"], {}, ["zorbix", "quuxd"], {}, ["quuxd"])
    assert run(root, "--base", "HEAD") == 1
    assert "'quuxd' was already linted at the base commit" in capsys.readouterr().out


def test_widening_an_existing_exemption_to_an_already_linted_product_fails(tmp_path, capsys):
    root = _based(
        tmp_path, ["zorbix", "quuxd"], {}, ["zorbix", "quuxd"], {}, ["zorbix", "quuxd"],
        then_allow=["zorbix"],
    )  # fmt: skip
    assert run(root, "--base", "HEAD") == 1
    out = capsys.readouterr().out
    assert (
        "'quuxd' was already linted at the base commit" in out and "'zorbix' was already" not in out
    )


def test_an_existing_exemption_cannot_be_moved_to_a_new_path_to_escape_judgement(tmp_path, capsys):
    root = _based(tmp_path, ["zorbix"], {}, ["zorbix"], {}, ["zorbix"], then_allow=["zorbix"])
    vocab = yaml.safe_load((root / "tools/product_names.yml").read_text())
    vocab["allow"][0]["path"] = "elsewhere/*.yml"  # same product, a path the base did not exempt
    (root / "tools/product_names.yml").write_text(yaml.safe_dump(vocab))
    assert run(root, "--base", "HEAD") == 1
    assert "'zorbix' was already linted at the base commit" in capsys.readouterr().out


def test_an_unknown_name_is_an_error_even_in_a_grandfathered_entry(tmp_path):
    root = _based(
        tmp_path, ["zorbix"], {}, ["zorbix"], {}, ["zorbix", "ghost"], then_allow=["zorbix"]
    )
    assert run(root, "--base", "HEAD") == 1
