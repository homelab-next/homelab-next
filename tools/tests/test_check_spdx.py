# SPDX-License-Identifier: Apache-2.0
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_spdx


def test_header_present_and_missing(tmp_path: Path):
    good = tmp_path / "good.py"
    good.write_text("#!/usr/bin/env python3\n# SPDX-License-Identifier: Apache-2.0\nx = 1\n")
    bad = tmp_path / "bad.py"
    bad.write_text("x = 1\n")
    empty = tmp_path / "__init__.py"
    empty.write_text("")
    assert check_spdx.main([str(good), str(empty)]) == 0
    assert check_spdx.main([str(bad)]) == 1


def test_repo_python_files_all_have_header():
    root = Path(__file__).resolve().parents[2]
    files = [p for p in root.rglob("*.py") if ".git" not in p.parts]
    assert [str(p) for p in files if check_spdx.missing_header(p)] == []


def test_shell_yaml_and_toml_need_the_header_too(tmp_path: Path):
    for name in ("run.sh", "conf.yml", "conf.yaml", "pyproject.toml"):
        f = tmp_path / name
        f.write_text("key = 1\n")
        assert check_spdx.main([str(f)]) == 1, name
        f.write_text("#!/bin/sh\n# SPDX-License-Identifier: Apache-2.0\nkey = 1\n")
        assert check_spdx.main([str(f)]) == 0, name


def test_golden_outputs_are_exempt(tmp_path: Path):
    g = tmp_path / "tests" / "golden" / "out.yml"
    g.parent.mkdir(parents=True)
    g.write_text("generated: true\n")
    assert check_spdx.main([str(g)]) == 0


def test_vendored_file_needs_its_own_spdx_identifier(tmp_path: Path, monkeypatch):
    v = tmp_path / "third_party" / "lib.sh"
    v.parent.mkdir()
    monkeypatch.setattr(check_spdx, "VENDORED", {"*/third_party/*": "kept verbatim"})
    v.write_text("# SPDX-License-Identifier: MIT\necho hi\n")
    assert check_spdx.main([str(v)]) == 0
    v.write_text("echo hi\n")
    assert check_spdx.main([str(v)]) == 1


def test_repo_tracked_files_all_have_header(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    monkeypatch.chdir(root)
    assert check_spdx.main([]) == 0


ROOT = Path(__file__).resolve().parents[2]
JINJA_HEADER = "{# SPDX-License-Identifier: Apache-2.0 -#}"
COMMENT = ("comment_begin", "comment", "comment_end")


def _tracked_templates(monkeypatch):
    monkeypatch.chdir(ROOT)
    return [p for p in check_spdx.collect([]) if p.suffix == ".j2"]


def test_jinja_templates_need_the_header(tmp_path: Path):
    t = tmp_path / "unit.service.j2"
    t.write_text("[Unit]\nDescription={{ name }}\n")
    assert check_spdx.main([str(t)]) == 1
    t.write_text(f"{JINJA_HEADER}\n[Unit]\n")
    assert check_spdx.main([str(t)]) == 0


def test_the_tree_walk_collects_templates(tmp_path: Path, monkeypatch):
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "a.conf.j2").write_text("x\n")
    monkeypatch.chdir(tmp_path)  # not a git work tree: the directory walk
    assert [p.as_posix() for p in check_spdx.collect([])] == ["templates/a.conf.j2"]
    assert check_spdx.main([]) == 1


def test_every_tracked_template_carries_the_header(monkeypatch):
    templates = _tracked_templates(monkeypatch)
    assert len(templates) >= 39
    assert [str(p) for p in templates if check_spdx.missing_header(p)] == []


def test_the_template_header_renders_nothing(monkeypatch):
    """The header is a Jinja comment that also eats its own newline: a template's tokens, and so
    its output in any context, are those of the same template without the header line."""
    jinja2 = pytest.importorskip("jinja2")
    seen = 0
    for trim in (False, True):  # plain Jinja, and Ansible's template module (trim_blocks)
        env = jinja2.Environment(trim_blocks=trim)
        for p in _tracked_templates(monkeypatch):
            text = p.read_text()
            if not text.startswith(JINJA_HEADER + "\n"):
                continue  # a script template: `#!` first, then the header as a shell comment
            seen += 1
            tokens = [(t, v) for _, t, v in env.lex(text)]
            assert tuple(t for t, _ in tokens[:3]) == COMMENT, p
            tokens = tokens[3:]
            body = text[len(JINJA_HEADER) + 1 :]
            assert tokens == [(t, v) for _, t, v in env.lex(body)], p
    assert seen >= 2 * 31


def test_the_pre_commit_hook_checks_the_same_suffixes():
    text = (ROOT / ".pre-commit-config.yaml").read_text()
    m = re.search(r"- id: spdx-header\n(?:\s+.*\n)*?\s+files: '(.+)'", text)
    assert m, "the spdx-header hook has no files pattern"
    rx = re.compile(m[1])
    for suffix in check_spdx.SUFFIXES:
        assert rx.search(f"a/b{suffix}"), suffix
    for other in (".md", ".json", ".txt"):
        assert not rx.search(f"a/b{other}"), other


def test_go_sources_need_the_header_but_go_mod_and_go_sum_do_not(tmp_path: Path, monkeypatch):
    src = tmp_path / "orchestrator" / "internal" / "queue" / "queue.go"
    src.parent.mkdir(parents=True)
    src.write_text("//go:build linux\n\npackage queue\n")
    assert check_spdx.main([str(src)]) == 1
    # line 1 above the build constraint: legal Go, and within the first five lines
    src.write_text("// SPDX-License-Identifier: Apache-2.0\n//go:build linux\n\npackage queue\n")
    assert check_spdx.main([str(src)]) == 0
    for name in ("go.mod", "go.sum"):
        (tmp_path / "orchestrator" / name).write_text("module example.com/x\n")
    (src.parent / "queue_test.go").write_text("package queue\n")
    monkeypatch.chdir(tmp_path)  # not a git work tree: the directory walk is the file list
    assert [p.as_posix() for p in check_spdx.collect([]) if p.suffix != ".go"] == []
    assert check_spdx.main([]) == 1  # the test file has no header


def test_generated_go_files_follow_the_go_convention(tmp_path: Path):
    cases = {
        # protoc-gen-go and stringer headers, as those tools write them
        "a.pb.go": (
            "// Code generated by protoc-gen-go. DO NOT EDIT.\n// versions:\n//  protoc v5\n"
            "// source: a.proto\n\npackage x\n",
            0,
        ),
        "state_string.go": (
            '// Code generated by "stringer -type=State"; DO NOT EDIT.\n\npackage x\n',
            0,
        ),
        "late.go": (
            "// Copyright\n// note\n// more\n// more\n// more\n// more\n"
            "// Code generated by mockgen. DO NOT EDIT.\npackage x\n",
            0,
        ),
        # the marker must be the exact convention, before the package clause
        "body.go": "package x\n\n// Code generated by hand. DO NOT EDIT.\n",
        "loose.go": "// Code generated by a tool, do not edit\n\npackage x\n",
        "suffix.go": "// Code generated by x. DO NOT EDIT. Really.\n\npackage x\n",
        "notgo.py": "# Code generated by x. DO NOT EDIT.\nx = 1\n",  # Go files only
    }
    for name, case in cases.items():
        text, want = case if isinstance(case, tuple) else (case, 1)
        f = tmp_path / name
        f.write_text(text)
        assert check_spdx.main([str(f)]) == want, name
