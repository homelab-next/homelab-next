# SPDX-License-Identifier: Apache-2.0
"""Every committed file that marks itself generated has a drift check (ADR-0028 decision 6).

A file is "marked" when one of its first lines is a comment or quote (``#``, ``//``, ``<!--``,
``>``, or a ``"_generated"`` key) that says both "generated" and "do not edit" (or "do not modify",
or "not this page"), or when it has a ``generated_from`` key.  What counts is the line, not the
sentence: a marker quoted inline in prose (a changelog entry) does not count, and neither does one
inside a fenced code block of a Markdown file or on an indented line of a YAML file (a block
scalar); a marker on its own comment-led line anywhere else does.  Each marked file must match a row of ``DERIVED``,
and each row names evidence that its check runs: a CI ``run:`` line, or a CI-run test module with
tests in it.  A new generator that commits a marked file without a check, or a row whose files or
evidence are gone, fails here.

This is a heuristic, not a proof: a derived file with no marker (JSON without a comment syntax, a
marker past the first lines or in other words), or one whose marker was stripped while a sibling
still matches its row, is not seen.  ADR-0028 lists those files by hand.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
HEAD_LINES = 20

#: test data (goldens, fixtures) is not a committed derived file
SKIP_PREFIXES = ("tests/",)
#: code that only *writes* a marker string
CODE_DIRS = ("homelabnext/", "tools/", "conformance/")

_LEADER = re.compile(r'^\s*(?:#|//|<!--|>|"_generated"\s*:)')
_GENERATED = re.compile(r"(?i)\bgenerated\b")
_DO_NOT_EDIT = re.compile(r"(?i)\bdo not (?:edit|modify)\b|\bnot this page\b")
_FROM_KEY = re.compile(r'^\s*"generated_from"\s*:')

#: (glob of committed files, evidence the check runs: "ci:<text of a CI run line>" or
#: "test:<path of a CI-run test module>")
DERIVED: tuple[tuple[str, str], ...] = (
    ("docs/capabilities/*.md", "ci:docs capabilities check"),
    ("docs/scripts/catalog.md", "ci:scripts catalog --check"),
    ("docs/status/sources.md", "test:tests/status/test_status_views.py"),
    ("docs/strategy/README.md", "test:tests/strategy/test_strategy_surfaces.py"),
    ("docs/terms.md", "test:tests/agent/test_agent_terms.py"),
    ("detections/det_map.yml", "ci:homelabnext.detections map --check"),
    ("examples/keyring/keyring.json", "ci:agent keyring check"),
    ("examples/mcp/clients/*/*", "ci:make mcp-check"),
    (
        "compose/lab-in-a-box/config/llm-gateway/litellm/*",
        "test:tests/generators/test_llm_gateway.py",
    ),
    ("examples/model-serving/gateway/*/*", "test:tests/models/test_serving_plan.py"),
    ("examples/model-serving/vllm_server/*", "test:tests/models/test_serving_plan.py"),
    ("workflows/stackstorm/*", "test:tests/workflows/test_workflows_st2.py"),
)


_FENCE = re.compile(r"^\s*(?:```|~~~)")


def is_marked(text: str, name: str = "") -> bool:
    markdown = name.endswith(".md")
    yaml_file = name.endswith((".yml", ".yaml"))
    fenced = False
    for line in text.splitlines()[:HEAD_LINES]:
        if markdown and _FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue  # an example in a Markdown code block, not this file's marker
        if yaml_file and line[:1].isspace():
            continue  # inside a block scalar or a nested value, not a file comment
        if _FROM_KEY.match(line):
            return True
        if _LEADER.match(line) and _GENERATED.search(line) and _DO_NOT_EDIT.search(line):
            return True
    return False


def marked_files(root: Path, names: list[str]) -> list[str]:
    out = []
    for name in names:
        if not name or name.startswith(SKIP_PREFIXES):
            continue
        if name.startswith(CODE_DIRS) and name.endswith(".py"):
            continue
        try:
            text = (root / name).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if is_marked(text, name):
            out.append(name)
    return out


def unlisted(files: list[str], rows=DERIVED) -> list[str]:
    return [f for f in files if not any(fnmatch.fnmatch(f, g) for g, _ in rows)]


def _tracked() -> list[str]:
    try:
        res = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("needs a git checkout")
    return res.stdout.decode().split("\0")


def test_every_marked_committed_file_has_a_listed_check():
    missing = unlisted(marked_files(ROOT, _tracked()))
    assert not missing, (
        "generated files with no drift check listed (add a --check step and a DERIVED row, "
        f"and a row in ADR-0028 decision 6): {missing}"
    )


def _ci_runs(ci: str, what: str) -> bool:
    """``what`` appears on a line CI executes: not a comment, not a step name."""
    for line in ci.splitlines():
        bare = line.strip()
        if what in bare and not bare.startswith(("#", "- name:", "name:")):
            return True
    return False


def test_every_row_matches_a_file_and_its_check_exists():
    marked = marked_files(ROOT, _tracked())
    ci = CI.read_text(encoding="utf-8")
    for glob, evidence in DERIVED:
        assert any(fnmatch.fnmatch(f, glob) for f in marked), f"stale row: {glob} matches nothing"
        kind, _, what = evidence.partition(":")
        if kind == "ci":
            assert _ci_runs(ci, what), f"{glob}: CI has no step running '{what}'"
        else:
            assert kind == "test", f"{glob}: unknown evidence {evidence}"
            module = ROOT / what
            assert module.is_file() and re.search(
                r"^def test_", module.read_text(encoding="utf-8"), re.M
            ), f"{glob}: no tests in {what}"


def test_an_unlisted_generated_file_is_reported(tmp_path):
    files_ = {
        "out/new.yml": "# generated by hnx new-thing; do not edit\nx: 1\n",
        "out/keys.json": '{\n  "generated_from": {"a": "sha256:0"}\n}\n',
        "out/page.md": "# Page\n\n> Generated by `hnx page`. Do not edit: regenerate.\n",
        "out/mod.json": '{\n  "_generated": "generated by hnx x; do not modify"\n}\n',
        "authored.yml": "# hand-written; generated pages read this\nx: 1\n",
        # prose quoting a marker, as a changelog entry does: not a marker
        "CHANGELOG.md": "## [Unreleased]\n\n- generated ones (`// Code generated ... DO NOT EDIT.`) exempt\n",
        # a marker split over two lines is not one marker
        "split.yml": "# generated by hnx x\n# and reviewed; do not edit by hand\n",
        # a marker shown in a fenced example, or inside a YAML block scalar: not this file's
        "guide.md": "# Guide\n\n```yaml\n# generated by hnx foo - do not edit\n```\n",
        "go.md": "# Go\n\n~~~go\n// Code generated by x. DO NOT EDIT.\n~~~\n",
        "scalar.yml": "header: |\n  # generated by hnx foo; do not edit\nx: 1\n",
        "tests/golden.yml": "# generated by hnx x; do not edit\n",
        "homelabnext/gen.py": "# generated by hnx x; do not edit\nHEADER = 1\n",
        "homelabnext/data.yml": "# generated by hnx x; do not edit\n",
    }
    for name, text in files_.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    files = marked_files(tmp_path, list(files_))
    assert files == [
        "out/new.yml",
        "out/keys.json",
        "out/page.md",
        "out/mod.json",
        "homelabnext/data.yml",
    ]
    assert unlisted(files) == files
    assert unlisted(files, rows=(("out/*", "ci:x"), ("homelabnext/*", "ci:x"))) == []


def test_ci_evidence_must_be_a_run_line_not_a_name_or_comment():
    ci = "      - name: docs capabilities check\n      # docs capabilities check\n"
    assert not _ci_runs(ci, "docs capabilities check")
    assert _ci_runs(ci + "        run: hnx docs capabilities check\n", "docs capabilities check")


#: ADR-0028 decision 3 and 6: the files ``python -m homelabnext.schemas`` writes, which carry no
#: marker, named by these globs
SCHEMA_GENERATOR_GLOBS = (
    "schemas/platform/module.schema.json",
    "schemas/platform/lake_table.schema.json",
    "schemas/platform/module_selection.schema.json",
    *(
        f"schemas/platform/{d}/{n}.*"
        for d in ("examples", "negative")
        for n in ("module", "module_selection", "lake_table")
    ),
)


def test_the_adr_globs_are_exactly_what_the_schema_generators_write():
    from homelabnext.schemas.__main__ import outputs

    written = set(outputs(ROOT))
    named = {f for f in _tracked() if any(fnmatch.fnmatch(f, g) for g in SCHEMA_GENERATOR_GLOBS)}
    assert named == written, (
        f"named but not generated: {sorted(named - written)}; "
        f"generated but not named: {sorted(written - named)}"
    )
    adr = (ROOT / "docs" / "adr" / "0028-veritas-single-source-of-truth.md").read_text("utf-8")
    assert "schemas/platform/{module,lake_table,module_selection}.schema.json" in adr
    assert "schemas/platform/{examples,negative}/{module,module_selection,lake_table}.*" in adr
