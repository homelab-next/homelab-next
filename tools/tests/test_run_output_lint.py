# SPDX-License-Identifier: Apache-2.0
"""tools/run_output_lint.py: scripts write scratch output into their run directory or build/."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_output_lint as lint

REPO = Path(__file__).resolve().parents[2]
HEADER = "# SPDX-License-Identifier: Apache-2.0\n# hnx-script:\n#   id: fake-script\n"


def _rules(text: str) -> list[tuple[int, str]]:
    return [(f.line, f.rule) for f in lint.scan_source("tools/fake.py", text)]


@pytest.mark.parametrize(
    "line",
    [
        'open("/tmp/fake-report.txt", "w")',
        'Path("out/scan.json").write_text("x")',
        'REPO_ROOT / "reports" / "x.json"',  # as a target below
        'shutil.copy("a", "dist/a")',
        'os.makedirs("scratch")',
        'open(f"/tmp/{name}.txt", mode="a")',
    ],
)
def test_a_literal_write_outside_the_run_dir_is_flagged(line):
    if line.startswith("REPO_ROOT"):
        line = f"({line}).write_text('x')"
    src = f"import os, shutil\nfrom pathlib import Path\nREPO_ROOT = Path('.')\n{line}\n"
    assert _rules(src) == [(4, "literal-write")]


def test_module_and_function_constants_are_followed():
    src = (
        "from pathlib import Path\n"
        "ROOT = Path(__file__).parent\n"
        "OUT = ROOT / 'out' / 'x.json'\n"
        "def main(args):\n"
        "    ok = args.root / 'build' / 'report.json'\n"
        "    ok.parent.mkdir(parents=True, exist_ok=True)\n"
        "    ok.write_text('x')\n"
        "    OUT.write_text('x')\n"
        "    mine = Path('runs') / args.run / 'a.txt'\n"
        "    mine.write_text('x')\n"
        "    Path(args.out).write_text('x')\n"
    )
    assert _rules(src) == [(8, "literal-write")]


def test_tempfile_misuse_is_flagged():
    src = (
        "import tempfile\n"
        "tempfile.mktemp()\n"
        "tempfile.mkdtemp()\n"
        "tempfile.NamedTemporaryFile(delete=False)\n"
        "tempfile.mkdtemp(dir=run)\n"
        "with tempfile.TemporaryDirectory() as d: pass\n"
    )
    assert _rules(src) == [(2, "tempfile"), (3, "tempfile"), (4, "tempfile")]


def test_inline_waiver_and_allowlist(tmp_path, capsys):
    (tmp_path / "tools").mkdir()
    planted = tmp_path / "tools" / "fake.py"
    planted.write_text(HEADER + 'open("/tmp/fake.txt", "w")\n')
    assert lint.main([str(tmp_path)]) == 1
    assert "tools/fake.py:4: literal-write" in capsys.readouterr().out
    allow = tmp_path / "allow.yml"
    allow.write_text("allow:\n  - {path: tools/fake.py, match: fake\\.txt, reason: a fake}\n")
    assert lint.main([str(tmp_path), "--allowlist", str(allow)]) == 0
    planted.write_text(HEADER + 'open("/tmp/fake.txt", "w")  # run-output: allow the fake\n')
    assert lint.main([str(tmp_path), "--allowlist", str(allow)]) == 1  # now the entry is stale
    assert "stale allowlist entry" in capsys.readouterr().out
    allow.write_text("allow:\n  - {path: tools/fake.py}\n")
    assert lint.main([str(tmp_path), "--allowlist", str(allow)]) == 2


def test_a_file_without_a_script_header_is_not_a_script(tmp_path):
    (tmp_path / "lib.py").write_text('open("/tmp/fake.txt", "w")\n')
    assert lint.scripts(tmp_path) == []


def test_the_repository_is_clean(capsys):
    assert lint.main([str(REPO)]) == 0, capsys.readouterr().out
