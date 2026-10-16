# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

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
