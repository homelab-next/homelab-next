# SPDX-License-Identifier: Apache-2.0
"""tools/yaml_loader_lint.py: package code parses YAML through homelabnext/_yaml.py's budgeted
loaders; the reviewed uses of yaml.safe_load/SafeLoader only shrink."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yaml_loader_lint as lint

REPO = Path(__file__).resolve().parents[2]
SAFE_LOAD = "yaml." + "safe_load"  # built from pieces so this file is not itself a use


def _tree(tmp_path: Path, files: dict[str, str], allow: str = "allow: []\n") -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (tmp_path / "tools").mkdir(exist_ok=True)
    (tmp_path / "tools" / "yaml_loader.allow.yml").write_text(allow)
    return tmp_path


def test_the_repository_holds_its_baseline():
    assert lint.main([str(REPO)]) == 0


def test_a_new_use_is_refused(tmp_path, capsys):
    root = _tree(tmp_path, {"homelabnext/a.py": f"x = {SAFE_LOAD}(t)\n"})
    assert lint.main([str(root)]) == 1
    assert "homelabnext/a.py: 1 use(s)" in capsys.readouterr().err


def test_the_loader_class_counts_and_the_budgeted_module_is_exempt(tmp_path):
    root = _tree(
        tmp_path,
        {
            "homelabnext/b.py": "import yaml\nyaml.load(t, Loader=yaml.SafeLoader)\n",
            "homelabnext/_yaml.py": "class BudgetedLoader(yaml.SafeLoader): ...\n",
        },
    )
    assert lint.counts(root) == {"homelabnext/b.py": 1}


def test_a_count_above_or_below_the_baseline_fails(tmp_path, capsys):
    allow = "allow:\n  - path: homelabnext/a.py\n    count: 2\n    reason: old\n"
    root = _tree(tmp_path, {"homelabnext/a.py": f"x = {SAFE_LOAD}(t)\n"}, allow)
    assert lint.main([str(root)]) == 1
    assert "lower its count" in capsys.readouterr().err
    (root / "homelabnext/a.py").write_text(f"x = {SAFE_LOAD}(t)\ny = {SAFE_LOAD}(u)\n")
    assert lint.main([str(root)]) == 0
    (root / "homelabnext/a.py").write_text(f"x = {SAFE_LOAD}(t)\n" * 3)
    assert lint.main([str(root)]) == 1


def test_a_malformed_allowlist_is_a_usage_error(tmp_path):
    root = _tree(tmp_path, {}, "allow:\n  - path: homelabnext/a.py\n    reason: x\n")
    assert lint.main([str(root)]) == 2
