# SPDX-License-Identifier: Apache-2.0
"""tools/shared_helpers_lint.py (checklist M-03): private notify/state/lake helpers are found."""

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shared_helpers_lint as lint

REPO = Path(__file__).resolve().parents[2]


def _rules(src: str) -> list[str]:
    return [f.rule for f in lint.lint_source(textwrap.dedent(src))]


@pytest.mark.parametrize(
    ("src", "rule"),
    [
        (
            """
            import urllib.request
            def page(msg):
                req = urllib.request.Request("https://ntfy.example.internal/ops", data=msg)
                urllib.request.urlopen(req)
            """,
            "notify",
        ),
        (
            """
            import requests
            def alert(url, msg):
                requests.post(url, data=msg, headers={"Priority": "5", "Tags": "warning"})
            """,
            "notify",
        ),
        ("import smtplib\n", "notify"),
        (
            """
            import json, os
            def save(path, doc):
                tmp = path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(doc, f)
                os.replace(tmp, path)
            """,
            "state",
        ),
        (
            """
            import json
            def remember(state_file, doc):
                state_file.write_text(json.dumps(doc))
            """,
            "state",
        ),
        (
            """
            import json
            def remember(doc):
                with open("/var/lib/check/last.state.json", "w") as f:
                    json.dump(doc, f)
            """,
            "state",
        ),
        ("import trino.dbapi\n", "lake"),
        ("from duckdb import connect\n", "lake"),
        ("import sqlite3\n", "lake"),
        ("from pyiceberg.catalog import load_catalog\n", "lake"),
        ('URL = "/v1/statement"\n', "lake"),
    ],
)
def test_flags_private_helpers(src, rule):
    assert rule in _rules(src), src


@pytest.mark.parametrize(
    "src",
    [
        '"""Pages through ntfy via the shared notifier."""\nfrom homelabnext.notify import Notifier\n',
        "import urllib.request\ndef fetch(u):\n    return urllib.request.urlopen(u).read()\n",
        "import json\ndef report(out, doc):\n    out.write_text(json.dumps(doc))\n",
        "from homelabnext.state import StateStore\nStateStore('x.json').set('k', 1)\n",
        "from homelabnext.lake import FakeLake\nFakeLake().query('SELECT 1')\n",
    ],
)
def test_allows_shared_library_use(src):
    assert _rules(src) == [], src


def _tree(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return tmp_path


def test_bad_tree_fails_and_allowlist_with_reason_passes(tmp_path, capsys):
    root = _tree(tmp_path, {"pkg/pager.py": "import smtplib\n"})
    assert lint.main([str(root)]) == 1
    assert "[notify]" in capsys.readouterr().err
    (root / "tools").mkdir()
    (root / lint.DEFAULT_ALLOWLIST).write_text(
        "allow:\n  - {path: pkg/pager.py, rule: notify, reason: fake reviewed exemption}\n"
    )
    assert lint.main([str(root)]) == 0


def test_owners_and_tests_are_out_of_scope(tmp_path):
    root = _tree(
        tmp_path,
        {
            "homelabnext/lake/fake.py": "import sqlite3\n",
            "tests/lake/test_x.py": "import duckdb\n",
            "pkg/test_y.py": "import smtplib\n",
        },
    )
    assert lint.main([str(root)]) == 0


def test_stale_entry_and_missing_reason(tmp_path, capsys):
    root = _tree(tmp_path, {"pkg/ok.py": "x = 1\n"})
    allow = root / "allow.yml"
    allow.write_text("allow:\n  - {path: pkg/ok.py, rule: lake, reason: fake stale entry}\n")
    assert lint.main([str(root), "--allowlist", str(allow)]) == 1
    assert "stale" in capsys.readouterr().err
    allow.write_text("allow:\n  - {path: pkg/ok.py, rule: lake}\n")
    assert lint.main([str(root), "--allowlist", str(allow)]) == 2


def test_the_repository_has_no_private_helpers():
    assert lint.main([str(REPO)]) == 0
