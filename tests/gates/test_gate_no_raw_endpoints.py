# SPDX-License-Identifier: Apache-2.0
"""The no-raw-endpoints gate: fails planted literals, honours the allowlist, passes this repo.

Literals are assembled at run time so this file itself contains none.
"""

import io
import json
from pathlib import Path

import no_raw_endpoints as gate
import pytest

ROOT = Path(__file__).resolve().parents[2]
DOT = "."
IP_PRIV = DOT.join(["192", "168", "7", "20"])
IP_10 = DOT.join(["10", "0", "0", "5"])
IP_DOC = DOT.join(["198", "51", "100", "7"])
IP_LOOP = DOT.join(["127", "0", "0", "1"])
HOST_PORT = "db" + DOT + "lab" + DOT + "internal" + ":5432"
URL_PORT = "https://" + "vault" + DOT + "example" + DOT + "com" + ":8200/v1"
LOCAL = "local" + "host" + ":8080"


def run(root, *args):
    out, err = io.StringIO(), io.StringIO()
    rc = gate.main([str(root), *args], out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


def plant(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


PLANTED = {
    "app/client.py": f'ENDPOINT = "http://{IP_PRIV}:8080/api"\n',
    "app/config.yml": f"host: {IP_10}\n",
    "app/doc_range.py": f'ADDR = "{IP_DOC}"\n',
    "app/loop.sh": f"curl {IP_LOOP}\n",
    "app/db.ini": f"dsn = {HOST_PORT}\n",
    "app/vault.toml": f'url = "{URL_PORT}"\n',
    "app/dev.js": f'fetch("http://{LOCAL}/x")\n',
}


@pytest.mark.parametrize("rel", sorted(PLANTED))
def test_each_planted_literal_fails(tmp_path, rel):
    plant(tmp_path, {rel: PLANTED[rel]})
    rc, out, err = run(tmp_path)
    assert rc == 1, (out, err)
    assert rel in err


def test_all_planted_reported_with_line_and_rule(tmp_path):
    plant(tmp_path, PLANTED)
    rc, out, _err = run(tmp_path, "--json")
    assert rc == 1
    doc = json.loads(out)
    assert {f["path"] for f in doc["findings"]} == set(PLANTED)
    assert {"ipv4", "host-port", "url-port"} <= {f["rule"] for f in doc["findings"]}
    assert all(f["line"] == 1 for f in doc["findings"])


CLEAN = {
    "app/client.py": "from homelabnext.registry import resolve\nep = resolve('lake-query')\n",
    "app/versions.txt": "pkg==" + DOT.join("1234") + "\nversion " + DOT.join("5678") + "\n",
    "app/bind.conf": "listen = 0.0.0.0\n",
    "app/time.log": "12:30:45 started at example.internal\n",
    "docs/link.md": "see https://example.com/docs and https://example.com\n",
    "app/blob.bin": "\0\0" + f"{IP_PRIV}",
}


def test_clean_tree_passes(tmp_path):
    plant(tmp_path, {k: v for k, v in CLEAN.items() if k != "app/blob.bin"})
    (tmp_path / "app" / "blob.bin").write_bytes(b"\0\0" + IP_PRIV.encode())
    rc, out, err = run(tmp_path)
    assert rc == 0, err
    assert "0 violation" in out


def test_allowlist_glob_with_reason_is_honoured(tmp_path):
    plant(tmp_path, {"examples/lab.yml": f"a: {IP_DOC}\n", "app/x.py": f"a = '{IP_DOC}'\n"})
    (tmp_path / "tools").mkdir()
    (tmp_path / gate.DEFAULT_ALLOWLIST).write_text(
        "allow:\n  - path: 'examples/**'\n    reason: synthetic data\n"
    )
    rc, _, err = run(tmp_path)
    assert rc == 1 and "app/x.py" in err and "examples/lab.yml" not in err
    plant(tmp_path, {"app/x.py": "a = 1\n"})
    assert run(tmp_path)[0] == 0


def test_allowlist_without_reason_is_refused(tmp_path):
    plant(tmp_path, {"app/x.py": "a = 1\n"})
    (tmp_path / "tools").mkdir()
    (tmp_path / gate.DEFAULT_ALLOWLIST).write_text("allow:\n  - path: 'app/**'\n")
    rc, _, err = run(tmp_path)
    assert rc == 2 and "no 'reason'" in err


def test_missing_explicit_allowlist_and_bad_root(tmp_path):
    assert run(tmp_path, "--allowlist", str(tmp_path / "nope.yml"))[0] == 2
    assert run(tmp_path / "absent")[0] == 2


def test_inline_allow_needs_a_reason(tmp_path):
    plant(
        tmp_path,
        {
            "ok.py": f"A = '{IP_DOC}'  # no-raw-endpoint: allow documentation example\n",
            "bad.py": f"A = '{IP_DOC}'  # no-raw-endpoint: allow\n",
        },
    )
    rc, _, err = run(tmp_path)
    assert rc == 1 and "bad.py" in err and "ok.py" not in err


def test_census_counts_and_never_fails(tmp_path):
    plant(tmp_path, PLANTED)
    rc, out, _ = run(tmp_path, "--census", "--json")
    assert rc == 0
    doc = json.loads(out)
    assert (
        doc["total"] >= len(PLANTED)
        and doc["by_rule"]["ipv4"] >= 3
        and len(doc["by_file"]) == len(PLANTED)
    )
    rc, text, _ = run(tmp_path, "--census")
    assert rc == 0 and text.startswith("raw endpoints:")


def test_skip_dirs_are_not_scanned(tmp_path):
    plant(tmp_path, {".git/hook": f"{IP_PRIV}\n", "node_modules/x.js": f"{IP_PRIV}\n"})
    assert run(tmp_path)[0] == 0


def test_url_with_ip_reports_once(tmp_path):
    plant(tmp_path, {"a.py": f"u = 'http://{IP_PRIV}:80'\n"})
    findings, _ = gate.scan_tree(tmp_path, [])
    assert len(findings) == 1 and findings[0].rule == "url-port"


def test_this_repo_passes_with_zero():
    rc, out, err = run(ROOT)
    assert rc == 0, err
    rc, out, _ = run(ROOT, "--census", "--json")
    assert json.loads(out)["total"] == 0
