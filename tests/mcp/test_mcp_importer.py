# SPDX-License-Identifier: Apache-2.0
"""``hnx mcp catalog import``: an existing lab's client configs (every shape below is fictional)
become draft records with no literal secret in them or in the report, and the drafts fail the
catalog check until the maintainer pins, classifies and maps them."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from homelabnext import cli
from homelabnext.mcp import importer, servers
from homelabnext.registry.model import load

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "fakeTok3nValue9Zq7Xw2Lp5Rt8Vb1Nm4"  # a fake credential: never copied anywhere
PASSWORD = "fake-Pa55word-Q8z1"

CLAUDE_CODE = {
    "mcpServers": {
        "Notes Store": {"command": "npx", "args": ["-y", "@example/notes-mcp@1.4.0"],
                        "env": {"NOTES_API_TOKEN": TOKEN, "NOTES_ROOT": "/srv/notes"}},
        "search": {"command": "uvx", "args": ["example-search-mcp", "--api-key", TOKEN],
                   "env": {"SEARCH_KEY": "${SEARCH_KEY}"}},
        "remote-lake": {"type": "http", "url": "https://lake-query.lab.example/mcp?x=1",
                        "headers": {"Authorization": f"Bearer {TOKEN}"}},
    }
}  # fmt: skip
DESKTOP = {
    "mcpServers": {
        "box": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "X=1",
                                              "registry.example/mcp/box@sha256:" + "a" * 64]},
        "local-tool": {"command": "/opt/tools/venv/bin/local-tool", "args": [f"--password={PASSWORD}"],
                       "description": "A local script."},
        "search": {"command": "uvx", "args": ["other"]},
    }
}  # fmt: skip
CLAUDE_JSON = {
    "projects": {
        "/work/repo": {"mcpServers": {"proj": {"command": "hnx", "args": ["mcp", "serve"]}}}
    }
}
HERMES = {"mcp_servers": {"events": {"type": "sse", "url": "https://bus.lab.example/sse"}}}


def _write(tmp_path: Path) -> list[Path]:
    files = []
    for name, doc in (("mcp.json", CLAUDE_CODE), ("claude_desktop_config.json", DESKTOP),
                      ("claude.json", CLAUDE_JSON)):  # fmt: skip
        (tmp_path / name).write_text(json.dumps(doc))
        files.append(tmp_path / name)
    (tmp_path / "hermes.yaml").write_text(yaml.safe_dump(HERMES))
    return [*files, tmp_path / "hermes.yaml"]


def test_drafts_carry_no_secret_and_the_report_names_each_one(tmp_path, capsys):
    out = tmp_path / "catalog"
    args = ["mcp", "catalog", "import", *map(str, _write(tmp_path)), "--out", str(out)]
    assert cli.main(args) == 0
    report = capsys.readouterr()
    written = {f.stem: yaml.safe_load(f.read_text()) for f in out.glob("*.yml")}
    assert sorted(written) == [
        "box",
        "events",
        "local-tool",
        "notes-store",
        "proj",
        "remote-lake",
        "search",
    ]
    every = "".join(f.read_text() for f in out.glob("*.yml")) + report.out + report.err
    assert TOKEN not in every and PASSWORD not in every  # never copied, never printed
    notes = written["notes-store"]
    assert notes["env"] == {"NOTES_API_TOKEN": "secret:mcp/notes-store-notes-api-token"}
    assert notes["settings"] == {"NOTES_ROOT": "/srv/notes"}  # not a credential: kept, flagged
    assert "env NOTES_ROOT kept as a setting: confirm it is not a credential" in report.out
    assert notes["origin"] == {"kind": "package", "ecosystem": "npm", "package": "@example/notes-mcp",
                               "version": "1.4.0", "sha256": None}  # fmt: skip
    assert written["search"]["env"] == {"SEARCH_KEY": "secret:mcp/search-key"}
    assert written["search"]["transport"]["args"] == [
        "example-search-mcp",
        "--api-key",
        "secret:mcp/search-arg-2",
    ]
    assert "search: also in claude_desktop_config.json; kept the first" in report.out
    lake = written["remote-lake"]
    assert lake["transport"] == {
        "type": "streamable-http",
        "endpoint": "svc:lake-query",
        "path": "/mcp",
    }
    assert lake["headers"] == {"Authorization": "Bearer secret:mcp/remote-lake-authorization"}
    assert "lab.example" not in (out / "remote-lake.yml").read_text()  # the URL is not copied
    assert written["box"]["origin"]["digest"] == "sha256:" + "a" * 64
    assert written["local-tool"]["transport"]["args"] == [
        "--password=secret:mcp/local-tool-password"
    ]
    assert written["local-tool"]["origin"]["kind"] == "unknown"
    assert written["proj"]["origin"] == {"kind": "first-party", "path": "homelabnext/"}
    assert written["events"]["transport"]["type"] == "sse"
    assert {r["status"] for r in written.values()} == {"draft"}


def test_drafts_fail_the_check_until_pinned_and_classified(tmp_path):
    out = tmp_path / "catalog"
    res = importer.import_configs(_write(tmp_path))
    importer.write_records(res.records, out)
    problems = servers.check(servers.load(out), registry=load(ROOT / "examples" / "services.yml"))
    text = "\n".join(problems)
    assert "notes-store.yml: package @example/notes-mcp has no sha256" in text
    assert "local-tool.yml: origin is unknown" in text
    assert "lists no tools" in text
    assert "remote-lake.yml: endpoint svc:lake-query speaks" not in text  # a real http service
    assert "events.yml: endpoint svc:bus is not a registry service" in text
    # every draft is valid against the schema (only the semantic rules fail)
    assert not [p for p in problems if ": $" in p or "is not valid" in p]


def test_existing_records_are_kept_unless_forced(tmp_path):
    out = tmp_path / "catalog"
    out.mkdir()
    (out / "box.yml").write_text("keep: me\n")
    res = importer.import_configs(_write(tmp_path))
    _, skipped = importer.write_records(res.records, out)
    assert (out / "box.yml").read_text() == "keep: me\n" and "exists" in skipped[0]
    importer.write_records(res.records, out, force=True)
    assert "keep: me" not in (out / "box.yml").read_text()


def test_looks_secret():
    assert importer.looks_secret(TOKEN)
    assert importer.looks_secret("postgres://user:fake-pw@db.lab.example/x")
    assert not importer.looks_secret("/srv/notes/agents") and not importer.looks_secret("info")
