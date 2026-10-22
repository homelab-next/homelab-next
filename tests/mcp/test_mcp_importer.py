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
                               "version": "1.4.0", "sha256": None,
                               "bins": ["notes-mcp"]}  # fmt: skip
    assert "origin.bins ['notes-mcp'] is what the config ran" in report.out  # for review
    assert written["search"]["env"] == {"SEARCH_KEY": "secret:mcp/search-key"}
    assert written["search"]["transport"] == {
        "type": "stdio",
        "args": ["--api-key", "secret:mcp/search-arg-2"],
    }
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
    # a path is not a launch a record can name: nothing of its command line is copied
    assert written["local-tool"]["transport"] == {"type": "stdio"}
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


# --------------------------------------------------------------- fail closed, round trip
SHAPES = {
    "mcpServers": {
        "remote-hdr": {"command": "npx", "args": ["-y", "mcp-remote@1.2.3", "https://mcp.lab.example/sse",
                                                  "--header", "Authorization: Bearer fakeTok3n"]},
        "zap": {"url": "https://zap.lab.example/api/mcp/s/fakePathSecret123/mcp?key=fakeq"},
        "uvxgit": {"command": "uvx", "args": ["--from", "git+https://fakeghp9876543210@git.lab.example/org/srv", "srv"]},
        "uvxgit2": {"command": "uvx", "args": ["--from", "git+https://user:fakepw@git.lab.example/org/srv", "srv"]},
        "dock": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "API_KEY=fakeshort", "-e", "LOG_LEVEL=debug", "img/x"]},
        "flags": {"command": "npx", "args": ["-y", "@example/flags-mcp@1.0.0", "--github-token", "fakeghpshort", "--db-password=fakehunter2",
                                             "--client-secret", "fakeabc"]},
        "shc": {"command": "sh", "args": ["-c", "GITHUB_TOKEN=fakeAbc123 npx foo"]},
        "envs": {"command": "srv", "env": {"DB_PASSPHRASE": "fakepp", "AUTH": "fakeauthval",
                                           "OPENAI_KEY": "fake-sk-1", "PAT": "fakepat",
                                           "CONN": "Server=x;Password=fakepw;", "DATA_DIR": "/srv/data",
                                           "SA": '{"private_key": "fake -----BEGIN"}', "NESTED": {"token": "fakenested"}}},
        "desc": {"command": "srv", "description": "token is fakeDescTok"},
        "pinned": {"command": "uvx", "args": ["--from", "example-notes-mcp==1.2.0", "notes-mcp"]},
        "pinned2": {"command": "uvx", "args": ["mcp-server-git==0.6.2", "--repository", "/srv/repo"]},
        "pinned3": {"command": "npx", "args": ["-y", "@example/mcp-github@3.2.0"]},
    }
}  # fmt: skip


def test_every_credential_shape_is_stripped_and_pinned_packages_are_kept(tmp_path, capsys):
    src = tmp_path / "cfg.json"
    src.write_text(json.dumps(SHAPES))
    out = tmp_path / "drafts"
    assert cli.main(["mcp", "catalog", "import", str(src), "--out", str(out)]) == 0
    report = capsys.readouterr()
    text = "".join(f.read_text() for f in out.glob("*.yml")) + report.out + report.err
    assert "fake" not in text.lower()  # no value anywhere: drafts, report
    rec = {f.stem: yaml.safe_load(f.read_text()) for f in out.glob("*.yml")}
    assert rec["flags"]["transport"]["args"] == [
        "--github-token", "secret:mcp/flags-arg-2", "--db-password=secret:mcp/flags-db-password",
        "--client-secret", "secret:mcp/flags-arg-5"]  # fmt: skip
    assert rec["flags"]["origin"]["package"] == "@example/flags-mcp"
    assert rec["remote-hdr"]["transport"]["args"][-1] == (
        "Authorization: Bearer secret:mcp/remote-hdr-header-authorization"
    )
    assert rec["uvxgit"]["origin"] == {"kind": "git", "ecosystem": "pypi",
        "repo": "https://git.lab.example/org/srv", "commit": None, "bins": ["srv"]}  # fmt: skip
    assert rec["uvxgit2"]["origin"]["repo"] == "https://git.lab.example/org/srv"
    assert rec["uvxgit2"]["transport"] == {"type": "stdio", "bin": "srv"}
    assert rec["dock"]["env"] == {"API_KEY": "secret:mcp/dock-api-key"}
    assert rec["dock"]["settings"] == {"LOG_LEVEL": "debug"}  # the runner's -e: the environment
    assert rec["dock"]["transport"] == {"type": "stdio"}
    assert rec["shc"]["transport"] == {"type": "stdio"}  # a shell line: not mapped, not copied
    assert rec["envs"]["settings"] == {"DATA_DIR": "/srv/data"}  # an allowlisted key only
    assert set(rec["envs"]["env"]) == {"DB_PASSPHRASE", "AUTH", "OPENAI_KEY", "PAT", "CONN", "SA",
                                       "NESTED"}  # fmt: skip
    assert "path" not in rec["zap"]["transport"]
    assert rec["desc"]["description"].startswith("Imported from cfg.json")
    # a pinned package spec is the package, never a secret
    assert rec["pinned"]["transport"] == {"type": "stdio", "bin": "notes-mcp"}
    assert rec["pinned2"]["transport"] == {"type": "stdio", "args": ["--repository", "/srv/repo"]}
    assert rec["pinned2"]["origin"]["version"] == "0.6.2"
    assert rec["pinned3"]["transport"] == {"type": "stdio"}
    assert rec["pinned3"]["origin"]["version"] == "3.2.0"
    assert not importer.looks_secret("example-notes-mcp==1.2.0")


def test_a_config_that_does_not_parse_is_named_by_line_never_quoted(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        'mcp_servers:\n  x:\n    env:\n      API_TOKEN: "fakeSecretValue123\n      foo: [\n'
    )
    shape = tmp_path / "shape.yaml"
    shape.write_text("mcp_servers:\n  x:\n    command: srv\n    env: [fakeListSecret]\n")
    for f, phrase in ((bad, "not valid YAML (line"), (shape, "env is not a mapping")):
        assert cli.main(["mcp", "catalog", "import", str(f), "--out", str(tmp_path / "o")]) == 2
        err = capsys.readouterr()
        assert phrase in err.err and "fake" not in err.out + err.err
    # --out is required: a draft never lands in a catalog (or a public checkout) by default
    assert cli.main(["mcp", "catalog", "import", str(bad)]) == 2


def test_a_rendered_record_imports_back_to_the_same_server(tmp_path):
    import shutil

    from homelabnext.agent.compiler import CeilingPolicy
    from homelabnext.mcp import clients

    d = tmp_path / "mcp"
    shutil.copytree(ROOT / "examples" / "mcp", d, ignore=shutil.ignore_patterns("clients"))
    gh = yaml.safe_load((d / "github.yml").read_text())
    gh["timeout"] = 45
    (d / "github.yml").write_text(yaml.safe_dump(gh))
    prof = tmp_path / "p.json"
    doc = json.loads((ROOT / "examples/mcp/clients/profile.collector.json").read_text())
    prof.write_text(json.dumps({**doc, "mcp": ["github"], "mcp_ceiling": ["github"],
                                "reads_untrusted": False}))  # fmt: skip
    policy = CeilingPolicy.from_mapping(
        {"ceilings": {"profile:collector": {"mcp": ["github"], "capabilities": doc["capabilities"],
                                            "tier": "write", "budgets": doc["budgets"]}}}
    )  # fmt: skip
    text, _ = clients.render_profile(
        servers.load(d), prof, "hermes", policy=policy, npm_prefix="/var/lib/hnx/npm-prefix"
    )
    rendered = tmp_path / "config.yaml"
    rendered.write_text(text)
    back = importer.import_configs([rendered]).records["github"]
    assert back["transport"] == gh["transport"]
    assert back["env"] == gh["env"]  # ${HNX_SECRET_MCP_GITHUB_TOKEN} -> secret:mcp/github-token
    assert back["timeout"] == 45
    assert {k: back["origin"][k] for k in ("package", "version")} == {
        "package": "@example/mcp-github", "version": "3.2.0"}  # fmt: skip
