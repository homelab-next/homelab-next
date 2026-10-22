# SPDX-License-Identifier: Apache-2.0
"""One credential rule for both directions (homelabnext/mcp/credentials.py): every shape in
FOUND is refused by ``catalog check`` *and* stripped by ``catalog import``; every shape in
ACCEPTED passes check *and* comes back from import unchanged.  A rule loosened to clear a false
positive fails a FOUND case, and one tightened to catch a bypass fails an ACCEPTED case, so the
two lists cannot regress against each other.  Every value is fictional; every credential-shaped
one contains "fake"."""

from __future__ import annotations

import json

import pytest

from homelabnext.mcp import credentials, importer, servers

DIGEST = "sha256:b77c4fdf59bc86d60de78a824ecc899f1dc358911341c04a9e763b1c9512ca8b"
COMMIT = "1caefa50d0a295c3adda038a408225769f771836"

#: (command, args, settings): each one carries a literal credential (or a $ a client expands)
FOUND = [
    # camelCase and short credential flags
    ("srv", ["--githubToken", "fakeshort1"], {}),
    ("srv", ["--clientSecret", "fakeabc"], {}),
    ("srv", ["--authToken", "fakexyz"], {}),
    ("srv", ["--accessToken=fakeq"], {}),
    ("srv", ["-p", "fakehunter2"], {}),
    ("srv", ["-u", "admin:fakehunter2"], {}),
    ("srv", ["-k", "fakesekrit"], {}),
    ("srv", ["--cookie", "sess=fake1"], {}),
    ("srv", ["--auth", "user:fakepw"], {}),
    ("srv", ["--api-key=fakeshort"], {}),
    ("srv", ["--github-token", "fakeGhTokenAbCdEf0123456789xyz"], {}),
    ("srv", ["--header", "Authorization: Bearer fakeTok3n"], {}),
    # tokens in URLs: a webhook path, an MCP URL's path, userinfo
    ("srv", ["https://hooks.chat.example/services/T0/B0/fakeW3bh00kS3cr3tPathXy9"], {}),
    ("mcp-remote", ["https://mcp.example/s/fakeK3yInPath9Zq7Xw2Lp5/mcp"], {}),
    ("srv", ["--db", "postgres://user:fakepw@db.example/x"], {}),
    ("srv", ["https://mcp.example/mcp?api_key=fakeq1"], {}),
    # what a client would expand, with a fallback value
    ("srv", ["${GH:-fakefallback}"], {}),
    ("srv", ["--x=${T:-fakelit}"], {}),
    # a launcher flag's value is never the package (npx --token X pkg)
    ("npx", ["--token", "ghp_fakeabcdefghijklmnop0123", "@x/pkg@1.0.0"], {}),
    ("uvx", ["--from", "git+https://fakeghp9876543210@git.example/org/repo", "srv"], {}),
    # shell lines, JSON, a container's -e
    ("sh", ["-c", "srv --pass fakehunter2 --key fakeabc"], {}),
    ("sh", ["-c", "GITHUB_TOKEN=fakeAbc123 npx foo"], {}),
    ("srv", ["--config", '{"password": "fakepw"}'], {}),
    ("docker", ["run", "-i", "--env=DB_PASS=fakepw", "-eAPI_KEY=fakek", f"img@{DIGEST}"], {}),
    # an AWS-style secret key has a / in it
    ("srv", ["fakeJalrXUtnFEMI/K7MDENG/bPxRfiCY3XAMPLEKEY"], {}),
    ("srv", ["fakeT0kenValue9Zq7Xw2Lp5Rt8Vb"], {}),
    # settings: a token in a URL, a credential key, a credential path key without a path
    ("srv", [], {"API_URL": "https://api.example/v1/fakeK3yInPath9Zq7Xw2Lp5"}),
    ("srv", [], {"SLACK_WEBHOOK_URL": "https://hooks.chat.example/services/T0/B0/fakeW3bh00kS3cr3tPathXy9"}),
    ("srv", [], {"NOTES_SESSION": "fakex"}),
    ("srv", [], {"KEY_PATH": "fakeabcd"}),
    ("srv", [], {"AUTH": "fake-literal-auth"}),
]  # fmt: skip

#: (command, args, settings): none of these is a credential
ACCEPTED = [
    ("srv", ["--model", "claude-3-5-sonnet-20241022"], {}),
    ("srv", ["--model=gpt-4o-mini-2024-07-18"], {}),
    ("srv", ["--model", "llama3.1-70b-instruct"], {}),
    ("srv", ["--workspace", "01ARZ3NDEKTSV4RRFFQ69G5FAV"], {}),  # a ULID
    ("srv", ["--id", "550e8400-e29b-41d4-a716-446655440000"], {}),  # a UUID
    ("srv", ["--image", f"postgres@{DIGEST}"], {}),
    ("srv", ["--no-auth", "--port", "8080"], {}),
    ("srv", ["--token-file", "/run/secrets/x"], {}),
    ("srv", ["--session-timeout", "30"], {}),
    ("srv", ["--key", "/etc/ssl/k.pem"], {}),
    ("srv", ["--secret-name", "prod-db"], {}),
    ("srv", ["--auth", "oauth"], {}),
    ("srv", ["--tokenFile=/run/secrets/x"], {}),
    ("srv", ["-p", "8080"], {}),
    ("srv", ["--repository", "/srv/repo"], {}),
    ("mcp-remote", ["https://mcp.example/mcp"], {}),
    ("docker", ["run", "-i", "--rm", "-p", "8080:80", "-u", "1000", "-e", "LOG_LEVEL=debug",
                f"registry.example/mcp/x@{DIGEST}", "--read-only"], {}),
    ("uvx", ["--from", "example-notes-mcp==1.2.0", "notes-mcp"], {}),
    ("npx", ["-y", "@example/mcp-github@3.2.0"], {}),
    ("uvx", ["--from", f"git+https://code.example/org/srv@{COMMIT}", "srv"], {}),
    ("srv", [], {"GOOGLE_APPLICATION_CREDENTIALS": "/etc/gcp/sa.json"}),
    ("srv", [], {"TOKEN_FILE": "/run/secrets/x"}),
    ("srv", [], {"SESSION_DIR": "/var/lib/srv/sessions"}),
    ("srv", [], {"LOG_LEVEL": "debug", "NOTES_ROOT": "/srv/notes"}),
]  # fmt: skip


def _record(command: str, args: list[str], settings: dict[str, str]) -> dict:
    rec = {"transport": {"type": "stdio", "command": command, "args": list(args)}}
    if settings:
        rec["settings"] = dict(settings)
    return rec


def _check(command, args, settings) -> list[str]:
    rec = _record(command, args, settings)
    return servers._literal_problems(rec, "x") + servers._template_problems(rec, "x")


def _imported(command, args, settings) -> dict:
    rec, _ = importer.draft("probe", {"command": command, "args": args, "env": settings}, "t.json")
    return rec


def _ids(cases):
    return [f"{c} {' '.join(a)[:50]} {' '.join(s)}" for c, a, s in cases]


@pytest.mark.parametrize(("command", "args", "settings"), FOUND, ids=_ids(FOUND))
def test_check_refuses_and_import_strips_every_credential_shape(command, args, settings):
    assert _check(command, args, settings), "check accepted a literal credential"
    rec = _imported(command, args, settings)
    assert "fake" not in json.dumps(rec).lower(), rec


@pytest.mark.parametrize(("command", "args", "settings"), ACCEPTED, ids=_ids(ACCEPTED))
def test_check_accepts_and_import_keeps_what_is_not_a_credential(command, args, settings):
    assert _check(command, args, settings) == []
    rec = _imported(command, args, settings)
    assert rec["transport"]["args"] == args
    assert rec.get("settings", {}) == settings and not rec.get("env")


def test_the_launch_position_is_not_taken_from_a_flag_value():
    rec = _imported("npx", ["--token", "ghp_fakeabcdefghijklmnop0123", "@x/pkg@1.0.0"], {})
    assert rec["origin"]["package"] == "@x/pkg" and rec["origin"]["version"] == "1.0.0"


def test_a_url_setting_keeps_its_host_and_an_env_default_names_its_variable():
    rec = _imported("srv", ["${GH_TOKEN:-x}"], {"API_URL": "https://api.example/v1/data"})
    assert rec["settings"] == {"API_URL": "https://api.example"}
    assert rec["transport"]["args"] == ["secret:mcp/gh-token"]


def test_looks_secret_both_ways():
    assert credentials.looks_secret("ghp_fakeabcdefghijklmnop0123")  # a token prefix
    assert credentials.looks_secret("fakeJalrXUtnFEMI/K7MDENG/bPxRfiCY3XAMPLEKEY")
    assert not credentials.looks_secret("homelabnext/mcp/servers/2024")  # a path-ish name
    assert not credentials.looks_secret(f"registry.example/mcp/x@{DIGEST}")
    assert credentials.credential_name("--githubToken")
    assert credentials.credential_name("DB_PASSWORD")
    assert not credentials.credential_name("--no-auth")
    assert not credentials.credential_name("--token-file")
