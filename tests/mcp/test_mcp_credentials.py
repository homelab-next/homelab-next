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

#: (args, settings) of a record: each one carries a literal credential (or a $ a client expands)
FOUND = [
    # camelCase and short credential flags
    (["--githubToken", "fakeshort1"], {}),
    (["--clientSecret", "fakeabc"], {}),
    (["--authToken", "fakexyz"], {}),
    (["--accessToken=fakeq"], {}),
    (["-p", "fakehunter2"], {}),
    (["-u", "admin:fakehunter2"], {}),
    (["-k", "fakesekrit"], {}),
    (["--cookie", "sess=fake1"], {}),
    (["--auth", "user:fakepw"], {}),
    (["--api-key=fakeshort"], {}),
    (["--github-token", "fakeGhTokenAbCdEf0123456789xyz"], {}),
    (["--header", "Authorization: Bearer fakeTok3n"], {}),
    # tokens in URLs: a webhook path, an MCP URL's path, userinfo
    (["https://hooks.chat.example/services/T0/B0/fakeW3bh00kS3cr3tPathXy9"], {}),
    (["https://mcp.example/s/fakeK3yInPath9Zq7Xw2Lp5/mcp"], {}),
    (["--db", "postgres://user:fakepw@db.example/x"], {}),
    (["https://mcp.example/mcp?api_key=fakeq1"], {}),
    # what a client would expand, with a fallback value
    (["${GH:-fakefallback}"], {}),
    (["--x=${T:-fakelit}"], {}),
    # JSON, KEY=VALUE
    (["--config", '{"password": "fakepw"}'], {}),
    (["GITHUB_TOKEN=fakeAbc123"], {}),
    # an AWS-style secret key has a / in it
    (["fakeJalrXUtnFEMI/K7MDENG/bPxRfiCY3XAMPLEKEY"], {}),
    (["fakeT0kenValue9Zq7Xw2Lp5Rt8Vb"], {}),
    # settings: a token in a URL, a credential key, a credential path key without a path
    ([], {"API_URL": "https://api.example/v1/fakeK3yInPath9Zq7Xw2Lp5"}),
    ([], {"SLACK_WEBHOOK_URL": "https://hooks.chat.example/services/T0/B0/fakeW3bh00kS3cr3tPathXy9"}),
    ([], {"NOTES_SESSION": "fakex"}),
    ([], {"KEY_PATH": "fakeabcd"}),
    ([], {"AUTH": "fake-literal-auth"}),
]  # fmt: skip

#: (args, settings) of a record: none of these is a credential
ACCEPTED = [
    (["--model", "claude-3-5-sonnet-20241022"], {}),
    (["--model=gpt-4o-mini-2024-07-18"], {}),
    (["--model", "llama3.1-70b-instruct"], {}),
    (["--workspace", "01ARZ3NDEKTSV4RRFFQ69G5FAV"], {}),  # a ULID
    (["--id", "550e8400-e29b-41d4-a716-446655440000"], {}),  # a UUID
    (["--image", f"postgres@{DIGEST}"], {}),
    (["--no-auth", "--port", "8080"], {}),
    (["--token-file", "/run/secrets/x"], {}),
    (["--session-timeout", "30"], {}),
    (["--key", "/etc/ssl/k.pem"], {}),
    (["--secret-name", "prod-db"], {}),
    (["--auth", "oauth"], {}),
    (["--tokenFile=/run/secrets/x"], {}),
    (["-p", "8080"], {}),
    (["--repository", "/srv/repo"], {}),
    (["https://mcp.example/mcp"], {}),
    ([], {"GOOGLE_APPLICATION_CREDENTIALS": "/etc/gcp/sa.json"}),
    ([], {"TOKEN_FILE": "/run/secrets/x"}),
    ([], {"SESSION_DIR": "/var/lib/srv/sessions"}),
    ([], {"LOG_LEVEL": "debug", "NOTES_ROOT": "/srv/notes"}),
]  # fmt: skip

#: a foreign command line whose launch carries a credential: import maps it (or refuses to) and
#: keeps none of it; a record cannot write a launcher at all (test_mcp_launch.py)
FOREIGN = [
    ("npx", ["--token", "ghp_fakeabcdefghijklmnop0123", "@x/pkg@1.0.0"], {}),
    ("npx", ["-y", "--registry", "https://fakeuser:fakepw@npm.example/", "@x/pkg@1.0.0"], {}),
    ("uvx", ["--from", "git+https://fakeghp9876543210@git.example/org/repo", "srv"], {}),
    ("uvx", ["--index-url", "https://fakeTok3nAbC9xYz12345@pypi.example/simple", "pkg==1.0.0"], {}),
    ("sh", ["-c", "srv --pass fakehunter2 --key fakeabc"], {}),
    ("sh", ["-c", "GITHUB_TOKEN=fakeAbc123 npx foo"], {}),
    ("bash", ["-lc", "export GITHUB_TOKEN=fakeabc; srv"], {}),
    ("env", ["GITHUB_TOKEN=fakeabc", "srv"], {}),
    ("/usr/bin/env", ["GITHUB_TOKEN=fakeabc", "npx", "-y", "x@1.0.0"], {}),
    ("docker", ["run", "-i", "--env=DB_PASS=fakepw", "-eAPI_KEY=fakek", f"img@{DIGEST}"], {}),
    ("docker", ["run", "-i", "--label", "token=fakeTok3nAbC9xYz12345a", f"img@{DIGEST}"], {}),
]  # fmt: skip

#: the package every case's record launches (its bin is the package's own)
ORIGIN = {"kind": "package", "ecosystem": "npm", "package": "@example/srv", "version": "1.0.0",
          "sha256": "b" * 64}  # fmt: skip


def _record(args: list[str], settings: dict[str, str]) -> dict:
    rec = {"origin": dict(ORIGIN), "transport": {"type": "stdio", "args": list(args)}}
    if settings:
        rec["settings"] = dict(settings)
    return rec


def _check(args, settings) -> list[str]:
    rec = _record(args, settings)
    return (
        servers.launch_problems(rec, "x")
        + servers._literal_problems(rec, "x")
        + servers._template_problems(rec, "x")
    )


def _imported(command, args, settings) -> dict:
    rec, _ = importer.draft("probe", {"command": command, "args": args, "env": settings}, "t.json")
    return rec


def _client_entry(args, settings) -> tuple[str, list[str], dict[str, str]]:
    """The record as a client config holds it: the generated launch, then its arguments."""
    command, prefix = servers.launch(_record(args, settings))
    return command, [*prefix, *args], settings


def _ids(cases):
    return [f"{' '.join(c[-2])[:50]} {' '.join(c[-1])}" for c in cases]


@pytest.mark.parametrize(("args", "settings"), FOUND, ids=_ids(FOUND))
def test_check_refuses_and_import_strips_every_credential_shape(args, settings):
    assert _check(args, settings), "check accepted a literal credential"
    rec = _imported(*_client_entry(args, settings))
    assert "fake" not in json.dumps(rec).lower(), rec


@pytest.mark.parametrize(("args", "settings"), ACCEPTED, ids=_ids(ACCEPTED))
def test_check_accepts_and_import_keeps_what_is_not_a_credential(args, settings):
    assert _check(args, settings) == []
    rec = _imported(*_client_entry(args, settings))
    assert rec["origin"]["package"] == ORIGIN["package"]
    assert rec["transport"].get("args", []) == args
    assert rec.get("settings", {}) == settings and not rec.get("env")


@pytest.mark.parametrize(("command", "args", "settings"), FOREIGN, ids=_ids(FOREIGN))
def test_import_keeps_no_credential_from_a_launch_it_maps_or_refuses(command, args, settings):
    rec = _imported(command, args, settings)
    assert "fake" not in json.dumps(rec).lower(), rec


def test_the_launch_position_is_not_taken_from_a_flag_value():
    rec = _imported("npx", ["--token", "ghp_fakeabcdefghijklmnop0123", "@x/pkg@1.0.0"], {})
    assert rec["origin"]["kind"] == "unknown"  # an unknown flag before it: not mapped


def test_a_url_setting_keeps_its_host_and_an_env_default_names_its_variable():
    rec = _imported("npx", ["-y", "--", "@x/srv@1.0.0", "${GH_TOKEN:-x}"],
                    {"API_URL": "https://api.example/v1/data"})  # fmt: skip
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
