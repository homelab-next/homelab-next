# SPDX-License-Identifier: Apache-2.0
"""Fixture tests for tools/leak_scan.py.

Planted values are assembled at run time so this file itself stays clean under the scanner.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCAN = ROOT / "tools" / "leak_scan.py"
sys.path.insert(0, str(ROOT / "tools"))
import leak_scan


def dot(*parts: object) -> str:
    return ".".join(str(p) for p in parts)


PLANTED = {
    "private-ipv4": f"server = {dot(192, 168, 1, 50)}",
    "private-ipv4-10": f"gw: {dot(10, 0, 0, 1)}",
    "private-ipv4-172": f"net {dot(172, 20, 3, 4)}",
    "cgnat-tailnet-ipv4": f"peer {dot(100, 100, 100, 100)}",
    "public-ipv4": f"upstream {dot(11, 22, 33, 44)}",
    "ipv6-compressed": "addr " + ":".join(["2600", "abcd", "", "1"]),
    "private-tld": "url = https://wiki." + "lab" + "." + "ho" + "me" + "/x",
    "private-tld-lan": "host nas." + "la" + "n",
    "email": "contact: someone" + "@" + "mailhost." + "io",
    # locally administered (02:...) and synthetic; the documentation range is tested as clean
    "mac-address": "mac " + ":".join(["02", "00", "00", "aa", "bb", "cc"]),
    "aws-access-key": "key = " + "AKIA" + "ABCDEFGHIJKLMNOP",
    "private-key-block": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "github-token": "t = gh" + "p_" + "a1B2c3D4e5F6g7H8" + "i9J0k1L2m3N4o5P6q7R8",
    "slack-token": "x = xox" + "b-1234567890-abcdefghij",
    "workstation-path": "cd /mnt/c/" + "Users/someone/src",
    "secret-name": "pw: {{ vault" + "_db_password }}",
    "keyed-secret": "db_pass" + "word: " + "Tr0ub4dor" + "&3",
    "vault-blob": "$ANSIBLE" + "_VAULT;1.1;AES256",
    "age-secret-key": "AGE-SECRET-" + "KEY-1" + ("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" * 2)[:58],
    "high-entropy-string": "api_key_value " + "Zx9Qw3Rt7Yp2" + "Lk8Vb5Nm1Cd4Fg6Hj0sA",
    "lowercase-entropy-string": "key " + "k7x2m9q4w8" + "z3n6b1v5c0",
    "hex-secret": "auth key " + "9f86d081884c7d65" + "9a2feaa0c55ad015",
    "detection-rule-number": "fires rule id: 123" + "456",
    "aws-account-id": "account: 4321" + "09876543",
}


def run_scan(*args: str, env: dict[str, str] | None = None, stdin: str | None = None):
    import os

    e = {k: v for k, v in os.environ.items() if k != "HNX_DENYLIST"}
    e.update(env or {})
    return subprocess.run(
        [sys.executable, str(SCAN), *args], capture_output=True, text=True, input=stdin, env=e
    )


@pytest.mark.parametrize(("name", "line"), sorted(PLANTED.items()))
def test_planted_example_is_flagged(tmp_path: Path, name: str, line: str):
    f = tmp_path / "sample.txt"
    f.write_text(line + "\n")
    r = run_scan(str(f))
    assert r.returncode == 1, (name, r.stdout, r.stderr)
    expected = name.rsplit("-10", 1)[0] if name.endswith(("-10", "-172", "-lan")) else name
    expected = {
        "private-ipv4-10": "private-ipv4",
        "private-ipv4-172": "private-ipv4",
        "private-tld-lan": "private-tld",
    }.get(name, expected)
    assert f"[{expected}]" in r.stdout


def test_clean_tree_exits_zero(tmp_path: Path):
    (tmp_path / "a.md").write_text(
        "Service at lake-query.svc.example.internal, addr 192.0.2.10 and 198.51.100.7.\n"
        "Mail ops@example.com or 123456+x@users.noreply.github.com. IPv6 2001:db8::1.\n"
        "MAC 00:00:5e:00:53:01. Account 123456789012. Rule det:auth-failure-burst id: 900001.\n"
        "Pinned action @" + "a" * 40 + " and sha " + "0123456789abcdef" * 4 + "\n"
    )
    r = run_scan(str(tmp_path))
    assert r.returncode == 0, r.stdout
    assert "clean" in r.stdout


def test_repo_scans_itself_clean():
    r = run_scan(str(ROOT / "tools"))
    assert r.returncode == 0, r.stdout


def test_example_internal_ok_but_other_internal_flagged(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text("a.svc.example.internal\n")
    assert run_scan(str(f)).returncode == 0
    f.write_text("db." + "corp" + "." + "internal\n")
    assert run_scan(str(f)).returncode == 1


def test_reserved_tld_emails_ok_but_lookalikes_flagged(tmp_path: Path):
    f = tmp_path / "x.txt"
    at = "@"
    f.write_text(f"user{at}status.lab.example ops{at}host.test bot{at}x.invalid\n")
    assert run_scan(str(f)).returncode == 0
    for addr in (f"user{at}lab.examples", f"user{at}example.co", f"user{at}tested.dev"):
        f.write_text(addr + "\n")
        assert run_scan(str(f)).returncode == 1, addr


def test_documentation_ipv4_and_public_dns_not_flagged(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text(f"{dot(203, 0, 113, 9)} {dot(8, 8, 8, 8)} version 1.2.3.4\n")
    assert run_scan(str(f)).returncode == 0
    # just below the CGNAT range: not a tailnet address (it is a public one, caught separately)
    pats = {h.pattern for h in leak_scan.scan_text(dot(100, 63, 0, 1), "t")}
    assert pats == {"public-ipv4"}


def test_settings_local_json_is_not_a_private_tld(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text("see settings.local.json and config.local.yml\n")
    assert run_scan(str(f)).returncode == 0


def test_suppression_marker_allows_line_and_is_reported(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text(f"ip {dot(10, 1, 2, 3)}  # scrub-allow: documented example in RFC discussion\n")
    r = run_scan(str(f))
    assert r.returncode == 0
    assert "suppressed" in r.stdout
    assert "documented example" in r.stdout


def test_suppression_without_reason_does_not_count(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text(f"ip {dot(10, 1, 2, 3)}  # scrub-allow:\n")
    assert run_scan(str(f)).returncode == 1


def test_secret_values_are_redacted_in_output(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text(PLANTED["aws-access-key"] + "\n")
    r = run_scan(str(f))
    assert "ABCDEFGHIJKLMNOP" not in r.stdout


def test_denylist_matches_without_echoing_term(tmp_path: Path):
    deny = tmp_path / "deny.txt"
    deny.write_text("# comment\nsecretcodename\nre:proj-\\d{3}\n")
    f = tmp_path / "x.txt"
    f.write_text("we call it SecretCodename here\n")
    r = run_scan(str(f), env={"HNX_DENYLIST": str(deny)})
    assert r.returncode == 1
    assert "[denylist]" in r.stdout
    assert "deny-list line 2" in r.stdout
    assert "ecretcodename" not in r.stdout.lower().replace("deny-list", "")
    f.write_text("see proj-123\n")
    assert run_scan(str(f), env={"HNX_DENYLIST": str(deny)}).returncode == 1
    f.write_text("nothing to see\n")
    assert run_scan(str(f), env={"HNX_DENYLIST": str(deny)}).returncode == 0


def test_denylist_word_boundaries(tmp_path: Path):
    deny = tmp_path / "deny.txt"
    deny.write_text("acme\n")
    f = tmp_path / "x.txt"
    f.write_text("a pacmen and acmeless words\n")
    assert run_scan(str(f), env={"HNX_DENYLIST": str(deny)}).returncode == 0


@pytest.mark.parametrize("content", [None, ""])
def test_bad_denylist_is_exit_2(tmp_path: Path, content):
    f = tmp_path / "x.txt"
    f.write_text("clean\n")
    deny = tmp_path / "deny.txt"
    if content is not None:
        deny.write_text(content)
    assert run_scan(str(f), env={"HNX_DENYLIST": str(deny)}).returncode == 2


def test_missing_path_is_exit_2(tmp_path: Path):
    assert run_scan(str(tmp_path / "nope")).returncode == 2


def test_unknown_group_is_exit_2(tmp_path: Path):
    assert run_scan("--groups", "bogus", str(tmp_path)).returncode == 2


def test_groups_filter(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text(PLANTED["private-ipv4"] + "\n")
    assert run_scan("--groups", "secret", str(f)).returncode == 0
    assert run_scan("--groups", "network", str(f)).returncode == 1


def test_stdin_mode_for_commit_messages():
    assert run_scan("--stdin", stdin="fix: tidy docs\n").returncode == 0
    r = run_scan("--stdin", stdin=PLANTED["email"] + "\n")
    assert r.returncode == 1
    assert "<stdin>" in r.stdout


def test_skipped_dirs_ignored(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(PLANTED["private-ipv4"])
    (tmp_path / "pkg" / "__pycache__").mkdir(parents=True)
    (tmp_path / "pkg" / "__pycache__" / "x.txt").write_text(PLANTED["private-ipv4"])
    assert run_scan(str(tmp_path)).returncode == 0


def test_json_string_values_scanned(tmp_path: Path):
    f = tmp_path / "x.json"
    f.write_text('{"endpoint": "' + dot(192, 168, 5, 5) + ':8443"}\n')
    assert run_scan(str(f)).returncode == 1


def test_list_shows_patterns():
    r = run_scan("--list")
    assert r.returncode == 0
    assert "private-ipv4" in r.stdout
    assert "high-entropy-string" in r.stdout


def test_every_builtin_pattern_has_a_planted_case():
    covered = {n.replace("-10", "").replace("-172", "").replace("-lan", "") for n in PLANTED}
    # patterns that need context-specific fixtures are covered by dedicated tests above
    optional = {
        "ipv6-nondoc",
        "ipv6-ula",
        "aws-secret-key",
        "google-api-key",
        "jwt",
        "gpu-uuid",
        "employer-term",
    }
    names = {p.name for p in leak_scan.PATTERNS}
    assert names - covered - optional == set()


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("addr " + ":".join(["fe80", "0", "0", "0", "1", "2", "3", "4"]), "ipv6-nondoc"),
        ("addr " + ":".join(["fd12", "3456", "", "1"]), "ipv6-ula"),
        ("k=AIza" + "SyA-12345678" + "90abcdefghijklmnopqrstu", "google-api-key"),
        ("GPU-" + "12345678-1234-1234-1234-123456789abc", "gpu-uuid"),
        ("aws_secret_access_key = " + "A" * 20 + "b" * 20, "aws-secret-key"),
    ],
)
def test_additional_patterns(text: str, name: str):
    hits = leak_scan.scan_text(text, "t")
    assert name in {h.pattern for h in hits}


def test_coauthor_trailer_address_allowed_but_other_addresses_at_that_domain_not():
    ok = "Co-Authored-By: Some Tool <noreply" + "@anthropic.com>"
    assert leak_scan.scan_text(ok, "t") == []
    bad = "Co-Authored-By: Person <person" + "@anthropic.com>"
    assert {h.pattern for h in leak_scan.scan_text(bad, "t")} == {"email"}


def test_dependabot_signoff_allowed_but_other_github_addresses_not():
    ok = "Signed-off-by: dependabot[bot] <support" + "@github.com>"
    assert leak_scan.scan_text(ok, "t") == []
    bad = "Signed-off-by: Person <person" + "@github.com>"
    assert {h.pattern for h in leak_scan.scan_text(bad, "t")} == {"email"}


def test_session_trailer_allowed_only_in_its_exact_shape():
    sid = "session_" + "01XRiJBb6qhT2AV6" + "CbxXnaWa"
    trailer = "Claude-Session: https://claude.ai/code/" + sid
    assert run_scan("--stdin", stdin="feat: x\n\n" + trailer + "\n").returncode == 0
    # same token with extra content on the line, or without the trailer key, is still flagged
    assert run_scan("--stdin", stdin=trailer + " extra\n").returncode == 1
    assert run_scan("--stdin", stdin="see https://claude.ai/code/" + sid + "\n").returncode == 1
    assert (
        run_scan("--stdin", stdin="X-Other: https://claude.ai/code/" + sid + "\n").returncode == 1
    )


# --- suppression cannot be abused --------------------------------------------------------------


def test_suppression_must_end_the_line(tmp_path: Path):
    """A marker in the middle of a line, with content after it, suppresses nothing."""
    f = tmp_path / "x.txt"
    f.write_text(f"# scrub-allow: ok {dot(10, 1, 2, 3)}\n")
    assert run_scan(str(f)).returncode == 1
    f.write_text(f"ip {dot(10, 1, 2, 3)} # scrub-allow: reviewed then {dot(10, 9, 9, 9)}\n")
    assert run_scan(str(f)).returncode == 1


def test_suppression_never_covers_secrets(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text(PLANTED["aws-access-key"] + "  # scrub-allow: test fixture\n")
    r = run_scan(str(f))
    assert r.returncode == 1
    assert "[aws-access-key]" in r.stdout


def test_suppression_note_does_not_echo_the_line(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text(f"ip {dot(10, 1, 2, 3)}  # scrub-allow: documented example\n")
    r = run_scan(str(f))
    assert r.returncode == 0
    assert dot(10, 1, 2, 3) not in r.stdout
    assert "[private-ipv4]" in r.stdout and "documented example" in r.stdout


def test_denylist_terms_are_never_suppressed(tmp_path: Path):
    deny = tmp_path / "deny.txt"
    deny.write_text("codenamex\n")
    f = tmp_path / "x.txt"
    f.write_text("see codenamex  # scrub-allow: reviewed\n")
    assert run_scan(str(f), env={"HNX_DENYLIST": str(deny)}).returncode == 1


# --- what gets scanned ---------------------------------------------------------------------------


def test_build_dirs_skipped_only_at_the_scan_root(tmp_path: Path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.txt").write_text(PLANTED["private-ipv4"] + "\n")
    assert run_scan(str(tmp_path)).returncode == 0
    nested = tmp_path / "src" / "dist"
    nested.mkdir(parents=True)
    (nested / "leak.txt").write_text(PLANTED["private-ipv4"] + "\n")
    r = run_scan(str(tmp_path))
    assert r.returncode == 1 and "leak.txt" in r.stdout


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=1+t@users.noreply.github.com",
         "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=cwd, check=True, capture_output=True,
    )  # fmt: skip


def test_git_mode_scans_tracked_and_untracked_but_not_ignored(tmp_path: Path):
    _git(tmp_path, "init")
    (tmp_path / ".gitignore").write_text("ignored.txt\n")
    (tmp_path / "ignored.txt").write_text(PLANTED["private-ipv4"] + "\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "tracked.txt").write_text("clean\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "seed")
    assert run_scan(str(tmp_path)).returncode == 0  # the ignored file is not part of the tree
    (tmp_path / "build" / "tracked.txt").write_text(PLANTED["private-ipv4"] + "\n")
    r = run_scan(str(tmp_path))
    assert r.returncode == 1 and "tracked.txt" in r.stdout  # tracked, so scanned at any depth
    (tmp_path / "build" / "tracked.txt").write_text("clean\n")
    (tmp_path / "new.txt").write_text(PLANTED["email"] + "\n")
    assert run_scan(str(tmp_path)).returncode == 1  # untracked and not ignored: scanned


def test_symlink_is_not_followed(tmp_path: Path):
    outside = tmp_path / "outside.txt"
    outside.write_text(PLANTED["private-ipv4"] + "\n")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "link.txt").symlink_to(outside)
    assert run_scan(str(tree)).returncode == 0


def test_unscannable_files_fail_unless_allowed(tmp_path: Path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + PLANTED["private-ipv4"].encode())
    r = run_scan(str(tmp_path))
    assert r.returncode == 1 and "[not-scanned]" in r.stdout and "blob.bin" in r.stdout
    assert run_scan("--allow-skip", "*.bin", str(tmp_path)).returncode == 0


def test_large_file_is_reported(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(leak_scan, "MAX_BYTES", 10)
    (tmp_path / "big.txt").write_text("x" * 100)
    skipped: list = []
    leak_scan.scan_paths([str(tmp_path)], skipped=skipped)
    assert len(skipped) == 1 and skipped[0].reason.startswith("larger than")


def test_utf16_with_bom_is_decoded(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_bytes((PLANTED["private-ipv4"] + "\n").encode("utf-16"))  # writes a BOM
    r = run_scan(str(f))
    assert r.returncode == 1 and "[private-ipv4]" in r.stdout


# --- new shapes and their negatives --------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        f"version {dot(1, 2, 3, 4)}",
        f"pkg=={dot(11, 22, 33, 44)}",
        f"v{dot(11, 22, 33, 44)}",
        f"oid {dot(11, 22, 33, 44)}",
        f"date {dot(2024, '01', '02', 3)}",
        f"{dot(203, 0, 113, 5)} {dot(198, 18, 0, 1)} {dot(240, 0, 0, 1)} {dot(0, 0, 0, 0)}",
        f"{dot(1, 3, 6, 1, 4, 1, 2021)} is an OID",
        f"resolver {dot(1, 1, 1, 1)}",
    ],
)
def test_public_ipv4_negatives(text: str):
    assert "public-ipv4" not in {h.pattern for h in leak_scan.scan_text(text, "t")}


@pytest.mark.parametrize(
    "text",
    [
        "doc " + ":".join(["2001", "db8", "", "1"]),
        "doc " + ":".join(["3fff", "", "7"]),
        "loopback ::1 and any ::",
        "C++ std::vector and Foo::Bar and ab::cd",
        "time 12:30:45",
    ],
)
def test_compressed_ipv6_negatives(text: str):
    assert "ipv6-compressed" not in {h.pattern for h in leak_scan.scan_text(text, "t")}


@pytest.mark.parametrize(
    "text",
    [
        "token = self._token",
        "password: {{ lookup('env', 'DB_PASS') }}",
        'secret_ref: "secret:network/router/api-key"',
        "POSTGRES_PASSWORD_FILE: /run/secrets/db",
        "LAB_SECRETS_DEV_TOKEN=fake-dev-root-token-0000",
        "HNX_ENDPOINT_SECRETS=http://127.0.0.1:8200",
        "max_context_tokens: 131072",
        "token_logprobs: tuple[float, ...] = ()",
        "password = os.environ['DB_PASSWORD']",
        "secret: required-option",
        '{"password": "ALL=(ALL) ALL", "nopasswd": "ALL=(ALL) NOPASSWD:ALL"}',
        "master_key: secret:llm-gateway/master-key",
        'make(throttle_key="secret:llm-gateway/key-conformance-throttle")',
        "input_cost_per_token: 2.0e-06",
        "a key in `secret:llm-gateway/key-reader` (Markdown)",
        "key: secret:llm-gateway/key.private",
        "front_door: secret:status/front-door-secret2",
        "cost_per_token: 0.000002",
        "rate: 1.5e-3",
        '{secret: "secret:<name>", header?: <name>}',
        # a model's tokenizer is not a token
        "tokenizer-mode: ^(auto|slow|mistral)",
        '({"tokenizer": "org/remote"}, "--tokenizer is not an allowed")',
    ],
)
def test_keyed_secret_negatives(text: str):
    assert "keyed-secret" not in {h.pattern for h in leak_scan.scan_text(text, "t")}


@pytest.mark.parametrize(
    "text",
    [
        "master_key: secret:" + "Zq8vLx2mPw4tKr",  # no store path: a value, not a reference
        "master_key: secret:" + "zq8v/Lx2mPw4tKr",  # upper case: not a store name
        "tok" + "en: 2.0e-06xKq9",  # starts like a number, is not one
        # a store path whose segments are random or hex: a value wearing the secret: prefix
        "secret:" + "hx7k2mq9wz4p/r8tv3n6yb1cd",
        "sec" + "ret:llm-gateway/9f86d081884c7d65" + "9a2feaa0c55ad015",
        "master_key: secret:" + "hx7k2mq9wz4p/r8tv3n6yb1cd",
        'key = "sec' + "ret:llm-gateway/9f86d081884c7d65" + '9a2feaa0c55ad015"',
        # a long mantissa carries as many digits as a numeric secret
        "tok" + "en: 1.23456789e+99",
        "tok" + "en: -4.2424242e-7",
    ],
)
def test_keyed_secret_reference_and_number_exemptions_stay_narrow(text: str):
    assert "keyed-secret" in {h.pattern for h in leak_scan.scan_text(text, "t")}


def test_hex_only_flagged_next_to_a_credential_word():
    tok = "9f86d081884c7d65" + "9a2feaa0c55ad015"
    assert "hex-secret" in {h.pattern for h in leak_scan.scan_text("auth key " + tok, "t")}
    for clean in ("sha256 " + tok, "commit " + tok, "plain " + tok, "auth key " + "0" * 40):
        assert "hex-secret" not in {h.pattern for h in leak_scan.scan_text(clean, "t")}


def test_lowercase_entropy_ignores_words_and_digests():
    for clean in ("abcdefghijklmnopqrstuvwxyz", "conformancecoveragecheck2024", "0123456789" * 3):
        assert "lowercase-entropy-string" not in {
            h.pattern for h in leak_scan.scan_text(clean, "t")
        }


# --- history and commit identities ---------------------------------------------------------------


def test_history_finds_a_value_that_was_added_then_deleted(tmp_path: Path):
    _git(tmp_path, "init")
    (tmp_path / "a.txt").write_text("clean\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "seed")
    (tmp_path / "a.txt").write_text(PLANTED["private-ipv4"] + "\n")
    _git(tmp_path, "commit", "-am", "leak")
    (tmp_path / "a.txt").write_text("clean\n")
    _git(tmp_path, "commit", "-am", "remove")
    assert run_scan(str(tmp_path)).returncode == 0  # the tree is clean
    r = subprocess.run(
        [sys.executable, str(SCAN), "--history", "HEAD~2..HEAD"],
        cwd=tmp_path, capture_output=True, text=True,
    )  # fmt: skip
    assert r.returncode == 1 and "[private-ipv4]" in r.stdout and ":a.txt:1:" in r.stdout
    r = subprocess.run(
        [sys.executable, str(SCAN), "--history", "HEAD~1..HEAD"],
        cwd=tmp_path, capture_output=True, text=True,
    )  # fmt: skip
    assert r.returncode == 0  # removal lines are not additions


def test_check_authors_requires_noreply(tmp_path: Path):
    _git(tmp_path, "init")
    (tmp_path / "a.txt").write_text("x\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "ok")
    ok = subprocess.run(
        [sys.executable, str(SCAN), "--check-authors", "HEAD"],
        cwd=tmp_path, capture_output=True, text=True,
    )  # fmt: skip
    assert ok.returncode == 0, ok.stdout
    (tmp_path / "a.txt").write_text("y\n")
    subprocess.run(
        ["git", "-c", "user.name=p", "-c", "user.email=p@example.org", "-c",
         "commit.gpgsign=false", "commit", "-am", "personal"],
        cwd=tmp_path, check=True, capture_output=True,
    )  # fmt: skip
    bad = subprocess.run(
        [sys.executable, str(SCAN), "--check-authors", "HEAD~1..HEAD"],
        cwd=tmp_path, capture_output=True, text=True,
    )  # fmt: skip
    assert bad.returncode == 1 and "not a noreply" in bad.stdout
    assert "p@" not in bad.stdout  # the local part of the address is not echoed


@pytest.mark.parametrize(
    ("identity", "ok"),
    [
        ("1+someone@users.noreply.github.com", True),
        ("49699333+dependabot[bot]@users.noreply.github.com", True),
        ("noreply" + "@github.com", True),
        ("someone[bot]@example.org", False),
        ("support" + "@github.com", False),  # allowed in message text, not as an author
    ],
)
def test_noreply_commit_identities(identity: str, ok: bool):
    assert bool(leak_scan.NOREPLY_COMMIT_RE.match(identity)) is ok


def test_product_defined_secret_names_are_not_findings():
    for name in ("VLLM_API_KEY", "IMAGES_OPENAI_API_KEY"):
        assert "secret-name" not in {h.pattern for h in leak_scan.scan_text(f"env: {name}", "t")}
    for name in ("LAB_ROUTER_API" + "_KEY", "MY_API" + "_KEY", "vau" + "lt_router_password"):
        assert "secret-name" in {h.pattern for h in leak_scan.scan_text(f"env: {name}", "t")}


# --- Go sources and modules (orchestrator/) --------------------------------------------------------

# A base64 SHA-256 shaped like go.sum's ``h1:`` hashes (43 characters and ``=``), built at run time.
H1 = "Gz9kY7T5VNhEkwH0PVJ" + "gjzfXq1rhBrR7pRT3mDkpeCY="
assert len(H1) == 44


def _secret_hits(text: str, path: str = "t") -> set[str]:
    hits = leak_scan.scan_text(text, path)
    return {h.pattern for h in hits if h.pattern in SECRET_PATTERNS}


SECRET_PATTERNS = {p.name for p in leak_scan.PATTERNS if p.group == "secret"}
RANDOM = "Zx9Qw3Rt7Yp2" + "Lk8Vb5Nm1Cd4Fg6Hj0sA"  # a credential-shaped token
AUTH = '"auth_tok' + 'en": '


@pytest.mark.parametrize(
    "text",
    [
        f"github.com/example/mod v1.0.1 h1:{H1}",
        f"github.com/example/mod v1.0.1/go.mod h1:{H1}",
        f"golang.org/x/sys v0.0.0-20240101000000-abcdef123456 h1:{H1}",
    ],
)
def test_go_sum_lines_are_digests(text: str):
    assert _secret_hits(text, "orchestrator/go.sum") == set()
    assert _secret_hits(text, "orchestrator/tools/go.sum") == set()
    # only in a go.sum: the same line anywhere else is scanned like any other
    for path in ("conf.yml", "orchestrator/go.mod", "notes/go.sum.txt", "<stdin>", "t"):
        assert "high-entropy-string" in _secret_hits(text, path), path


@pytest.mark.parametrize(
    "text",
    [
        f"h1:{H1}",  # the hash alone, not a go.sum line
        f"token {H1}",  # the same value without the go.sum shape
        f"github.com/example/mod v1.0.1 h1:{H1} " + RANDOM,
        f"github.com/example/mod v1.0.1 h1:{H1}\nkey " + RANDOM,
        "github.com/example/mod v1.0.1 h2:" + H1,  # not the h1 scheme
    ],
)
def test_go_sum_allowance_is_only_the_hash_of_a_go_sum_line(text: str):
    assert "high-entropy-string" in _secret_hits(text, "orchestrator/go.sum")


@pytest.mark.parametrize(
    "text",
    [
        "func TestSubmit_IdempotencyKeyReplayForADifferentRunIs422(t *testing.T) {",
        "// TestInvoke_Exit2WithEmptyStderrIsATurnFailure pins the exit-code mapping",
        "func TestMatchRunbooks_RealKeywordHitFindsRB001(t *testing.T) {",
        "go test ./internal/api -run '^BenchmarkQueueAdmissionUnderHeavyLoad4096$'",
    ],
)
def test_go_test_function_names_are_not_secrets(text: str):
    assert _secret_hits(text) == set()


@pytest.mark.parametrize(
    "text",
    [
        # random base64 after a Test prefix: short lowercase runs
        "func Test" + RANDOM + "(t *testing.T) {",
        # a real-looking value next to a Go test name is still found
        f'func TestSubmit_IdempotencyKeyReplayIs422(t *testing.T) {{ k := "{RANDOM}" }}',
        # a lowercase prefix is not a Go test function
        "test" + RANDOM,
    ],
)
def test_go_test_name_allowance_stays_narrow(text: str):
    assert "high-entropy-string" in _secret_hits(text)


@pytest.mark.parametrize(
    "text",
    [
        '"input_tokens": float64(435783), "cache_read_tokens": float64(0),',
        '"last_prompt_tokens": float64(61234), "max_tokens": float64(16384)',
        'map[string]any{"path": "docs/w.md", "max_tokens": math.MaxInt64 / 2}',
        '[]byte("db_path: /x.db\\ntok'
        + 'en_weighted_admission: true\\nkv_budget_fraction: 0.7\\n")',
    ],
)
def test_go_numeric_values_and_escaped_newlines_are_not_keyed_secrets(text: str):
    assert "keyed-secret" not in _secret_hits(text, "orchestrator/internal/x/x_test.go")


@pytest.mark.parametrize(
    "text",
    [
        # a long number is as good as a numeric secret, cast or not
        AUTH + "float64(" + "84726193" + "50213)",
        AUTH + "int64(" + "84726193" + "50213)",
        # a cast of something that is not a number
        AUTH + "float64(" + "Zq81kXw" + "Lm2pV9a)",
        # only the limit constants: any other dotted value with digits stays a finding
        AUTH + "math." + "Zq81kXw" + "Lm2pV9a",
        # an escape ends the value, but what precedes it is still scanned
        '"db_pass' + "word: " + "Tr0ub4dor" + '&3\\nuser: admin"',
    ],
)
def test_go_numeric_and_escape_exemptions_stay_narrow(text: str):
    assert "keyed-secret" in _secret_hits(text)
    assert "keyed-secret" in _secret_hits(text, "orchestrator/internal/x/x.go")


# fictional credential-shaped values, assembled here so this file does not match itself
VAL_A = "Wq7Ty2" + "Lm9Xc4Vb!"
VAL_B = "h3Rd8" + "Kq6Zt1Np5"
ESCAPED = [
    # a value right after an escape sequence: on either side of an escape is still a value
    "db_pass" + 'word: "\\t' + VAL_A + '"',
    "api_tok" + 'en: "\\r' + VAL_B + '"',
    'var d = "pass' + "word: \\t" + VAL_A + '"',
    'var e = "db_pass' + "word=\\n" + VAL_B + '"',
    # a value before the escape, and one after a harmless first segment
    'var f = "secret_' + "key: " + VAL_B + '\\nnext: x"',
    'var g = "pass' + "word: ab\\t" + VAL_A + '"',
]


# verify.md: a word segment then a short tail, and segments each under the 6-character minimum;
# a .txt copy and the scanner before Go escapes were split both flag them
ESCAPED += [
    'var s3 = "pass' + "word: abcdef\\nQ9x" + '!z"',
    'var s4 = "pass' + "word: Zx9K\\tq2Lm" + '\\n7Wp4"',
]


@pytest.mark.parametrize("text", ESCAPED)
@pytest.mark.parametrize("path", ["conf.yml", "x.py", "orchestrator/internal/x/x_test.go", "-"])
def test_an_escape_sequence_never_hides_a_keyed_value(text: str, path: str):
    assert "keyed-secret" in _secret_hits(text, "<stdin>" if path == "-" else path)


@pytest.mark.parametrize("path", ["orchestrator/internal/x/x.go", "notes.md"])
def test_a_go_short_variable_declaration_is_a_keyed_value(path: str):
    # Go's most idiomatic form: the separator is ":=", which used to leave the value at "="
    for text in (
        "func f() { dbPass" + 'word := "' + VAL_A + '" }',
        "apiTok" + "en := " + VAL_B,
        "secret_" + 'key:= "' + VAL_B + '"',
    ):
        assert "keyed-secret" in _secret_hits(text, path), text


@pytest.mark.parametrize(
    "text",
    [
        'token := os.Getenv("X")',
        "secret := cfg.Secret",
        'token := r.Header.Get("Authorization")',
        "apiToken := strings.TrimSpace(string(b))",
        'password := ""',
        "tokenizer := x",
        'secretRef := "secret:llm-gateway/key"',
        "maxTokens := 4096",
    ],
)
def test_go_short_declarations_of_code_and_references_are_not_keyed_secrets(text: str):
    assert "keyed-secret" not in _secret_hits(text, "orchestrator/internal/x/x.go")


def test_history_reads_go_sum_by_the_path_of_the_diff(tmp_path):
    git = ["git", "-C", str(tmp_path), "-c", "user.email=t@example.org", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], check=True)
    line = f"github.com/example/mod v1.0.1 h1:{H1}\n"
    for name in ("go.sum", "conf.yml"):
        (tmp_path / name).write_text(line)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "add"], check=True)
    hits = leak_scan.scan_history("HEAD", leak_scan.PATTERNS, cwd=tmp_path)
    assert [h.path.split(":", 1)[1] for h in hits if h.pattern == "high-entropy-string"] == [
        "conf.yml"
    ]


def test_escape_segments_are_go_string_literals_only():
    # outside a Go source, the value is the whole run, escapes and all: as on main
    line = "db_path: /x.db\\ntok" + "en_weighted_admission: true\\nkv_budget_fraction: 0.7"
    assert "keyed-secret" in _secret_hits(line, "conf.yml")
    assert "keyed-secret" not in _secret_hits(f'x := "{line}"', "x.go")
    # in a Go comment or raw string the backslash is not an escape either
    assert "keyed-secret" in _secret_hits(f"// {line}", "x.go")
    assert "keyed-secret" in _secret_hits(f"x := `{line}`", "x.go")
    for code, inside in [
        ('a := "b\\"c" + `d"` + \'"\' + "e', True),  # past an escaped quote, a raw string, a rune
        ('a := "b" + `"c', False),  # in a raw string
        ('a := "b" // "c', False),  # in a comment
    ]:
        assert leak_scan._in_go_string(code, len(code)) is inside, code


def test_vault_prefixed_names_are_findings_whatever_product_uses_them():
    # vault_* is the Ansible-vault secret convention secret-name exists to catch; a product's notes
    # store keys are no exception (the orchestrator's are renamed notes_* rather than allowed)
    for line in (
        "vau" + "lt_root: /srv/notes",
        "vau" + "lt_scope: [findings]",
        "tools: [vau" + "lt_write]",
    ):
        assert "secret-name" in _secret_hits(line), line
    for line in ("notes_root: /srv/notes", "notes_scope: [findings]", "tools: [notes_write]"):
        assert _secret_hits(line) == set(), line
