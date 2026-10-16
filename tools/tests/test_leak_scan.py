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
    "private-tld": "url = https://wiki." + "lab" + "." + "ho" + "me" + "/x",
    "private-tld-lan": "host nas." + "la" + "n",
    "email": "contact: someone" + "@" + "mailhost." + "io",
    "mac-address": "mac " + ":".join(["02", "11", "22", "33", "44", "55"]),
    "aws-access-key": "key = " + "AKIA" + "ABCDEFGHIJKLMNOP",
    "private-key-block": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "github-token": "t = gh" + "p_" + "a1B2c3D4e5F6g7H8" + "i9J0k1L2m3N4o5P6q7R8",
    "slack-token": "x = xox" + "b-1234567890-abcdefghij",
    "hypervisor-name": "ssh hv-" + "201",
    "lab-path": "cat /mnt/c/User" + "s/me/notes",
    "secret-name": "pw: {{ vault" + "_db_password }}",
    "vault-blob": "$ANSIBLE" + "_VAULT;1.1;AES256",
    "high-entropy-string": "api_token = Zx9Qw3Rt7Yp2" + "Lk8Vb5Nm1Cd4Fg6Hj0sA",
    "detection-rule-number": "fires rule id: 100" + "001",
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


def test_documentation_ipv4_and_public_dns_not_flagged(tmp_path: Path):
    f = tmp_path / "x.txt"
    f.write_text(f"{dot(203, 0, 113, 9)} {dot(8, 8, 8, 8)} {dot(100, 63, 0, 1)} version 1.2.3.4\n")
    assert run_scan(str(f)).returncode == 0


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


def test_binary_and_skipped_dirs_ignored(tmp_path: Path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + PLANTED["private-ipv4"].encode())
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(PLANTED["private-ipv4"])
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
        ("addr fd" + "12:3456::1", "ipv6-ula"),
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
