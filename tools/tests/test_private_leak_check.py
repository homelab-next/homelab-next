# SPDX-License-Identifier: Apache-2.0
"""tools/private_leak_check.py: every rule fails on a bad tree and passes on a good one.

Planted credential values are assembled at run time so this file stays clean under the public
scanner; the private overlays are built in ``tmp_path`` (outside any git work tree).
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "private_leak_check.py"
SKELETON = ROOT / "examples" / "private-overlay"
sys.path.insert(0, str(ROOT / "tools"))
import private_leak_check as plc

# the sdist leaves the template out (MANIFEST.in); the tests that read it skip there
needs_skeleton = pytest.mark.skipif(
    not (SKELETON / ".hnx-private-overlay.yml").is_file(),
    reason="the private-overlay template is not in this tree (an sdist leaves it out)",
)

MARKER = "hnx_private_overlay: 1\nansible_vault_files:\n  - inv/*/group_vars/*/vault.yml\n"
SOPS_RULES = "creation_rules:\n  - path_regex: (^|/)lab/sealed/\n    age: x\n"
AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"
AGE_KEY = "AGE-SECRET-" + "KEY-1" + ("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" * 2)[:58]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def enc(plain: bytes = b"fake-sealed-value", kind: str = "str") -> str:
    """A token shaped exactly as sops writes one (32-byte IV, 16-byte tag); not real ciphertext."""
    iv, tag = b64(b"fake-iv-" * 4), b64(b"fake-tag" * 2)
    return f"ENC[AES256_GCM,data:{b64(plain)},iv:{iv},tag:{tag},type:{kind}]"


def vault(inner: str | None = None) -> str:
    """An ansible-vault envelope: hexlify(salt-hex NL hmac-hex NL ciphertext-hex), 80 a line."""
    inner = inner or "\n".join(("ab12" * 16, "cd34" * 16, "ef56" * 24))
    body = inner.encode().hex()
    return (
        "$"
        + "ANSIBLE_VAULT;1.1;AES256\n"
        + "\n".join(body[i : i + 80] for i in range(0, len(body), 80))
        + "\n"
    )


VAULT = vault()
SOPS_META = (
    "sops:\n    age:\n        - recipient: age1fake\n          enc: |\n"
    "            -----BEGIN AGE ENCRYPTED FILE-----\n"
    "            YWdlLWVuY3J5cHRp" + "b24ub3JnL3YxCi0+" + "IFgyNTUxOSBhYmNk\n"
    "            -----END AGE ENCRYPTED FILE-----\n"
    "    lastmodified: '2026-10-21T00:00:00Z'\n"
    f"    mac: {enc(b'fake-mac')}\n"
    "    unencrypted_suffix: _unencrypted\n"
    "    version: 3.9.0\n"
)
SOPS_FILE = f"wan:\n    address: {enc()}\n    port_unencrypted: 51820\n" + SOPS_META


def overlay(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "overlay"
    for rel, text in {
        ".hnx-private-overlay.yml": MARKER,
        ".sops.yaml": SOPS_RULES,
        **files,
    }.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def rules(found) -> set[str]:
    return {f.rule for f in found}


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(TOOL), *args], capture_output=True, text=True)


# ---- private mode ------------------------------------------------------------------------------


def test_a_good_overlay_passes_with_real_looking_addresses(tmp_path):
    root = overlay(
        tmp_path,
        {
            # real addresses and host names are what the private repository is for
            "lab/site.yml": "gw: "
            + ".".join(["10", "20", "0", "1"])
            + "\nhost: nas."
            + "la"
            + "n\n",
            "lab/sealed/wan.sops.yaml": SOPS_FILE,
            "inv/prod/group_vars/all/vault.yml": VAULT,
            "inv/prod/group_vars/all/main.yml": "smtp_password: '{{ vault" + "_smtp_password }}'\n",
            "inv/prod/host_vars/a.yml": "key: !vault |\n  " + VAULT.replace("\n", "\n  "),
        },
    )
    assert plc.check_private(root) == []


@needs_skeleton
def test_skeleton_passes_private_mode():
    assert plc.check_private(SKELETON) == []


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("lab/notes.md", f"aws key {AWS_KEY}\n"),
        ("lab/age.txt", AGE_KEY + "\n"),
        ("inv/prod/group_vars/all/main.yml", "db_pass" + "word: Tr0ub4dor&3x\n"),
        # a SOPS file whose metadata is fine but where one value was left in the clear
        (
            "lab/other.yml",
            SOPS_FILE.replace(
                "wan:\n", "token: gh" + "p_" + "a1B2c3D4e5F6g7H8" + "i9J0k1L2m3N4o5P6q7R8\nwan:\n"
            ),
        ),
    ],
)
def test_plaintext_secret_fails(tmp_path, rel, text):
    found = plc.check_private(overlay(tmp_path, {rel: text}))
    assert rules(found) == {"secret"}, found
    assert all(f.path == rel for f in found)


def test_file_the_sops_rules_cover_must_be_sealed(tmp_path):
    root = overlay(tmp_path, {"lab/sealed/wan.sops.yaml": "wan:\n    address: plain\n"})
    found = plc.check_private(root)
    assert [(f.path, f.rule) for f in found] == [("lab/sealed/wan.sops.yaml", "sops-unencrypted")]


GH_TOKEN = "gh" + "p_" + "a1B2c3D4e5F6g7H8" + "i9J0k1L2m3N4o5P6q7R8"
WAN = ".".join(["203", "0", "113", "7"])  # a documentation address, assembled
PEER_KEY = b64(b"fake-wireguard-peer-public-key!!")  # 44 chars of base64, like a WireGuard key


def found_at(found) -> set[tuple[str, str]]:
    return {(f.path, f.rule) for f in found}


@pytest.mark.parametrize(
    "rel",
    [
        "lab/sealed/wan.yml",  # no .sops infix: the .sops.yaml rule does not cover it
        "lab/sealed/sub/peers.sops.yaml.bak",  # a backup copy, under a subdirectory
        "lab/sealed/notes.txt",
    ],
)
def test_everything_under_a_sealed_path_must_be_sealed(tmp_path, rel):
    # the skeleton's first rule only named *.sops.yaml: what it did not cover went unchecked
    narrow = SOPS_RULES.replace("lab/sealed/", "lab/sealed/.*\\.sops\\.ya?ml$")
    found = plc.check_private(overlay(tmp_path, {".sops.yaml": narrow, rel: f"wan_ipv4: {WAN}\n"}))
    assert found_at(found) == {(rel, "sops-unencrypted"), (".sops.yaml", "sops-policy")}
    assert WAN not in "\n".join(map(str, found))


def test_a_readme_under_a_sealed_path_stays_plain_and_is_still_scanned(tmp_path):
    assert plc.check_private(overlay(tmp_path, {"lab/sealed/README.md": "what lives here\n"})) == []
    found = plc.check_private(overlay(tmp_path / "b", {"lab/sealed/README.md": f"k {AWS_KEY}\n"}))
    assert rules(found) == {"secret"}


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        # plaintext values next to a fake sops block (JSON): the metadata is not real
        (f'{{"wan": "{WAN}", "sops": {{"mac": "x"}}}}', "without a well-formed mac"),
        # plaintext values with a sops block that has a version only
        (f"wan_ipv4: {WAN}\nwg_peer: {PEER_KEY}\nsops:\n  version: 3.9.0\n", "no recipient"),
        # real-looking metadata, but one value was never encrypted
        (f"wan:\n    address: {WAN}\n    peer: {enc()}\n" + SOPS_META, "wan/address"),
        # a comment sops would have encrypted, left in the clear
        (f"# peer is {WAN}\n" + SOPS_FILE, "line 1 (comment)"),
        # a value wrapped to look like ciphertext
        (f"wan:\n    address: ENC[AES256_GCM,data:{GH_TOKEN}]\n" + SOPS_META, "wan/address"),
        # metadata with a key sops never writes, where plain text could hide
        (SOPS_FILE + "    note: anything\n", "unknown SOPS metadata key"),
    ],
    ids=[
        "fake-json-mac",
        "version-only",
        "one-plain-value",
        "plain-comment",
        "wrapped",
        "extra-key",
    ],
)
def test_a_sealed_file_must_be_encrypted_throughout(tmp_path, text, needle):
    rel = "lab/sealed/wan.sops.yaml"
    found = plc.check_private(overlay(tmp_path, {rel: text}))
    assert found_at(found) <= {(rel, "sops-malformed")} and found, found
    shown = "\n".join(map(str, found))
    assert needle in shown
    assert WAN not in shown and GH_TOKEN not in shown  # keys and rules, never values


def test_partial_encryption_is_refused_on_a_sealed_path(tmp_path):
    text = f"wan:\n    address: {WAN}\n    peer: {enc()}\n" + SOPS_META.replace(
        "    version:", "    encrypted_regex: ^peer$\n    version:"
    )
    found = plc.check_private(overlay(tmp_path, {"lab/sealed/wan.sops.yaml": text}))
    assert ("lab/sealed/wan.sops.yaml", "sops-partial") in found_at(found)
    assert any("encrypted_regex" in f.detail for f in found)


def test_only_the_configured_unencrypted_suffix_stays_plain(tmp_path):
    custom = SOPS_META.replace("_unencrypted", "_plain")
    pinned = {".hnx-private-overlay.yml": MARKER + "unencrypted_suffix: _plain\n"}
    ok = f"wan:\n    address: {enc()}\n    port_plain: 51820\n" + custom
    root = overlay(tmp_path / "a", {"lab/sealed/a.sops.yaml": ok, **pinned})
    assert plc.check_private(root) == []
    bad = f"wan:\n    address: {enc()}\n    port_unencrypted: 51820\n" + custom
    found = plc.check_private(overlay(tmp_path / "b", {"lab/sealed/a.sops.yaml": bad, **pinned}))
    assert [f.detail for f in found] == ["wan/port_unencrypted: not a well-formed ENC[...] value"]


def test_a_sealed_file_cannot_choose_its_own_unencrypted_suffix(tmp_path):
    """``unencrypted_suffix: s`` in the file's own metadata used to make every key ending in ``s``
    plain: any key at all, with a one-letter suffix."""
    text = f"wan:\n    address: {WAN}\n    peer: {enc()}\n" + SOPS_META.replace("_unencrypted", "s")
    found = plc.check_private(overlay(tmp_path, {"lab/sealed/wan.sops.yaml": text}))
    assert ("lab/sealed/wan.sops.yaml", "sops-partial") in found_at(found)
    assert any("wan/address" in f.detail for f in found)  # and the value is checked anyway
    assert WAN not in "\n".join(map(str, found))
    with pytest.raises(plc.ConfigError):
        plc.read_marker(
            overlay(
                tmp_path / "m", {".hnx-private-overlay.yml": MARKER + "unencrypted_suffix: ''\n"}
            )
            / ".hnx-private-overlay.yml"
        )


@pytest.mark.parametrize("fmt", ["yaml", "json"])
def test_a_key_set_twice_in_a_sealed_file_is_a_finding(tmp_path, fmt):
    """PyYAML and json keep the last of two equal keys: a plain first value went unchecked."""
    if fmt == "yaml":
        text = f"wan:\n    address: {AWS_KEY}\n    address: {enc()}\n" + SOPS_META
    else:
        meta = {"age": [{"recipient": "age1fake"}], "mac": enc(b"fake-mac"), "version": "3.9.0"}
        text = f'{{"address": "{AWS_KEY}", "address": "{enc()}", "sops": {json.dumps(meta)}}}'
    rel = f"lab/sealed/wan.sops.{fmt}"
    found = plc.check_private(overlay(tmp_path, {rel: text}))
    assert (rel, "sops-malformed") in found_at(found)
    assert any("duplicate key 'address'" in f.detail for f in found)
    assert AWS_KEY not in "\n".join(map(str, found))
    # outside a sealed path the plain first value is scanned, not dropped by re-serialising
    other = "lab/other.json"
    if fmt == "json":
        assert "secret" in rules(plc.check_private(overlay(tmp_path / "o", {other: text})))


def test_sealed_dotenv_and_ini_are_checked_too(tmp_path):
    meta = f"sops_age__list_0__map_recipient=age1fake\nsops_mac={enc(b'fake-mac')}\n"
    good = f"WAN={enc()}\n" + meta
    assert plc.check_private(overlay(tmp_path / "a", {"lab/sealed/wan.env": good})) == []
    found = plc.check_private(
        overlay(tmp_path / "b", {"lab/sealed/wan.env": f"WAN={WAN}\n" + meta})
    )
    assert [f.detail for f in found] == ["WAN: not a well-formed ENC[...] value"]
    ini = f"[wan]\naddress = {enc()}\n[sops]\nage__list_0__map_recipient = age1fake\nmac = {enc(b'm')}\n"
    assert plc.check_private(overlay(tmp_path / "c", {"lab/sealed/wan.ini": ini})) == []


@pytest.mark.parametrize(
    ("files", "needle"),
    [
        # one commit drops the rule: the sealed path is pinned in the tool, so it still holds,
        # and the rule set that no longer covers it is itself the finding
        (
            {".sops.yaml": "creation_rules:\n  - path_regex: ^elsewhere/\n    age: x\n"},
            "no creation rule covers lab/sealed/probe.sops.yaml",
        ),
        (
            {
                ".sops.yaml": SOPS_RULES.replace(
                    "    age: x", "    encrypted_regex: ^nothing$\n    age: x"
                )
            },
            "encrypts only in part (encrypted_regex)",
        ),
        (
            {"lab/.sops.yaml": "creation_rules:\n  - path_regex: .*\n    age: x\n"},
            "nested .sops.yaml",
        ),
    ],
)
def test_a_sops_config_that_narrows_the_sealed_paths_is_a_finding(tmp_path, files, needle):
    found = plc.check_private(overlay(tmp_path, {"lab/sealed/wan.sops.yaml": SOPS_FILE, **files}))
    assert rules(found) == {"sops-policy"}, found
    assert any(needle in f.detail for f in found)


def test_without_a_sops_config_the_sealed_paths_still_hold(tmp_path):
    root = overlay(tmp_path, {"lab/sealed/wan.yml": f"wan_ipv4: {WAN}\n"})
    (root / ".sops.yaml").unlink()
    found = plc.check_private(root)
    assert found_at(found) == {
        ("lab/sealed/wan.yml", "sops-unencrypted"),
        (".sops.yaml", "sops-policy"),
    }


def test_the_marker_may_add_sealed_paths(tmp_path):
    marker = MARKER + "sealed_paths:\n  - lab/peers/\n"
    root = overlay(tmp_path, {".hnx-private-overlay.yml": marker, "lab/peers/a.yml": "a: b\n"})
    assert ("lab/peers/a.yml", "sops-unencrypted") in found_at(plc.check_private(root))


def test_vault_file_must_be_vault_encrypted(tmp_path):
    for rel in ("inv/prod/group_vars/all/vault.yml", "roles/x/creds.vault.yml"):
        found = plc.check_private(overlay(tmp_path / rel.replace("/", "_"), {rel: "a: b\n"}))
        assert [(f.path, f.rule) for f in found] == [(rel, "vault-unencrypted")]


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        # the header, then plain text: the header alone used to pass
        (VAULT.splitlines()[0] + f"\ngithub_token: {GH_TOKEN}\n", "not only hex"),
        (VAULT + f"github_token: {GH_TOKEN}\n", "not only hex"),
        # hex lines that are plain text hexlified, not salt, HMAC and ciphertext
        (vault(f"github_token: {GH_TOKEN}"), "salt, HMAC and ciphertext"),
        ("$" + "ANSIBLE_VAULT;9.9;ROT13\n" + "ab" * 40 + "\n", "header"),
    ],
    ids=["header-then-plain", "envelope-then-plain", "hexlified-plain", "bad-header"],
)
def test_a_vault_file_is_the_header_then_hex_only(tmp_path, text, needle):
    rel = "inv/prod/group_vars/all/vault.yml"
    found = plc.check_private(overlay(tmp_path, {rel: text}))
    assert [(f.path, f.rule) for f in found] == [(rel, "vault-unencrypted")]
    assert needle in found[0].detail and GH_TOKEN not in found[0].detail


def test_a_vault_header_does_not_hide_the_rest_of_a_file(tmp_path):
    text = VAULT.splitlines()[0] + f"\ngithub: {GH_TOKEN}\n"
    found = plc.check_private(overlay(tmp_path, {"lab/notes.md": text}))
    assert rules(found) == {"secret"} and all(f.detail.startswith("line 2:") for f in found)


def test_only_well_formed_ciphertext_is_masked(tmp_path):
    found = plc.check_private(
        overlay(tmp_path, {"lab/enc.yml": f"x: ENC[AES256_GCM,data:{GH_TOKEN}]\n"})
    )
    assert rules(found) == {"secret"}
    assert plc.masked(SOPS_FILE).splitlines()[1].strip() == "address: ENC[]"
    for bad in (
        f"ENC[AES256_GCM,data:{b64(b'x')},iv:abc,tag:def,type:str]",  # short IV and tag
        enc().replace("type:str", "type:secret"),
        enc().replace("AES256_GCM", "PLAIN"),
    ):
        assert not plc.well_formed_enc(bad), bad
        assert plc.masked(bad) == bad


@pytest.mark.parametrize(
    "rel", ["lab/notes.md", "lab/hosts.yml", "lab/plain.env", "lab/wan.sops.yaml"]
)
def test_a_well_formed_token_hides_nothing_outside_a_sops_value(tmp_path, rel):
    """An access key id is valid base64, so ``ENC[AES256_GCM,data:<key>,iv:..,tag:..]`` was a
    well-formed token and was masked in ANY file: the key vanished from the scan."""
    wrapped = enc().replace(f"data:{b64(b'fake-sealed-value')}", f"data:{AWS_KEY}")
    assert plc.well_formed_enc(wrapped)  # the shape alone cannot tell
    if rel.endswith(".sops.yaml"):  # a SOPS file (not sealed), the token inside a value
        text = f"wan:\n    address: id {wrapped}\n" + SOPS_META
    else:
        text = f"token: {wrapped}\n"
    assert "secret" in rules(plc.check_private(overlay(tmp_path, {rel: text}))), rel
    assert plc.masked(f"x: {wrapped}\n") == f"x: {wrapped}\n"  # not a SOPS file: unchanged


def test_files_that_cannot_be_scanned_fail_unless_allowed(tmp_path):
    root = overlay(tmp_path, {"lab/a.yml": "a: b\n"})
    (root / "logs").mkdir()
    (root / "logs" / "big.log").write_text("x" * (6 * 1024 * 1024))
    (root / "lab" / "blob.bin").write_bytes(b"\x00\x01\x02\xff" * 64)
    found = plc.check_private(root)
    assert found_at(found) == {("logs/big.log", "unscanned"), ("lab/blob.bin", "unscanned")}
    assert "larger than 5 MB" in str(found)
    marker = MARKER + "allow_unscanned:\n  - logs/*.log\n  - '*.bin'\n"
    (root / ".hnx-private-overlay.yml").write_text(marker)
    assert plc.check_private(root) == []
    # a sealed file is never let through unscanned
    (root / "lab" / "sealed").mkdir()
    (root / "lab" / "sealed" / "x.sops.yaml").write_bytes(b"\x00\x01\x02\xff" * 8)
    assert found_at(plc.check_private(root)) == {("lab/sealed/x.sops.yaml", "unscannable")}


def test_utf16_without_a_byte_order_mark_is_scanned(tmp_path):
    root = overlay(tmp_path, {})
    (root / "lab").mkdir()
    for name, codec in (("le.txt", "utf-16-le"), ("be.txt", "utf-16-be")):
        (root / "lab" / name).write_bytes(f"github: {GH_TOKEN}\n".encode(codec))
    found = plc.check_private(root)
    assert {f.path for f in found} == {"lab/le.txt", "lab/be.txt"} and rules(found) == {"secret"}


@pytest.mark.parametrize(
    "rel", ["keys/deploy.agekey", ".vault" + "_pass", ".vault-pass.txt", "home/sops/age/keys.txt"]
)
def test_key_next_to_ciphertext_fails(tmp_path, rel):
    found = plc.check_private(overlay(tmp_path, {rel: "anything\n"}))
    assert [(f.path, f.rule) for f in found] == [(rel, "key-file")]


def test_private_mode_needs_the_marker(tmp_path):
    (tmp_path / "a.yml").write_text("a: b\n")
    with pytest.raises(plc.ConfigError, match=r"no \.hnx-private-overlay\.yml"):
        plc.check_private(tmp_path)
    r = run("private", str(tmp_path))
    assert r.returncode == 2 and "private overlay" in r.stderr


@pytest.mark.parametrize(
    ("name", "text", "msg"),
    [
        (".hnx-private-overlay.yml", "hnx_private_overlay: 2\n", "not an overlay marker"),
        (".hnx-private-overlay.yml", MARKER + "private_paths: lab/\n", "private_paths must be"),
        (".sops.yaml", "creation_rules:\n  - age: x\n", "no path_regex"),
        (".sops.yaml", "creation_rules:\n  - path_regex: '('\n", "path_regex"),
        (".sops.yaml", "creation_rules: {}\n", "creation_rules list"),
    ],
)
def test_bad_config_is_exit_2(tmp_path, name, text, msg):
    root = overlay(tmp_path, {name: text})
    with pytest.raises(plc.ConfigError, match=msg):
        plc.check_private(root)


def test_masking_keeps_plaintext_lines(tmp_path):
    text = SOPS_FILE + "after: " + AWS_KEY + "\n"
    out = plc.masked(text)
    assert "ENC[AES256_GCM" not in out and "BEGIN AGE" not in out
    assert out.splitlines()[-1] == "after: " + AWS_KEY  # top-level key after the block is kept
    doc = {"a": enc(), "sops": {"mac": "m"}}
    assert json.loads(plc.masked(json.dumps(doc))) == {"a": "ENC[]"}
    assert plc.sops_format("k=ENC[AES256_GCM,data:x]\nsops_mac=y\n") == "dotenv"
    assert plc.sops_format("[x]\nk=v\n[sops]\nmac=y\n") == "ini"
    assert plc.masked(VAULT).strip() == ""


def test_cli_private_exit_codes(tmp_path):
    good = overlay(tmp_path / "g", {"lab/a.yml": "a: b\n"})
    r = run("private", str(good))
    assert r.returncode == 0 and "clean (private)" in r.stdout
    bad = overlay(tmp_path / "b", {"lab/a.md": f"k {AWS_KEY}\n"})
    r = run("private", str(bad))
    assert r.returncode == 1 and "[secret]" in r.stdout
    assert AWS_KEY not in r.stdout  # the value itself is redacted


# ---- public mode -------------------------------------------------------------------------------


def public_tree(tmp_path: Path) -> Path:
    root = tmp_path / "public"
    shutil.copytree(SKELETON, root / "examples" / "private-overlay")
    (root / "README.md").write_text("public\n")
    return root


def test_this_repository_passes_public_mode():
    assert plc.check_public(ROOT) == []
    r = run("public", str(ROOT))
    assert r.returncode == 0, r.stdout


@needs_skeleton
def test_public_tree_with_only_the_skeleton_passes(tmp_path):
    assert plc.check_public(public_tree(tmp_path)) == []


@needs_skeleton
@pytest.mark.parametrize(
    ("rel", "text", "rule"),
    [
        (".hnx-private-overlay.yml", MARKER, "overlay-marker"),
        ("lab/site.yml", "site: {}\n", "overlay-path"),
        ("ansible/inventory/production/hosts.yml", "all: {}\n", "overlay-path"),
        (".sops.yaml", SOPS_RULES, "sops-config"),
        ("examples/thing.yml", SOPS_FILE, "ciphertext"),
        ("keys/ops.agekey", "x\n", "key-file"),
    ],
)
def test_public_tree_with_private_material_fails(tmp_path, rel, text, rule):
    root = public_tree(tmp_path)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    assert rule in rules(plc.check_public(root))
    assert run("public", str(root)).returncode == 1


#: non-documentation networks, assembled at run time so this file stays clean under the scanner
PRIVATE_NET = ".".join(("10", "20", "0", "0")) + "/16"
PUBLIC_HOST = ".".join(("8", "8", "4", "4"))
PUBLIC_V4 = ".".join(("81", "2", "69", "142"))
#: the same public address as an integer and in hex (what inet_aton also reads)
PUBLIC_INT = str(int.from_bytes(bytes(int(o) for o in PUBLIC_V4.split(".")), "big"))
PUBLIC_HEX = hex(int(PUBLIC_INT))
#: zero-padded octets: a person reads decimal, inet_aton reads octal
PADDED = ".".join(f"{int(o):03d}" for o in PUBLIC_V4.split("."))
EVERYTHING = ".".join(("0",) * 4) + "/0"
EVERYTHING_V6 = ":" * 2 + "/0"
DOC = "192.0.2"  # a three-part documentation prefix (no four-part literal in this source)
DOC3 = "203.0.113"
#: the public address in the other spellings a YAML 1.1 loader, TOML or int() reads
PUBLIC_FLOAT = PUBLIC_INT + ".0"
PUBLIC_BIN = bin(int(PUBLIC_INT))
PUBLIC_OCT = "0o" + oct(int(PUBLIC_INT))[2:]
PUBLIC_UNDERSCORED = f"{int(PUBLIC_INT):_}"
FULLWIDTH = "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in PUBLIC_V4)
#: inet_aton short form of a private address (the octets 10, 0, 0, 20; a person reads the 10.20/16 prefix)
SHORT_PRIVATE = ".".join(("10", "20"))
#: NAT64 local-use (RFC 6052 /48 layout) embedding the public address, with a documentation tail
NAT64_LOCAL = ":".join(("64", "ff9b", "1", "5102", "45", "8e00", "c000", "201"))
#: the public address as inet_aton short forms no version takes (a part over 255, hex parts)
SHORT_GLOBAL = "81.2." + str(69 * 256 + 142)
SHORT_HEX = "0x51.0x" + format(2 * 65536 + 69 * 256 + 142, "x")
SHORT_TWO = "81." + str(2 * 65536 + 69 * 256 + 142)
#: an allowlisted path (SCOPE_BLOCK_PATHS): a site block there is parsed strictly
#: special-use addresses that name no site (VERIFY4 SF2), assembled
LOOPBACK = ".".join(("127", "0", "0", "1"))
UNSPECIFIED = ".".join(("0",) * 4)
METADATA = ".".join(("169", "254", "169", "254"))
#: the public address in the deprecated IPv4-compatible form (::/96, no ffff)
COMPAT_REAL = ":" * 2 + f"{int(PUBLIC_INT) >> 16:x}:{int(PUBLIC_INT) & 0xFFFF:x}"
SITE = "examples/modules/sites/probe.yml"

TQ = "'" * 3


def notebook(kind: str, source: list[str], outputs: list | None = None) -> str:
    """A one-cell Jupyter notebook as written to disk (one JSON string per line)."""
    cell = {"cell_type": kind, "metadata": {}, "source": source}
    if kind == "code":
        cell["outputs"] = outputs or []
    return json.dumps(
        {"cells": [cell], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=1
    )


#: a non-documentation address under a scope key, in every shape and spelling: refused at
#: EVERY path, whatever the file is called and whatever the block around it looks like
ADDRESS_CASES = {
    "plain": f"scope:\n  trusted:\n    wan: [{PUBLIC_HOST}/32]\n",
    "private": f"scope:\n  target: [{DOC}.0/24, {PRIVATE_NET}]\n",
    "everything": f"scope:\n  target: ['{EVERYTHING}']\n",
    "everything v6": f"scope:\n  exclude:\n    offensive: ['{EVERYTHING_V6}']\n",
    "widened": f"scope:\n  target: [{DOC}.0/16]\n",
    "misspelt part": f"scope:\n  trusted:\n    lan: [{PRIVATE_NET}]\n",
    "malformed real": f"scope:\n  target: ['{PRIVATE_NET.replace('/16', '/33')}']\n",
    "json": f'{{"profile": "x", "scope": {{"target": ["{PRIVATE_NET}"]}}}}\n',
    "zero-padded": f"scope:\n  trusted:\n    wan: ['{PADDED}/32']\n",
    "integer string": f"scope:\n  trusted:\n    wan: ['{PUBLIC_INT}']\n",
    "yaml int": f"scope:\n  trusted:\n    wan: [{PUBLIC_INT}]\n",
    "hex string": f"scope:\n  trusted:\n    wan: ['{PUBLIC_HEX}']\n",
    "yaml hex int": f"scope:\n  trusted:\n    wan: [{PUBLIC_HEX}]\n",
    "yaml float": f"scope:\n  target: [{PUBLIC_FLOAT}]\n",
    "yaml binary": f"scope:\n  target: [{PUBLIC_BIN}]\n",
    "octal": f"scope:\n  target: [{PUBLIC_OCT}]\n",
    "underscored": f"scope:\n  target: [{PUBLIC_UNDERSCORED}]\n",
    "fullwidth digits": f"scope:\n  target: ['{FULLWIDTH}']\n",
    "inet_aton short form with a prefix": f"scope:\n  target: ['{SHORT_PRIVATE}/16']\n",
    "short form in a url": f"scope: http://{SHORT_PRIVATE}.5/\n",
    "space before prefix": f"scope:\n  target: ['{PUBLIC_V4} /32']\n",
    "mapped real": f"scope:\n  target: ['::ffff:{PUBLIC_V4}']\n",
    "nat64 local-use": f"scope:\n  target: ['{NAT64_LOCAL}']\n",  # N4
    "prefix length that is an address": f"scope:\n  target: ['{DOC}.1/{PUBLIC_INT}']\n",  # N5
    "flow style": f"{{scope: {{target: ['{EVERYTHING}']}}}}\n",
    "single-quoted key": f"'scope':\n  target: ['{EVERYTHING}']\n",
    "explicit key": f"? scope\n: target: ['{EVERYTHING}']\n",
    "complex key": f"? [scope]\n: target: ['{PADDED}/32']\n",
    "tab before colon": f"scope\t:\n  target: ['{EVERYTHING}']\n",
    "byte-order mark": f"\ufeffscope:\n  target: ['{EVERYTHING}']\n",
    "json escaped key": '{"\\u0073cope": {"target": ["' + EVERYTHING + '"]}}\n',
    "yaml escaped key": f"\"\\x73cope\":\n  target: ['{EVERYTHING}']\n",
    "escaped line break in the key": f"? \"sco\\\n  pe\"\n: trusted:\n    wan: ['{PADDED}/32']\n",  # N1
    "escaped value": 'scope:\n  target: ["\\x38\\x31.'
    + ".".join(PUBLIC_V4.split(".")[1:])
    + '"]\n',
    "html character reference": "scope: &#56;" + PUBLIC_V4[1:] + "\n",
    "custom tag elsewhere": f"x: !vault |\n  abc\nscope:\n  target: ['{EVERYTHING}']\n",
    "custom tag and padding": f"x: !Ref y\nscope:\n  trusted:\n    wan: ['{PADDED}']\n",
    "a binary value": "scope:\n  target: [!" + "!binary 'UQJFjg==']\n",  # split: this source
    "merge key": f"base: &b\n  scope:\n    target: ['{EVERYTHING}']\n<<: *b\n",
    "alias to an anchor outside": f"x: &x ['{PADDED}/32']\nscope:\n  target: *x\n",
    "duplicate scope key": (
        f"scope:\n  target: ['{EVERYTHING}']\nscope:\n  target: [{DOC}.0/24]\n"
    ),
    "duplicate part": f"scope:\n  target: [{DOC}.0/24]\n  target: [{PRIVATE_NET}]\n",
    "json duplicate key": (
        f'{{"scope": {{"target": ["{DOC}.0/24"], "target": ["{EVERYTHING}"]}}}}\n'
    ),
    "upper-case key": f"Scope:\n  target: ['{EVERYTHING}']\n",
    "nested": f"site:\n  scope:\n    target: ['{EVERYTHING}']\n",
    "a scope list": f"scope: [{PRIVATE_NET}]\n",
    "second document": f"a: 1\n---\nscope:\n  target: ['{EVERYTHING}']\n",
    "address as a key": f"scope:\n  target:\n    '{PUBLIC_V4}': x\n",
    # SF1: under a scope key that is not a site block, at any depth
    "schema examples": (
        f"properties:\n  scope:\n    type: object\n    examples:\n    - target: ['{PADDED}/32']\n"
    ),
    "schema default": (
        '{"properties": {"scope": {"type": "object", "default": {"trusted": {"wan": ["'
        + PADDED
        + '/32"]}}}}}\n'
    ),
    "schema const": f"scope:\n  const: '{PADDED}'\n",
    "selectors' hosts": f"scope:\n  hosts: ['{PADDED}']\n",
    "a parameter's env": f"scope:\n  env: {{WAN: '{PADDED}'}}\n",
    "deep in another document's mapping": f"scope:\n  hosts:\n    a:\n      b: ['{PADDED}']\n",
    "a list of blocks": f"scope:\n- target: ['{PADDED}/32']\n",
    "a list of blocks, everything": f"scope:\n- target: ['{EVERYTHING}']\n",
    "toml": f'[scope]\ntarget = ["{EVERYTHING}"]\n',
    "toml array of tables": f'[[scope]]\ntarget = ["{PADDED}/32"]\n',
    "toml dotted key": f'scope.trusted.wan = ["{PADDED}/32"]\n',
    "free text": f"scope: 'wan is {PADDED}'\n",  # N9
    # SF2: Markdown, judged on raw text: any fence, any indent, any info string, or none
    "markdown fence": f"# x\n\n```yaml\nscope:\n  target: ['{EVERYTHING}']\n```\n",
    "markdown untagged fence": f"```\nscope:\n  target: ['{EVERYTHING}']\n```\n",
    "markdown indented fence": f"- step\n\n   ```yaml\n   scope:\n     target: ['{PADDED}/32']\n   ```\n",
    "markdown longer closing fence": (
        f"```\ntext\n`````\n\n```yaml\nscope:\n  target: ['{PADDED}/32']\n```\n"
    ),
    "markdown fence with a bad line": f"```\nscope:\n  target: ['{PADDED}/32']\n\tbad: [\n```\n",
    "markdown text fence": f"```text\nscope:\n  target: ['{PADDED}/32']\n```\n",
    "markdown tilde fence": f"~~~yaml\nscope:\n  target: ['{PADDED}/32']\n~~~\n",
    "markdown html": f"<pre>\nscope:\n  target: ['{PADDED}/32']\n</pre>\n",
    "markdown prose": f"The lab's scope: {PADDED} and nothing else.\n",
    # VERIFY4 SF1: an indented `scope =` key still holds its value and its deeper lines
    "indented ini key": f"[site]\n  scope = {PADDED}/32\n",
    "indented ini value on the next deeper line": f"[site]\n  scope =\n      {PADDED}/32\n",
    "indented toml key": f'[site]\n  scope = ["{PRIVATE_NET}"]\n',
    # VERIFY4 SF2: special-use addresses are let through, and never shield a real one
    "ipv4-compatible real": f"scope:\n  target: ['{COMPAT_REAL}']\n",
    "loopback beside a real address": f"scope:\n  bind: {LOOPBACK}\n  wan: [{PUBLIC_V4}]\n",
    "mapped loopback beside a real address": (
        f"scope:\n  bind: '::ffff:{LOOPBACK}'\n  wan: ['{PADDED}/32']\n"
    ),
    # VERIFY4 SF3: a Python subscript assignment, this repository's own test idiom
    "subscript, short form": f'site["scope"]["target"] = ["{SHORT_PRIVATE}/16"]\n',
    "subscript, zero-padded": f'site["scope"]["trusted"]["wan"] = ["{PADDED}/32"]\n',
    "subscript, integer": f"site['scope']['trusted']['wan'] = [{PUBLIC_INT}]\n",
    "subscript, augmented": f'site["scope"]["target"] += ["{PADDED}/32"]\n',
    "subscript, multi-line": f'site["scope"] = {{\n    "target": ["{PRIVATE_NET}"],\n}}\n',
    # VERIFY4 N1: a dotted key needs its `:` or `=`, and every spelling of one still has it
    "yaml dotted key": f"scope.trusted.wan: ['{PADDED}/32']\n",
    "markdown dotted key": f"`scope.trusted.wan`: {PADDED}\n",
    "toml spaced dotted key": f'scope . trusted . wan = ["{PADDED}/32"]\n',
    "toml quoted dotted key": f'scope."trusted".wan = ["{PADDED}/32"]\n',
    "attribute assignment": f'self.scope.target = ["{PRIVATE_NET}"]\n',
    "indexed dotted key": f"helm upgrade x . --set scope.target[0]={SHORT_PRIVATE}/16\n",
    # VERIFY2 B1: loader-valid layouts the raw locator alone missed (the parse pass reads them)
    "toml header, CRLF": f'[scope]\r\ntarget = ["{PRIVATE_NET}"]\r\n',
    "toml array of tables, CRLF": f'[[scope]]\r\ntarget = ["{PRIVATE_NET}"]\r\n',
    "yaml, CR only": f"scope:\r  target:\r  - '{PRIVATE_NET}'\r",
    "explicit key with a comment": (
        f'? scope  # the lab\n: trusted:\n    nets: ["{PRIVATE_NET}"]\n'
    ),
    "flow continued dedented": f'site:\n  scope:\n    target: [\n "{PRIVATE_NET}"]\n',
    "key spelled by an alias": f'labels: [&k scope]\n*k :\n  target: ["{PRIVATE_NET}"]\n',
    "alias key, alias value": f"k: &k scope\nv: &v {{target: ['{PADDED}/32']}}\n*k : *v\n",
    "json value on the next line": '{"scope":\n{"target": ["' + PADDED + '/32"]}}\n',
    "json value dedented": '  {"scope":\n{"target": ["' + PADDED + '/32"]}}\n',
    "flow mapping, key and value on later lines": f"{{\nscope\n:\n['{PADDED}/32']}}\n",
    "double-quoted value continued at column 0": f'scope: "wan\n{PADDED}"\n',
    # VERIFY2 B1/SF3: anchors are real definitions, the last one before the alias
    "anchor redefined": f"d: &a ['{DOC}.0/24']\nr: &a ['{PADDED}/32']\nscope:\n  target: *a\n",
    "anchor decoy in a comment": f"# see &a below\nr: &a ['{PADDED}/32']\nscope:\n  target: *a\n",
    "anchor decoy in a string": f"n: 'x &a y'\nr: &a ['{PADDED}/32']\nscope:\n  target: *a\n",
    "anchor decoy in a block scalar": (
        f"n: |\n  &a\nr: &a ['{PADDED}/32']\nscope:\n  target: *a\n"
    ),
    "the 257th alias": (
        "".join(f"d{i}: &a{i} 1\n" for i in range(260))
        + f"real: &zz ['{PADDED}/32']\nscope:\n  target: ["
        + ", ".join(f"*a{i}" for i in range(260))
        + ", *zz]\n"
    ),
    # VERIFY2 SF2: inet_aton short forms that cannot be a version
    "short form, a part over 255": f"scope:\n  target: ['{SHORT_GLOBAL}']\n",
    "short form, hex parts": f"scope:\n  target: ['{SHORT_HEX}']\n",
    "short form, two parts": f"scope:\n  target: ['{SHORT_TWO}']\n",
    # VERIFY3 SF3: Markdown spellings of the key, and a CIDR short form leak_scan does not see
    "markdown backtick key": f"- `scope`: `{PRIVATE_NET}`\n",
    "markdown bold key": f"- **scope**: {SHORT_PRIVATE}/16\n",
    "markdown underscore key": f"_scope_: {SHORT_PRIVATE}/16\n",
    "markdown table row": f"| key | value |\n|---|---|\n| scope | {SHORT_PRIVATE}/16 |\n",
    "markdown table row, code": f"| `scope` | `{SHORT_PRIVATE}/16` |\n",
    # VERIFY3 SF4: a notebook stores each line of a cell as its own JSON string
    "notebook code cell": notebook(
        "code",
        [
            "x = yaml.safe_load(" + TQ + "\n",
            "scope:\n",
            "  target:\n",
            f"  - {PADDED}/32\n",
            TQ + ")\n",
        ],
    ),
    "notebook markdown cell": notebook(
        "markdown", ["```yaml\n", "scope:\n", "  target:\n", f"  - {SHORT_PRIVATE}/16\n", "```\n"]
    ),
    "notebook output": notebook(
        "code",
        ["print(sel)"],
        [{"output_type": "stream", "text": ["{'scope':\n", f" {{'target': ['{PADDED}/32']}}}}\n"]}],
    ),
}

#: a site block in the wrong shape, holding documentation addresses only (or none): refused at
#: an allowlisted path, where the strict parse judges every leaf; elsewhere it shows no address,
#: so the location rule lets it through (a public page may show a scope block's shape)
SHAPE_CASES = {
    "not an address": "scope:\n  target: [not-an-address]\n",
    "a bool": "scope:\n  target: [true]\n",
    "a float": "scope:\n  target: [1.5]\n",
    "tagged entry": f"scope:\n  target: [!ip '{DOC}.0/24']\n",
    "json with comments": f'// c\n{{"scope": {{"target": ["{DOC}.0/24"]}}}}\n',
    "misspelt top-level part": f"scope:\n  targets: [{DOC}.0/24]\n",
    "upper-case key": f"Scope:\n  target: [{DOC}.0/24]\n",
    "nested": f"site:\n  scope:\n    target: [{DOC}.0/24]\n",
    "unparseable": "scope: [unclosed\n",
    "self alias": "scope:\n  target: &a [*a]\n",
    "alias into scope": f"a: &x {{target: [{DOC}.0/24]}}\nscope: *x\n",
    "documentation address, prefix beyond three digits": f"scope:\n  target: ['{DOC}.1/0033']\n",
    "too deep to parse": "scope:\n  target: " + "[" * 100 + "]" * 100 + "\n",  # N3
}

#: where a file holding a scope key may sit: every one is read (N2: any suffix, none at all)
ANYWHERE = (
    "examples/site.yml",
    "examples/site.yml.tpl",
    "examples/site.yaml.dist",
    "examples/site.jsonc",
    "examples/site.yml.bak",
    "examples/modules",
    "docs/guide.md",
    "notes.txt",
)


def _plant(tmp_path: Path, rel: str, text: str) -> Path:
    root = public_tree(tmp_path)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return root


SCOPE_RULES = {"scope-address", "scope-shape", "scope-unparsed"}


@pytest.mark.parametrize("case", sorted(ADDRESS_CASES))
def test_a_real_address_under_a_scope_key_fails_wherever_it_is(case):
    """Negative: a non-documentation address under any scope key, in any spelling, fails in every
    file at every path; at an allowlisted path the strict parse also judges it."""
    text = ADDRESS_CASES[case]
    for rel in ANYWHERE:
        found = plc.scope_findings(rel, text)
        assert "scope-address" in rules(found), (case, rel)
        assert rules(found) <= SCOPE_RULES, (case, rel)
    found = plc.scope_findings(SITE, text)
    assert found and rules(found) <= SCOPE_RULES, case


@needs_skeleton
@pytest.mark.parametrize("case", ["zero-padded", "markdown indented fence", "schema examples"])
@pytest.mark.parametrize("rel", ["notes.txt", "examples/modules", SITE])
def test_the_public_check_reads_every_file(tmp_path, case, rel):
    """N2: check_public hands every file the scanner reads to the scope check, any suffix."""
    root = _plant(tmp_path, rel, ADDRESS_CASES[case])
    assert "scope-address" in rules(plc.check_public(root))
    assert run("public", str(root)).returncode == 1


@pytest.mark.parametrize("case", sorted(SHAPE_CASES))
def test_a_wrong_shape_fails_at_an_allowlisted_path(case):
    """Negative: at an allowlisted path every leaf is judged, any shape the strict parse cannot
    judge is a finding, and a file too deep or too large is refused before any parser sees it."""
    found = plc.scope_findings(SITE, SHAPE_CASES[case])
    assert found and rules(found) <= SCOPE_RULES, case


@pytest.mark.parametrize("case", sorted(SHAPE_CASES))
def test_a_wrong_shape_without_an_address_is_not_judged_elsewhere(case):
    """The location rule: outside the allowlist only addresses are judged, so a page showing a
    block's shape with documentation addresses (or none) passes."""
    for rel in ANYWHERE:
        assert plc.scope_findings(rel, SHAPE_CASES[case]) == [], (case, rel)


#: site blocks in the selection's shape with documentation networks only: pass everywhere
PASSING_SITE_BLOCKS = [
    f"scope:\n  trusted:\n    wan: [{DOC3}.7/32]\n    nets: [{DOC}.0/24, 2001:db8::/48]\n",
    "scope:\n  target: [" + "198.51.100" + ".0/33]\n",  # the generated negative's malformed entry
    f"scope:\n  target: ['::ffff:{DOC}.1']\n",  # a mapped documentation address
    "scope:\n  target: ['3fff::/20']\n",  # RFC 9637
    "scope:\n  target: ['2001:db8::1e8']\n",  # a hex group is not a number
    f"scope:\n  target: [{DOC}.0/24]\n  exclude:\n    offensive: []\n",  # nothing excluded
    "scope:\n  trusted:\n    wan: [{source: wan-dhcp}]\n",  # a dynamic source names nothing
    "scope:\n  trusted:\n    wan:\n",  # null: no value
]
#: other documents' scope keys, and text near a scope key that names no address: pass outside
#: the allowlist (at an allowlisted path a scope key is the selection's, so these are shapes)
PASSING_ELSEWHERE = [
    "scope: analyst\n",  # a record's scope
    "scope:\n  capabilities: [cap:monitoring]\n",  # a customization's selectors
    'scope: {"type": "object", "properties": {"target": {"type": "array"}}, "maxItems": 6}\n',
    "parameters:\n  scope: {env: RECORDS_SCOPE, default: '{profile}'}\n",  # an MCP parameter
    "scope: {since: 1.0, versions: [1.2, 16.4, 2.1.0]}\n",  # versions, not short forms
    'note: "\\x38\\x31.' + PUBLIC_V4.split(".", 1)[1] + '"\n',  # an escape outside any scope
    "x: !vault |\n  abc\ny: [broken\n",  # no scope here: hygiene's finding, not this one's
    f"scope: x\nother: {PADDED}\n",  # a sibling of the scope key, not under it
    # VERIFY3 SF2: a keyword argument or an HTML attribute is no scope key, and a bare short
    # form that can be a version or a decimal is never an address (literals split: this source
    # is scanned too)
    "@pytest.fixture(scope='module', params=[0." + "05, 0.1])\n",
    '@pytest.fixture(scope="module")\n' + '@pytest.fixture(scope="session")\n',
    "run(scope='x', timeout=1." + "500)\n",
    '        scope=g.raw.get("scope"),\n        timeout=0.' + "05,\n",
    '<th scope="row">1.' + '300</th><th scope="col">24.' + "04</th>\n",
    '{"scope": "read", "ratio": 0.' + '05, "iat": 1' + "700000000}\n",
    "scope:\n  ubuntu: 24."
    + "04\n  ratio: 0."
    + "05\n  v: 1.0."
    + "3\n  bare: "
    + SHORT_PRIVATE
    + "\n",
    "The scope: we cut latency by 0." + "05 s.\n",
    # VERIFY4 SF1: an indented `scope =` holds the lines deeper than the key, not the rest of
    # its enclosing block (the column is the key's first character, not its line's start)
    "def f(x):\n    scope = x.scope\n    if scope:\n        pass\n    return 17" + "00000000\n",
    "[server]\n  scope = 'local'\n  since = 17" + "00000000\n",
    # VERIFY4 SF2: loopback, unspecified and link-local name no site; `::` in code (a slice, a
    # C++ or Ruby scope operator) is judged by its embedded IPv4 address, which is in 0/8
    "scope = sorted(nets)[" + "::-1]\n",
    'top = scope.get("nets", [])[' + "::2]\n",
    "scope = Foo<T>" + "::bar()\nscope = " + ":" * 2 + "Account.find(1)\n",
    f'scope = {{"type": "http", "client": ("{LOOPBACK}", 51234)}}\n',  # an ASGI test scope
    f"scope:\n  bind: {LOOPBACK}\n  any: {UNSPECIFIED}:9090\n  metadata: {METADATA}\n"
    + "  v6: '["
    + ":" * 2
    + "1]:9090'\n  wild: '["
    + ":" * 2
    + "]:80'\n  ll: 'fe80"
    + "::1%eth0'\n"
    + f"  mapped: '::ffff:{LOOPBACK}'\n",
    # VERIFY4 SF3: a comparison is no assignment
    'assert site["scope"]["n"] == 17' + "00000000\n",
    # VERIFY4 N1: an attribute access or a method call is no dotted key
    'scope.set_extra("max_body", 10' + "4857600)\n",
    'limit = scope.get("limit", 26' + "8435456)\nif scope.x == 17" + "00000000:\n    pass\n",
]


@pytest.mark.parametrize("text", PASSING_SITE_BLOCKS)
def test_a_site_block_with_documentation_ranges_passes_everywhere(text):
    for rel in (SITE, *ANYWHERE):
        assert plc.scope_findings(rel, text) == [], rel


@pytest.mark.parametrize("text", PASSING_ELSEWHERE)
def test_a_scope_key_naming_no_address_passes_outside_the_allowlist(text):
    for rel in ANYWHERE:
        assert plc.scope_findings(rel, text) == [], rel


@needs_skeleton
def test_a_public_tree_with_documentation_scope_blocks_passes(tmp_path):
    root = _plant(tmp_path, SITE, PASSING_SITE_BLOCKS[0])
    (root / "docs").mkdir()
    (root / "docs" / "guide.md").write_text(PASSING_SITE_BLOCKS[0] + PASSING_ELSEWHERE[4])
    assert plc.check_public(root) == []


@pytest.mark.parametrize(
    ("rel", "allowed"),
    [
        ("examples/modules/sites/full.yml", True),
        ("schemas/platform/examples/module_selection.full.yml", True),
        ("schemas/platform/negative/module_selection.scope-empty-list.yml", True),
        ("examples/modules/sites/sub/full.yml", False),
        ("examples/modules/sites/full.yml.bak", False),
        ("examples/modules/sites/full.yaml", False),
        ("schemas/platform/examples/module.feature.yml", False),
        ("lab/modules.yml", False),
    ],
)
def test_the_allowlist_is_exact_paths(rel, allowed):
    assert plc.scope_block_path(rel) is allowed


@pytest.mark.parametrize(
    "rel",
    [
        "examples/Modules/sites/full.yml",
        "examples/modules/sites/full.YML",
        "EXAMPLES/modules/sites/x.yml",
    ],
)
def test_a_case_variant_of_an_allowlisted_path_is_refused(rel):
    """N1: a case-insensitive file system would load it as a site profile."""
    assert not plc.scope_block_path(rel)
    assert "scope-shape" in rules(plc.scope_findings(rel, PASSING_SITE_BLOCKS[0]))


@pytest.mark.parametrize("text", ["scope:\n  target: ['1." + "300']\n", "scope: [0x1." + "0x2]\n"])
def test_a_short_form_that_is_no_version_is_judged_strictly(text):
    """SF2: only plain decimal parts of at most 255 read as a version."""
    assert "scope-address" in rules(plc.scope_findings("x.yml", text))


def test_every_allowlist_entry_names_files_that_exist():
    for glob in plc.SCOPE_BLOCK_PATHS:
        assert list(ROOT.glob(glob)), glob


def test_an_alias_shape_is_never_expanded(monkeypatch):
    """S8: a self-alias and a billion-laughs shape (10**9 leaves by value) are answered from one
    pass over the composed nodes: the leaf check runs a handful of times, not once per leaf."""
    calls = []
    real = plc._documentation_leaf
    monkeypatch.setattr(plc, "_documentation_leaf", lambda n: calls.append(1) or real(n))
    laughs = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
    for i in range(1, 9):
        prev, cur = chr(96 + i), chr(97 + i)
        laughs += f"{cur}: &{cur} [" + ", ".join([f"*{prev}"] * 10) + "]\n"
    laughs += "scope:\n  target: [*i, *i]\n"
    for text in ("scope:\n  target: &a [*a]\n", laughs):
        assert "scope-shape" in rules(plc.scope_findings(SITE, text))
    assert len(calls) < 50


@pytest.mark.parametrize(
    "text",
    [
        "scope:\n  target: " + "[" * 100_000 + "]" * 100_000 + "\n",
        "scope:\n" + "".join(" " * (2 * i) + "a:\n" for i in range(1, 80)),
        "scope:\n  target:\n  " + "- " * 200 + "x\n",
        "scope:\n  target: [" + ", ".join([f"{DOC}.1"] * 60_000) + "]\n",
    ],
    ids=["deep flow", "deep indent", "block indicators", "large"],
)
def test_a_deep_or_large_allowlisted_file_is_refused_before_parsing(text):
    """N3: libyaml's C composer segfaults on deep nesting; the strict parse bounds depth and size
    first and refuses what is over the limit, so no file can take the gate down."""
    # in a child process: a parser crash (the segfault this guards against) fails this test
    # instead of taking the whole test run down with it
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import private_leak_check as plc; "
        "print(sorted({f.rule for f in plc.scope_findings(sys.argv[2], sys.stdin.read())}))"
    )
    r = subprocess.run(
        [sys.executable, "-c", code, str(TOOL.parent), SITE],
        input=text,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, (r.returncode, r.stderr[-300:])
    assert "scope-unparsed" in r.stdout


@needs_skeleton
def test_a_deeply_nested_file_fails_the_command_cleanly(tmp_path):
    root = _plant(tmp_path, SITE, "scope:\n  target: " + "[" * 100_000 + "]" * 100_000 + "\n")
    r = run("public", str(root))
    assert r.returncode == 1, (r.returncode, r.stderr[-300:])
    assert "scope-unparsed" in r.stdout


def test_the_scope_check_never_crashes_open(monkeypatch):
    def boom(*_a, **_k):
        raise RecursionError

    monkeypatch.setattr(plc, "_raw_findings", boom)
    assert rules(plc.scope_findings("docs/x.md", "scope: x\n")) == {"scope-unparsed"}


#: (file, text at size n): every shape VERIFY2 and VERIFY3 found quadratic, and the earlier
#: ones; each must grow about linearly
LINEAR_SHAPES = {
    "unclosed flows": ("x.yml", lambda n: "scope: [\n" * n),
    "nested closed flows": ("x.yml", lambda n: "scope: [" * n + "]" * n + "\n"),
    "indented keys": ("x.yml", lambda n: "".join("  " * (i % 20) + "scope:\n" for i in range(n))),
    "one closed flow per line": ("x.yml", lambda n: "scope: [x]\n" * n),
    "TOML tables leaving an array open": ("x.toml", lambda n: "[scope]\nx = [\n" * n),
    "list items starting with the key": (
        "x.yml",
        lambda n: "".join(f"- scope: read\n  id: {i}\n" for i in range(n)),
    ),
    "minified JSON, one line": (
        "x.json",
        lambda n: "[" + ",".join(f'{{"scope":"a","id":{i}}}' for i in range(n)) + "]",
    ),
    "dotted paths that never assign": ("x.py", lambda n: "scope." * n + "\n"),
    "subscripts that never assign": ("x.py", lambda n: '["scope"]' * n + "\n"),
    "one-line HTML with entities": (
        "x.html",
        lambda n: "".join(
            '<th scope="row">Tom &amp; Jerry</th><td>a &nbsp; b</td>' for _ in range(n)
        ),
    ),
}


class _CpuCap:
    """Fail a call that uses more than ``seconds`` of this process's CPU time (``ITIMER_PROF``,
    so other processes on a busy runner do not count): a superlinear rule fails in seconds
    instead of running for minutes, as it would where this test runs against a quadratic parent
    (``tools/fix_has_test.py --prove``).  The timer raises a ``BaseException`` so the gate's
    fail-closed ``except Exception`` cannot swallow it, and leaving the block turns it into an
    assertion.  A no-op without ``setitimer`` or off the main thread."""

    class Exceeded(BaseException):
        pass

    def __init__(self, seconds: float, what: str) -> None:
        import signal
        import threading

        self.signal, self.seconds, self.what = signal, seconds, what
        self.armed = hasattr(signal, "setitimer") and (
            threading.current_thread() is threading.main_thread()
        )
        self.old = None

    def _stop(self, signum, frame):
        raise _CpuCap.Exceeded

    def __enter__(self) -> _CpuCap:
        if self.armed:
            self.old = self.signal.signal(self.signal.SIGPROF, self._stop)
            self.signal.setitimer(self.signal.ITIMER_PROF, self.seconds)
        return self

    def __exit__(self, kind: object, *_: object) -> bool:
        if self.armed:
            self.signal.setitimer(self.signal.ITIMER_PROF, 0)
            self.signal.signal(self.signal.SIGPROF, self.old)
        if kind is _CpuCap.Exceeded:
            raise AssertionError(f"{self.what}: more than {self.seconds:.2f} s of CPU in one call")
        return False


@pytest.mark.parametrize("shape", sorted(LINEAR_SHAPES))
def test_the_raw_rule_grows_linearly(shape):
    """VERIFY3 SF1: a ratio, not an absolute bound.  Time at n, 4n and 16n; each 4x step may
    cost at most 8x (plus a small floor for timer noise), so a quadratic shape (16x a step)
    fails.  VERIFY4 SF4: the time is this process's CPU time (``time.process_time``), best of
    five, not wall clock: a busy runner's other processes and CPU steal moved wall-clock ratios
    by 7x and failed this test on noise alone."""
    import gc
    import time

    rel, make = LINEAR_SHAPES[shape]

    def timed(n: int, cap: float) -> float:
        text = make(n)
        best = float("inf")
        gc.collect()
        gc.disable()  # the collector's full passes grow with live objects: noise, not the rule
        try:
            for _ in range(5):
                t0 = time.process_time()
                with _CpuCap(cap, f"{shape} at n={n}"):
                    plc.scope_findings(rel, text)
                best = min(best, time.process_time() - t0)
        finally:
            gc.enable()
        return best

    # each step is capped at a generous multiple of the last, so a superlinear shape fails at
    # the first step it blows up instead of running the larger sizes
    t1 = timed(2_000, 2.0)
    t4 = timed(8_000, 20 * t1 + 1.0)
    assert t4 <= 8 * t1 + 0.1, (shape, t1, t4)
    t16 = timed(32_000, 20 * t4 + 1.0)
    assert t16 <= 8 * t4 + 0.1, (shape, t4, t16)


@needs_skeleton
def test_the_one_exemption_is_one_exact_location_in_one_file(tmp_path):
    """N6: the generated misspelt-part negative passes only at its own path and only for its own
    misspelt key, matched exactly; what that key holds is still read."""
    rel = "schemas/platform/negative/module_selection.scope-unknown-part.yml"
    assert [k[0] for k in plc.SCOPE_EXEMPT] == [rel]
    text = (ROOT / rel).read_text()
    root = public_tree(tmp_path)
    (root / rel).parent.mkdir(parents=True)
    (root / rel).write_text(text)
    assert plc.check_public(root) == []
    copy = root / "examples" / "modules" / "sites" / "copy.yml"
    copy.parent.mkdir(parents=True)
    copy.write_text(text)
    assert rules(plc.check_public(root)) == {"scope-shape"}
    copy.unlink()
    (root / rel).write_text(text.replace("    lan:\n", "    'lan: x':\n"))
    assert rules(plc.check_public(root)) == {"scope-shape"}
    (root / rel).write_text(text.replace(f"lan:\n    - {DOC}.0/24", f"lan:\n    - {PRIVATE_NET}"))
    assert rules(plc.check_public(root)) == {"scope-address"}


def test_the_example_sites_carry_a_scope_block_the_check_reads():
    """The check is not vacuous on this tree: every example site has a scope block it parses
    strictly, and a planted non-documentation address fails it."""
    sites = sorted((ROOT / "examples" / "modules" / "sites").glob("*.yml"))
    assert sites
    for p in sites:
        rel = p.relative_to(ROOT).as_posix()
        text = p.read_text()
        assert plc.scope_block_path(rel)
        assert plc.scope_findings(rel, text) == []
        planted = text.replace("203.0.113.", "198.18.0.", 1)
        assert rules(plc.scope_findings(rel, planted)) == {"scope-address"}, p


@needs_skeleton
def test_skeleton_marker_must_stay_fictional(tmp_path):
    root = public_tree(tmp_path)
    m = root / "examples" / "private-overlay" / ".hnx-private-overlay.yml"
    m.write_text(m.read_text().replace("fictional: true", "fictional: false"))
    assert rules(plc.check_public(root)) == {"overlay-marker"}


@needs_skeleton
def test_skeleton_declares_the_private_layout():
    doc = plc.read_marker(SKELETON / ".hnx-private-overlay.yml")
    assert doc["fictional"] is True
    assert "lab/" in doc["private_paths"]
    for p in doc["private_paths"]:
        assert (SKELETON / p).is_dir(), p
