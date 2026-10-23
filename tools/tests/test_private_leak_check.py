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
DOC = "192.0.2"  # a three-part documentation prefix (no four-part literal in this source)

#: (file name, text): a public scope block that names a real address or network, in every
#: shape the gate reads.  Each must fail; the review's probe rows are all here.
FAILING_SCOPES = {
    "plain": ("site.yml", f"scope:\n  trusted:\n    wan: [{PUBLIC_HOST}/32]\n"),
    "private": ("site.yml", f"scope:\n  target: [{DOC}.0/24, {PRIVATE_NET}]\n"),
    "everything": ("site.yml", f"scope:\n  target: ['{EVERYTHING}']\n"),
    "everything v6": ("site.yml", "scope:\n  exclude:\n    offensive: ['::/0']\n"),
    "widened": ("site.yml", f"scope:\n  target: [{DOC}.0/16]\n"),
    "misspelt part": ("site.yml", f"scope:\n  trusted:\n    lan: [{PRIVATE_NET}]\n"),
    "malformed real": ("site.yml", f"scope:\n  target: ['{PRIVATE_NET.replace('/16', '/33')}']\n"),
    "json": ("site.json", f'{{"profile": "x", "scope": {{"target": ["{PRIVATE_NET}"]}}}}\n'),
    # B1: spellings ipaddress refuses but a person and inet_aton read as an address
    "zero-padded": ("site.yml", f"scope:\n  trusted:\n    wan: ['{PADDED}/32']\n"),
    "integer string": ("site.yml", f"scope:\n  trusted:\n    wan: ['{PUBLIC_INT}']\n"),
    "yaml int": ("site.yml", f"scope:\n  trusted:\n    wan: [{PUBLIC_INT}]\n"),
    "hex string": ("site.yml", f"scope:\n  trusted:\n    wan: ['{PUBLIC_HEX}']\n"),
    "yaml hex int": ("site.yml", f"scope:\n  trusted:\n    wan: [{PUBLIC_HEX}]\n"),
    "not an address": ("site.yml", "scope:\n  target: [not-an-address]\n"),
    "a bool": ("site.yml", "scope:\n  target: [true]\n"),
    "a float": ("site.yml", "scope:\n  target: [1.5]\n"),
    "space before prefix": ("site.yml", f"scope:\n  target: ['{PUBLIC_V4} /32']\n"),
    "zone id": ("site.yml", "scope:\n  target: ['2001:db8::1%eth0']\n"),
    "mapped real": ("site.yml", f"scope:\n  target: ['::ffff:{PUBLIC_V4}']\n"),
    # S1: every YAML and JSON form of the key and the block
    "flow style": ("site.yml", f"{{scope: {{target: ['{EVERYTHING}']}}}}\n"),
    "single-quoted key": ("site.yml", f"'scope':\n  target: ['{EVERYTHING}']\n"),
    "explicit key": ("site.yml", f"? scope\n: target: ['{EVERYTHING}']\n"),
    "tab before colon": ("site.yml", f"scope\t:\n  target: ['{EVERYTHING}']\n"),
    "byte-order mark": ("site.yml", f"\ufeffscope:\n  target: ['{EVERYTHING}']\n"),
    "json escaped key": ("site.json", '{"\\u0073cope": {"target": ["' + EVERYTHING + '"]}}\n'),
    "yaml escaped key": ("site.yml", f"\"\\x73cope\":\n  target: ['{EVERYTHING}']\n"),
    "custom tag elsewhere": (
        "site.yml",
        f"x: !vault |\n  abc\nscope:\n  target: ['{EVERYTHING}']\n",
    ),
    "custom tag and padding": (
        "site.yml",
        f"x: !Ref y\nscope:\n  trusted:\n    wan: ['{PADDED}']\n",
    ),
    "tagged entry": ("site.yml", f"scope:\n  target: [!ip '{DOC}.0/24']\n"),
    "merge key": ("site.yml", f"base: &b\n  scope:\n    target: ['{EVERYTHING}']\n<<: *b\n"),
    "duplicate scope key": (
        "site.yml",
        f"scope:\n  target: ['{EVERYTHING}']\nscope:\n  target: [{DOC}.0/24]\n",
    ),
    "duplicate part": ("site.yml", f"scope:\n  target: [{DOC}.0/24]\n  target: [{PRIVATE_NET}]\n"),
    "json duplicate key": (
        "site.json",
        f'{{"scope": {{"target": ["{DOC}.0/24"], "target": ["{EVERYTHING}"]}}}}\n',
    ),
    "json with comments": ("site.json", f'// c\n{{"scope": {{"target": ["{DOC}.0/24"]}}}}\n'),
    "upper-case key": ("site.yml", f"Scope:\n  target: ['{EVERYTHING}']\n"),
    "nested": ("site.yml", f"site:\n  scope:\n    target: ['{EVERYTHING}']\n"),
    "misspelt top-level part": ("site.yml", f"scope:\n  targets: [{DOC}.0/24]\n"),
    "a scope list": ("site.yml", f"scope: [{PRIVATE_NET}]\n"),
    "second document": ("site.yml", f"a: 1\n---\nscope:\n  target: ['{EVERYTHING}']\n"),
    "address as a key": ("site.yml", f"scope:\n  target:\n    '{PUBLIC_V4}': x\n"),
    "unparseable": ("site.yml", "scope: [unclosed\n"),
    "upper-case suffix": ("site.YML", f"scope:\n  target: ['{EVERYTHING}']\n"),
    "a template": ("site.yml.j2", f"scope:\n  target: ['{EVERYTHING}']\n"),
    "an example": ("lab.yaml.example", f"scope:\n  target: ['{EVERYTHING}']\n"),
    "toml": ("site.toml", f'[scope]\ntarget = ["{EVERYTHING}"]\n'),
    "markdown fence": ("guide.md", f"# x\n\n```yaml\nscope:\n  target: ['{EVERYTHING}']\n```\n"),
    "markdown untagged fence": ("guide.md", f"```\nscope:\n  target: ['{EVERYTHING}']\n```\n"),
    # S8: an alias in a scope block is refused, and never expanded
    "self alias": ("site.yml", "scope:\n  target: &a [*a]\n"),
    "alias into scope": ("site.yml", f"a: &x {{target: [{DOC}.0/24]}}\nscope: *x\n"),
}


@needs_skeleton
@pytest.mark.parametrize("case", sorted(FAILING_SCOPES))
def test_public_scope_block_with_a_real_address_fails(tmp_path, case):
    """Negative: a public scope block that names a real address or network, or that the gate
    cannot read, fails in every shape the gate reads (no shape is silently skipped)."""
    name, text = FAILING_SCOPES[case]
    root = public_tree(tmp_path)
    p = root / "examples" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    assert rules(plc.check_public(root)) <= {"scope-address", "scope-shape", "scope-unparsed"}
    assert plc.check_public(root), case
    assert run("public", str(root)).returncode == 1


@needs_skeleton
@pytest.mark.parametrize(
    "text",
    [
        f"scope:\n  trusted:\n    wan: [{DOC.replace('192.0.2', '203.0.113')}.7/32]\n    nets: [{DOC}.0/24, 2001:db8::/48]\n",
        "scope:\n  target: [198.51.100.0/33]\n",  # the generated negative's malformed entry
        f"scope:\n  target: ['::ffff:{DOC}.1']\n",  # a mapped documentation address
        "scope:\n  target: ['3fff::/20']\n",  # RFC 9637
        f"scope:\n  target: [{DOC}.0/24]\n  exclude:\n    offensive: []\n",  # nothing excluded
        "scope:\n  trusted:\n    wan: [{source: wan-dhcp}]\n",  # a dynamic source names nothing
        "scope:\n  trusted:\n    wan:\n",  # null: no value
        "scope: analyst\n",  # another document's scope (a record's)
        "scope:\n  capabilities: [cap:monitoring]\n",  # a customization's selectors
        'scope: {"type": "object", "properties": {"target": {"type": "array"}}}\n',  # a schema
        "parameters:\n  scope: {env: RECORDS_SCOPE, default: '{profile}'}\n",  # an MCP parameter
        'note: "\\x38\\x31.2.69.142"\n',  # an escape outside any scope block
        "x: !vault |\n  abc\ny: [broken\n",  # no scope here: hygiene's finding, not this one's
    ],
)
def test_public_scope_block_with_documentation_ranges_passes(tmp_path, text):
    root = public_tree(tmp_path)
    (root / "examples" / "site.yml").write_text(text)
    assert plc.check_public(root) == []


@needs_skeleton
@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("guide.md", "```python\nscope = {'target': ['x']}\n```\n"),  # another language
        ("guide.md", "```\nhnx scope check --target x: [y\n```\n"),  # shell, not YAML
        ("notes.txt", f"scope:\n  target: ['{EVERYTHING}']\n"),  # not read: leak_scan's
    ],
)
def test_what_the_scope_gate_does_not_read(tmp_path, name, text):
    root = public_tree(tmp_path)
    (root / "examples" / name).write_text(text)
    assert not any(f.rule.startswith("scope-") for f in plc.check_public(root))


@pytest.mark.parametrize(
    ("rel", "fmt"),
    [
        ("a/site.yml", "yaml"),
        ("a/site.YAML", "yaml"),
        ("a/site.yml.j2", "yaml"),
        ("a/site.yaml.example", "yaml"),
        ("a/site.json", "json"),
        ("a/site.toml", "toml"),
        ("a/README.md", "md"),
        ("a/site.py", None),
        ("a/.yml", None),
    ],
)
def test_scope_format_reads_through_template_suffixes(rel, fmt):
    assert plc.scope_format(rel) == fmt


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
        assert rules(plc.scope_findings("x.yml", text)) == {"scope-shape"}
    assert len(calls) < 50


def test_the_foreign_scope_vocabulary_matches_the_schemas_it_names():
    """A scope mapping with only these keys is another document's scope; the set must hold the
    customization selectors and the MCP parameter keys, or those files would read as site
    scope blocks with misspelt parts."""
    cust = json.loads((ROOT / "schemas/platform/customization.schema.json").read_text())
    mcp = json.loads((ROOT / "schemas/platform/mcp_server.schema.json").read_text())
    names = set(cust["properties"]["scope"]["properties"])
    names |= set(mcp["$defs"]["parameter"]["properties"])
    assert names <= plc.FOREIGN_SCOPE_KEYS
    assert not plc.FOREIGN_SCOPE_KEYS & {"trusted", "target", "exclude"}


@needs_skeleton
def test_the_one_exemption_is_one_location_in_one_file(tmp_path):
    """The generated misspelt-part negative passes only at its own path and only for its own
    misspelt key; what that key holds is still read."""
    rel = "schemas/platform/negative/module_selection.scope-unknown-part.yml"
    assert [k[0] for k in plc.SCOPE_EXEMPT] == [rel]
    text = (ROOT / rel).read_text()
    root = public_tree(tmp_path)
    (root / rel).parent.mkdir(parents=True)
    (root / rel).write_text(text)
    assert plc.check_public(root) == []
    (root / "examples" / "copy.yml").write_text(text)
    assert rules(plc.check_public(root)) == {"scope-shape"}
    (root / "examples" / "copy.yml").unlink()
    (root / rel).write_text(text.replace(f"lan:\n    - {DOC}.0/24", f"lan:\n    - {PRIVATE_NET}"))
    assert rules(plc.check_public(root)) == {"scope-address"}


def test_the_example_sites_carry_a_scope_block_the_check_reads():
    """The check is not vacuous on this tree: every example site has a scope block it parses."""
    sites = sorted((ROOT / "examples" / "modules" / "sites").glob("*.yml"))
    assert sites
    for p in sites:
        text = p.read_text()
        assert plc.scope_findings(p.name, text) == []
        planted = text.replace("203.0.113.", "198.18.0.", 1)
        assert rules(plc.scope_findings(p.name, planted)) == {"scope-address"}, p


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
