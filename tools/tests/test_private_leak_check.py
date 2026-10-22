# SPDX-License-Identifier: Apache-2.0
"""tools/private_leak_check.py: every rule fails on a bad tree and passes on a good one.

Planted credential values are assembled at run time so this file stays clean under the public
scanner; the private overlays are built in ``tmp_path`` (outside any git work tree).
"""

from __future__ import annotations

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
SOPS_RULES = "creation_rules:\n  - path_regex: (^|/)lab/sealed/.*\\.sops\\.ya?ml$\n    age: x\n"
VAULT = "$" + "ANSIBLE_VAULT;1.1;AES256\n" + "6331" * 16 + "\n" + "3964" * 16 + "\n"
AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"
AGE_KEY = "AGE-SECRET-" + "KEY-1" + ("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" * 2)[:58]
SOPS_FILE = (
    "wan:\n    address: ENC[AES256_GCM,data:"
    + "Zx9Qw3Rt7Yp2Lk8V"
    + "b5Nm1Cd4Fg6Hj0sA"
    + ",iv:abc,tag:def,type:str]\n"
    "sops:\n    age:\n        - recipient: age1x\n          enc: |\n"
    "            -----BEGIN AGE ENCRYPTED FILE-----\n"
    "            YWdlLWVuY3J5cHRp" + "b24ub3JnL3YxCi0+" + "IFgyNTUxOSBhYmNk\n"
    "            -----END AGE ENCRYPTED FILE-----\n"
    "    mac: ENC[AES256_GCM,data:Qk9Mzx7Lp2Vb5N" + "m1Cd4Fg6Hj0sAZx9,iv:a,tag:b,type:str]\n"
    "    version: 3.9.0\n"
)


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


def test_vault_file_must_be_vault_encrypted(tmp_path):
    for rel in ("inv/prod/group_vars/all/vault.yml", "roles/x/creds.vault.yml"):
        found = plc.check_private(overlay(tmp_path / rel.replace("/", "_"), {rel: "a: b\n"}))
        assert [(f.path, f.rule) for f in found] == [(rel, "vault-unencrypted")]


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
    doc = {"a": "ENC[AES256_GCM,data:abc,iv:x,tag:y,type:str]", "sops": {"mac": "m"}}
    assert json.loads(plc.masked(json.dumps(doc))) == {"a": "ENC[]"}
    assert plc.sops_format("k=ENC[AES256_GCM,data:x]\nsops_mac=y\n") == "dotenv"
    assert plc.sops_format("[x]\nk=v\n[sops]\nmac=y\n") == "ini"
    assert plc.masked(VAULT) == ""


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
