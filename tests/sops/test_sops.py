# SPDX-License-Identifier: Apache-2.0
"""SOPS-encrypted data files (homelabnext/sops.py) through the document readers.

The ``sops`` binary is a fake written into ``tmp_path``: it understands only its own
``ENC[FAKE,data:<base64>]`` values, drops the ``sops`` metadata and reads nothing outside the file
it is given.  Every value it "decrypts" is from the fictional example lab.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

from homelabnext import sops
from homelabnext.compute.loader import load_guests
from homelabnext.customization.loader import read_document
from homelabnext.network.loader import SiteError, load_site
from homelabnext.registry import model as registry_model

ROOT = Path(__file__).resolve().parents[2]
MINIMAL = ROOT / "examples" / "minimal"

FAKE_SOPS = """\
#!{python}
# a fake sops: decrypts ENC[FAKE,data:<base64>] values, drops the sops metadata
import base64, json, os, re, sys, time
args = sys.argv[1:]
mode = os.environ.get("FAKE_SOPS_MODE", "ok")
log = os.environ.get("FAKE_SOPS_ARGV")
if log:
    with open(log, "w", encoding="utf-8") as fh:
        json.dump(args, fh)
if mode == "fail":
    sys.stderr.write("first line\\n\\x1b[31mGroup 0: FAILED: no age identity matched\\x1b[0m\\n")
    sys.exit(128)
if mode == "slow":
    time.sleep(30)
if mode == "still-encrypted":
    sys.stdout.write(open(args[-1], encoding="utf-8").read())
    sys.exit(0)
assert args[:5] == ["--decrypt", "--input-type", args[2], "--output-type", args[2]], args
text = open(args[-1], encoding="utf-8").read()
dec = lambda m: base64.b64decode(m.group(1)).decode("utf-8")
rx = re.compile(r"ENC\\[FAKE,data:([A-Za-z0-9+/=]*)\\]")
if args[2] == "json":
    doc = json.loads(text)
    doc.pop("sops")
    sys.stdout.write(rx.sub(dec, json.dumps(doc)))
else:
    sys.stdout.write(rx.sub(dec, text.split("\\nsops:\\n")[0].rstrip("\\n") + "\\n"))
"""

META_YAML = """
sops:
    age:
        - recipient: age1fakefakefakefakefakefakefakefakefakefakefakefakefakefakefake
          enc: fake-wrapped-data-key
    lastmodified: "2026-01-01T00:00:00Z"
    mac: ENC[FAKE,data:]
    version: 3.9.0
"""


def enc(value: str) -> str:
    return "ENC[FAKE,data:" + base64.b64encode(value.encode()).decode() + "]"


def encrypt_yaml(text: str, key: str) -> str:
    """``text`` with the first ``key:`` value encrypted and the sops metadata appended."""
    rx = re.compile(rf"^(\s*{re.escape(key)}: )(\S.*)$", re.MULTILINE)
    m = rx.search(text)
    assert m, key
    out = text[: m.start(2)] + enc(m.group(2)) + text[m.end(2) :]
    return out.rstrip("\n") + "\n" + META_YAML


@pytest.fixture
def fake_sops(tmp_path, monkeypatch) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "sops"
    exe.write_text(FAKE_SOPS.format(python=sys.executable), encoding="utf-8")
    exe.chmod(0o700)
    monkeypatch.setenv(sops.SOPS_ENV, str(exe))
    monkeypatch.delenv("FAKE_SOPS_MODE", raising=False)
    return exe


@pytest.fixture
def no_sops(tmp_path, monkeypatch) -> None:
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.delenv(sops.SOPS_ENV, raising=False)
    monkeypatch.setenv("PATH", str(empty))


def write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ---- detection ---------------------------------------------------------------------------------


def test_plain_documents_are_not_encrypted():
    assert sops.format_of((MINIMAL / "site.yml").read_text(encoding="utf-8")) is None
    assert sops.format_of('{"a": 1}') is None
    # a field that happens to be called sops, without SOPS metadata, is data
    assert sops.format_of("sops:\n  note: a plain field\n") is None
    assert sops.format_of('{"sops": {"note": "plain"}}') is None
    assert sops.format_of("sops:\n  - [unbalanced\n") is None


def test_encrypted_yaml_and_json_are_detected():
    assert sops.format_of(encrypt_yaml("a: b\n", "a")) == "yaml"
    doc = {"a": enc("b"), "sops": {"mac": "ENC[FAKE,data:]", "version": "3.9.0"}}
    assert sops.format_of(json.dumps(doc, indent=1)) == "json"


# ---- the readers -------------------------------------------------------------------------------


def test_plain_file_is_read_without_sops(tmp_path, no_sops):
    p = write(tmp_path, "site.yml", (MINIMAL / "site.yml").read_text(encoding="utf-8"))
    assert load_site(p) == load_site(MINIMAL / "site.yml")


def test_encrypted_site_is_decrypted(tmp_path, fake_sops):
    plain = (MINIMAL / "site.yml").read_text(encoding="utf-8")
    p = write(tmp_path, "site.yml", encrypt_yaml(plain, "domain"))
    assert "domain: example.internal" not in p.read_text(encoding="utf-8")
    assert load_site(p) == load_site(MINIMAL / "site.yml")


def test_sops_runs_without_a_shell_on_the_exact_file(tmp_path, fake_sops, monkeypatch):
    argv_log = tmp_path / "argv.json"
    monkeypatch.setenv("FAKE_SOPS_ARGV", str(argv_log))
    p = write(tmp_path, "odd name; $(x).yml", encrypt_yaml("a: b\n", "a"))
    assert sops.read_text(p) == "a: b\n"
    assert json.loads(argv_log.read_text(encoding="utf-8")) == [
        "--decrypt",
        "--input-type",
        "yaml",
        "--output-type",
        "yaml",
        str(p),
    ]


def test_encrypted_registry_is_decrypted(tmp_path, fake_sops):
    plain = (MINIMAL / "services.yml").read_text(encoding="utf-8")
    p = write(tmp_path, "services.yml", encrypt_yaml(plain, "domain"))
    got = registry_model.load(p)
    assert got.domain == "example.internal"
    assert got.digest == registry_model.load(MINIMAL / "services.yml").digest


def test_encrypted_guest_is_decrypted(tmp_path, fake_sops):
    d = tmp_path / "guests"
    shutil.copytree(MINIMAL / "guests", d)
    g = d / "bus-core.yml"
    g.write_text(encrypt_yaml(g.read_text(encoding="utf-8"), "id"), encoding="utf-8")
    guests, problems = load_guests(d)
    assert problems == []
    assert "guest:bus-core" in {x.id for x in guests}


def test_encrypted_json_customization_is_decrypted(tmp_path, fake_sops):
    doc = {"id": enc("custom:fake-thing"), "sops": {"mac": "ENC[FAKE,data:]", "version": "3"}}
    p = write(tmp_path, "customization.json", json.dumps(doc))
    assert read_document(p) == {"id": "custom:fake-thing"}


def test_sops_found_on_path(tmp_path, fake_sops, monkeypatch):
    monkeypatch.delenv(sops.SOPS_ENV)
    monkeypatch.setenv("PATH", str(fake_sops.parent))
    p = write(tmp_path, "x.yml", encrypt_yaml("a: b\n", "a"))
    assert sops.read_text(p) == "a: b\n"


# ---- failures are loud -------------------------------------------------------------------------


def test_missing_binary_is_a_clear_error(tmp_path, no_sops):
    p = write(tmp_path, "site.yml", encrypt_yaml("site_version: 1\n", "site_version"))
    with pytest.raises(SiteError, match=r"SOPS-encrypted and sops on PATH was not found"):
        load_site(p)


def test_missing_explicit_binary_names_the_variable(tmp_path, monkeypatch):
    monkeypatch.setenv(sops.SOPS_ENV, str(tmp_path / "nope"))
    p = write(tmp_path, "x.yml", encrypt_yaml("a: b\n", "a"))
    with pytest.raises(sops.SopsError, match=r"\$HNX_SOPS"):
        sops.read_text(p)


def test_missing_binary_in_guest_dir_is_a_problem_not_a_guest(tmp_path, no_sops):
    d = tmp_path / "guests"
    d.mkdir()
    g = d / "bus-core.yml"
    g.write_text(
        encrypt_yaml((MINIMAL / "guests" / "bus-core.yml").read_text(encoding="utf-8"), "id"),
        encoding="utf-8",
    )
    guests, problems = load_guests(d)
    assert guests == []
    assert any("SOPS-encrypted" in p.message for p in problems)


def test_failed_decrypt_reports_sanitised_stderr(tmp_path, fake_sops, monkeypatch):
    monkeypatch.setenv("FAKE_SOPS_MODE", "fail")
    p = write(tmp_path, "services.yml", encrypt_yaml("lab: x\n", "lab"))
    with pytest.raises(registry_model.RegistryError) as exc:
        registry_model.load(p)
    msg = str(exc.value)
    assert "exit 128" in msg and "no age identity matched" in msg
    assert "\x1b" not in msg and "first line" not in msg


def test_output_still_encrypted_is_refused(tmp_path, fake_sops, monkeypatch):
    monkeypatch.setenv("FAKE_SOPS_MODE", "still-encrypted")
    p = write(tmp_path, "x.yml", encrypt_yaml("a: b\n", "a"))
    with pytest.raises(sops.SopsError, match="still carries SOPS metadata"):
        sops.read_text(p)


def test_decrypt_times_out(tmp_path, fake_sops, monkeypatch):
    monkeypatch.setenv("FAKE_SOPS_MODE", "slow")
    p = write(tmp_path, "x.yml", encrypt_yaml("a: b\n", "a"))
    with pytest.raises(sops.SopsError, match=r"did not finish within 0\.5 s"):
        sops.decrypt(p, "yaml", timeout=0.5)


def test_unknown_format_is_refused(tmp_path):
    with pytest.raises(ValueError, match="unsupported"):
        sops.decrypt(tmp_path / "x", "ini", env={})


# ---- a decrypted value never reaches a validation message --------------------------------------

SEALED_VALUE = "fake-sealed-WAN-" + ".".join(["203", "0", "113", "9"])


def test_a_sealed_guest_value_that_fails_the_schema_is_not_printed(tmp_path, fake_sops):
    d = tmp_path / "guests"
    shutil.copytree(MINIMAL / "guests", d)
    g = d / "bus-core.yml"
    text = g.read_text(encoding="utf-8").replace("kind: vm", f"kind: {SEALED_VALUE}")
    g.write_text(encrypt_yaml(text, "kind"), encoding="utf-8")
    _, problems = load_guests(d)
    shown = "\n".join(map(str, problems))
    assert "schema: kind: is not one of" in shown  # the path and the rule
    assert SEALED_VALUE not in shown


def test_a_sealed_site_value_that_fails_the_schema_is_not_printed(tmp_path, fake_sops):
    from homelabnext.network.validate import schema_problems

    plain = (MINIMAL / "site.yml").read_text(encoding="utf-8")
    p = write(tmp_path, "site.yml", encrypt_yaml(plain, "domain"))
    doc = load_site(p)
    doc["site"]["domain"] = SEALED_VALUE  # as if the decrypted value were malformed
    shown = "\n".join(schema_problems(doc))
    assert "schema: site/domain: does not match" in shown and SEALED_VALUE not in shown


def test_a_sealed_registry_value_that_fails_the_schema_is_not_printed():
    doc = registry_model.yaml.safe_load((MINIMAL / "services.yml").read_text(encoding="utf-8"))
    doc["lab"]["domain"] = SEALED_VALUE
    shown = "\n".join(registry_model.schema_problems(doc))
    assert "schema: lab/domain: does not match" in shown and SEALED_VALUE not in shown


@pytest.mark.parametrize(
    ("schema", "value", "expect"),
    [
        ({"type": "integer"}, SEALED_VALUE, "is not of type 'integer'"),
        ({"pattern": "^[a-z]+$"}, SEALED_VALUE, "does not match '^[a-z]+$'"),
        ({"enum": ["a", "b"]}, SEALED_VALUE, "is not one of ['a', 'b']"),
        ({"const": "a"}, SEALED_VALUE, "is not the constant 'a'"),
        ({"maxLength": 3}, SEALED_VALUE, "fails maxLength 3"),
        (
            {"anyOf": [{"type": "integer"}, {"type": "null"}]},
            SEALED_VALUE,
            "allowed shapes (anyOf)",
        ),
        ({"not": {"type": "string"}}, SEALED_VALUE, "allowed shapes (not)"),
        ({"required": ["x"]}, {"y": SEALED_VALUE}, "'x' is a required property"),
        (
            {"additionalProperties": False},
            {"extra": SEALED_VALUE},
            "('extra' was unexpected)",
        ),
        ({"propertyNames": {"maxLength": 2}}, {SEALED_VALUE: 1}, "fails maxLength 2"),
    ],
)
def test_safe_message_names_the_rule_not_the_value(schema, value, expect):
    import jsonschema

    from homelabnext._schema_text import safe_message

    (err,) = jsonschema.Draft202012Validator(schema).iter_errors(value)
    got = safe_message(err)
    assert expect in got and SEALED_VALUE not in got
