# SPDX-License-Identifier: Apache-2.0
import io
from pathlib import Path

from homelabnext.registry.cli import main
from homelabnext.registry.dns import SystemDNS

EXAMPLE = str(Path(__file__).resolve().parents[2] / "examples" / "services.yml")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    rc = main(list(argv), out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


def test_validate_ok_and_bad(tmp_path):
    rc, out, _ = run("validate", EXAMPLE)
    assert rc == 0 and "19 services" in out
    bad = tmp_path / "bad.yml"
    bad.write_text("registry_version: 1\n")
    rc, _, err = run("validate", str(bad))
    assert rc == 1 and "invalid registry" in err


def test_resolve_failure_exit_1_and_message(monkeypatch):
    # the CLI uses the system resolver; answer "no such name" without a real DNS query
    monkeypatch.setattr(SystemDNS, "lookup_host", lambda self, name: [])
    rc, _, err = run("resolve", EXAMPLE, "lake-query")
    assert rc == 1 and "does not resolve" in err


def test_generate_check_roundtrip_and_drift(tmp_path):
    assert run("generate", EXAMPLE, str(tmp_path))[0] == 0
    assert run("check", EXAMPLE, str(tmp_path))[0] == 0
    (tmp_path / "hosts" / "hosts.block").write_text("tampered\n")
    rc, _, err = run("check", EXAMPLE, str(tmp_path))
    assert rc == 1 and "differs: hosts/hosts.block" in err


def test_unknown_generator_is_usage_error(tmp_path):
    rc, _, err = run("generate", EXAMPLE, str(tmp_path), "--only", "nope")
    assert rc == 2 and "unknown generator" in err


def test_list_generators_shows_eleven():
    rc, out, _ = run("list-generators")
    assert rc == 0 and len(out.split()) == 11
