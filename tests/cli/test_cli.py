# SPDX-License-Identifier: Apache-2.0
"""hnx dispatcher: every subcommand is reachable and its --help works."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from homelabnext import cli

ROOT = Path(__file__).resolve().parents[2]


def test_top_level_help_lists_every_command(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    for name in cli.COMMANDS:
        assert name in out


def test_no_args_is_usage_error(capsys):
    assert cli.main([]) == 2
    assert "usage: hnx" in capsys.readouterr().out


def test_unknown_command(capsys):
    assert cli.main(["nope"]) == 2
    assert "unknown command" in capsys.readouterr().err


def test_version(capsys):
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out.startswith("hnx ")


@pytest.mark.parametrize("name", sorted(cli.COMMANDS))
def test_every_subcommand_help_works(name, capsys):
    assert cli.main([name, "--help"]) == 0
    assert "usage" in capsys.readouterr().out.lower()


@pytest.mark.parametrize("name", sorted(cli.COMMANDS))
def test_one_line_help_names_every_subcommand(name, capsys):
    # the help string is the only map `hnx --help` gives; a subcommand it omits is undiscoverable
    cli.main([name, "--help"])
    usage = capsys.readouterr().out
    m = re.search(r"\{([a-z0-9,-]+)\}", usage)
    subs = m.group(1).split(",") if m else []
    missing = [
        s
        for s in subs
        if not re.search(rf"(?<![\w-]){re.escape(s)}(?![\w-])", cli.COMMANDS[name][0])
    ]
    assert not missing, f"hnx {name}: help omits {missing}"


def test_events_routes_to_the_events_cli(capsys):
    assert cli.main(["events", "--help"]) == 0
    out = capsys.readouterr().out
    assert "usage: hnx events" in out and "deploy-changed" in out and "enrich-coverage" in out


def test_gen_subcommand_help_and_unknown(capsys):
    assert cli.main(["gen", "fleet-units", "--help"]) == 0
    assert cli.main(["gen", "bogus"]) == 2
    capsys.readouterr()


def test_argv0_is_restored():
    before = sys.argv[0]
    cli.main(["new", "--help"])
    assert sys.argv[0] == before


def test_registry_validate_and_gen_roundtrip(tmp_path, capsys):
    example = ROOT / "examples" / "services.yml"
    assert cli.main(["registry", "validate", str(example)]) == 0
    out = tmp_path / "gen"
    assert cli.main(["gen", "registry", str(example), str(out)]) == 0
    assert cli.main(["gen", "check", str(example), str(out)]) == 0
    capsys.readouterr()


def test_schema_check_dispatches_to_the_checker(capsys):
    assert cli.main(["schema-check", "--root", str(ROOT), "--dir", "ids"]) == 0
    assert "schema_check:" in capsys.readouterr().out


def test_new_scaffolds_through_the_cli(tmp_path, capsys):
    assert cli.main(["new", "role", "demo_role", "--dest", str(tmp_path)]) == 0
    assert any(tmp_path.rglob("*demo_role*"))
    capsys.readouterr()


def test_ids_alloc_unknown_register_is_an_error(capsys):
    assert cli.main(["ids", "alloc", "not-a-register.yml"]) != 0
    capsys.readouterr()


def test_python_dash_m_entry_point():
    r = subprocess.run(
        [sys.executable, "-m", "homelabnext.cli", "--help"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert r.returncode == 0 and "commands:" in r.stdout


def test_console_script_is_declared():
    text = (ROOT / "pyproject.toml").read_text()
    assert 'hnx = "homelabnext.cli:main"' in text


def test_invariants_and_registers_reachable(tmp_path, capsys):
    src = ROOT / "examples" / "registers"
    out = tmp_path / "out"
    shutil.copytree(src, tmp_path / "src")
    assert cli.main(["registers", "build", str(tmp_path / "src"), str(out)]) == 0
    capsys.readouterr()
    assert json.loads(next(out.glob("*.json")).read_text()) is not None
