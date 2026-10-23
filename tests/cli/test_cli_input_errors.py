# SPDX-License-Identifier: Apache-2.0
"""docs/interfaces.md: "Exit codes everywhere: 0 ok, 1 a check failed, 2 misconfiguration or bad
input".  A file that is missing or cannot be parsed is bad input, never "a check failed", and is
reported in one line, never a traceback; sibling commands must agree, or a script that tells
"the registry is wrong" from "the path is wrong" by exit code is right for only some of them."""

import pathlib
import shutil

import pytest

from homelabnext import cli

REPO = pathlib.Path(__file__).resolve().parents[2]

# commands that read one document named on the command line
COMMANDS = [
    ["registry", "validate"],
    ["site", "validate"],
    ["swap", "status"],
    ["status", "views", "check"],
    ["models", "store", "validate"],
    ["broker", "validate"],
]
MALFORMED = {"bad.yml": b"a: [1,\n", "bad.json": b"{not json"}


@pytest.mark.parametrize("cmd", COMMANDS, ids=" ".join)
def test_a_missing_file_is_exit_2(tmp_path, capsys, cmd):
    assert cli.main([*cmd, str(tmp_path / "nosuch.yml")]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.strip()


@pytest.mark.parametrize("name", sorted(MALFORMED))
@pytest.mark.parametrize("cmd", COMMANDS, ids=" ".join)
def test_a_file_that_does_not_parse_is_exit_2(tmp_path, capsys, cmd, name):
    (tmp_path / name).write_bytes(MALFORMED[name])
    assert cli.main([*cmd, str(tmp_path / name)]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.strip()


@pytest.mark.parametrize("cmd", COMMANDS, ids=" ".join)
def test_a_readable_but_invalid_document_is_not_exit_2(tmp_path, capsys, cmd):
    """The positive control: each command reaches its loader and validator, so a usage error
    (argparse's own exit 2) can never be what satisfies the tests above."""
    shutil.copy(REPO / "examples" / "services.yml", tmp_path / "services.yml")  # site's registry
    (tmp_path / "doc.yml").write_text('{"a": 1}\n')  # parses as JSON and as YAML
    assert cli.main([*cmd, str(tmp_path / "doc.yml")]) == 1
    assert "Traceback" not in capsys.readouterr().err


# hnx guests reads a directory and a --site file; each can be missing or not parse
GUESTS = REPO / "tests" / "compute" / "fleet"
SITE = REPO / "tests" / "compute" / "site.yml"


def _guests(capsys, directory, site):
    rc = cli.main(["guests", "validate", str(directory), "--site", str(site)])
    err = capsys.readouterr().err
    assert "Traceback" not in err
    return rc, err


def test_guests_validate_reads_a_good_fleet(capsys):
    assert _guests(capsys, GUESTS, SITE)[0] == 0


@pytest.mark.parametrize("name", ["nosuch.yml", *sorted(MALFORMED)])
def test_guests_with_a_bad_site_file_is_exit_2(tmp_path, capsys, name):
    if name in MALFORMED:
        (tmp_path / name).write_bytes(MALFORMED[name])
    rc, err = _guests(capsys, GUESTS, tmp_path / name)
    assert rc == 2 and err.strip()


def test_guests_with_a_missing_directory_is_exit_2(tmp_path, capsys):
    rc, err = _guests(capsys, tmp_path / "nosuch", SITE)
    assert rc == 2 and "not a directory" in err


@pytest.mark.parametrize("name", ["_backup_policies.yml", "_nodes.yml", "_baselines.yml"])
def test_guests_with_a_side_file_that_does_not_parse_is_exit_2(tmp_path, capsys, name):
    fleet = tmp_path / "fleet"
    shutil.copytree(GUESTS, fleet)
    (fleet / name).write_bytes(MALFORMED["bad.yml"])
    rc, err = _guests(capsys, fleet, SITE)
    assert rc == 2 and name in err


def test_guests_with_a_guest_file_that_does_not_parse_is_exit_2(tmp_path, capsys):
    fleet = tmp_path / "fleet"
    shutil.copytree(GUESTS, fleet)
    (fleet / "broken.yml").write_bytes(MALFORMED["bad.yml"])
    rc, err = _guests(capsys, fleet, SITE)
    assert rc == 2 and "broken.yml: unreadable YAML" in err


def test_guests_with_an_invalid_but_readable_guest_is_a_failed_check(tmp_path, capsys):
    fleet = tmp_path / "fleet"
    shutil.copytree(GUESTS, fleet)
    (fleet / "broken.yml").write_text("id: broken\n")  # parses; fails the schema
    rc, err = _guests(capsys, fleet, SITE)
    assert rc == 1 and "broken.yml" in err


def test_an_invalid_but_readable_registry_is_still_a_failed_check(tmp_path, capsys):
    (tmp_path / "services.yml").write_text("schema_version: '2.0'\nservices: 3\n")
    assert cli.main(["registry", "validate", str(tmp_path / "services.yml")]) == 1
