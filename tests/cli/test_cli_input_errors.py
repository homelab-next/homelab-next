# SPDX-License-Identifier: Apache-2.0
"""docs/interfaces.md: "Exit codes everywhere: 0 ok, 1 a check failed, 2 misconfiguration or bad
input".  A file that is missing or cannot be parsed is bad input, never "a check failed", and is
reported in one line, never a traceback; sibling commands must agree, or a script that tells
"the registry is wrong" from "the path is wrong" by exit code is right for only some of them."""

import pytest

from homelabnext import cli

# commands that read one document named on the command line
COMMANDS = [
    ["registry", "validate"],
    ["site", "validate"],
    ["swap", "status"],
    ["status", "views", "check"],
    ["models", "store", "validate"],
    ["broker", "validate"],
    ["guests", "validate"],
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


def test_an_invalid_but_readable_registry_is_still_a_failed_check(tmp_path, capsys):
    (tmp_path / "services.yml").write_text("schema_version: '2.0'\nservices: 3\n")
    assert cli.main(["registry", "validate", str(tmp_path / "services.yml")]) == 1
