# SPDX-License-Identifier: Apache-2.0
import json

import pytest
import yaml
from agent_support import GATE_OK, PARTS, inputs, manifest, spec

from homelabnext import cli
from homelabnext.agent import verify_profile


@pytest.fixture
def work(tmp_path):
    lib = tmp_path / "lib"
    lib.mkdir()
    index = {}
    for lid, text in PARTS.items():
        rel = lid.replace(":", "-") + ".md"
        (lib / rel).write_text(text)
        index[lid] = rel
    (lib / "library.yml").write_text(yaml.safe_dump({"parts": index}))
    (tmp_path / "spec.yml").write_text(yaml.safe_dump(spec()))
    (tmp_path / "manifest.yml").write_text(yaml.safe_dump(manifest()))
    (tmp_path / "inputs.json").write_text(json.dumps(inputs()))
    return tmp_path


def test_listed_in_help(capsys):
    assert cli.main(["--help"]) == 0
    assert "agent" in capsys.readouterr().out
    assert cli.main(["agent", "--help"]) == 0


def test_compile_roundtrip(work, capsys):
    out = work / "profile.json"
    rc = cli.main(
        [
            "agent",
            "compile",
            str(work / "spec.yml"),
            "--library",
            str(work / "lib" / "library.yml"),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    profile = json.loads(out.read_text())
    assert verify_profile(profile) == []
    assert profile["digest"] in capsys.readouterr().err
    # second run is byte-identical
    out2 = work / "profile2.json"
    cli.main(
        [
            "agent",
            "compile",
            str(work / "spec.yml"),
            "--library",
            str(work / "lib" / "library.yml"),
            "--out",
            str(out2),
        ]
    )
    assert out.read_bytes() == out2.read_bytes()


def test_compile_missing_part_exit_1(work, capsys):
    (work / "lib" / "skill-triage.md").unlink()
    index = yaml.safe_load((work / "lib" / "library.yml").read_text())
    del index["parts"]["skill:triage"]
    (work / "lib" / "library.yml").write_text(yaml.safe_dump(index))
    rc = cli.main(
        ["agent", "compile", str(work / "spec.yml"), "--library", str(work / "lib" / "library.yml")]
    )
    assert rc == 1
    assert "skill:triage" in capsys.readouterr().err


def test_compile_ceiling_violation_exit_1(work, capsys):
    s = spec()
    s["mcp"].append("shell")
    (work / "spec.yml").write_text(yaml.safe_dump(s))
    rc = cli.main(
        ["agent", "compile", str(work / "spec.yml"), "--library", str(work / "lib" / "library.yml")]
    )
    assert rc == 1 and "outside ceiling" in capsys.readouterr().err


def test_library_path_cannot_escape(work, capsys):
    (work / "secret.txt").write_text("nope")
    (work / "lib" / "library.yml").write_text(
        yaml.safe_dump(
            {
                "parts": {
                    **{k: k.replace(":", "-") + ".md" for k in PARTS},
                    "skill:triage": "../secret.txt",
                }
            }
        )
    )
    rc = cli.main(
        ["agent", "compile", str(work / "spec.yml"), "--library", str(work / "lib" / "library.yml")]
    )
    assert rc == 1 and "escapes" in capsys.readouterr().err


def test_pack_ready_and_deterministic(work, capsys):
    outs = []
    for n in (1, 2):
        out = work / f"pack{n}.json"
        rc = cli.main(
            [
                "agent",
                "pack",
                str(work / "manifest.yml"),
                "--inputs",
                str(work / "inputs.json"),
                "--out",
                str(out),
            ]
        )
        assert rc == 0
        outs.append(json.loads(out.read_text()))
    assert outs[0] == outs[1] and outs[0]["hash"].startswith("sha256:")
    assert outs[0]["pack"]["status"] == "ready"


def test_pack_deferred_exit_3(work, capsys):
    bad = inputs()
    bad["pregates"] = {}
    (work / "inputs.json").write_text(json.dumps(bad))
    rc = cli.main(
        ["agent", "pack", str(work / "manifest.yml"), "--inputs", str(work / "inputs.json")]
    )
    assert rc == 3
    assert "deferred: required pre-gate" in capsys.readouterr().err


def test_pack_invalid_manifest_exit_1(work, capsys):
    m = manifest()
    m["sections"][0]["tier"] = "eternal"
    (work / "manifest.yml").write_text(yaml.safe_dump(m))
    rc = cli.main(
        ["agent", "pack", str(work / "manifest.yml"), "--inputs", str(work / "inputs.json")]
    )
    assert rc == 1 and "manifest invalid" in capsys.readouterr().err
    assert GATE_OK  # fixture import used


def test_compile_with_policy_and_verify(work, capsys):
    policy = {
        "ceilings": {
            "profile:reader": {
                "mcp": ["lake"],
                "capabilities": ["cap:lake-query"],
                "tier": "read",
                "data_tier": "local-only",
            }
        }
    }
    (work / "policy.yml").write_text(yaml.safe_dump(policy))
    s = spec()
    del s["ceiling"]  # the policy owns it
    (work / "spec.yml").write_text(yaml.safe_dump(s))
    out = work / "profile.json"
    lib = str(work / "lib" / "library.yml")
    base = ["agent", "compile", str(work / "spec.yml"), "--library", lib]
    assert cli.main([*base, "--policy", str(work / "policy.yml"), "--out", str(out)]) == 0
    digest = json.loads(out.read_text())["digest"]
    (work / "profiles.lock").write_text(yaml.safe_dump({"profiles": {"profile:reader": digest}}))
    verify = ["agent", "verify", str(out), "--policy", str(work / "policy.yml")]
    assert cli.main([*verify, "--lock", str(work / "profiles.lock")]) == 0
    s = spec()  # its own ceiling allows records; the policy does not
    s["mcp"].append("records")
    (work / "spec.yml").write_text(yaml.safe_dump(s))
    capsys.readouterr()
    assert cli.main([*base, "--policy", str(work / "policy.yml")]) == 1
    assert "outside ceiling" in capsys.readouterr().err
    assert cli.main([*base, "--out", str(out)]) == 0  # self-declared ceiling, with a warning
    assert "ceiling comes from the spec itself" in capsys.readouterr().err
    assert cli.main([*verify, "--lock", str(work / "profiles.lock")]) == 1


def test_compile_notes_a_policy_entry_without_a_tlp_ceiling(work, capsys):
    """ADR-0033 decision 12: an entry that attests no tlp_ceiling is read from its data_tier, and
    the compile says so; one that attests it compiles it into the profile, with no note."""
    s = {k: v for k, v in spec().items() if k != "ceiling"}
    (work / "spec.yml").write_text(yaml.safe_dump(s))
    entry = {**spec()["ceiling"], "data_tier": "local-only"}
    argv = [
        "agent",
        "compile",
        str(work / "spec.yml"),
        "--library",
        str(work / "lib" / "library.yml"),
    ]
    argv += ["--policy", str(work / "policy.yml"), "--out", str(work / "p.json")]
    (work / "policy.yml").write_text(yaml.safe_dump({"ceilings": {"profile:reader": entry}}))
    assert cli.main(argv) == 0
    assert "attest no tlp_ceiling" in capsys.readouterr().err
    entry["tlp_ceiling"] = "red"
    (work / "policy.yml").write_text(yaml.safe_dump({"ceilings": {"profile:reader": entry}}))
    assert cli.main(argv) == 0
    assert "tlp_ceiling" not in capsys.readouterr().err
    assert json.loads((work / "p.json").read_text())["tlp_ceiling"] == "red"
