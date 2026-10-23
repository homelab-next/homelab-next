# SPDX-License-Identifier: Apache-2.0
"""``hnx broker``: validate, and the documented walkthrough (docs/broker.md) through the CLI."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from homelabnext.broker.cli import main
from homelabnext.cli import main as hnx

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker" / "manifest.yml"


def test_validate_passes_on_the_example_and_fails_on_a_tampered_copy(tmp_path, capsys):
    assert hnx(["broker", "validate", str(EXAMPLE)]) == 0
    assert "ok (5 actions, 3 lanes)" in capsys.readouterr().out
    shutil.copytree(EXAMPLE.parent, tmp_path / "ex")
    h = tmp_path / "ex" / "handlers" / "service-restart.sh"
    h.write_text(h.read_text() + "\n# edited\n")
    assert main(["validate", str(tmp_path / "ex" / "manifest.yml"), "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and "handler_digest" in out["problems"][0]


def test_validate_unreadable_and_non_mapping(tmp_path, capsys):
    assert main(["validate", str(tmp_path / "missing.yml")]) == 2
    (tmp_path / "list.yml").write_text("- a\n")
    assert main(["validate", str(tmp_path / "list.yml")]) == 1
    capsys.readouterr()


def test_validate_shows_lane_usage_and_warns_near_the_quota(tmp_path, capsys):
    """A lane at its quota refused the agent alone: nothing showed the operator a lane directory
    filling up, nor one already over its quota on the day --data-root was pointed at it."""
    own = tmp_path / "data" / "memory" / "triage"
    own.mkdir(parents=True)
    for i in range(3500):  # 85% of the default 4096 files
        (own / f"n{i}.md").write_text("x")
    assert main(["validate", str(EXAMPLE), "--data-root", str(tmp_path / "data")]) == 0
    out = capsys.readouterr().out
    assert "lane memory memory/triage: 3500/4096 files" in out and "WARNING: over 80%" in out
    assert main(["validate", str(EXAMPLE), "--json", "--data-root", str(tmp_path / "data")]) == 0
    [row] = json.loads(capsys.readouterr().out)["lane_usage"]
    assert (row["lane"], row["files"], row["warn"]) == ("memory", 3500, True)


def test_the_production_example_sets_its_append_only_findings_lane(capsys):
    from homelabnext.broker.service import load_manifest

    manifest, _ = load_manifest(EXAMPLE.parent / "manifest.production.yml")
    [findings] = [ld for ld in manifest["lanes"] if ld["name"] == "findings"]
    assert findings["max_files"] is None, "a file cap is a retention limit for append-only notes"
    assert findings["max_total_bytes"] >= 1 << 30 and findings["max_writes_per_hour"] >= 1


@pytest.fixture
def broker(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HNX_BROKER_MANIFEST", str(EXAMPLE))
    monkeypatch.setenv("HNX_BROKER_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("HNX_BROKER_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("HNX_BROKER_SECRET_DEMO_API_TOKEN", "fake-cli-token")

    def run(*argv, code=0, as_json=True):
        rc = main([argv[0], *(["--json"] if as_json else []), *argv[1:]])
        out = capsys.readouterr()
        assert rc == code, (rc, out.out, out.err)
        return json.loads(out.out) if as_json and out.out.strip() else out

    return run


def test_walkthrough(broker, tmp_path):
    note = '{"name":"queue-notes.md","content":"drains slowly\\n"}'
    rid = broker("submit", "memory.write", "--as", "profile:triage", "--params", note)["request_id"]
    assert (
        broker("run", rid, "--as", "profile:triage")["result"]["path"]
        == "memory/triage/queue-notes.md"
    )
    assert (tmp_path / "data/memory/triage/queue-notes.md").exists()
    bad = broker(
        "submit",
        "memory.write",
        "--as",
        "profile:triage",
        "--params",
        '{"name":"../../x.md","content":"x"}',
        code=1,
    )
    assert bad["error"] == "lane-name-invalid"
    req = broker(
        "submit",
        "service.restart",
        "--as",
        "profile:triage",
        "--target",
        "svc:queue",
        "--params",
        '{"grace_s": 30}',
    )
    assert req["awaiting_approval"] is True
    rid = req["request_id"]
    assert broker("run", rid, "--as", "profile:triage", code=1)["error"] == "approval-required"
    assert [r["request_id"] for r in broker("pending")] == [rid]
    assert broker("approve", rid, "--as", "sso:triage", code=1)["error"] == "approval-self-approved"
    assert (
        broker("approve", rid, "--as", "sso:operator-one", "--note", "ok")["decision"] == "approved"
    )
    out = broker("run", rid, "--as", "profile:triage")["result"]["output"]
    assert out == {"would_restart": "svc:queue", "token_present": True, "params": {"grace_s": 30}}
    assert broker("status", rid, "--as", "profile:triage")["state"] == "done"
    assert broker("status", rid, "--as", "profile:reader", code=1)["error"] == "not-request-owner"
    assert len(broker("audit", "--request", rid, "--outcome", "ok")) == 4
    assert len(broker("audit", "--tail", "2")) == 2 and broker("audit", "--tail", "0") == []
    text = broker("audit", "--operation", "approve", as_json=False).out
    assert "approval-self-approved" in text and "sso:operator-one" in text


def test_text_output_cancel_and_deny(broker, tmp_path):
    rid = broker(
        "submit",
        "service.restart",
        "--as",
        "profile:triage",
        "--params",
        '{"grace_s": 1}',
        as_json=False,
    ).out.split()[0]
    assert "nothing awaiting" not in broker("pending", as_json=False).out
    assert "denied" in broker("deny", rid, "--as", "sso:operator-one", as_json=False).out
    assert "nothing awaiting approval" in broker("pending", as_json=False).out
    params = tmp_path / "p.json"
    params.write_text('{"name":"a.md","content":"x"}')
    rid = broker(
        "submit",
        "memory.write",
        "--as",
        "profile:triage",
        "--params-file",
        str(params),
        as_json=False,
    ).out.split()[0]
    assert "pending" in broker("status", rid, "--as", "profile:triage", as_json=False).out
    assert "cancelled" in broker("cancel", rid, "--as", "profile:triage", as_json=False).out
    assert (
        "refused (not-pending)"
        in broker("run", rid, "--as", "profile:triage", code=1, as_json=False).err
    )


def test_usage_errors(broker, monkeypatch, capsys):
    assert (
        "must be a JSON object"
        in broker(
            "submit",
            "memory.write",
            "--as",
            "profile:triage",
            "--params",
            "[1]",
            code=2,
            as_json=False,
        ).err
    )
    monkeypatch.delenv("HNX_BROKER_STATE")
    with pytest.raises(SystemExit):
        main(["pending"])
    monkeypatch.setenv("HNX_BROKER_STATE", "x")
    monkeypatch.setenv(
        "HNX_BROKER_MANIFEST", str(ROOT / "schemas/broker/negative/manifest.default-allow.json")
    )
    assert main(["pending"]) == 2
    capsys.readouterr()
