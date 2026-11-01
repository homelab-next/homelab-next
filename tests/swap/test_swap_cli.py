# SPDX-License-Identifier: Apache-2.0
"""``hnx swap`` through the real dispatcher with the manual (attestation) backend."""

from __future__ import annotations

import json

import pytest
from support import registry_text

from homelabnext import cli
from homelabnext.swap import record

T0 = "2026-05-01T09:00:00+00:00"
ADR = "docs/adr/0005-swap-procedure-and-conformance.md"


@pytest.fixture
def ws(tmp_path):
    (tmp_path / "services.yml").write_text(registry_text(), encoding="utf-8")
    (tmp_path / "tree").mkdir()
    for n in (
        "conformance-old",
        "conformance-new",
        "shadow",
        "mirror",
        "parity",
        "canary",
        "old-stopped",
    ):
        (tmp_path / f"{n}.json").write_text(
            json.dumps({"ok": True, "rows_compared": 120, "unresolved": 0})
        )
    return tmp_path


def run(capsys, *args):
    code = cli.main(["swap", *map(str, args)])
    out = capsys.readouterr()
    return code, out.out, out.err


def attest(ws, *names):
    out = []
    for n in names:
        out += ["--attest", f"{n}={ws / (n + '.json')}"]
    return out


def start(ws, capsys, **extra):
    return run(
        capsys,
        "start",
        "--record",
        ws / "s.swap.json",
        "--capability",
        "cap:lake-query",
        "--from",
        "trino-lake",
        "--to",
        "duckdb-lake",
        "--service",
        "lake-query",
        "--registry",
        ws / "services.yml",
        "--to-host",
        "lake-core-2",
        "--to-impl",
        "duckdb",
        "--to-version",
        "1.5",
        "--soak-hours",
        extra.get("soak", 24),
        "--rollback-window-hours",
        24,
        "--min-parity-rows",
        100,
        "--swap-id",
        "swap-cli-0001",
        "--actor",
        "tester",
        "--now",
        T0,
    )


def adv(ws, capsys, now, *names, extra=()):
    return run(
        capsys,
        "advance",
        ws / "s.swap.json",
        "--rehearsal",
        "--now",
        now,
        "--scan-root",
        ws / "tree",
        "--retired-env-var",
        "OLD_ENDPOINT",
        *attest(ws, *names),
        *extra,
    )


def test_help_and_plan(capsys):
    assert run(capsys, "--help")[0] == 0
    code, out, _ = run(capsys)
    assert code == 2 and "usage: hnx swap" in out
    code, out, _ = run(capsys, "plan")
    assert code == 0 and "1. declare" in out and "9. close" in out


def test_start_prints_flip_and_plan_with_record(ws, capsys):
    code, out, _ = start(ws, capsys)
    assert code == 0 and "services.lake-query.host: lake-core -> lake-core-2" in out
    d = record.load(ws / "s.swap.json")
    assert d["route"]["before"]["host"] == "lake-core" and d["route"]["after"]["impl"] == "duckdb"
    code, out, _ = run(capsys, "plan", "--record", ws / "s.swap.json")
    assert "[pending]" in out
    code, out, _ = run(
        capsys,
        "plan",
        "--registry",
        ws / "services.yml",
        "--service",
        "lake-query",
        "--to-host",
        "lake-core-2",
    )
    assert "rollback (inverse):" in out and "lake-core-2 -> lake-core" in out
    assert start(ws, capsys)[0] == 2  # refuses to overwrite an existing record


def test_full_swap_via_cli(ws, capsys):
    assert start(ws, capsys)[0] == 0
    # nothing attested: the gate refuses, exit 1, and the record says so
    code, out, _ = adv(ws, capsys, T0)
    assert code == 1 and "REFUSED step declare" in out
    code, out, _ = run(
        capsys, "advance", ws / "s.swap.json", "--dry-run", "--rehearsal", "--now", T0
    )
    assert code == 0 and "dry run: step declare" in out
    assert adv(ws, capsys, T0, "conformance-old")[0] == 0
    assert adv(ws, capsys, T0, "conformance-new", "shadow")[0] == 0
    assert adv(ws, capsys, T0, "mirror")[0] == 0
    assert adv(ws, capsys, T0, "parity", "mirror")[0] == 0
    assert adv(ws, capsys, "2026-05-01T20:00:00+00:00", "parity")[0] == 1  # soak not elapsed
    assert adv(ws, capsys, "2026-05-02T10:00:00+00:00", "parity", "mirror")[0] == 0
    code, out, _ = adv(ws, capsys, "2026-05-02T10:00:00+00:00", "canary", "old-stopped")
    assert code == 0 and "cutover passed" in out.replace("step ", "")
    flipped = (ws / "services.yml").read_text()
    assert "host: lake-core-2" in flipped and "impl: duckdb" in flipped
    code, out, _ = run(capsys, "status", ws / "s.swap.json")
    assert "current step: rollback-window" in out and "flipped: True" in out
    assert adv(ws, capsys, "2026-05-03T10:00:00+00:00", "canary", "old-stopped")[0] == 0
    # a stale reference blocks the decommission check
    (ws / "tree" / "deploy.env").write_text("OLD_ENDPOINT=x\n")
    assert adv(ws, capsys, "2026-05-03T11:00:00+00:00")[0] == 1
    (ws / "tree" / "deploy.env").unlink()
    assert adv(ws, capsys, "2026-05-03T12:00:00+00:00")[0] == 0
    assert adv(ws, capsys, "2026-05-03T13:00:00+00:00")[0] == 1  # no ADR reference
    code, out, _ = adv(ws, capsys, "2026-05-03T14:00:00+00:00", extra=["--adr", ADR])
    assert code == 0 and "swap closed" in out
    code, out, _err = run(capsys, "record", ws / "s.swap.json", "--verify")
    assert code == 0 and "hash chain consistent" in out
    anchor = next(ln.split("head: ")[1] for ln in out.splitlines() if "head: " in ln)
    assert run(capsys, "record", ws / "s.swap.json", "--anchor", anchor)[0] == 0
    seq = anchor.split(":", 1)[0]
    assert run(capsys, "record", ws / "s.swap.json", "--anchor", f"{seq}:sha256:{'0' * 64}")[0] == 1
    code, out, _ = run(
        capsys, "rollback", ws / "s.swap.json", "--reason", "too late to undo this one"
    )
    assert code == 1
    code, out, _ = run(capsys, "status", ws / "s.swap.json", "--json")
    assert json.loads(out)["status"] == "closed"


def test_rollback_via_cli_restores_the_registry_text(ws, capsys):
    start(ws, capsys)
    original = (ws / "services.yml").read_text()
    seq = [("conformance-old",), ("conformance-new", "shadow"), ("mirror",), ("parity", "mirror")]
    for names in seq:
        assert adv(ws, capsys, T0, *names)[0] == 0
    assert adv(ws, capsys, "2026-05-02T10:00:00+00:00", "parity", "mirror")[0] == 0
    assert adv(ws, capsys, "2026-05-02T10:00:00+00:00", "canary", "old-stopped")[0] == 0
    assert (ws / "services.yml").read_text() != original
    code, out, _ = run(
        capsys,
        "rollback",
        ws / "s.swap.json",
        "--reason",
        "p99 latency regression on candidate",
        "--rehearsal",
        "--now",
        "2026-05-02T12:00:00+00:00",
        *attest(ws, "canary"),
    )
    assert code == 0 and "route restored: True" in out
    assert (ws / "services.yml").read_text() == original
    assert record.load(ws / "s.swap.json")["status"] == "rolled_back"


def test_a_forged_clock_needs_rehearsal_and_is_named_in_the_record(ws, capsys):
    """--now passes the soak and rollback-window gates in seconds: without --rehearsal it is a
    usage error, and with it every transition it writes names the forged clock."""
    start(ws, capsys)
    p = ws / "s.swap.json"
    code, _, err = run(capsys, "advance", p, "--now", "2099-01-01T00:00:00+00:00")
    assert code == 2 and "pass --rehearsal" in err
    code, _, err = run(capsys, "rollback", p, "--reason", "rehearsing the undo", "--now", T0)
    assert code == 2 and "pass --rehearsal" in err
    assert len(record.load(p)["transitions"]) == 1  # nothing written
    assert adv(ws, capsys, T0, "conformance-old")[0] == 0
    assert record.load(p)["transitions"][-1]["actor"] == "operator@rehearsal-clock"


def test_step_evidence_is_written_0600(ws, capsys):
    """A step's evidence (a parity report carries row data) is 0600 like every evidence file."""
    start(ws, capsys)
    assert adv(ws, capsys, T0, "conformance-old")[0] == 0
    ev = next(ws.glob("*.evidence"))
    files = sorted(ev.iterdir())
    assert files and all(f.stat().st_mode & 0o777 == 0o600 for f in files), files


def test_a_clock_behind_the_record_is_refused(ws, capsys):
    start(ws, capsys)
    assert adv(ws, capsys, "2026-05-02T10:00:00+00:00", "conformance-old")[0] == 0
    before = record.load(ws / "s.swap.json")
    code, _, err = adv(ws, capsys, T0, "conformance-new", "shadow")
    assert code == 1 and "earlier than the record's last transition" in err
    assert record.load(ws / "s.swap.json") == before


def test_record_verify_refuses_transition_times_that_go_backwards(ws, capsys):
    start(ws, capsys)
    p = ws / "s.swap.json"
    assert adv(ws, capsys, "2026-05-02T10:00:00+00:00", "conformance-old")[0] == 0
    d = record.load(p)
    t = d["transitions"][-1]
    t["at"] = "2026-04-01T00:00:00Z"
    t["hash"] = record.chain_hash(t["prev"], t, None)
    d["updated_at"] = t["at"]
    assert any("transition times may not go backwards" in x for x in record.record_problems(d))


def test_record_command_validates_notes_and_detects_tampering(ws, capsys):
    start(ws, capsys)
    p = ws / "s.swap.json"
    assert run(capsys, "record", p, "--note", "freeze window until Monday", "--now", T0)[0] == 0
    d = json.loads(p.read_text())
    assert d["transitions"][-1]["note"].startswith("freeze")
    d["transitions"][0]["note"] = "edited"
    p.write_text(json.dumps(d))
    code, _, err = run(capsys, "record", p)
    assert code == 1 and "INVALID" in err
    code, _, err = run(capsys, "status", ws / "missing.json")
    assert code == 2 and "cannot read swap record" in err  # an I/O error, not an invalid record
    (ws / "garbled.json").write_text("{not json")
    code, _, err = run(capsys, "status", ws / "garbled.json")
    assert code == 2 and "is not valid JSON" in err and "INVALID" not in err


def test_start_errors(ws, capsys):
    code, _, err = run(
        capsys,
        "start",
        "--record",
        ws / "x.json",
        "--capability",
        "cap:lake-query",
        "--from",
        "a",
        "--to",
        "b",
    )
    assert code == 2 and "--registry and --service" in err
    code, _out, err = run(
        capsys,
        "start",
        "--record",
        ws / "x.json",
        "--capability",
        "cap:lake-query",
        "--from",
        "a",
        "--to",
        "b",
        "--service",
        "lake-query",
        "--registry",
        ws / "services.yml",
        "--to-host",
        "lake-core",
    )
    assert code == 1 and "nothing to flip" in err
    code, _, err = run(
        capsys,
        "start",
        "--record",
        ws / "x.json",
        "--capability",
        "cap:lake-query",
        "--from",
        "a",
        "--to",
        "b",
        "--service",
        "lake-query",
        "--registry",
        ws / "services.yml",
        "--to-host",
        "ghost",
    )
    assert code == 2 and "not in the registry" in err
