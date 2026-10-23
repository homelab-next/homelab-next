# SPDX-License-Identifier: Apache-2.0
"""Per-turn records through a turn source: the join by tag, read windows and settling, and the
store refusing a record outside the neutral turn shape.  The source is the first adapter on a
loopback fake of its gateway's log, or an in-memory fake source.  The adapter's own rules (the
allow-list, the key, the transport, paging) are tested in
``tests/conform/test_conform_litellm_turn_source.py``."""

from __future__ import annotations

import copy
import json

import pytest
from orch_helpers import NEVER, T0, FakeSpendLogs, body, examples, turn_source

from conformance.protocols.inference import TURN_FIELDS, TurnSourceError
from homelabnext.orchestration.gateway import MAX_WINDOW_S, SLACK_S, _span, sync_turns
from homelabnext.status.model import iso, parse_iso


def _turn(turn_id: str, tag: str, started: float, **kw) -> dict:
    """A neutral turn record with everything but its id, tag and start unknown."""
    return dict.fromkeys(TURN_FIELDS) | {
        "turn_id": turn_id, "gateway_tag": tag, "started_at": iso(started), **kw
    }  # fmt: skip


class Source:
    """An in-memory turn source: ``read(lo, hi, tags)`` gives the turns, every call recorded."""

    def __init__(self, read):
        self.read, self.asked = read, []

    def turns(self, start, end, tags):
        self.asked.append((start, end))
        return self.read(start, end, tags)


def test_sync_joins_turns_by_tag_and_settles_only_finished_jobs(filled):
    just_after = parse_iso("2026-01-01T03:01:00Z")  # run-0004 finished a minute ago
    with FakeSpendLogs() as gw:
        got = sync_turns(filled, turn_source(gw), now=just_after)
    assert got == {"jobs": 4, "turns": 4, "settled": 3, "refused": 0}
    # the four jobs sit within an hour of each other: read together from the first start time
    # (00:00:12, less the slack) to now, in windows of at most an hour
    assert sorted({(r["start_date"], r["end_date"]) for r in gw.requests}) == [
        ("2025-12-31 23:58:12", "2026-01-01 00:44:09"),
        ("2026-01-01 00:44:09", "2026-01-01 01:30:06"),
        ("2026-01-01 01:30:06", "2026-01-01 02:16:03"),
        ("2026-01-01 02:16:03", "2026-01-01 03:01:00"),
    ]
    turns = filled.turns()
    assert {t: [x["turn_id"] for x in v] for t, v in turns.items()} == {
        "run-0001": ["req-a1", "req-a2"], "hnx-run-0002": ["req-b1"], "run-0003": ["req-c1"],
    }  # fmt: skip
    assert [j["run_id"] for j in filled.unsettled()] == ["run-0004"]
    with FakeSpendLogs() as gw:  # reading again rewrites the same rows; now run-0004 settles too
        again = sync_turns(filled, turn_source(gw), now=T0)
    assert again == {"jobs": 1, "turns": 0, "settled": 1, "refused": 0}
    assert filled.unsettled() == []
    assert filled.turns() == turns
    stored = filled.path.read_bytes() + b"".join(
        p.read_bytes() for p in filled.path.parent.glob("*-wal")
    )
    assert [n for n in NEVER if n.encode() in stored] == []


def test_a_failed_read_settles_nothing(filled):
    with FakeSpendLogs(status=503) as gw, pytest.raises(TurnSourceError):
        sync_turns(filled, turn_source(gw), now=T0)
    assert len(filled.unsettled()) == 4 and filled.turns() == {}


def _a_week_of_jobs(store, every_s: float = 1800.0) -> list[str]:
    """A job every half hour for seven days (the first replay of a new durable): one chain."""
    template, runs = examples()[0], []
    start = T0 - 7 * 86400
    for n in range(int(7 * 86400 // every_s)):
        ev = copy.deepcopy(template) | {"id": f"evt-w{n:04d}"}
        q = start + n * every_s
        ev["data"].update(
            run_id=f"run-w{n:04d}", gateway_tag=f"run-w{n:04d}", queued_at=iso(q),
            started_at=iso(q + 10), finished_at=iso(q + 300),
        )  # fmt: skip
        assert store.consume(body(ev)).status == "processed"
        runs.append(f"run-w{n:04d}")
    return runs


def test_a_week_of_close_jobs_is_read_in_bounded_windows_settled_as_each_succeeds(store):
    """Jobs less than an hour apart used to chain into one window over the whole week, which
    holds all the gateway's traffic: past the page budget it failed every run and nothing ever
    settled.  Windows are capped; each one's jobs settle as soon as it is read, so a failure
    keeps what was read before it, and the next run carries on from there."""
    runs = _a_week_of_jobs(store)
    fail_at = [T0 - 3 * 86400]

    def read(lo, hi, tags):  # the window it was asked for: each asked job's one turn
        if fail_at and lo <= fail_at[0] <= hi:
            raise TurnSourceError("more than 200 pages of 500 rows in one window")
        return [_turn(f"req-{r}", r, lo + 1) for r in tags]

    gateway = Source(read)
    asked = gateway.asked
    with pytest.raises(TurnSourceError):
        sync_turns(store, gateway, now=T0)
    assert max(hi - lo for lo, hi in asked) <= MAX_WINDOW_S
    assert asked == sorted(asked)  # oldest first
    left = {j["run_id"] for j in store.unsettled()}
    assert 0 < len(left) < len(runs)  # everything before the failing window is settled
    first_left = min(parse_iso(j["queued_at"]) for j in store.unsettled())
    assert first_left >= fail_at[0] - MAX_WINDOW_S - 300 - 120
    fail_at.clear()
    asked.clear()
    got = sync_turns(store, gateway, now=T0)
    assert got["jobs"] == len(left) and got["settled"] == len(left) and store.unsettled() == []
    assert min(lo for lo, _ in asked) >= first_left - SLACK_S - 1  # only what was left


def test_a_job_whose_times_are_reversed_is_still_read_and_settled():
    """The store refuses such a record; this is the backstop. A start hours after the finish
    made a span that overlapped no window, so the job was never read and never settled."""
    job = copy.deepcopy(examples()[0]["data"])
    finished = parse_iso(job["finished_at"])
    job.update(started_at=iso(finished + 3 * 3600))  # started hours after it finished

    class Store:
        retention_s = 90 * 86400.0

        def __init__(self):
            self.turns: list = []
            self.settled: list = []

        def unsettled(self):
            return [job]

        def add_turns(self, turns):
            self.turns += turns

        def settle(self, run_ids, now):
            self.settled += run_ids

    store = Store()

    def read(lo, hi, tags):  # the job's one turn, ten seconds before it finished
        if not lo <= finished - 10 <= hi:
            return []
        return [_turn("req-r1", job["gateway_tag"], finished - 10)]

    gateway = Source(read)
    asked = gateway.asked
    got = sync_turns(store, gateway, now=finished + 86400)
    assert got == {"jobs": 1, "turns": 1, "settled": 1, "refused": 0}
    assert store.settled == [job["run_id"]] and [t["turn_id"] for t in store.turns] == ["req-r1"]
    assert asked[0][0] <= finished - SLACK_S and asked[-1][1] >= finished + 3 * 3600


def test_a_span_starts_when_the_job_started_and_never_before_retention():
    """No turn happens while a job is queued: the span starts at its start (less the slack), so a
    job held in the queue for days is not read over every hour it waited, and one that never
    started is read only around its finish.  Whatever the record says, the span never reaches
    past the retention cutoff (a zero time would otherwise be millions of one-hour windows)."""
    job = copy.deepcopy(examples()[0]["data"])
    finished = parse_iso(job["finished_at"])
    floor = finished - 90 * 86400
    job.update(queued_at=iso(finished - 8 * 86400), started_at=iso(finished - 3600))
    assert _span(job, floor) == (finished - 3600 - SLACK_S, finished + SLACK_S)
    job.update(started_at=None)  # held, then cancelled in the queue
    assert _span(job, floor) == (finished - SLACK_S, finished + SLACK_S)
    job.update(queued_at="0001-01-01T00:00:00Z", started_at="0001-01-01T00:00:00Z")
    assert _span(job, floor) == (floor - SLACK_S, finished + SLACK_S)


def test_a_job_held_in_the_queue_for_days_is_read_from_its_start(filled):
    """Regression: the span ran from the queue time, so a job held a week read a week of the
    gateway's traffic for turns it could not have had while it waited."""
    job = filled.unsettled()[0]
    finished = parse_iso(job["finished_at"])
    with filled._db() as db:  # the store accepts such a record now; set one up directly
        doc = dict(job, queued_at=iso(finished - 6 * 86400))
        db.execute("UPDATE jobs SET doc = ? WHERE run_id = ?", (json.dumps(doc), job["run_id"]))
    gateway = Source(lambda lo, hi, tags: [])
    sync_turns(filled, gateway, now=T0)
    assert min(lo for lo, _ in gateway.asked) >= parse_iso(job["started_at"]) - SLACK_S - 1


def test_a_turn_with_a_tag_no_job_asked_for_is_not_joined(filled):
    """A source that answers more than it was asked never attaches a call to a job."""
    gateway = Source(lambda lo, hi, tags: [_turn("req-o1", "run-elsewhere", lo + 1)])
    got = sync_turns(filled, gateway, now=T0)
    assert got["turns"] == 0 and filled.turns() == {}


@pytest.mark.parametrize(
    "change, needle",
    [
        ({"prompt": "fake prompt text"}, "fields outside the turn record: prompt"),
        ({"model_group": "mdl:triage-large"}, "fields outside the turn record: model_group"),
        ({"input_tokens": -1}, "input_tokens is not a count"),
        ({"model": "has spaces in it"}, "model is not a name"),
        ({"started_at": "yesterday"}, "started_at is not an ISO 8601 UTC time"),
        ({"cost_usd": float("nan")}, "cost_usd is not a non-negative number"),
    ],
)
def test_the_store_refuses_a_turn_outside_the_neutral_record(filled, change, needle):
    """An adapter cannot widen what is stored: a record with another field, or a value of the
    wrong kind, is refused before anything is written.  A sync drops and counts it and keeps
    the rest of the window: one bad record of a source must not stop every later pass (a
    refused turn used to fail the window, which was then read again, and failed, forever)."""
    tag = examples()[0]["data"]["gateway_tag"]
    started = parse_iso(examples()[0]["data"]["finished_at"]) - 10
    bad = _turn("req-bad", tag, started) | change
    with pytest.raises(ValueError, match=needle):
        filled.add_turns([bad])
    good = _turn("req-good", tag, started + 1)
    gateway = Source(lambda lo, hi, tags: [bad, good] if tag in tags else [])
    got = sync_turns(filled, gateway, now=T0)
    assert got == {"jobs": 4, "turns": 1, "settled": 4, "refused": 1}
    assert [t["turn_id"] for t in filled.turns()[tag]] == ["req-good"]
    assert filled.unsettled() == []


def test_a_gateway_row_with_an_odd_model_name_never_wedges_the_sync(filled):
    """Regression: the adapter passed a model such as ``hosted_vllm//models/x`` that the record
    then refused, so every pass failed on the same row and no job was ever settled.  The fixture
    now holds a URL as a model and an address as a call type: both are mapped to null."""
    with FakeSpendLogs() as gw:
        got = sync_turns(filled, turn_source(gw), now=T0)
    assert got == {"jobs": 4, "turns": 4, "settled": 4, "refused": 0}
    turns = {t["turn_id"]: t for v in filled.turns().values() for t in v}
    assert turns["req-c1"]["model"] is None and turns["req-b1"]["call_type"] is None


# ----------------------------------------------------- which code --turn-source may name
_SITE_ADAPTER = """
import json, os
from os.path import join as borrowed  # a callable defined elsewhere, re-exported
TURN_SOURCES = {"make": {"secrets": ["credential_ref"]}, "borrowed": {}}
class Src:
    def __init__(self, opts): self.opts = opts
    def turns(self, start, end, tags): return []
def make(**opts):
    with open(os.environ["HNX_TEST_OPTS_OUT"], "w") as f: json.dump(opts, f)
    return Src(opts)
"""


@pytest.fixture
def site_adapters(tmp_path, monkeypatch):
    """A site's own adapter package (``labsite.turns:make``) and a module whose import alone
    leaves a mark (``sideeffect``), both importable; the adapter writes the options it got."""
    pkg = tmp_path / "pkgs" / "labsite"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "turns.py").write_text(_SITE_ADAPTER)
    mark = tmp_path / "imported"
    (tmp_path / "pkgs" / "sideeffect.py").write_text(
        f"open({str(mark)!r}, 'w').close()\ndef make(**k): return None\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path / "pkgs"))
    monkeypatch.setenv("HNX_TEST_OPTS_OUT", str(tmp_path / "opts.json"))
    monkeypatch.delenv("HNX_ORCHESTRATION_TURN_SOURCE_NAMESPACES", raising=False)
    return tmp_path


def _turns_cli(tmp, *argv) -> int:
    from homelabnext.orchestration import cli

    return cli.main(["turns", "--db", str(tmp / "t.db"), *argv], clock=lambda: T0)


@pytest.mark.parametrize(
    "spec",
    [
        "builtins:print",
        "os:system",
        "sideeffect:make",
        ".x:make",
        "homelabnext.conform.adaptersx:make",
        "homelabnext.conform:target",
        "labsite.turns:make",  # a site namespace, but not declared
    ],
)
def test_a_turn_source_outside_the_allowed_namespaces_is_never_imported(
    site_adapters, capsys, spec
):
    assert _turns_cli(site_adapters, "--turn-source", spec) == 2
    out, err = capsys.readouterr()
    assert "--turn-source" in err and "homelabnext.conform.adapters" in err and out == ""
    assert not (site_adapters / "imported").exists()  # the module never ran


def test_a_declared_site_namespace_gets_its_options_and_secrets_only_by_name(
    site_adapters, capsys, monkeypatch
):
    spec = ["--turn-source", "labsite.turns:make"]
    opts = ["--turn-source-option", "project=lab-1", "--turn-source-option", "token=secret:gw/tok"]
    assert _turns_cli(site_adapters, *spec, "--turn-source-namespace", "labsite", *opts) == 0
    got = json.loads((site_adapters / "opts.json").read_text())
    assert got == {"project": "lab-1", "token": "secret:gw/tok"}
    capsys.readouterr()
    monkeypatch.setenv("HNX_ORCHESTRATION_TURN_SOURCE_NAMESPACES", "other, labsite")
    assert _turns_cli(site_adapters, *spec, "--turn-source-option", "verify=false") == 0
    assert json.loads((site_adapters / "opts.json").read_text()) == {"verify": False}
    for bad, why in [
        ("token=plain-value", "secret:"),
        ("api_key=abc", "secret:"),
        ("password=secret:", "secret:"),
        ("no-equals", "key=value"),
        ("Bad Key=x", "key=value"),
        ("base_url=http://x", "--gateway-url"),
    ]:
        assert _turns_cli(site_adapters, *spec, "--turn-source-option", bad) == 2
        assert why in capsys.readouterr().err


def test_a_turn_source_whose_import_fails_any_way_is_exit_2(site_adapters, capsys):
    pkg = site_adapters / "pkgs" / "labsite"
    (pkg / "broken.py").write_text("raise TypeError('at import')\n")
    for spec in ("labsite.broken:make", "labsite.missing:make"):
        assert (
            _turns_cli(site_adapters, "--turn-source", spec, "--turn-source-namespace", "labsite")
            == 2
        )
        assert "cannot be imported" in capsys.readouterr().err
    assert _turns_cli(site_adapters, "--turn-source", "x:y", "--turn-source-namespace", "a..b") == 2
    assert "namespace" in capsys.readouterr().err


@pytest.mark.parametrize(
    "spec, why",
    [
        ("homelabnext.conform.adapters.ntfy:safe_urlopen", "not a declared turn source factory"),
        ("homelabnext.conform.adapters.litellm_spend_log:SpendLogReader", "not a declared"),
        ("labsite.turns:Src", "not a declared turn source factory"),  # defined there, undeclared
        ("labsite.turns:borrowed", "not defined in labsite.turns"),  # declared, but re-exported
    ],
)
def test_only_a_declared_factory_defined_in_its_module_is_called(site_adapters, capsys, spec, why):
    argv = ["--turn-source", spec, "--turn-source-namespace", "labsite"]
    never = "req=http://127.0.0.1:9/never"  # no-raw-endpoint: allow a value never sent
    argv += ["--turn-source-option", never]
    assert _turns_cli(site_adapters, *argv) == 2
    assert why in capsys.readouterr().err
    assert not (site_adapters / "opts.json").exists()


@pytest.mark.parametrize("ns", ["homelabnext", "homelabnext.cli", "os", "os.path", "json", "sys"])
def test_a_namespace_that_is_the_standard_library_or_homelabnext_is_refused(
    site_adapters, capsys, ns
):
    argv = ["--turn-source", f"{ns}.x:make", "--turn-source-namespace", ns]
    assert _turns_cli(site_adapters, *argv) == 2
    assert "--turn-source-namespace" in capsys.readouterr().err


def test_the_shipped_adapter_declares_its_factory():
    from homelabnext.conform.adapters import litellm_spend_log

    assert set(litellm_spend_log.TURN_SOURCES) == {"make"}
