# SPDX-License-Identifier: Apache-2.0
"""The lake-writer module's script (modules/lake-writer/roles/lake_writer/files), run in process
against the lake fake and the object-store fake: no ansible, no network.

* The namespace guard: the writer accepts the namespace ``soc`` and no other, by function, by
  configuration, by client and from the command line; a refusal reads and writes nothing.
* The table guard: only the module's own tables, never a qualified name.
* Rows: the row's ``tlp`` is the event's ``labels.hnx_tlp`` and never its own ``tlp`` field; an
  unlabelled event is refused (dead-lettered, never labelled); a run in which every row was
  refused fails.
* Commit then checkpoint: a crash between the commit and the checkpoint, or between the
  checkpoint and the delete, or a lost checkpoint, replays with no row added.
* One writer per table (a held lock means no second run), bounded retries, status.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from conformance.fakes.object_store import FakeObjectStore
from homelabnext.lake import FakeLake
from homelabnext.lake.errors import LakeError
from homelabnext.state.store import file_lock
from tests.lake.fake_lab import FakeLab

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "lake-writer"
FILES = MODULE / "roles" / "lake_writer" / "files"
SCHEMAS = FILES / "schemas"


def _load(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


lw = _load("hnx_lake_writer", FILES / "hnx_lake_writer.py")

BUCKET = "soc-staging"
PREFIX = "lake-writer/staging/"
T0 = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def schemas():
    return lw.table_schemas(str(SCHEMAS))


@pytest.fixture
def lake(schemas):
    return FakeLake(schemas.values())


@pytest.fixture
def store():
    s = FakeObjectStore()
    s.create_bucket(BUCKET)
    return s


def event(table: str, n: int, tlp: str | None = "amber", **more) -> dict:
    """A staged event of ``table`` as the log pipeline leaves it (labelled by the pipeline)."""
    base = {
        "uid": f"{table}-{n}",
        "time": "2026-11-22T11:00:00Z",
        "activity_id": 1,
        "severity_id": 2,
    }
    extra = {
        "dns_activity": {
            "class_uid": 4003,
            "category_uid": 4,
            "query_hostname": f"h{n}.example.internal",
        },
        "authentication": {"class_uid": 3002, "category_uid": 3, "user_name": f"user{n}"},
        "raw_archive": {"location": "journald", "decoder_name": "sshd", "full_log": "a line"},
    }[table]
    ev = {**base, **extra, **more}
    if table == "raw_archive":
        ev.pop("activity_id"), ev.pop("severity_id")
    if tlp is not None:
        ev["labels"] = {"hnx_tlp": tlp}
    return ev


def stage(store, table: str, name: str, events: list, raw: bytes | None = None) -> str:
    key = f"{PREFIX}{table}/{name}"
    body = raw if raw is not None else "".join(json.dumps(e) + "\n" for e in events).encode()
    store.put(BUCKET, key, body)
    return key


def make(lake, store, schemas, tmp_path: Path, table="dns_activity", **kw) -> object:
    return lw.Writer(
        lake,
        store,
        schemas[table],
        namespace="soc",
        bucket=BUCKET,
        prefix=PREFIX,
        state_dir=tmp_path / "state",
        sleep=lambda s: None,
        clock=lambda: T0,
        **kw,
    )


def count(lake, table="dns_activity") -> int:
    return lake.describe(table).row_count


def staged(store, table="dns_activity") -> list[str]:
    return list(store.list(BUCKET, f"{PREFIX}{table}/").keys)


# ------------------------------------------------------------------ the namespace guard


@pytest.mark.parametrize(
    "ns",
    [
        "cti",
        "rba",
        "cape",
        "honeypot",
        "archive",
        "ocsf",
        "obs",
        "lake.cti",
        "Soc",
        "SOC",
        "soc ",
        " soc",
        "soc\n",
        "soc.dns_activity",
        "",
        None,
        7,
        ["soc"],
    ],
)
def test_the_namespace_guard_refuses_everything_but_soc(ns, lake, store, schemas, tmp_path):
    with pytest.raises(lw.NamespaceRefused):
        lw.require_namespace(ns)
    with pytest.raises(lw.NamespaceRefused):
        lw.Writer(
            lake, store, schemas["dns_activity"], namespace=ns, bucket=BUCKET, state_dir=tmp_path
        )
    assert not (tmp_path / "dns_activity").exists()  # nothing was set up for the refused writer


def test_the_namespace_guard_accepts_soc_and_names_the_protected_ones():
    assert lw.require_namespace("soc") == "soc"
    with pytest.raises(lw.NamespaceRefused, match="protected namespace"):
        lw.require_namespace("cti")
    with pytest.raises(lw.NamespaceRefused) as other:
        lw.require_namespace("scratch")
    assert "protected" not in str(other.value)
    assert set(lw.PROTECTED) >= {"cti", "rba", "cape", "honeypot", "archive", "ocsf", "obs"}


def test_a_lake_client_built_for_another_namespace_is_refused(lake, store, schemas, tmp_path):
    class Imported:
        _ns = "cti"

    with pytest.raises(lw.NamespaceRefused):
        make(Imported(), store, schemas, tmp_path)


def _env(tmp_path, **over):
    env = {
        "HNX_LW_STAGING_BUCKET": BUCKET,
        "HNX_LW_STAGING_PREFIX": PREFIX,
        "HNX_LW_STATE_DIR": str(tmp_path / "state"),
        "HNX_LW_SCHEMA_DIR": str(SCHEMAS),
        "HNX_LW_LAKE_USER": "writer",
        "HNX_LW_LAKE_WAREHOUSE": "wh",
        "HNX_LW_LAKE_CREDENTIAL": "secret:lake-writer/lake-password",
    }
    env.update(over)
    return env


@pytest.mark.parametrize("ns", ["cti", "ocsf", "archive", "obs", "rba", ""])
def test_a_configured_namespace_other_than_soc_refuses_before_anything_is_opened(ns, tmp_path):
    with pytest.raises(lw.NamespaceRefused):
        lw.Config(_env(tmp_path, HNX_LW_NAMESPACE=ns))
    # the command line: exit 2, and no lake or object-store client was ever built (their endpoints
    # are not even set, so building one would fail differently)
    code = lw.main(["commit"], env=_env(tmp_path, HNX_LW_NAMESPACE=ns))
    assert code == lw.EXIT_REFUSED
    assert not (tmp_path / "state").exists()


def test_a_plain_http_object_store_is_refused_unless_the_site_allows_it(tmp_path, monkeypatch):
    got = {}

    def fake(**kw):
        got.update(kw)
        return object()

    import homelabnext.conform.adapters.s3 as s3

    monkeypatch.setattr(s3, "make_object_store", fake)
    lw.open_store(lw.Config(_env(tmp_path)))
    assert got["allow_plaintext"] is False
    lw.open_store(lw.Config(_env(tmp_path, HNX_LW_S3_ALLOW_PLAINTEXT="true")))
    assert got["allow_plaintext"] is True
    lw.open_store(lw.Config(_env(tmp_path, HNX_LW_S3_ALLOW_PLAINTEXT="yes")))
    assert got["allow_plaintext"] is False  # only the literal true allows it


def test_ensure_reports_only_the_tables_it_created(tmp_path, monkeypatch, capsys):
    class Lake:
        def __init__(self, tables):
            self.tables = tables

        def list_tables(self):
            return list(self.tables)

    calls = []

    def fake_open(cfg, schemas, *, ensure):
        calls.append(ensure)
        return Lake(["raw_archive", "dns_activity"] if ensure else ["raw_archive"])

    monkeypatch.setattr(lw, "open_lake", fake_open)
    assert lw.cmd_ensure(lw.Config(_env(tmp_path)), {}) == lw.EXIT_OK
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["created"] == ["dns_activity"] and calls == [False, True]


def test_the_default_namespace_is_soc(tmp_path):
    cfg = lw.Config(_env(tmp_path))
    assert cfg.namespace == "soc"
    assert cfg.tables == list(lw.ALL_TABLES)


def test_open_lake_refuses_another_namespace_before_building_a_client(schemas, tmp_path):
    cfg = lw.Config(_env(tmp_path))
    cfg.namespace = "cti"  # as if a caller set it after the fact
    with pytest.raises(lw.NamespaceRefused):
        lw.open_lake(cfg, schemas, ensure=True)


@pytest.mark.static
def test_no_other_namespace_is_named_outside_the_refusal_list():
    text = (FILES / "hnx_lake_writer.py").read_text()
    code = re.sub(r"PROTECTED = \(.*?\)\n", "", text, flags=re.S)
    code = "\n".join(
        ln for ln in code.splitlines() if not ln.lstrip().startswith(("#", '"""', "*"))
    )
    for ns in ("cti", "rba", "cape", "honeypot", "obs"):
        assert not re.search(rf"[\"'.]{ns}[\"'.]", code), ns


# ------------------------------------------------------------------ the table guard


@pytest.mark.parametrize(
    "name", ["cti.events", "soc.dns_activity", "events", "", "DNS_ACTIVITY", None, "../x"]
)
def test_only_the_modules_own_tables_are_accepted(name, schemas):
    with pytest.raises(lw.TableRefused):
        lw.require_table(name, schemas)


def test_every_table_the_old_writers_fed_is_here_with_a_label_column(schemas):
    assert set(schemas) == {
        "authentication",
        "compliance_finding",
        "detection_finding",
        "dns_activity",
        "file_activity",
        "http_activity",
        "network_activity",
        "process_activity",
        "vulnerability_finding",
        "raw_archive",
    }
    assert all(s.labelled and s.key == ("uid",) for s in schemas.values())


def test_a_command_line_table_outside_the_set_is_refused(tmp_path, capsys):
    code = lw.main(["commit", "--table", "cti.events"], env=_env(tmp_path))
    assert code == lw.EXIT_REFUSED
    assert "refused" in capsys.readouterr().err
    assert (
        lw.main(["commit"], env=_env(tmp_path, HNX_LW_TABLES="dns_activity,events"))
        == lw.EXIT_REFUSED
    )


# ------------------------------------------------------------------ rows and the TLP label


def test_a_staged_batch_lands_with_the_pipelines_label_and_the_object_is_deleted(
    lake, store, schemas, tmp_path
):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1), event("dns_activity", 2)])
    res = make(lake, store, schemas, tmp_path).run()
    assert res["ok"] and res["batches"] == 1 and res["rows_written"] == 2
    assert res["pending_after"] == 0 and staged(store) == []
    rows = lake.query("SELECT uid, tlp FROM dns_activity ORDER BY uid")
    assert rows == [
        {"uid": "dns_activity-1", "tlp": "amber"},
        {"uid": "dns_activity-2", "tlp": "amber"},
    ]


def test_the_rows_label_is_the_pipelines_never_the_events_own_tlp(lake, store, schemas, tmp_path):
    ev = {**event("dns_activity", 1, tlp="red"), "tlp": "clear"}  # the source says clear
    stage(store, "dns_activity", "b1.jsonl", [ev])
    res = make(lake, store, schemas, tmp_path).run()
    assert res["ok"] and res["rows_written"] == 1
    assert lake.query("SELECT tlp FROM dns_activity") == [{"tlp": "red"}]


def test_an_unlabelled_event_is_refused_and_never_given_a_label(lake, store, schemas, tmp_path):
    stage(
        store,
        "dns_activity",
        "b1.jsonl",
        [event("dns_activity", 1), event("dns_activity", 2, tlp=None), event("dns_activity", 3)],
    )
    w = make(lake, store, schemas, tmp_path)
    res = w.run()
    assert res["ok"] and res["rows_written"] == 2 and res["rows_rejected"] == 1
    assert count(lake) == 2
    (key,) = w.rejected()
    assert key == f"{PREFIX}dns_activity/_rejected/b1.jsonl"
    (rec,) = (json.loads(x) for x in store.get(BUCKET, key).decode().splitlines())
    assert rec["line"] == 2 and "hnx_tlp" in rec["reason"]
    assert staged(store) == [f"{PREFIX}dns_activity/_rejected/b1.jsonl"]  # the batch itself is gone


@pytest.mark.parametrize("label", ["white", "RED", "Amber", "tlp:red", "", None, 3, {"x": 1}])
def test_a_label_that_is_not_canonical_is_refused_too(label, lake, store, schemas, tmp_path):
    ev = event("dns_activity", 1)
    ev["labels"] = {"hnx_tlp": label}
    stage(store, "dns_activity", "b1.jsonl", [ev])
    res = make(lake, store, schemas, tmp_path).run()
    assert res["rows_rejected"] == 1 and res["rows_written"] == 0 and count(lake) == 0


def test_a_run_in_which_every_row_was_refused_fails(lake, store, schemas, tmp_path, capsys):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1, tlp=None)])
    cfg = lw.Config(_env(tmp_path))
    code = lw.cmd_commit(cfg, ["dns_activity"], schemas, lake, store)
    assert code == lw.EXIT_FAILED and count(lake) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_lines_that_are_not_events_are_refused_without_stopping_the_batch(
    lake, store, schemas, tmp_path
):
    good = json.dumps(event("dns_activity", 1))
    raw = "\n".join([good, "not json", "[1,2]", '"text"', "", json.dumps({"uid": "x"}), "null"])
    stage(store, "dns_activity", "b1.jsonl", [], raw=raw.encode())
    res = make(lake, store, schemas, tmp_path).run()
    assert res["rows_written"] == 1 and res["rows_rejected"] == 5 and count(lake) == 1


def test_an_object_that_is_not_text_is_refused_whole(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [], raw=b"\xff\xfe\x00bad")
    w = make(lake, store, schemas, tmp_path)
    res = w.run()
    assert res["rows_rejected"] == 1 and res["rows_written"] == 0 and w.pending() == []


def test_the_raw_archive_and_a_second_class_have_their_own_writers(lake, store, schemas, tmp_path):
    stage(store, "raw_archive", "b1.jsonl", [event("raw_archive", 1)])
    stage(store, "authentication", "b1.jsonl", [event("authentication", 1, tlp="red")])
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    for t in ("raw_archive", "authentication"):
        assert make(lake, store, schemas, tmp_path, table=t).run()["rows_written"] == 1
    assert count(lake, "raw_archive") == 1 and count(lake, "authentication") == 1
    assert count(lake, "dns_activity") == 0 and staged(store) == [f"{PREFIX}dns_activity/b1.jsonl"]


def test_the_objects_of_another_table_or_prefix_are_never_read(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    store.put(BUCKET, f"{PREFIX}dns_activity_x/b1.jsonl", b"{}\n")
    store.put(BUCKET, f"{PREFIX}other/b1.jsonl", b"{}\n")
    w = make(lake, store, schemas, tmp_path)
    assert w.pending() == [f"{PREFIX}dns_activity/b1.jsonl"]
    w.run()
    assert store.get(BUCKET, f"{PREFIX}dns_activity_x/b1.jsonl")
    assert store.get(BUCKET, f"{PREFIX}other/b1.jsonl")


# ------------------------------------------------------------------ commit, then checkpoint


class Crash(BaseException):  # a process death: nothing in the writer may catch it
    pass


def _boom():
    raise Crash


def test_a_crash_between_the_commit_and_the_checkpoint_adds_no_row(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", i) for i in range(5)])
    with pytest.raises(Crash):
        make(lake, store, schemas, tmp_path, before_checkpoint=_boom).run()
    assert count(lake) == 5  # committed
    assert staged(store) == [f"{PREFIX}dns_activity/b1.jsonl"]  # still staged: the delete is last
    w = make(lake, store, schemas, tmp_path)
    assert w.checkpoint.get(w.source) is None  # the checkpoint is behind the lake, never ahead
    res = w.run()
    assert res["ok"] and count(lake) == 5 and res["rows_written"] == 0
    assert staged(store) == []
    assert lake.query("SELECT count(*) AS n, count(DISTINCT uid) AS d FROM dns_activity") == [
        {"n": 5, "d": 5}
    ]


def test_start_fast_forwards_the_checkpoint_to_the_lakes_mark(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    with pytest.raises(Crash):
        make(lake, store, schemas, tmp_path, before_checkpoint=_boom).run()
    w = make(lake, store, schemas, tmp_path)
    assert w.ingestor.start() == f"{PREFIX}dns_activity/b1.jsonl"
    assert w.checkpoint.get(w.source).batch_id == f"{PREFIX}dns_activity/b1.jsonl"


def test_a_crash_between_the_checkpoint_and_the_delete_adds_no_row(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", i) for i in range(3)])
    with pytest.raises(Crash):
        make(lake, store, schemas, tmp_path, before_delete=_boom).run()
    assert count(lake) == 3 and staged(store) == [f"{PREFIX}dns_activity/b1.jsonl"]
    res = make(lake, store, schemas, tmp_path).run()
    assert res["ok"] and res["replayed"] == 1 and res["rows_written"] == 0
    assert count(lake) == 3 and staged(store) == []


def test_a_lost_checkpoint_replays_with_no_row_added(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", i) for i in range(3)])
    with pytest.raises(Crash):
        make(lake, store, schemas, tmp_path, before_delete=_boom).run()
    (tmp_path / "state" / "dns_activity" / "checkpoint.json").unlink()
    res = make(lake, store, schemas, tmp_path).run()
    assert res["ok"] and count(lake) == 3 and res["rows_written"] == 0


def test_the_same_events_under_another_batch_name_add_no_row(lake, store, schemas, tmp_path):
    events = [event("dns_activity", i) for i in range(4)]
    stage(store, "dns_activity", "b1.jsonl", events)
    make(lake, store, schemas, tmp_path).run()
    stage(store, "dns_activity", "b2-renamed.jsonl", events)  # the ledger cannot know this one
    res = make(lake, store, schemas, tmp_path).run()
    assert res["rows_written"] == 0 and res["rows_skipped"] == 4 and count(lake) == 4


def test_a_batch_is_committed_under_its_object_key_and_the_tables_source(
    lake, store, schemas, tmp_path
):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    w = make(lake, store, schemas, tmp_path)
    w.run()
    mark = lake.describe("dns_activity").committed["lake-writer/dns_activity"]
    assert (
        mark.batch_id == f"{PREFIX}dns_activity/b1.jsonl"
        and mark.high_water == f"{PREFIX}dns_activity/b1.jsonl"
    )
    # another writer cannot make this writer's batch replay by committing its id first
    from homelabnext.lake.errors import BatchSourceMismatch

    with pytest.raises(BatchSourceMismatch):
        lake.write_batch(
            "dns_activity",
            [],
            idempotency_key=f"{PREFIX}dns_activity/b1.jsonl",
            source="someone-else",
        )


def test_objects_are_committed_oldest_name_first_and_a_cap_leaves_the_rest(
    lake, store, schemas, tmp_path
):
    for n in (3, 1, 2):
        stage(store, "dns_activity", f"b{n}.jsonl", [event("dns_activity", n)])
    w = make(lake, store, schemas, tmp_path, max_batches=2)
    res = w.run()
    assert res["batches"] == 2 and res["pending_after"] == 1
    assert staged(store) == [f"{PREFIX}dns_activity/b3.jsonl"]


# ------------------------------------------------------------------ failures


class Flaky:
    """A lake whose writes fail ``fails`` times (a commit conflict, a restart) and then work."""

    def __init__(self, lake, fails, error=LakeError):
        self._lake, self.fails, self.error, self.calls = lake, fails, error, 0

    def __getattr__(self, name):
        return getattr(self._lake, name)

    def write_batch(self, *a, **kw):
        self.calls += 1
        if self.fails > 0:
            self.fails -= 1
            raise self.error("commit failed")
        return self._lake.write_batch(*a, **kw)


def test_a_transient_lake_failure_is_retried_boundedly_and_adds_one_row_set(
    lake, store, schemas, tmp_path
):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", i) for i in range(3)])
    flaky = Flaky(lake, 2)
    sleeps: list[int] = []
    w = make(flaky, store, schemas, tmp_path)
    w._sleep = sleeps.append
    res = w.run()
    assert res["ok"] and flaky.calls == 3 and count(lake) == 3 and sleeps == [2, 4]


def test_a_lake_that_stays_away_fails_the_table_and_keeps_the_object(
    lake, store, schemas, tmp_path
):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    stage(store, "dns_activity", "b2.jsonl", [event("dns_activity", 2)])
    flaky = Flaky(lake, 99)
    w = make(flaky, store, schemas, tmp_path)
    res = w.run()
    assert res["ok"] is False and flaky.calls == 5  # bounded
    assert res["failed"] == [f"{PREFIX}dns_activity/b1.jsonl"] and count(lake) == 0
    assert staged(store) == [f"{PREFIX}dns_activity/b1.jsonl", f"{PREFIX}dns_activity/b2.jsonl"]
    assert make(lake, store, schemas, tmp_path).run()["batches"] == 2  # the next run recovers


def test_a_store_that_cannot_read_one_object_fails_that_object_only(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    stage(store, "dns_activity", "b2.jsonl", [event("dns_activity", 2)])

    class Unreadable(FakeObjectStore):
        def get(self, bucket, key):
            if key.endswith("b1.jsonl"):
                raise OSError("connection reset")
            return store.get(bucket, key)

        def list(self, *a, **kw):
            return store.list(*a, **kw)

        def delete(self, *a):
            return store.delete(*a)

        def put(self, *a, **kw):
            return store.put(*a, **kw)

    res = make(lake, Unreadable(), schemas, tmp_path).run()
    assert res["ok"] is False and res["failed"] == [f"{PREFIX}dns_activity/b1.jsonl"]
    assert res["batches"] == 1 and count(lake) == 1  # b2 still landed


def test_the_failure_exit_code_is_nonzero_when_any_table_fails_after_all_had_a_turn(
    lake, store, schemas, tmp_path, capsys
):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1, tlp=None)])
    stage(store, "authentication", "b1.jsonl", [event("authentication", 1)])
    cfg = lw.Config(_env(tmp_path, HNX_LW_MAX_ATTEMPTS="1"))
    code = lw.cmd_commit(cfg, ["dns_activity", "authentication"], schemas, lake, store)
    assert code == lw.EXIT_FAILED
    assert count(lake, "authentication") == 1  # the second table still had its turn
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [x["table"] for x in lines] == ["dns_activity", "authentication"]


# ------------------------------------------------------------------ one writer per table


def test_a_second_run_finds_the_tables_lock_held_and_does_nothing(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    lock = tmp_path / "state" / "dns_activity" / "lock"
    lock.parent.mkdir(parents=True)
    with file_lock(lock):
        res = lw.run_table(
            lake,
            store,
            schemas["dns_activity"],
            namespace="soc",
            bucket=BUCKET,
            prefix=PREFIX,
            state_dir=tmp_path / "state",
        )
    assert res is None and count(lake) == 0 and staged(store) == [f"{PREFIX}dns_activity/b1.jsonl"]
    res = lw.run_table(
        lake,
        store,
        schemas["dns_activity"],
        namespace="soc",
        bucket=BUCKET,
        prefix=PREFIX,
        state_dir=tmp_path / "state",
    )
    assert res["rows_written"] == 1


def test_each_table_has_its_own_lock_checkpoint_and_source(lake, store, schemas, tmp_path):
    a = make(lake, store, schemas, tmp_path, table="dns_activity")
    b = make(lake, store, schemas, tmp_path, table="authentication")
    assert a.source != b.source and a.dir != b.dir
    assert a.checkpoint.path != b.checkpoint.path


# ------------------------------------------------------------------ status


def test_status_finds_a_table_that_never_ran_a_failed_run_an_old_one_and_a_backlog(
    lake, store, schemas, tmp_path
):
    def st(**kw):
        return lw.status(
            store,
            schemas,
            ["dns_activity"],
            bucket=BUCKET,
            prefix=PREFIX,
            state_dir=tmp_path / "state",
            max_pending=kw.get("max_pending", 0),
            max_age_s=kw.get("max_age_s", 0),
            now=kw.get("now", T0),
        )

    assert st()["problems"] == ["dns_activity: has never run"]
    assert not (tmp_path / "state").exists()  # reading status creates nothing
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    stage(store, "dns_activity", "b2.jsonl", [event("dns_activity", 2)])
    make(lake, store, schemas, tmp_path, max_batches=1).run()
    assert st()["problems"] == []
    assert st()["tables"]["dns_activity"]["pending"] == 1
    assert st(max_pending=1)["problems"] == []
    stage(store, "dns_activity", "b3.jsonl", [event("dns_activity", 3)])
    assert any("staged objects wait" in p for p in st(max_pending=1)["problems"])
    assert any("s ago" in p for p in st(max_age_s=3600, now=T0 + timedelta(hours=3))["problems"])
    stage(store, "dns_activity", "b4.jsonl", [event("dns_activity", 4, tlp=None)])
    make(Flaky(lake, 99), store, schemas, tmp_path).run()
    assert any("last run failed" in p for p in st()["problems"])


def test_status_command_prints_json_and_exits_by_its_problems(store, schemas, tmp_path, capsys):
    cfg = lw.Config(_env(tmp_path, HNX_LW_TABLES="dns_activity"))
    assert lw.cmd_status(cfg, schemas, 0, 0, store=store) == lw.EXIT_FAILED
    out = capsys.readouterr()
    assert json.loads(out.out)["problems"] == ["dns_activity: has never run"]
    assert "has never run" in out.err


def test_schema_check_is_ok_for_the_fake_and_reports_a_missing_table(
    lake, schemas, tmp_path, capsys
):
    cfg = lw.Config(_env(tmp_path, HNX_LW_TABLES="dns_activity"))
    assert lw.cmd_schema_check(cfg, schemas, lake=lake) == lw.EXIT_OK

    class Missing:
        def describe(self, t):
            raise LakeError("table does not exist")

    assert lw.cmd_schema_check(cfg, schemas, lake=Missing()) == lw.EXIT_FAILED
    assert "does not exist" in capsys.readouterr().out


# ------------------------------------------------------------------ the module's declarations


def test_every_table_has_a_lake_table_record_in_the_soc_namespace_owned_by_the_module(schemas):
    records = {}
    for p in sorted((MODULE / "lake").glob("*.table.yml")):
        rec = yaml.safe_load(p.read_text())
        records[rec["id"]] = rec
    assert set(records) == {f"table:soc.{t}" for t in schemas}
    for rec in records.values():
        assert rec["owner"] == "lake-writer" and rec["retention_days"] >= 1
        assert ("schema" in rec) != ("schema_id" in rec)
        if "schema" in rec:
            assert (MODULE / rec["schema"]).is_file()
        else:
            tbl = rec["id"].split(".")[1]
            assert rec["schema_id"] == schemas[tbl].schema_id


# ------------------------------------------------------------------ the platform's real adapter


@pytest.fixture
def lab(monkeypatch):
    """The loopback stand-in for the query service and the catalog, behind the platform's own lake
    client: what ``open_lake`` builds in production."""
    with FakeLab() as fl:
        monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", fl.url)
        monkeypatch.setenv("HNX_ENDPOINT_LAKE_CATALOG", fl.url)
        monkeypatch.setenv("HNX_SECRET_LAKE_WRITER_LAKE_PASSWORD", "pw" * 8)
        yield fl


def _real_cfg(tmp_path, **over):
    env = _env(
        tmp_path,
        HNX_LW_TABLES="dns_activity",
        HNX_LW_LAKE_WAREHOUSE="lab",
        HNX_LW_LAKE_CREDENTIAL="secret:lake-writer/lake-password",
        **over,
    )
    return lw.Config(env)


def test_the_real_client_creates_only_soc_tables_and_a_crash_replay_adds_no_row(
    lab, store, schemas, tmp_path
):
    cfg = _real_cfg(tmp_path)
    lake = lw.open_lake(cfg, schemas, ensure=True)
    assert lw.lake_namespace(lake) == "soc"
    assert {ns for ns, _ in lab.tables} == {"soc"} and {t for _, t in lab.tables} == {
        "dns_activity"
    }
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", i) for i in range(4)])
    with pytest.raises(Crash):
        make(lake, store, schemas, tmp_path, before_checkpoint=_boom).run()
    assert lake.describe("dns_activity").row_count == 4
    res = make(lake, store, schemas, tmp_path).run()
    assert res["ok"] and res["rows_written"] == 0 and res["replayed"] == 1
    assert lake.describe("dns_activity").row_count == 4 and staged(store) == []
    assert lake.query("SELECT DISTINCT tlp FROM dns_activity") == [{"tlp": "amber"}]


def test_a_check_opens_the_lake_without_creating_anything(lab, schemas, tmp_path, capsys):
    cfg = _real_cfg(tmp_path)
    assert lw.cmd_schema_check(cfg, schemas) == lw.EXIT_FAILED  # the table is not there
    assert lab.tables == {} and "dns_activity" in capsys.readouterr().out
    lw.open_lake(cfg, schemas, ensure=True)
    assert lw.cmd_schema_check(cfg, schemas) == lw.EXIT_OK
    assert lw.cmd_schema_check(cfg, schemas) == lw.EXIT_OK and len(lab.tables) == 1


def test_the_real_client_refuses_a_namespace_other_than_soc_before_any_request(
    lab, schemas, tmp_path
):
    cfg = _real_cfg(tmp_path)
    cfg.namespace = "cti"
    with pytest.raises(lw.NamespaceRefused):
        lw.open_lake(cfg, schemas, ensure=True)
    assert lab.tables == {} and lab.statements == [] and lab.auth == []


# ------------------------------------------------------------------ the pipeline's staging layout


def test_an_object_in_the_pipelines_partitioned_gzip_form_is_picked_up_and_committed(
    lake, store, schemas, tmp_path
):
    import gzip

    when = datetime(2026, 11, 22, 13, 5, tzinfo=UTC)
    key = lw.staging_key(PREFIX, "dns_activity", when, "0192ab-uuid")
    # the form the log-pipeline module documents: <prefix><table>/dt=%Y-%m-%d/hour=%H/<id>.ndjson.gz
    assert key == f"{PREFIX}dns_activity/dt=2026-11-22/hour=13/0192ab-uuid.ndjson.gz"
    body = "".join(json.dumps(event("dns_activity", i)) + "\n" for i in range(3)).encode()
    store.put(BUCKET, key, gzip.compress(body))
    plain = lw.staging_key(PREFIX, "dns_activity", when, "plain", gz=False)
    store.put(BUCKET, plain, json.dumps(event("dns_activity", 9)).encode())
    w = make(lake, store, schemas, tmp_path)
    assert w.pending() == sorted([key, plain])
    res = w.run()
    assert res["ok"] and res["rows_written"] == 4 and count(lake) == 4 and staged(store) == []
    assert lw.STAGING_LAYOUT.startswith("<prefix><table>/dt=")


def test_a_corrupt_or_oversized_gzip_is_refused_whole(lake, store, schemas, tmp_path, monkeypatch):
    import gzip

    key = lw.staging_key(PREFIX, "dns_activity", T0, "bad")
    store.put(BUCKET, key, b"\x1f\x8bnot gzip")
    res = make(lake, store, schemas, tmp_path).run()
    assert res["rows_rejected"] == 1 and count(lake) == 0
    monkeypatch.setattr(lw, "MAX_INFLATED", 10)
    store.put(BUCKET, lw.staging_key(PREFIX, "dns_activity", T0, "big"), gzip.compress(b"x" * 100))
    assert make(lake, store, schemas, tmp_path).run()["rows_rejected"] == 1


# ---------------------------------------------------------------- the contract with the pipeline
GOLDEN = ROOT / "tests" / "modules" / "golden" / "log-pipeline" / "expected.json"


def test_every_row_the_log_pipeline_stages_is_one_the_writer_takes(schemas):
    """The log pipeline's golden rows (each route, each table it stages) go through the writer's
    own preparation without a rejection: the two modules' table contract is the same (a staged
    column the writer's schema lacks rejected every raw-archive row on the lab's first run)."""
    golden = json.loads(GOLDEN.read_text())
    seen = set()
    for route, events in golden.items():
        for staged in events:
            for item in staged:
                table, row = item["table"], item["row"]
                if table not in schemas:
                    continue  # a class the writer does not own yet: staged, not committed
                seen.add(table)
                line = json.dumps(row).encode() + b"\n"
                rows, rejects = lw.prepare(schemas[table], line)
                assert rejects == [], (route, table, rejects)
                assert len(rows) == 1
    assert "raw_archive" in seen


# ------------------------------------------------------------------ one commit per run, snapshot retention


class Spy:
    """A lake that counts its commits and records the expiry it is asked for."""

    def __init__(self, lake, *, expire=None):
        self._lake, self.commits, self.expiries, self._expire = lake, [], [], expire

    def __getattr__(self, name):
        return getattr(self._lake, name)

    def write_batch(self, table, rows, **kw):
        self.commits.append((kw["idempotency_key"], len(rows), kw["high_water"]))
        return self._lake.write_batch(table, rows, **kw)

    def expire_snapshots(self, table, **kw):
        self.expiries.append((table, kw))
        if isinstance(self._expire, Exception):
            raise self._expire
        return self._expire or {"expired": 7, "kept": 500, "before": 507}


def test_every_staged_object_of_a_run_is_one_commit(lake, store, schemas, tmp_path):
    for n in range(1, 6):
        stage(store, "dns_activity", f"b{n}.jsonl", [event("dns_activity", n)])
    spy = Spy(lake)
    res = make(spy, store, schemas, tmp_path).run()
    assert len(spy.commits) == 1 and spy.commits[0][1:] == (5, f"{PREFIX}dns_activity/b5.jsonl")
    assert res["ok"] and res["batches"] == 5 and res["commits"] == 1 and res["rows_written"] == 5
    assert staged(store) == [] and count(lake) == 5


def test_a_crash_after_a_grouped_commit_replays_the_same_set_with_no_row_added(
    lake, store, schemas, tmp_path
):
    for n in range(1, 4):
        stage(store, "dns_activity", f"b{n}.jsonl", [event("dns_activity", n)])
    with pytest.raises(Crash):
        make(lake, store, schemas, tmp_path, before_delete=_boom).run()
    assert count(lake) == 3 and len(staged(store)) == 3
    res = make(lake, store, schemas, tmp_path).run()
    assert res["ok"] and res["replayed"] == 1 and res["rows_written"] == 0
    assert count(lake) == 3 and staged(store) == []


def test_a_grouped_replay_after_a_new_object_arrived_adds_no_row(lake, store, schemas, tmp_path):
    for n in range(1, 4):
        stage(store, "dns_activity", f"b{n}.jsonl", [event("dns_activity", n)])
    with pytest.raises(Crash):
        make(lake, store, schemas, tmp_path, before_delete=_boom).run()
    stage(store, "dns_activity", "b4.jsonl", [event("dns_activity", 4)])  # another set: other id
    res = make(lake, store, schemas, tmp_path).run()
    assert res["ok"] and res["rows_written"] == 1 and res["rows_skipped"] == 3
    assert lake.query("SELECT count(*) AS n, count(DISTINCT uid) AS d FROM dns_activity") == [
        {"n": 4, "d": 4}
    ]


def test_the_row_cap_splits_a_run_into_as_few_commits_as_it_allows(lake, store, schemas, tmp_path):
    for n in range(1, 6):
        stage(store, "dns_activity", f"b{n}.jsonl", [event("dns_activity", n)])
    spy = Spy(lake)
    res = make(spy, store, schemas, tmp_path, max_commit_rows=2).run()
    assert [c[1] for c in spy.commits] == [2, 2, 1] and res["commits"] == 3 and count(lake) == 5


def test_a_failed_commit_keeps_every_object_of_the_group_staged(lake, store, schemas, tmp_path):
    for n in (1, 2, 3):
        stage(store, "dns_activity", f"b{n}.jsonl", [event("dns_activity", n)])
    res = make(Flaky(lake, 99), store, schemas, tmp_path).run()
    assert res["ok"] is False and len(staged(store)) == 3 and "commit of 3 objects" in res["error"]


def test_a_run_reports_what_it_expired_and_asks_for_the_configured_retention(
    lake, store, schemas, tmp_path
):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    spy = Spy(lake)
    res = make(spy, store, schemas, tmp_path, snapshot_keep=500, snapshot_max_age_hours=72).run()
    assert spy.expiries == [("dns_activity", {"keep": 500, "max_age_ms": 72 * 3600 * 1000})]
    assert res["expired"] == 7 and res["snapshots"] == 500 and "expire_error" not in res
    assert json.loads(json.dumps(res))["expired"] == 7  # the run's JSON line carries it
    assert lw.last_run(tmp_path / "state", "dns_activity")["expired"] == 7


def test_the_json_line_names_expired_on_every_run(lake, store, schemas, tmp_path, capsys):
    res = make(lake, store, schemas, tmp_path).run()  # nothing staged, no retention configured
    assert res["expired"] == 0 and res["snapshots"] is None and "expired" in res


def test_no_expiry_when_the_run_failed_or_committed_nothing(lake, store, schemas, tmp_path):
    spy = Spy(lake)
    make(spy, store, schemas, tmp_path, snapshot_keep=500).run()  # nothing staged: no commit
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    flaky = Spy(Flaky(lake, 99))
    res = make(flaky, store, schemas, tmp_path, snapshot_keep=500).run()
    assert res["ok"] is False and spy.expiries == [] and flaky.expiries == []
    assert res["expired"] == 0


def test_a_failed_expiry_is_recorded_and_never_fails_the_run(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    spy = Spy(lake, expire=LakeError("catalog gone"))
    res = make(spy, store, schemas, tmp_path, snapshot_keep=500).run()
    assert res["ok"] and "catalog gone" in res["expire_error"] and res["expired"] == 0


def test_a_lake_without_expiry_or_a_retention_of_zero_skips_it(lake, store, schemas, tmp_path):
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    assert make(lake, store, schemas, tmp_path, snapshot_keep=500).run()["expired"] == 0
    stage(store, "dns_activity", "b2.jsonl", [event("dns_activity", 2)])
    spy = Spy(lake)
    make(spy, store, schemas, tmp_path).run()  # keep 0 and age 0: retention off
    assert spy.expiries == []


def test_retention_and_catalog_cap_settings_come_from_the_environment(tmp_path):
    cfg = lw.Config(_env(tmp_path))
    assert (cfg.snapshot_keep, cfg.snapshot_max_age_hours) == (500, 72)
    assert cfg.catalog_max_bytes == 64 * 1024 * 1024 and cfg.max_commit_rows == 100_000
    cfg = lw.Config(_env(tmp_path, HNX_LW_SNAPSHOT_KEEP="0", HNX_LW_SNAPSHOT_MAX_AGE_HOURS="0.5"))
    assert (cfg.snapshot_keep, cfg.snapshot_max_age_hours) == (0, 0.5)
    with pytest.raises(lw.Refused):
        lw.Config(_env(tmp_path, HNX_LW_SNAPSHOT_KEEP="-1"))


# ------------------------------------------------------------------ expiry through the real client


def _seed(lab, ages_h, refs=None):
    """The table's snapshots as ``ages_h`` hours old (oldest first); main on the newest."""
    import time

    now = int(time.time() * 1000)  # hermetic: allow the real client expires by the real clock
    meta = lab.tables[("soc", "dns_activity")]
    meta["snapshots"] = [
        {"snapshot-id": i, "timestamp-ms": now - int(h * 3600_000), "manifest-list": f"m{i}"}
        for i, h in enumerate(ages_h, 1)
    ]
    meta["refs"] = {"main": {"snapshot-id": len(ages_h)}} if refs is None else refs


def _ids(lab):
    return [s["snapshot-id"] for s in lab.tables[("soc", "dns_activity")]["snapshots"]]


def test_expiry_keeps_main_and_the_newest_n(lab, schemas, tmp_path):
    lake = lw.open_lake(_real_cfg(tmp_path), schemas, ensure=True)
    # snapshot 1 is the oldest but main points at it: it survives any count
    _seed(lab, [9, 8, 7, 6, 5, 4, 3, 2], refs={"main": {"snapshot-id": 1}})
    out = lake.expire_snapshots("dns_activity", keep=3)
    assert _ids(lab) == [1, 6, 7, 8] and out["expired"] == 4 and out["kept"] == 4


def test_expiry_by_age_never_takes_main_and_no_op_sends_nothing(lab, schemas, tmp_path):
    lake = lw.open_lake(_real_cfg(tmp_path), schemas, ensure=True)
    _seed(lab, [100, 80, 10, 1])
    assert lake.expire_snapshots("dns_activity", max_age_ms=72 * 3600_000)["expired"] == 2
    assert _ids(lab) == [3, 4]
    assert lake.expire_snapshots("dns_activity", keep=500)["expired"] == 0 and _ids(lab) == [3, 4]
    _seed(lab, [100, 99], refs={"main": {"snapshot-id": 1}})
    lake.expire_snapshots("dns_activity", max_age_ms=3600_000)
    assert _ids(lab) == [1]


@pytest.mark.parametrize(
    "refs",
    [
        {"main": {"snapshot-id": 4}, "release": {"snapshot-id": 2}},
        {"main": {"snapshot-id": 4}, "audit": {"snapshot-id": 1}},
        {},
    ],
)
def test_expiry_refuses_a_table_with_any_ref_but_main(refs, lab, schemas, tmp_path):
    lake = lw.open_lake(_real_cfg(tmp_path), schemas, ensure=True)
    _seed(lab, [4, 3, 2, 1], refs=refs)
    out = lake.expire_snapshots("dns_activity", keep=1)
    assert out["expired"] == 0 and "skipped" in out and len(_ids(lab)) == 4


def test_expiry_retries_a_raced_commit_on_fresh_metadata_then_gives_up(lab, schemas, tmp_path):
    lake = lw.open_lake(_real_cfg(tmp_path), schemas, ensure=True)
    _seed(lab, [5, 4, 3, 2, 1])
    lab.conflicts = 1
    assert lake.expire_snapshots("dns_activity", keep=2)["expired"] == 3
    _seed(lab, [5, 4, 3, 2, 1])
    lab.conflicts = 9
    with pytest.raises(LakeError):
        lake.expire_snapshots("dns_activity", keep=2)
    assert len(_ids(lab)) == 5
    with pytest.raises(LakeError, match="keep or max_age_ms"):
        lake.expire_snapshots("dns_activity")


def test_a_run_through_the_real_client_expires_and_reports(lab, store, schemas, tmp_path):
    lake = lw.open_lake(_real_cfg(tmp_path), schemas, ensure=True)
    stage(store, "dns_activity", "b1.jsonl", [event("dns_activity", 1)])
    res = make(lake, store, schemas, tmp_path, snapshot_keep=2).run()
    assert res["ok"] and res["commits"] == 1 and "expire_error" not in res
    stage(store, "dns_activity", "b2.jsonl", [event("dns_activity", 2)])
    _seed(lab, [5, 4, 3, 2, 1])
    lab.tables[("soc", "dns_activity")]["refs"] = {"main": {"snapshot-id": 5}}
    res = make(lake, store, schemas, tmp_path, snapshot_keep=2).run()
    # the seeded five plus the run's own commit, newest two kept (main is among them)
    assert res["ok"] and res["expired"] == 4 and res["snapshots"] == 2 and len(_ids(lab)) == 2
