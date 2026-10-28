# SPDX-License-Identifier: Apache-2.0
"""The inventory gathered from the hosts (homelabnext.modules.census, ``hnx modules gather``) and
the deploy's check (``hnx modules check --deploy``): docs/modules.md, "What the loader checks"."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

import pytest

from homelabnext.modules import census
from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
SMALL_LAB = EXAMPLES / "sites" / "small-lab.yml"


#: the host's facts in every census answer here: a boot id, a clock, and the start time of the
#: process every record below names (pid 4242, started 1000: still running)
BOOT = "00000000-0000-4000-8000-000000000001"
NOW = 1_800_000_000
STARTED = 1000
NOPAIRS = {"boot_id": BOOT, "now": NOW, "records": {"broker": None, "status": None}}


def answer_pairs(records: dict[str, str | None], **over) -> dict:
    """A host's pairs answer: owner -> the record's text (its process running), or None."""
    held = {
        o: None if t is None else {"text": t, "pid_started": STARTED} for o, t in records.items()
    }
    return {**NOPAIRS, "records": {**NOPAIRS["records"], **held}, **over}


def write_census(
    d: Path,
    answers: dict[str, list[str]],
    hosts: list[str] | None = None,
    active: dict[str, list[str]] | None = None,
    pairs: dict[str, dict[str, str | None]] | None = None,
    listening: dict[str, list[str]] | None = None,
) -> Path:
    """A census as the role writes it: ``answers`` the enabled unit files per host, ``active``
    the active units (none by default), ``pairs`` the pairs records per host (owner -> text;
    none by default), ``listening`` the sockets each host listens on (none by default)."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "_hosts.json").write_text(json.dumps(sorted(answers) if hosts is None else hosts))
    for host, lines in answers.items():
        doc = {
            "host": host,
            "enabled": lines,
            "active": (active or {}).get(host, []),
            "pairs": answer_pairs((pairs or {}).get(host, {})),
            "listening": (listening or {}).get(host, []),
        }
        (d / f"{host}.json").write_text(json.dumps(doc))
    return d


# ----------------------------------------------------------------------------- gather


def test_units_are_the_union_of_what_every_host_reports_enabled(tmp_path):
    d = write_census(
        tmp_path / "c",
        {
            "gpu-1": [
                "hnx-egress.service enabled enabled",
                "hnx-egress.timer enabled -",
            ],
            "infer-core.example": ["hnx-external-collector-pull.timer enabled"],
            "quiet": [],
        },
    )
    inventory, notes = census.gather(d)
    assert inventory == {
        "schema_version": "1.0",
        "units": ["egress", "external-collector-pull"],
        "not_gathered": ["rows", "mcp_servers", "agents", "tables"],
        "listening": [
            {"host": "gpu-1", "sockets": []},
            {"host": "infer-core.example", "sockets": []},
            {"host": "quiet", "sockets": []},
        ],
    }
    assert notes == [
        "gathered from 3 host(s): 2 fleet unit(s) enabled or active",
        "the census is a union across hosts: a unit is not checked against the host it runs on",
        "no host holds a notify pairs record that counts: the recovery pairs were not compared "
        "(a notifier records them with --notify-pairs-dir)",
        "service rows are not gathered by name: each selected module's row is judged by whether "
        "its placed host listens on its port (derived from the hosts' sockets)",
        "no host's census asked a broker (module_census_broker_socket): agents not gathered",
        "no host lists an installed MCP client configuration (module_census_mcp_configs): "
        "MCP servers not gathered",
        "no host's census listed a lake catalog (module_census_catalog_url): tables not gathered",
    ]
    # what it writes is a valid inventory
    schema = ld._schema("platform", "module_inventory.schema.json")
    assert ld._errors(schema, inventory) == []


def test_each_hosts_listening_sockets_are_listed_once_and_in_order(tmp_path):
    d = write_census(
        tmp_path / "c",
        {"a": [], "b": []},
        listening={"a": ["udp/53", "tcp/9000", "tcp/443@lo", "tcp/443", "tcp/443"], "b": []},
    )
    inventory, _ = census.gather(d)
    assert inventory["listening"] == [
        {"host": "a", "sockets": ["tcp/443", "tcp/443@lo", "tcp/9000", "udp/53"]},
        {"host": "b", "sockets": []},
    ]
    assert "rows" in inventory["not_gathered"]  # a socket names no row


@pytest.mark.parametrize(
    "found",
    [
        "tcp/80",  # not a list
        [80],
        ["tcp/0"],
        ["tcp/65536"],
        ["tcp/080"],
        ["sctp/80"],
        ["tcp/80 "],
        ["tcp/80\n"],
        ["tcp/80@local"],
        ["tcp/80@"],
        ["tcp/65536@lo"],
        ["tcp/80"] * (census.MAX_SOCKETS + 1),
    ],
)
def test_a_listening_answer_of_another_shape_fails_the_census(tmp_path, found):
    d = write_census(tmp_path / "c", {"a": []})
    doc = json.loads((d / "a.json").read_text())
    doc["listening"] = found
    (d / "a.json").write_text(json.dumps(doc))
    with pytest.raises(census.CensusError, match="listening socket"):
        census.gather(d)


def _with_agents(d: Path, host: str, agents) -> None:
    """Give ``host``'s answer the broker's agents, as the role writes it on a broker host."""
    doc = json.loads((d / f"{host}.json").read_text())
    doc["agents"] = agents
    (d / f"{host}.json").write_text(json.dumps(doc))


def test_agents_are_gathered_from_the_brokers_that_answered(tmp_path):
    d = write_census(tmp_path / "c", {"agent-core": [], "edge": [], "lake": []})
    _with_agents(d, "agent-core", ["core-staff-scorecard", "external-collector-analyst"])
    _with_agents(d, "lake", ["core-staff-scorecard"])  # a second broker: the union
    inventory, notes = census.gather(d)
    assert inventory["agents"] == ["core-staff-scorecard", "external-collector-analyst"]
    assert inventory["not_gathered"] == ["rows", "mcp_servers", "tables"]
    assert "asked 2 broker(s): 2 agent(s) served" in notes
    assert ld._errors(ld._schema("platform", "module_inventory.schema.json"), inventory) == []


def test_a_broker_that_serves_no_agent_is_an_empty_list_not_not_gathered(tmp_path):
    d = write_census(tmp_path / "c", {"agent-core": []})
    _with_agents(d, "agent-core", [])
    inventory, _ = census.gather(d)
    assert inventory["agents"] == [] and "agents" not in inventory["not_gathered"]


@pytest.mark.parametrize(
    "agents",
    [
        "core-staff-scorecard",  # not a list of lines
        [7],
        ["Core-Staff"],
        ["core staff"],
        ["profile:core-staff"],  # a key, never the profile id
        [""],
        ["a" * 65],
        ["../x"],
        ["ok\nhnx-x.service enabled"],
        ["k"] * (census.MAX_LINES + 1),
    ],
)
def test_an_agent_line_that_is_not_one_key_fails_the_census(tmp_path, agents):
    d = write_census(tmp_path / "c", {"agent-core": []})
    _with_agents(d, "agent-core", agents)
    with pytest.raises(census.CensusError):
        census.gather(d)


def test_an_answer_with_another_extra_key_fails_the_census(tmp_path):
    d = write_census(tmp_path / "c", {"agent-core": []})
    doc = json.loads((d / "agent-core.json").read_text())
    doc["rows"] = []
    (d / "agent-core.json").write_text(json.dumps(doc))
    with pytest.raises(
        census.CensusError, match="not \\{host, enabled, active, pairs, listening\\}"
    ):
        census.gather(d)


def _with_tables(d: Path, host: str, found) -> None:
    """Give ``host``'s answer its catalog's tables, as the role writes it on a catalog host."""
    doc = json.loads((d / f"{host}.json").read_text())
    doc["tables"] = found
    (d / f"{host}.json").write_text(json.dumps(doc))


def test_tables_are_gathered_from_the_catalogs_that_answered(tmp_path):
    d = write_census(tmp_path / "c", {"lake": [], "lake-2": [], "edge": []})
    _with_tables(d, "lake", {"tables": ["ocsf.authentication", "lab_own.x"], "left_out": 2})
    _with_tables(d, "lake-2", {"tables": ["ocsf.authentication"], "left_out": 0})  # the union
    inventory, notes = census.gather(d)
    assert inventory["tables"] == ["table:lab_own.x", "table:ocsf.authentication"]
    assert inventory["not_gathered"] == ["rows", "mcp_servers", "agents"]
    assert "listed 2 lake catalog(s): 2 table(s)" in notes
    assert any(n.startswith("2 catalog namespace(s) or table(s) not of the") for n in notes)
    assert ld._errors(ld._schema("platform", "module_inventory.schema.json"), inventory) == []
    # a catalog that holds no table is an empty list, never "not gathered"
    d = write_census(tmp_path / "e", {"lake": []})
    _with_tables(d, "lake", {"tables": [], "left_out": 0})
    inventory, _ = census.gather(d)
    assert inventory["tables"] == [] and "tables" not in inventory["not_gathered"]
    # no catalog asked: tables stay not gathered, and the note says why
    inventory, notes = census.gather(write_census(tmp_path / "n", {"edge": []}))
    assert "tables" in inventory["not_gathered"] and "tables" not in inventory
    assert any("module_census_catalog_url" in n for n in notes)


@pytest.mark.parametrize(
    "found",
    [
        ["ocsf.authentication"],  # not {tables, left_out}
        {"tables": ["ocsf.authentication"]},
        {"tables": ["ocsf.authentication"], "left_out": 0, "extra": 1},
        {"tables": "ocsf.authentication", "left_out": 0},
        {"tables": [7], "left_out": 0},
        {"tables": [], "left_out": -1},
        {"tables": [], "left_out": True},
        {"tables": [], "left_out": "0"},
        {"tables": ["table:ocsf.authentication"], "left_out": 0},  # the bare name, no prefix
        {"tables": ["ocsf"], "left_out": 0},
        {"tables": ["ocsf.a.b"], "left_out": 0},
        {"tables": ["OCSF.authentication"], "left_out": 0},
        {"tables": ["ocsf.authentication\nhnx-x.service enabled"], "left_out": 0},
        {"tables": ["o." + "a" * 122], "left_out": 0},  # 130 with its prefix: over 129
        {"tables": ["o.t"] * (census.MAX_LINES + 1), "left_out": 0},
    ],
)
def test_a_tables_answer_off_the_shape_fails_the_census(tmp_path, found):
    d = write_census(tmp_path / "c", {"lake": []})
    _with_tables(d, "lake", found)
    with pytest.raises(census.CensusError):
        census.gather(d)


def test_the_union_of_the_catalogs_is_capped_like_one(tmp_path):
    d = write_census(tmp_path / "c", {"a": [], "b": []})
    half = census.MAX_LINES // 2 + 1
    _with_tables(d, "a", {"tables": [f"a.t{i}" for i in range(half)], "left_out": 0})
    _with_tables(d, "b", {"tables": [f"b.t{i}" for i in range(half)], "left_out": 0})
    with pytest.raises(census.CensusError, match="over 4096 tables"):
        census.gather(d)


def test_a_template_unit_is_left_out_and_noted(tmp_path):
    d = write_census(tmp_path / "c", {"h": ["hnx-page@.service enabled disabled"]})
    inventory, notes = census.gather(d)
    assert inventory["units"] == [] and "1 template unit(s) or instance(s)" in notes[-1]


def test_a_unit_that_runs_without_being_enabled_is_counted(tmp_path):
    """A static, runtime-enabled or linked unit, or one another unit or systemd-run started, has
    no enabled unit file; while it is active, list-units reports it, and the census counts it."""
    d = write_census(
        tmp_path / "c",
        {"a": ["hnx-egress.timer enabled"], "b": []},
        active={
            "a": ["hnx-egress.timer loaded active waiting Compact the lake"],
            "b": [
                "hnx-stray.service loaded active running Started by hand",
                # an instance, built in two parts (whole, the leak scan reads it as an address)
                "hnx-page@" + "alert.service loaded active running One page",
                "hnx-oneshot.service loaded active exited",
            ],
        },
    )
    inventory, notes = census.gather(d)
    assert inventory["units"] == ["egress", "oneshot", "stray"]
    assert "1 template unit(s) or instance(s)" in notes[-1]


@pytest.mark.parametrize(
    "line",
    [
        "hnx-x.service loaded failed failed X",  # --state=active lists active units only
        "hnx-x.service not-found active running X",
        "hnx-x.service loaded active running \x1b[31mred",  # a control character in the text
        "hnx-x.socket loaded active listening X",
        "other.service loaded active running X",
        "hnx-X.service loaded active running X",
        "hnx-x.service loaded active",
        "",
    ],
)
def test_an_active_line_of_another_shape_makes_the_census_unreadable(tmp_path, line):
    d = write_census(
        tmp_path / "c", {"h": []}, active={"h": ["hnx-ok.timer loaded active waiting", line]}
    )
    with pytest.raises(census.CensusError, match=r"h: active line 2"):
        census.gather(d)


@pytest.mark.parametrize(
    "line",
    [
        "hnx-x.service disabled",  # not enabled: systemctl was asked for enabled ones only
        "hnx-x.service enabled-runtime",
        "other.service enabled",  # not a fleet unit
        "hnx-X.service enabled",  # not the fleet's name shape
        "hnx-x.socket enabled",
        "hnx-x.service enabled enabled extra",
        "hnx-x.service enabled\nhnx-y.service enabled",  # one line is one line
        "hnx-1x.service enabled",  # a fleet name, but not an inventory name
        "hnx-x--y.service enabled",
        "",
    ],
)
def test_a_host_that_prints_anything_else_makes_the_census_unreadable(tmp_path, line):
    d = write_census(tmp_path / "c", {"h": ["hnx-ok.timer enabled", line]})
    with pytest.raises(census.CensusError, match=r"h: enabled line 2"):
        census.gather(d)


def test_every_host_the_play_targeted_must_have_answered(tmp_path):
    d = write_census(tmp_path / "c", {"a": []}, hosts=["a", "b"])
    with pytest.raises(census.CensusError, match="no answer from b"):
        census.gather(d)


@pytest.mark.parametrize(
    "hosts",
    [[], ["a", "a"], ["../a"], [".a"], ["_hosts"], "a", [1], None],
)
def test_the_host_list_is_a_list_of_distinct_plain_names(tmp_path, hosts):
    d = tmp_path / "c"
    d.mkdir()
    (d / "_hosts.json").write_text(json.dumps(hosts))
    with pytest.raises(census.CensusError, match=re.escape("_hosts.json")):
        census.gather(d)


def test_without_a_host_list_the_census_is_unreadable(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "_hosts.json").unlink()
    with pytest.raises(census.CensusError, match=re.escape("_hosts.json: cannot be read")):
        census.gather(d)


# What a host can do is print lines; the files are the controller's.  A file nobody asked for, an
# answer under another host's name, or a link are refused, never read as an answer.


def test_an_entry_that_is_no_listed_hosts_answer_is_refused(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "forged.json").write_text(
        json.dumps(
            {"host": "forged", "enabled": [], "active": [], "pairs": NOPAIRS, "listening": []}
        )
    )
    with pytest.raises(
        census.CensusError, match=re.escape("not a listed host's answer: forged.json")
    ):
        census.gather(d)


def test_an_answer_written_for_another_host_is_refused(tmp_path):
    d = write_census(tmp_path / "c", {"a": [], "b": []})
    (d / "a.json").write_text(
        json.dumps({"host": "b", "enabled": [], "active": [], "pairs": NOPAIRS, "listening": []})
    )
    with pytest.raises(census.CensusError, match=re.escape("a.json: written for b")):
        census.gather(d)


@pytest.mark.parametrize(
    "doc",
    [
        {"host": "a"},
        {"host": "a", "enabled": []},  # both queries' answers, always
        {"host": "a", "systemctl": []},  # the shape before the active units were asked for
        {
            "host": "a",
            "enabled": "hnx-x.service enabled",
            "active": [],
            "pairs": NOPAIRS,
            "listening": [],
        },
        {"host": "a", "enabled": [1], "active": [], "pairs": NOPAIRS, "listening": []},
        {"host": "a", "enabled": [], "active": [None], "pairs": NOPAIRS, "listening": []},
        {
            "host": "a",
            "enabled": [],
            "active": [],
            "pairs": NOPAIRS,
            "listening": [],
            "units": ["x"],
        },  # no finished list
        ["a"],
    ],
)
def test_an_answer_of_another_shape_is_refused(tmp_path, doc):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "a.json").write_text(json.dumps(doc))
    with pytest.raises(census.CensusError):
        census.gather(d)


def test_a_linked_answer_or_directory_is_refused(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    real = tmp_path / "elsewhere.json"
    real.write_text(
        json.dumps(
            {
                "host": "a",
                "enabled": ["hnx-x.service enabled"],
                "active": [],
                "pairs": NOPAIRS,
                "listening": [],
            }
        )
    )
    (d / "a.json").unlink()
    (d / "a.json").symlink_to(real)
    with pytest.raises(census.CensusError, match=re.escape("a.json: not a regular file")):
        census.gather(d)
    link = tmp_path / "link"
    link.symlink_to(write_census(tmp_path / "c2", {"a": []}))
    with pytest.raises(census.CensusError, match="not a directory"):
        census.gather(link)


def test_a_fifo_answer_is_refused_never_waited_on(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "a.json").unlink()
    os.mkfifo(d / "a.json")
    with pytest.raises(census.CensusError, match=re.escape("a.json: not a regular file")):
        census.gather(d)


def test_an_oversized_answer_is_refused(tmp_path):
    d = write_census(tmp_path / "c", {"a": []})
    (d / "a.json").write_bytes(b" " * (ld.MAX_BYTES + 1))
    with pytest.raises(census.CensusError, match=re.escape("a.json: over")):
        census.gather(d)


def test_too_many_lines_are_refused(tmp_path):
    lines = [f"hnx-u{i}.service enabled" for i in range(census.MAX_LINES + 1)]
    d = write_census(tmp_path / "c", {"a": lines})
    with pytest.raises(census.CensusError, match=r"over .* enabled lines"):
        census.gather(d)
    active = [f"hnx-u{i}.service loaded active running" for i in range(census.MAX_LINES + 1)]
    d = write_census(tmp_path / "c2", {"a": []}, active={"a": active})
    with pytest.raises(census.CensusError, match=r"over .* active lines"):
        census.gather(d)


# ----------------------------------------------------------------------------- notify pairs

CORE = {"problem": "UPS on battery", "recovery": "UPS back on line power"}
MODULE_PAIR = {
    "problem": "External data collector: no new sessions",
    "recovery": "External data collector: sessions arriving again",
    "module": "external-collector",
}


def _record(owner, *pairs, ago=10, **over):
    import time

    doc = {
        "schema_version": 2, "owner": owner,
        "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - ago)),
        "boot_id": BOOT, "pid": 4242, "started": STARTED, "pairs": list(pairs), **over,
    }  # fmt: skip
    return json.dumps(doc)


def test_notify_pairs_are_every_pair_some_record_holds_each_once(tmp_path):
    d = write_census(
        tmp_path / "c",
        {"hub": [], "broker-host": [], "quiet": []},
        pairs={
            "hub": {"status": _record("status", CORE, MODULE_PAIR)},
            # the same pair held by two owners (or hosts) alike is one
            "broker-host": {"broker": _record("broker", CORE)},
        },
    )
    inventory, notes = census.gather(d)
    assert inventory["notify_pairs"] == [MODULE_PAIR, CORE]
    assert "2 notify pair(s) from 2 pairs record(s)" in notes
    schema = ld._schema("platform", "module_inventory.schema.json")
    assert ld._errors(schema, inventory) == []


def test_one_title_held_with_two_recoveries_is_listed_twice_for_the_loader(tmp_path):
    other = {**CORE, "recovery": "UPS fine"}
    d = write_census(
        tmp_path / "c",
        {"a": [], "b": []},
        pairs={"a": {"status": _record("status", CORE)}, "b": {"status": _record("status", other)}},
    )
    inventory, _ = census.gather(d)
    assert inventory["notify_pairs"] == [CORE, other]


def test_one_pair_held_for_two_modules_is_listed_twice_for_the_loader(tmp_path):
    unbound = {k: v for k, v in MODULE_PAIR.items() if k != "module"}
    d = write_census(
        tmp_path / "c",
        {"a": [], "b": []},
        pairs={
            "a": {"status": _record("status", MODULE_PAIR)},
            "b": {"status": _record("status", unbound)},
        },
    )
    inventory, _ = census.gather(d)
    assert inventory["notify_pairs"] == [unbound, MODULE_PAIR]


def test_without_any_record_the_pairs_are_left_out_and_not_compared(tmp_path):
    inventory, notes = census.gather(write_census(tmp_path / "c", {"a": []}))
    assert "notify_pairs" not in inventory
    assert any("no host holds a notify pairs record that counts" in n for n in notes)


def _gather_one(tmp_path, pairs):
    d = tmp_path / "c"
    d.mkdir()
    (d / "_hosts.json").write_text('["a"]')
    (d / "a.json").write_text(
        json.dumps({"host": "a", "enabled": [], "active": [], "pairs": pairs, "listening": []})
    )
    return census.gather(d)


@pytest.mark.parametrize(
    "pairs, why",
    [
        # a broker's record counts while its process runs, however old
        (answer_pairs({"broker": _record("broker", CORE, ago=86_400)}), None),
        (
            {
                **NOPAIRS,
                "records": {
                    "broker": {"text": _record("broker", CORE), "pid_started": None},
                    "status": None,
                },
            },
            "the broker pairs record does not count (its process (pid 4242) is not running)",
        ),
        (
            {
                **NOPAIRS,
                "records": {
                    "broker": {"text": _record("broker", CORE), "pid_started": 7},
                    "status": None,
                },
            },
            "its process (pid 4242) is not running",
        ),  # the pid reused by another process
        (
            answer_pairs(
                {"broker": _record("broker", CORE)}, boot_id="00000000-0000-4000-8000-0000000000ff"
            ),
            "written before the host's last boot",
        ),
        (answer_pairs({"broker": _record("broker", CORE)}, boot_id=None), "boot cannot be told"),
        # a status pass's record counts while it is at most 900 s old
        (answer_pairs({"status": _record("status", CORE, ago=900)}), None),
        (answer_pairs({"status": _record("status", CORE, ago=901)}), "written 901s ago"),
    ],
)
def test_a_leftover_record_is_noted_and_never_read_as_running(tmp_path, pairs, why):
    inventory, notes = _gather_one(tmp_path, pairs)
    if why is None:
        assert inventory["notify_pairs"] == [CORE]
    else:
        assert "notify_pairs" not in inventory
        assert any(why in n and n.startswith("a: the ") for n in notes), notes


@pytest.mark.parametrize(
    "pairs, why",
    [
        ({"broker": None, "status": None}, "not {boot_id, now, records}"),
        ({**NOPAIRS, "extra": 1}, "not {boot_id, now, records}"),
        ({**NOPAIRS, "boot_id": 3}, "boot id is not text or null"),
        ({**NOPAIRS, "now": "soon"}, "clock is not a time"),
        ({**NOPAIRS, "now": True}, "clock is not a time"),
        ({**NOPAIRS, "records": {"broker": None}}, "not one entry per owner"),
        (
            {**NOPAIRS, "records": {"broker": None, "status": None, "relay": None}},
            "not one entry per owner",
        ),
        ({**NOPAIRS, "records": {"broker": "text", "status": None}}, "is not {text, pid_started}"),
        (
            {**NOPAIRS, "records": {"broker": {"text": 3, "pid_started": None}, "status": None}},
            "the broker pairs record is not text",
        ),
        (
            {**NOPAIRS, "records": {"broker": {"text": "{}", "pid_started": "1"}, "status": None}},
            "process start time is not a number",
        ),
        (answer_pairs({"broker": "{"}), "pairs record broker: not JSON"),
        (answer_pairs({"broker": _record("status")}), "written for another owner"),
        (
            answer_pairs({"broker": _record("broker", {"problem": "A\nB", "recovery": "B"})}),
            "not one line of text",
        ),
    ],
)
def test_a_pairs_answer_off_the_shape_makes_the_census_unreadable(tmp_path, pairs, why):
    with pytest.raises(census.CensusError, match=re.escape(why)):
        _gather_one(tmp_path, pairs)


def _check_pairs(pairs, core):
    tree, _ = ld.discover(ROOT / "modules", EXAMPLES, None)
    inventory = {"schema_version": "1.0", "units": [], "notify_pairs": pairs,
                 "not_gathered": ["rows", "mcp_servers", "agents", "tables"]}  # fmt: skip
    slots = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
    roles = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
    report = ld.check(
        tree, slots=slots, roles=roles, in_tree_roots=(ROOT / "modules", EXAMPLES),
        site=ld.load_yaml(SMALL_LAB), inventory=inventory, core=core,
    )  # fmt: skip
    _check_pairs.notes = report.notes
    return [str(p) for p in report.problems]


def test_a_pair_bound_to_no_module_must_be_one_of_the_cores_with_its_recovery():
    from homelabnext.notify.core_pairs import CORE_PAIRS

    core = ld.CoreNames(pairs=dict(CORE_PAIRS))
    assert _check_pairs([MODULE_PAIR, CORE], core) == []
    stray = {"problem": "Quietly added", "recovery": "Quietly cleared"}
    renamed = {**CORE, "recovery": "UPS fine"}
    assert _check_pairs([MODULE_PAIR, CORE, stray], core) == [
        "running: notify pair 'Quietly added' with recovery 'Quietly cleared' runs but is no "
        "module's or the core's"
    ]
    assert _check_pairs([MODULE_PAIR, renamed], core) == [
        "running: notify pair 'UPS on battery' with recovery 'UPS fine' runs but is no module's "
        "or the core's"
    ]
    assert not any("core's own notify pairs" in n for n in _check_pairs.notes)
    # without the core's pairs to compare with, an unbound pair is not judged, and the report says so
    assert _check_pairs([MODULE_PAIR, stray], ld.CoreNames()) == []
    assert (
        "the core's own notify pairs were not read: a running pair bound to no module was not judged"
        in _check_pairs.notes
    )


# ----------------------------------------------------------------------------- the loader


def test_a_gathered_inventory_compares_units_and_notes_the_kinds_it_does_not_report():
    tree, _ = ld.discover(ROOT / "modules", EXAMPLES, None)
    site = ld.load_yaml(SMALL_LAB)
    inventory = {"schema_version": "1.0", "units": ["external-collector-extra", "egress"],
                 "not_gathered": ["rows", "mcp_servers", "agents", "tables"]}  # fmt: skip
    slots = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
    roles = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
    report = ld.check(
        tree, slots=slots, roles=roles, in_tree_roots=(ROOT / "modules", EXAMPLES), site=site,
        inventory=inventory,
    )  # fmt: skip
    assert [str(p) for p in report.problems] == [
        "running: units external-collector-extra runs but external-collector declares no such entry"
    ]
    assert (
        "the inventory does not report rows, mcp_servers, agents, tables: not compared "
        "(not_gathered)" in report.notes
    )


# ----------------------------------------------------------------------------- the CLI


def test_hnx_modules_gather_writes_a_new_inventory(tmp_path, capsys):
    d = write_census(tmp_path / "c", {"a": ["hnx-egress.timer enabled"]})
    out = tmp_path / "inventory.json"
    assert mcli.main(["gather", str(d), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["units"] == ["egress"]
    assert out.stat().st_mode & 0o777 == 0o600  # the runner's alone, like the census answers
    assert "1 unit(s) written" in capsys.readouterr().out
    # never over an existing file, and an unreadable census is a usage error (2), not an inventory
    assert mcli.main(["gather", str(d), "--out", str(out)]) == 2
    (d / "a.json").unlink()
    assert mcli.main(["gather", str(d), "--out", str(tmp_path / "other.json")]) == 2
    assert "no answer from a" in capsys.readouterr().err
    assert not (tmp_path / "other.json").exists()


def overlay(tmp_path: Path, *, site=True, roles=True, services=True) -> Path:
    """An overlay whose lab is the repository's small-lab example."""
    lab = tmp_path / "overlay" / "lab"
    lab.mkdir(parents=True)
    if site:
        shutil.copy(SMALL_LAB, lab / "modules.yml")
    if roles:
        shutil.copy(ROOT / "examples" / "model_roles.json", lab / "model_roles.json")
    if services:
        shutil.copy(ROOT / "examples" / "services.yml", lab / "services.yml")
    return lab.parent


def deploy_check(capsys, ov: Path, *extra: str) -> tuple[int, dict]:
    code = mcli.main(["check", "--root", str(ROOT), "--overlay", str(ov), "--deploy", "--json",
                      *extra])  # fmt: skip
    out = capsys.readouterr().out
    return code, json.loads(out) if out else {}


@pytest.mark.parametrize("present", ["modules.lock", "modules", "dangling-modules.yml"])
def test_the_deploy_check_refuses_a_lab_that_falls_back_to_the_examples(tmp_path, capsys, present):
    """A lab that names any of its module inputs takes up modules, so every input is its own:
    a fallback is a problem.  A dangling link counts as present (it never reads as absent)."""
    ov = overlay(tmp_path, site=False, roles=False, services=False)
    lab = ov / "lab"
    if present == "modules":
        (lab / "modules").mkdir()
    elif present == "dangling-modules.yml":
        (lab / "modules.yml").symlink_to(tmp_path / "nowhere.yml")
    else:
        (lab / present).write_text("schema_version: '1.0'\n")
    code, doc = deploy_check(capsys, ov)
    assert code == 1
    site = (
        "lab/modules.yml is not a regular file"
        if present == "dangling-modules.yml"
        else "the overlay has no lab/modules.yml"
    )
    assert [p for p in doc["problems"] if p.startswith("deploy:")] == [
        "deploy: the core registry: the overlay has no lab/services.yml",
        "deploy: the role table: the overlay has no lab/model_roles.json",
        f"deploy: the site selection: {site}",
    ]
    assert not any("empty selection" in n for n in doc["notes"])


def test_a_lab_that_takes_up_no_modules_is_checked_as_an_empty_selection(tmp_path, capsys):
    """None of lab/modules.yml, lab/modules/ and lab/modules.lock: the deploy's check still runs,
    over an empty selection; what only judges selected modules (the role table, the registry,
    the MCP catalog, the keyring) is a note, and the gathered census is still compared."""
    ov = overlay(tmp_path, site=False, roles=False, services=False)
    d = write_census(tmp_path / "c", {"a": ["hnx-egress.timer enabled"]})
    inv = tmp_path / "inventory.json"
    assert mcli.main(["gather", str(d), "--out", str(inv)]) == 0
    capsys.readouterr()
    for extra in ((), ("--running", str(inv))):
        code, doc = deploy_check(capsys, ov, *extra)
        assert code == 0, doc
        assert doc["problems"] == []
        assert any("an empty selection" in n for n in doc["notes"])
        assert any("the overlay has no keyring" in n for n in doc["notes"])
    # with --running the runtime half ran: the kinds it does not report are noted
    assert any("not compared (not_gathered)" in n for n in doc["notes"])


def test_an_empty_selection_judges_every_running_unit_of_a_module():
    """With an empty selection no module is selected, a core module included: a running unit of
    any module is one the site does not select; a unit bound to no module is the core's."""
    tree, _ = ld.discover(ROOT / "modules", EXAMPLES, None)
    slots = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
    roles = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
    inventory = {"schema_version": "1.0", "units": ["egress", "external-collector-pull"],
                 "not_gathered": ["rows", "mcp_servers", "agents", "tables"]}  # fmt: skip
    report = ld.check(
        tree, slots=slots, roles=roles, in_tree_roots=(ROOT / "modules", EXAMPLES),
        inventory=inventory, empty_selection=True,
    )  # fmt: skip
    running = [str(p) for p in report.problems if p.where == "running"]
    assert running == [
        "running: units external-collector-pull runs for external-collector, which the site does "
        "not select"
    ]
    assert "an empty selection: the site selects no module" in report.notes


def test_gathered_agents_are_judged_like_any_running_name(tmp_path):
    """A broker's answer reaches the loader: an agent of a module the site does not select is a
    problem, and agents is no longer noted as not compared."""
    d = write_census(tmp_path / "c", {"agent-core": []})
    _with_agents(d, "agent-core", ["external-collector-analyst"])
    inventory, _ = census.gather(d)
    tree, _ = ld.discover(ROOT / "modules", EXAMPLES, None)
    slots = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
    roles = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
    report = ld.check(
        tree, slots=slots, roles=roles, in_tree_roots=(ROOT / "modules", EXAMPLES),
        inventory=inventory, empty_selection=True,
    )  # fmt: skip
    running = [str(p) for p in report.problems if p.where == "running"]
    assert running == [
        "running: agents external-collector-analyst runs for external-collector, which the site "
        "does not select"
    ]
    assert not any("agents" in n and "not compared" in n for n in report.notes)


def test_gathered_tables_are_judged_and_the_cores_namespace_holds_only_its_own(tmp_path):
    """A catalog's answer reaches the loader: a module's table the site does not select is a
    problem, a core OCSF table is the core's, a table in the core's namespace that is no core table
    is a problem, and a table in the lab's own namespace is not judged."""
    d = write_census(tmp_path / "c", {"lake": []})
    found = ["external_collector.sessions", "ocsf.authentication", "ocsf.planted", "lab_own.x"]
    _with_tables(d, "lake", {"tables": found, "left_out": 0})
    inventory, _ = census.gather(d)
    tree, _ = ld.discover(ROOT / "modules", EXAMPLES, None)
    slots = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
    roles = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
    core, problems = ld.core_names(
        None, tables=["authentication", "dns_activity"], table_namespace="ocsf"
    )
    assert problems == []

    def running(core):
        report = ld.check(
            tree, slots=slots, roles=roles, in_tree_roots=(ROOT / "modules", EXAMPLES),
            inventory=inventory, empty_selection=True, core=core,
        )  # fmt: skip
        return [str(p) for p in report.problems if p.where == "running"], report.notes

    problems, notes = running(core)
    assert problems == [
        "running: tables table:external_collector.sessions runs for external-collector, which "
        "the site does not select",
        "running: tables table:ocsf.planted is in the core's namespace but is no core table",
    ]
    assert not any("tables" in n and "not compared" in n for n in notes)
    # an empty selection declares no lab namespaces: lab_own.x is not judged, and the check says so
    assert any(n.startswith("the lab's own table namespaces are not declared") for n in notes)
    # without the core's tables nothing in its namespace is judged, and the check says so
    problems, notes = running(None)
    assert problems == [
        "running: tables table:external_collector.sessions runs for external-collector, which "
        "the site does not select"
    ]
    assert "the core's OCSF tables were not read: a table bound to no module was not judged" in (
        notes
    )


def test_the_deploy_check_refuses_problems_in_the_lab(tmp_path, capsys):
    """The small lab's modules live under examples/, which a deploy never loads: its selection
    then names modules that do not exist, and the deploy is refused."""
    code, doc = deploy_check(capsys, overlay(tmp_path))
    assert code == 1
    assert doc["problems"] and not any(p.startswith("deploy:") for p in doc["problems"])
    # no review policy: not a problem of its own (the supply chain refuses every fetched module
    # without one, so a lab of in-tree modules needs none), but the deploy says so
    assert any("no review policy" in n and "every fetched module is refused" in n
               for n in doc["notes"])  # fmt: skip


def test_the_deploy_check_needs_an_overlay_and_never_loads_the_fixtures(tmp_path, capsys):
    assert mcli.main(["check", "--root", str(ROOT), "--deploy"]) == 2
    assert "--deploy needs --overlay" in capsys.readouterr().err
    ov = overlay(tmp_path)
    assert mcli.main(["check", "--root", str(ROOT), "--overlay", str(ov), "--deploy",
                      "--examples"]) == 2  # fmt: skip
    assert "--deploy refuses --examples" in capsys.readouterr().err


def test_with_every_input_the_overlays_own_the_deploy_check_is_the_plain_check(tmp_path, capsys):
    """--deploy adds no rule of its own once nothing falls back: the same problems as the check
    make gates runs, here over a lab whose selection names modules it does not ship (no public
    module tree exists yet, so a lab brings its own); the gathered inventory passes its schema."""
    ov = overlay(tmp_path)
    d = write_census(tmp_path / "c", {"a": ["hnx-egress.timer enabled"]})
    inv = tmp_path / "inventory.json"
    assert mcli.main(["gather", str(d), "--out", str(inv)]) == 0
    capsys.readouterr()
    code, deploy = deploy_check(capsys, ov, "--running", str(inv))
    plain = mcli.main(["check", "--root", str(ROOT), "--overlay", str(ov), "--running", str(inv),
                       "--json"])  # fmt: skip
    doc = json.loads(capsys.readouterr().out)
    assert code == plain == 1
    assert deploy["problems"] == doc["problems"] and deploy["problems"]
    assert not any(p.startswith(("deploy:", "running: schema")) for p in deploy["problems"])
