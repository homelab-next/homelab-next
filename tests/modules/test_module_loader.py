# SPDX-License-Identifier: Apache-2.0
"""The module loader (ADR-0027 follow-up 9; docs/modules.md, "What the loader checks"): it
discovers the manifests, refuses what cannot load, runs every rule with every input, and checks
what runs against what is declared, saying what it did not check.  Every planted input it reads
is a named problem or a usage error, never a hang or an internal error."""

from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import cli as mcli
from homelabnext.modules import loader as ld

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "modules"
SITES = {p.stem: ld.load_yaml(p) for p in sorted((EXAMPLES / "sites").glob("*.yml"))}
SLOTS = ld.load_yaml(EXAMPLES / "slots.yml")["slots"]
ROLES = json.loads((ROOT / "examples" / "model_roles.json").read_text())["roles"]
CORE, _ = ld.core_names(ld.load_yaml(ROOT / "examples" / "services.yml"))
INVENTORY = ld.load_yaml(ROOT / "schemas/platform/examples/module_inventory.small-lab.yml")
NO_INVENTORY = "no inventory of what runs: the runtime half of the two-way check did not run"
NO_SITE = "no site selection: the site rules, the supply chain and the runtime check did not run"


def check(tree, roots=(EXAMPLES,), **kw):
    return ld.check(tree, slots=SLOTS, roles=ROLES, in_tree_roots=roots, core=CORE, **kw)


def examples(tmp_path=None, without=()):
    """The example modules, or a copy of them (to plant a defect) without some ids."""
    if tmp_path is None:
        return ld.discover(fixtures=EXAMPLES)
    root = tmp_path / "fixtures"
    shutil.copytree(EXAMPLES, root, ignore=shutil.ignore_patterns(*without))
    return ld.discover(fixtures=root)


def messages(report_or_list):
    items = report_or_list.problems if hasattr(report_or_list, "problems") else report_or_list
    return [str(p) for p in items]


def overlay_module(tmp_path, mid, edit=None):
    """A copy of an example module in an overlay, with the roles/ and playbooks/ files it names
    (an overlay ships them: the fixture exemption is not its)."""
    overlay = tmp_path / "overlay"
    d = overlay / "lab" / "modules" / mid
    shutil.copytree(EXAMPLES / mid, d)
    doc = ld.load_yaml(d / "module.yml")
    for _, rel in ld.contributed_files(doc):
        if rel.startswith(ld.FIXTURE_UNSHIPPED) and not (d / rel).exists():
            (d / rel).parent.mkdir(parents=True, exist_ok=True)
            (d / rel).write_text("- {}\n")
    if edit:
        edit(doc)
        (d / "module.yml").write_text(yaml.safe_dump(doc))
    return overlay, d


# ----------------------------------------------------------------------------- the example lab


@pytest.mark.parametrize("profile", sorted(SITES))
def test_the_example_lab_loads_clean_for_every_profile(profile):
    tree, found = examples()
    assert found == []
    report = check(tree, site=SITES[profile])
    assert report.problems == []
    assert report.notes[-1] == NO_INVENTORY


def test_what_runs_on_the_small_lab_matches_what_it_declares():
    tree, _ = examples()
    report = check(tree, site=SITES["small-lab"], inventory=INVENTORY)
    assert report.problems == [] and NO_INVENTORY not in report.notes


def test_without_a_site_the_site_half_is_named_as_not_checked():
    tree, _ = examples()
    report = check(tree)
    assert report.problems == [] and report.notes[-1] == NO_SITE


def test_the_notes_say_which_kinds_are_not_validated_and_where_the_fixture_exemption_applied():
    tree, _ = examples()
    notes = check(tree).notes
    unvalidated = [n for n in notes if n.startswith("contributed files checked for containment")]
    assert unvalidated == [
        "contributed files checked for containment only (no record type is validated): "
        "agents, conformance, docs, invariants, roles"
    ]
    assert any(n.startswith("the fixture root's modules may omit roles/") for n in notes)


# ----------------------------------------------------------------------------- what runs


def test_a_running_name_must_be_declared_selected_and_every_declared_one_must_run():
    tree, _ = examples()
    inv = copy.deepcopy(INVENTORY)
    inv["agents"].remove("core-staff-scorecard")  # declared but not running
    inv["units"].append("external-collector-extra")  # runs, undeclared
    inv["rows"].append("publishing-site")  # runs for a module the site does not select
    inv["units"].append("lake-compact")  # bound to no module id: the core's, not judged here
    inv["tables"].append("table:external_collector.extra")
    got = messages(check(tree, site=SITES["small-lab"], inventory=inv))
    assert got == [
        "running: agents core-staff-scorecard (core-staff) is declared but not running",
        "running: rows publishing-site runs for publishing, which the site does not select",
        "running: tables table:external_collector.extra runs but external-collector "
        "declares no such entry",
        "running: units external-collector-extra runs but external-collector declares no such "
        "entry",
    ]


LAB_NS_NOTE = (
    "the lab's own table namespaces are not declared (lab_table_namespaces): a table in a "
    "namespace that is no module's or the core's was not judged"
)


def _lab_tables(namespaces=None):
    """The small lab's site (with ``lab_table_namespaces`` when given) and its inventory with
    tables in the lab's, the core's and a stray namespace."""
    site = copy.deepcopy(SITES["small-lab"])
    if namespaces is not None:
        site["lab_table_namespaces"] = [
            {"namespace": n, "why": f"the lab's own, entry {i}"} for i, n in enumerate(namespaces)
        ]
    inv = copy.deepcopy(INVENTORY)
    inv["tables"] += ["table:archive.old_sessions", "table:stray.x", "table:ocsf.authentication"]
    return site, inv


def test_with_the_lab_s_namespaces_declared_a_table_in_any_other_unbound_one_is_a_problem():
    tree, _ = examples()
    site, inv = _lab_tables(["archive"])
    report = check(tree, site=site, inventory=inv)
    assert messages(report) == [
        "running: tables table:stray.x runs in namespace stray, which is no module's, the "
        "core's or the lab's"
    ]
    assert LAB_NS_NOTE not in report.notes
    # an empty list declares that the lab keeps no namespace of its own
    site, inv = _lab_tables([])
    assert messages(check(tree, site=site, inventory=inv)) == [
        "running: tables table:archive.old_sessions runs in namespace archive, which is no "
        "module's, the core's or the lab's",
        "running: tables table:stray.x runs in namespace stray, which is no module's, the "
        "core's or the lab's",
    ]


def test_without_the_lab_s_namespaces_an_unbound_table_is_not_judged_and_the_check_says_so():
    tree, _ = examples()
    site, inv = _lab_tables()
    report = check(tree, site=site, inventory=inv)
    assert report.problems == [] and LAB_NS_NOTE in report.notes
    # tables not gathered: nothing to judge, so no note about the lab's namespaces
    inv["not_gathered"] = [*inv.get("not_gathered", []), "tables"]
    inv.pop("tables")
    assert LAB_NS_NOTE not in check(tree, site=site, inventory=inv).notes


@pytest.mark.parametrize(
    ("namespaces", "message"),
    [
        (["ocsf"], "lab_table_namespaces: ocsf is the core's namespace, never the lab's"),
        (
            ["external_collector"],
            "lab_table_namespaces: external_collector is module external-collector's "
            "namespace, never the lab's",
        ),
        (["archive", "archive"], "lab_table_namespaces: archive is listed twice"),
    ],
)
def test_a_lab_namespace_that_is_a_module_s_the_core_s_or_listed_twice_is_refused(
    namespaces, message
):
    tree, _ = examples()
    site, _ = _lab_tables(namespaces)
    assert messages(check(tree, site=site)) == [f"site: {message}"]


def _listening(*hosts):
    """The small lab's inventory with the hosts' listening sockets, its rows left ungathered (as
    a census leaves them): ``hosts`` are ``(census host, sockets)``."""
    inv = {k: v for k, v in INVENTORY.items() if k != "rows"}
    inv["not_gathered"] = ["rows"]
    inv["listening"] = [{"host": h, "sockets": list(s)} for h, s in hosts]
    return inv


def test_a_selected_modules_row_is_judged_by_what_its_placed_host_listens_on():
    """Derived, one way: the receiver (feature row, host role receiver) and the samples store (a
    provider's row under its instance, host role store) are both placed on the small lab's data
    host, which the census knows by its full name; each must listen on its row's port."""
    tree, _ = examples()
    site = SITES["small-lab"]
    clean = check(
        tree,
        site=site,
        inventory=_listening(
            ("data.example.internal", ["tcp/8443", "tcp/9000"]), ("core", ["udp/53"])
        ),
    )
    assert clean.problems == []
    assert not any(n.startswith("service rows not judged") for n in clean.notes)
    got = messages(
        check(
            tree,
            site=site,
            inventory=_listening(
                ("data.example.internal", ["tcp/8443", "udp/9000"]), ("core", ["tcp/9000"])
            ),
        )
    )
    # a UDP socket is not the HTTPS row's, and the core host's TCP 9000 is not the data host's
    assert got == [
        "running: rows samples (example-object-store) is declared on data but "
        "data.example.internal listens on no tcp/9000"
    ]


def test_a_row_whose_placed_host_the_census_cannot_name_is_noted_not_judged():
    tree, _ = examples()
    site = SITES["small-lab"]
    for hosts, why in (
        ((("core", []),), "no census host has that name"),
        ((("data.a.example", []), ("data.b.example", [])), "two census hosts share that name"),
    ):
        report = check(tree, site=site, inventory=_listening(*hosts))
        assert report.problems == []
        note = next(n for n in report.notes if n.startswith("service rows not judged"))
        assert f"samples (example-object-store) on data: {why}" in note


def test_each_provider_entry_is_judged_on_its_own_placed_host():
    """Two instances of one provider, placed on different hosts: each instance's row is judged on
    the host its own entry places it on, never on another entry's."""
    tree, _ = examples()
    site = copy.deepcopy(SITES["small-lab"])
    site["slots"]["object-store"].append(
        {"provider": "example-object-store", "instance": "archive", "placement": {"store": "core"}}
    )
    hosts = (("data.example.internal", ["tcp/8443", "tcp/9000"]), ("core", ["udp/53"]))
    assert messages(check(tree, site=site, inventory=_listening(*hosts))) == [
        "running: rows archive (example-object-store) is declared on core but core listens on "
        "no tcp/9000"
    ]
    hosts = (("data.example.internal", ["tcp/8443"]), ("core", ["udp/53", "tcp/9000"]))
    assert messages(check(tree, site=site, inventory=_listening(*hosts))) == [
        "running: rows samples (example-object-store) is declared on data but "
        "data.example.internal listens on no tcp/9000"
    ]


def test_a_socket_bound_only_to_loopback_answers_no_other_host():
    tree, _ = examples()
    hosts = (("data.example.internal", ["tcp/8443", "tcp/9000@lo"]), ("core", ["udp/53"]))
    assert messages(check(tree, site=SITES["small-lab"], inventory=_listening(*hosts))) == [
        "running: rows samples (example-object-store) is declared on data but "
        "data.example.internal listens on no tcp/9000 (only on loopback: tcp/9000)"
    ]
    # bound to loopback and to every address is the every-address socket's
    hosts = (("data.example.internal", ["tcp/8443", "tcp/9000", "tcp/9000@lo"]), ("core", []))
    assert check(tree, site=SITES["small-lab"], inventory=_listening(*hosts)).problems == []


def test_a_census_host_name_matches_whatever_its_case():
    tree, _ = examples()
    hosts = (("Data.Example.Internal", ["tcp/8443", "tcp/9000"]), ("CORE", ["udp/53"]))
    report = check(tree, site=SITES["small-lab"], inventory=_listening(*hosts))
    assert report.problems == []
    assert not any(n.startswith("service rows not judged") for n in report.notes)


PAIR = {
    "problem": "External data collector: no new sessions",
    "recovery": "External data collector: sessions arriving again",
    "module": "external-collector",
}


def _pairs(*entries):
    inv = copy.deepcopy(INVENTORY)
    inv["notify_pairs"] = list(entries)
    return inv


def test_a_running_pair_must_be_declared_by_a_selected_module_with_the_same_recovery():
    tree, _ = examples()
    gate = {
        "problem": "Publishing: an item was blocked by the gate",
        "recovery": "Publishing: the gate passes every item again",
        "module": "publishing",
    }
    got = messages(
        check(
            tree,
            site=SITES["small-lab"],
            inventory=_pairs(
                gate,  # declared, but by a module the site does not select
                {**PAIR, "problem": "External data collector: stalled"},  # not declared
                {"problem": "Lake: compaction late", "recovery": "Lake: compacted"},  # the core's
                {"problem": "Orphan: down", "recovery": "Orphan: up", "module": "no-such-module"},
            ),
        )
    )
    assert got == [
        "running: notify pair 'External data collector: no new sessions' (external-collector) "
        "is declared but not running",
        "running: notify pair 'External data collector: stalled' runs but external-collector "
        "declares no such pair",
        "running: notify pair 'Orphan: down' runs for no-such-module, which is no module",
        "running: notify pair 'Publishing: an item was blocked by the gate' runs for publishing, "
        "which the site does not select",
    ]


def test_a_running_pair_is_compared_by_both_titles_and_held_once():
    tree, _ = examples()
    other = {**PAIR, "recovery": "External data collector: back"}
    got = messages(check(tree, site=SITES["small-lab"], inventory=_pairs(other, PAIR)))
    assert got == [
        "running: notify pair 'External data collector: no new sessions' runs twice (the "
        "notifier holds one per title)",
        "running: notify pair 'External data collector: no new sessions' runs with recovery "
        "'External data collector: back' but external-collector declares "
        "'External data collector: sessions arriving again'",
    ]


def test_without_notify_pairs_in_the_inventory_the_pairs_are_named_as_not_compared():
    tree, _ = examples()
    inv = {k: v for k, v in INVENTORY.items() if k != "notify_pairs"}
    report = check(tree, site=SITES["small-lab"], inventory=inv)
    assert report.problems == []
    assert "the inventory names no notify_pairs: the recovery pairs were not compared" in (
        report.notes
    )
    assert "notify_pairs" in INVENTORY  # the example names them, so its check compares them
    assert not [
        n
        for n in check(tree, site=SITES["small-lab"], inventory=INVENTORY).notes
        if "notify_pairs" in n
    ]


def test_a_problem_title_is_declared_once_across_the_selected_modules():
    tree, _ = examples()
    m = tree.mods["publishing"]
    m["contributes"]["notify_pairs"] = [
        {"problem": PAIR["problem"], "recovery": "Publishing: fine"},
        {"problem": "Publishing: same", "recovery": "Publishing: same"},
    ]
    got = [
        str(p)
        for p in ld.pair_problems({n: tree.mods[n] for n in ("external-collector", "publishing")})
    ]
    assert got == [
        "publishing: notify pair 'External data collector: no new sessions' is also declared "
        "by external-collector",
        "publishing: notify pair 'Publishing: same': the recovery is its own title",
    ]


def test_a_recovery_title_names_one_thing():
    """A recovery is not another pair's problem or another pair's recovery: a recovery page
    always says which alert cleared."""
    tree, _ = examples()
    m = tree.mods["publishing"]
    m["contributes"]["notify_pairs"] = [
        {"problem": "Publishing: blocked", "recovery": PAIR["problem"]},
        {"problem": "Publishing: stale", "recovery": PAIR["recovery"]},
    ]
    got = [
        str(p)
        for p in ld.pair_problems({n: tree.mods[n] for n in ("external-collector", "publishing")})
    ]
    assert got == [
        "publishing: notify pair 'Publishing: blocked': the recovery 'External data collector: "
        "no new sessions' is a problem title",
        "publishing: notify pair 'Publishing: stale': the recovery 'External data collector: "
        "sessions arriving again' is also external-collector's for 'External data collector: "
        "no new sessions'",
    ]


def test_a_running_pair_with_a_control_character_is_refused_by_the_schema():
    tree, _ = examples()
    inv = _pairs({**PAIR, "problem": "External data collector:\nno new sessions"})
    got = messages(check(tree, site=SITES["small-lab"], inventory=inv))
    assert got and all(m.startswith("running: schema: ") for m in got)


def test_an_inventory_that_breaks_its_schema_is_refused_not_judged():
    tree, _ = examples()
    inv = {k: v for k, v in INVENTORY.items() if k != "tables"}
    got = messages(check(tree, site=SITES["small-lab"], inventory=inv))
    assert got and all(m.startswith("running: schema: ") for m in got)


# ----------------------------------------------------------------------------- discovery


def test_an_overlay_module_that_shadows_a_shipped_id_is_refused(tmp_path):
    overlay, _ = overlay_module(tmp_path, "publishing")
    tree, found = ld.discover(fixtures=EXAMPLES, overlay=overlay)
    assert messages(found) == [
        "publishing: an overlay module shadows the fixture module of that id"
    ]
    assert tree.dirs["publishing"] == EXAMPLES / "publishing"


def test_a_module_under_both_the_public_and_the_fixture_roots_is_refused(tmp_path):
    public = tmp_path / "modules"
    shutil.copytree(EXAMPLES / "publishing", public / "publishing")
    tree, found = ld.discover(public=public, fixtures=EXAMPLES)
    assert "publishing: defined under both the public and fixture roots" in messages(found)
    assert tree.origin["publishing"] == "public"


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("id: other\n", "the manifest's id 'other' is not its directory"),
        ("id: [\n", "module.yml: not valid YAML (ParserError"),
        ("- a list\n", "module.yml is not a mapping"),
        ("id: x\nid: x\n", "module.yml: not valid YAML (ConstructorError: duplicate key 'id')"),
        ("[" * 20000 + "]" * 20000 + "\n", "module.yml: nested too deeply"),
        ("a: &a [x]\nb: *a\n", "module.yml: not valid YAML (ComposerError: an alias (refused))"),
        (b"id: \xff\n", "module.yml: not UTF-8"),
    ],
)
def test_a_manifest_that_cannot_be_read_as_its_own_id_is_refused(tmp_path, body, message):
    d = tmp_path / "lab" / "modules" / "x"
    d.mkdir(parents=True)
    (d / "module.yml").write_bytes(body if isinstance(body, bytes) else body.encode())
    tree, found = ld.discover(overlay=tmp_path)
    assert len(found) == 1 and str(found[0]).startswith(f"x: {message}"), found
    assert tree.mods == {}


def test_a_reserved_id_is_refused(tmp_path):
    d = tmp_path / "lab" / "modules" / "core"
    d.mkdir(parents=True)
    (d / "module.yml").write_text("id: core\n")
    assert messages(ld.discover(overlay=tmp_path)[1]) == ["core: a reserved id"]


def test_a_symbolic_link_module_directory_or_manifest_is_refused(tmp_path):
    mods = tmp_path / "lab" / "modules"
    mods.mkdir(parents=True)
    (mods / "linked").symlink_to(EXAMPLES / "publishing")
    real = mods / "x"
    real.mkdir()
    (tmp_path / "elsewhere.yml").write_text("id: x\n")
    (real / "module.yml").symlink_to(tmp_path / "elsewhere.yml")
    tree, found = ld.discover(overlay=tmp_path)
    assert messages(found) == [
        "linked: a symbolic-link module directory or module.yml",
        "x: a symbolic-link module directory or module.yml",
    ]
    assert tree.mods == {}


def test_a_hard_linked_module_yml_is_refused(tmp_path):
    d = tmp_path / "lab" / "modules" / "publishing"
    shutil.copytree(EXAMPLES / "publishing", d)
    (d / "module.yml").unlink()
    os.link(_alias(tmp_path), d / "module.yml")
    tree, found = ld.discover(overlay=tmp_path)
    assert messages(found) == [
        "publishing: module.yml: a hard link (it may alias a file outside the module)"
    ]
    assert tree.mods == {}


def _alias(tmp_path):
    outside = tmp_path / "alias.yml"
    outside.write_bytes((EXAMPLES / "publishing" / "module.yml").read_bytes())
    return outside


def test_an_untrusted_name_is_printed_escaped():
    p = ld.Problem("::error::x\n\x1b[31m", "y\x1b[0m\nz")
    assert str(p) == "'::error::x\\n\\x1b[31m': y\\x1b[0m\\nz"
    assert str(ld.Problem("external-collector", "ok")) == "external-collector: ok"


# ----------------------------------------------------------------------------- reading


def test_a_fifo_a_device_or_an_oversized_file_is_refused_never_waited_on(tmp_path, monkeypatch):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ld.Unreadable, match="not a regular file"):
        ld.read_bytes(fifo)  # opened without blocking: no writer, no hang
    with pytest.raises(ld.Unreadable, match="not a regular file"):
        ld.read_bytes("/dev/zero")
    big = tmp_path / "big.yml"
    big.write_text("a: 1\n" * 100)
    monkeypatch.setattr(ld, "MAX_BYTES", 10)
    with pytest.raises(ld.Unreadable, match="over 10 bytes"):
        ld.load_yaml(big)
    with pytest.raises(ld.Unreadable, match="over 10 bytes"):
        ld.load_json(big)


def test_a_deep_or_bad_json_file_is_refused(tmp_path):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 100000 + "]" * 100000)
    with pytest.raises(ld.Unreadable, match="nested too deeply"):
        ld.load_json(deep)
    deep.write_text("{")
    with pytest.raises(ld.Unreadable, match="not valid JSON"):
        ld.load_json(deep)


def test_a_yaml_alias_bomb_is_refused_before_it_expands(tmp_path):
    lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x]"]
    lines += [f"a{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 9)}]" for i in range(1, 12)]
    bomb = tmp_path / "bomb.yml"
    bomb.write_text("\n".join(lines) + "\n")
    with pytest.raises(ld.Unreadable, match="an alias"):
        ld.load_yaml(bomb)


def test_each_contributed_file_is_read_and_parsed_once_per_run(tmp_path, monkeypatch):
    tree, _ = examples()
    reads = []
    real = ld.read_bytes
    monkeypatch.setattr(ld, "read_bytes", lambda p, **k: reads.append(Path(p)) or real(p, **k))
    check(tree, site=SITES["small-lab"], inventory=INVENTORY)
    assert reads and len(reads) == len(set(reads))  # the rules read some files more than once


def test_a_module_whose_files_add_up_past_its_budget_is_refused(monkeypatch):
    tree, _ = examples()
    got = messages(check(tree, budget=ld.Budget(per_module=200)))
    assert any(m.endswith("its files add up to over 200 bytes") for m in got), got


def test_a_run_whose_files_add_up_past_its_budget_is_refused(tmp_path):
    budget = ld.Budget(per_run=2000)
    _, found = ld.discover(fixtures=EXAMPLES, budget=budget)
    assert any("the run's files add up to over 2000 bytes" in m for m in messages(found))


def test_a_sigma_rule_is_validated_from_the_text_the_loader_read(monkeypatch):
    import homelabnext.detections.sigma as sigma

    seen = []
    real = sigma.load_rule
    monkeypatch.setattr(
        sigma, "load_rule", lambda p, text=None: seen.append(text) or real(p, text=text)
    )
    tree, _ = examples()
    check(tree)
    assert seen and all(isinstance(t, str) for t in seen)  # never re-opened by the rule loader


# ----------------------------------------------------------------------------- per manifest


def test_a_manifest_is_held_to_its_schema_before_any_rule_reads_it(tmp_path):
    tree, _ = examples(tmp_path)
    tree.mods["publishing"] = {**tree.mods["publishing"], "requires": "nothing"}
    got = messages(check(tree, (tmp_path / "fixtures",)))
    # the invalid manifest reaches no rule (it would crash one); the others are judged without it
    assert "publishing: schema: requires: is not of type 'object'" in got
    assert not [m for m in got if m.startswith("publishing: ") and ": schema: " not in m]


def _service_file(tree, mid="external-collector"):
    return tree.dirs[mid], tree.mods[mid]["contributes"]["services"][0]["file"]


def test_a_contributed_file_must_be_a_regular_contained_unlinked_file(tmp_path):
    tree, _ = examples(tmp_path)
    d, target = _service_file(tree)
    fx = (tmp_path / "fixtures",)
    outside = tmp_path / "outside.yml"
    outside.write_text((d / target).read_text())
    (d / target).unlink()
    (d / target).symlink_to(outside)
    assert f"external-collector: {target}: reached through a symbolic link" in messages(
        check(tree, fx)
    )
    (d / target).unlink()
    os.link(outside, d / target)  # a hard link to a file outside the module
    assert (
        f"external-collector: {target}: a hard link (it may alias a file outside the module)"
        in messages(check(tree, fx))
    )
    (d / target).unlink()
    os.mkfifo(d / target)
    assert f"external-collector: {target}: not a regular file in the module" in messages(
        check(tree, fx)
    )
    (d / target).unlink()
    assert f"external-collector: {target}: not a regular file in the module" in messages(
        check(tree, fx)
    )


def test_a_file_that_fails_containment_is_never_read(tmp_path, monkeypatch):
    tree, _ = examples(tmp_path)
    d, target = _service_file(tree)
    (d / target).unlink()
    (d / target).symlink_to("/etc/passwd")
    read = []
    real = ld.load_yaml
    monkeypatch.setattr(ld, "load_yaml", lambda p, **k: read.append(Path(p)) or real(p, **k))
    check(tree, (tmp_path / "fixtures",))
    assert d / target not in read


def test_an_oversized_contributed_record_is_a_named_problem(tmp_path, monkeypatch):
    tree, _ = examples(tmp_path)
    d, target = _service_file(tree)
    monkeypatch.setattr(ld, "MAX_BYTES", (d / target).stat().st_size - 1)
    got = messages(check(tree, (tmp_path / "fixtures",)))
    assert any(m.startswith(f"external-collector: {target}: over ") for m in got), got


@pytest.mark.parametrize(
    "body", ["services: [a]\n", "services:\n", "services: {foo: bar}\n", "- a\n"]
)
def test_a_malformed_service_file_is_a_named_problem_not_a_crash(tmp_path, body):
    tree, _ = examples(tmp_path)
    d, target = _service_file(tree)
    (d / target).write_text(body)
    got = messages(check(tree, (tmp_path / "fixtures",), site=SITES["small-lab"]))
    assert f"external-collector: {target}: not a services mapping of row name to row" in got


def test_a_malformed_unit_spec_is_a_named_problem_not_a_crash(tmp_path):
    tree, _ = examples(tmp_path)
    d = tree.dirs["publishing"]
    target = tree.mods["publishing"]["contributes"]["scheduler_jobs"][0]["file"]
    (d / target).write_text("name: x\n")
    got = messages(check(tree, (tmp_path / "fixtures",)))
    assert f"publishing: {target}: not a list of unit specs" in got


def test_a_contributed_record_is_validated_against_its_record_type(tmp_path):
    tree, _ = examples(tmp_path)
    d = tree.dirs["external-collector"]
    rec = tree.mods["external-collector"]["contributes"]["mcp_servers"][0]["file"]
    doc = ld.load_yaml(d / rec)
    (d / rec).write_text(yaml.safe_dump({**doc, "id": "external-collector-other"}))
    got = messages(check(tree, (tmp_path / "fixtures",)))
    assert f"external-collector: {rec}: an MCP record's id is its file name" in got


def test_a_contributed_sigma_rule_is_validated(tmp_path):
    tree, _ = examples(tmp_path)
    mid = next(n for n, m in tree.mods.items() if m.get("contributes", {}).get("detections"))
    d, rel = tree.dirs[mid], tree.mods[mid]["contributes"]["detections"][0]["file"]
    doc = ld.load_yaml(d / rel)
    del doc["level"]
    (d / rel).write_text(yaml.safe_dump(doc))
    got = messages(check(tree, (tmp_path / "fixtures",)))
    assert f"{mid}: {rel}: not a Sigma rule (missing required key 'level')" in got


def test_the_roles_and_playbooks_exemption_is_the_fixture_root_s_only(tmp_path):
    tree, _ = examples(tmp_path, without=("publishing",))
    overlay = tmp_path / "overlay"
    shutil.copytree(EXAMPLES / "publishing", overlay / "lab" / "modules" / "publishing")
    tree, found = ld.discover(fixtures=tmp_path / "fixtures", overlay=overlay)
    assert found == []
    got = messages(check(tree, (tmp_path / "fixtures",)))
    roles = [r for _, r in ld.contributed_files(tree.mods["publishing"]) if r.startswith("roles/")]
    assert roles and all(
        f"publishing: {r}: not a regular file in the module" in got for r in roles
    ), got


# ----------------------------------------------------------------------------- the core's names


def test_a_module_id_or_feature_row_that_is_a_core_name_is_refused():
    tree, _ = examples()
    core = ld.CoreNames(rows={"publishing": "x", "external-collector-receiver": "x"})
    got = messages(ld.check(tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=core))
    assert got == [
        "external-collector: service row external-collector-receiver is a core service name",
        "publishing: the module id is a core service name",
    ]


@pytest.mark.parametrize(
    "core, message",
    [
        (
            ld.CoreNames(mcp_servers=frozenset({"external-collector-probe"})),
            "external-collector: MCP server external-collector-probe is a core MCP server id",
        ),
        (
            ld.CoreNames(agents=frozenset({"external-collector-analyst"})),
            "external-collector: agent external-collector-analyst is a core agent key",
        ),
        (
            ld.CoreNames(tables=frozenset({"table:external_collector.sessions"})),
            "external-collector: table table:external_collector.sessions is a core table",
        ),
        (
            ld.CoreNames(table_namespace="external_collector"),
            "external-collector: the module's table namespace is the core's (external_collector)",
        ),
    ],
)
def test_a_module_mcp_id_agent_key_table_or_namespace_that_is_the_core_s_is_refused(core, message):
    tree, _ = examples()
    got = messages(ld.check(tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=core))
    assert got == [message]


def test_the_core_s_names_are_read_from_the_sources_it_already_has():
    core, problems = ld.core_names(
        {"services": {"lake-query": {"capability": "cap:lake-query"}}},
        mcp=[
            ("lake.yml", {"id": "lake"}),
            ("bad.yml", ["x"]),
            ("anon.yml", {"id": 3}),
            ("stem.yml", {"name": "no id: the file's stem"}),
            ("other.yml", {"id": "elsewhere"}),
        ],
        keyring={
            "principals": [
                {"kind": "agent", "principal": "profile:reader"},
                {"kind": "human", "principal": "sso:approver-one"},
                {"kind": "network", "principal": "zone:data"},
                {"kind": "agent"},
            ]
        },
        tables=["authentication"],
        table_namespace="ocsf",
    )
    assert core.rows == {"lake-query": "cap:lake-query"}
    # the id as the catalog's own loader takes it: the record's, else the file's stem
    assert core.mcp_servers == {"lake", "stem", "elsewhere"} and core.agents == {"reader"}
    assert core.tables == {"table:ocsf.authentication"} and core.table_namespace == "ocsf"
    assert [str(p) for p in problems] == [
        "registry: mcp/bad.yml: a record must be a mapping",
        "registry: mcp/anon.yml: an id that is not a string",
        "registry: mcp/other.yml: id elsewhere is not the file name",
        "registry: a keyring principal without a name",
    ]


@pytest.mark.parametrize("keyring", [{"principals": "x"}, ["x"], {}])
def test_a_malformed_keyring_is_a_named_problem(keyring):
    core, problems = ld.core_names(None, keyring=keyring)
    assert [str(p) for p in problems] == ["registry: the keyring's principals is not a list"]
    assert core.agents == frozenset()


def test_the_core_mcp_catalog_is_read_like_any_input(tmp_path):
    cat = tmp_path / "mcp"
    cat.mkdir()
    (cat / "lake.yml").write_text("id: lake\n")
    (cat / "notes.txt").write_text("not a record\n")
    (cat / "linked.yml").symlink_to(cat / "lake.yml")
    os.mkfifo(cat / "fifo.yml")
    recs, problems = ld.core_mcp_records(cat)
    assert recs == [("lake.yml", {"id": "lake"})]
    assert [p.message.split(": ")[0] for p in problems] == ["mcp/fifo.yml", "mcp/linked.yml"]
    linked = tmp_path / "linked-mcp"
    linked.symlink_to(cat)
    assert [str(p) for p in ld.core_mcp_records(linked)[1]] == [
        "registry: the MCP catalog linked-mcp/ is not a directory"
    ]


def test_another_record_like_file_in_the_mcp_catalog_is_named_not_skipped(tmp_path):
    cat = tmp_path / "mcp"
    cat.mkdir()
    for name in ("a.yaml", "b.YML", "c.json", "d.Yml"):
        (cat / name).write_text("id: x\n")
    (cat / "README.md").write_text("notes\n")
    recs, problems = ld.core_mcp_records(cat)
    assert recs == []
    assert [p.message for p in problems] == [
        f"mcp/{n}: a record file is <id>.yml; this one is not read"
        for n in ("a.yaml", "b.YML", "c.json", "d.Yml")
    ]


def test_an_oversized_mcp_record_or_a_crowded_catalog_is_refused(tmp_path, monkeypatch):
    cat = tmp_path / "mcp"
    cat.mkdir()
    (cat / "big.yml").write_bytes(b"id: big\nx: '" + b"a" * ld.MAX_BYTES + b"'\n")
    recs, problems = ld.core_mcp_records(cat)
    assert recs == [] and [p.message for p in problems] == [
        f"mcp/big.yml: over {ld.MAX_BYTES} bytes"
    ]
    for i in range(3):
        (cat / f"r{i}.yml").write_text(f"id: r{i}\n")
    monkeypatch.setattr(ld, "MAX_CATALOG_FILES", 3)
    recs, problems = ld.core_mcp_records(cat)
    assert recs == [] and [str(p) for p in problems] == [
        "registry: the MCP catalog mcp/ holds over 3 entries"
    ]


def test_the_core_s_ocsf_tables_are_read_like_any_input(tmp_path):
    names, problems = ld.core_table_names(ROOT / "schemas" / "ocsf")
    from homelabnext.lake.tables import load_schemas

    assert problems == [] and names == sorted(load_schemas(ROOT / "schemas" / "ocsf"))
    d = tmp_path / "ocsf"
    d.mkdir()
    shutil.copy(ROOT / "schemas" / "ocsf" / "authentication.v1.json", d)
    (d / "broken.v1.json").write_text("{")
    os.mkfifo(d / "fifo.v1.json")
    (d / "linked.v1.json").symlink_to(d / "authentication.v1.json")
    names, problems = ld.core_table_names(d)
    assert names == ["authentication"]
    assert [p.message.split(": ")[0] for p in problems] == [
        "ocsf/broken.v1.json",
        "ocsf/fifo.v1.json",
        "ocsf/linked.v1.json",
    ]
    empty = tmp_path / "empty"
    empty.mkdir()
    assert [str(p) for p in ld.core_table_names(empty)[1]] == [
        "registry: the OCSF tables: no subset (*.v*.json)"
    ]
    linked = tmp_path / "linked-ocsf"
    linked.symlink_to(d)
    assert [str(p) for p in ld.core_table_names(linked)[1]] == [
        "registry: the OCSF tables linked-ocsf/ is not a directory"
    ]


CORE_WITH_PAIRS = ld.CoreNames(
    rows=CORE.rows, pairs={"Core thing broke": "Core thing fixed", "Core other": "Core fine"}
)


@pytest.mark.parametrize(
    ("pair", "which"),
    [
        ({"problem": "Core thing broke", "recovery": "External: fixed"}, "problem"),
        ({"problem": "External: broke", "recovery": "Core thing fixed"}, "recovery"),
        ({"problem": "Core fine", "recovery": "External: fine"}, "problem"),
    ],
)
def test_a_module_pair_may_not_take_a_core_title(pair, which):
    """The notifier keys pairs by problem title: a module taking a core title would change the
    recovery the core's own alert clears with (or name a core recovery as its own)."""
    tree, _ = examples()
    tree.mods["external-collector"]["contributes"]["notify_pairs"] = [pair]
    got = messages(
        ld.check(tree, slots=SLOTS, roles=ROLES, in_tree_roots=(EXAMPLES,), core=CORE_WITH_PAIRS)
    )
    assert (
        f"external-collector: notify pair {pair['problem']!r}: its {which} title is a core title"
        in got
    )


def test_the_cli_refuses_a_module_pair_with_one_of_the_core_s_own_titles(capsys, tmp_path):
    from homelabnext.notify.core_pairs import STATUS_ITEM

    fixtures = tmp_path / "root"
    shutil.copytree(ROOT / "examples" / "modules", fixtures / "examples" / "modules")
    for name in ("model_roles.json", "services.yml"):
        shutil.copy(ROOT / "examples" / name, fixtures / "examples" / name)
    shutil.copytree(ROOT / "examples" / "keyring", fixtures / "examples" / "keyring")
    (fixtures / "modules").mkdir()
    m = fixtures / "examples" / "modules" / "publishing" / "module.yml"
    doc = ld.load_yaml(m)
    doc["contributes"]["notify_pairs"] = [{"problem": STATUS_ITEM[0], "recovery": "Ours"}]
    m.write_text(yaml.safe_dump(doc))
    code = mcli.main(["check", "--root", str(fixtures), "--examples", "--json"])
    got = json.loads(capsys.readouterr().out)["problems"]
    assert code == 1
    assert f"publishing: notify pair {STATUS_ITEM[0]!r}: its problem title is a core title" in got


def test_the_title_pattern_is_one_for_manifest_and_inventory():
    from homelabnext.schemas.module_manifest import TITLE_PATTERN

    inv = json.loads((ROOT / "schemas/platform/module_inventory.schema.json").read_text())
    man = json.loads((ROOT / "schemas/platform/module.schema.json").read_text())
    assert inv["$defs"]["title"]["pattern"] == TITLE_PATTERN
    for k in ("problem", "recovery"):
        assert man["$defs"]["notify_pair"]["properties"][k]["pattern"] == TITLE_PATTERN


@pytest.mark.parametrize(
    "bad", ["no\u00a0break", "bidi\u202eflip", "zero\u200bwidth", "line\nfeed", "c1\u0085"]
)
def test_a_notify_title_that_could_pass_for_another_is_refused(bad):
    import re

    from homelabnext.schemas.module_manifest import TITLE_PATTERN

    assert not re.search(TITLE_PATTERN, bad)
    assert re.search(TITLE_PATTERN, "Publishing: the gate passes every item again")


def test_the_cli_reads_the_core_s_names_from_the_registry_catalog_keyring_and_tables(
    capsys, tmp_path
):
    services = tmp_path / "services.yml"
    services.write_text("services: {}\n")
    (tmp_path / "mcp").mkdir()
    (tmp_path / "mcp" / "external-collector-probe.yml").write_text("id: external-collector-probe\n")
    keyring = tmp_path / "keyring.json"
    keyring.write_text(
        json.dumps(
            {"principals": [{"kind": "agent", "principal": "profile:external-collector-analyst"}]}
        )
    )
    code, out = run(capsys, "--services", str(services), "--keyring", str(keyring), "--json")
    assert code == 1
    assert json.loads(out.out)["problems"] == [
        "external-collector: MCP server external-collector-probe is a core MCP server id",
        "external-collector: agent external-collector-analyst is a core agent key",
    ]


def test_without_a_catalog_or_keyring_the_cli_names_what_it_did_not_compare(capsys, tmp_path):
    services = tmp_path / "services.yml"
    services.write_text("services: {}\n")
    code, out = run(capsys, "--services", str(services))
    assert code == 0
    assert "the core's MCP server ids were not compared" in out.out
    assert "note: the keyring is the repository's example" in out.out


def _overlay(tmp_path, mcp=False, keyring=False):
    lab = tmp_path / "overlay" / "lab"
    lab.mkdir(parents=True)
    if mcp:
        (lab / "mcp").mkdir()
    if keyring:
        (lab / "keyring").mkdir()
        (lab / "keyring" / "keyring.json").write_text('{"principals": []}')
    return tmp_path / "overlay"


def test_an_overlay_without_its_own_catalog_or_keyring_is_a_problem_not_the_examples(
    capsys, tmp_path
):
    """The repository's example keyring and catalog would answer for a lab they do not
    describe: with --overlay, a missing source is a problem, never a fallback."""
    code, out = run(capsys, "--overlay", str(_overlay(tmp_path)), "--json")
    assert code == 1
    doc = json.loads(out.out)
    assert [p for p in doc["problems"] if p.startswith("registry: the overlay has no")] == [
        "registry: the overlay has no MCP catalog ("
        + str(tmp_path / "overlay" / "lab" / "mcp")
        + "): give --mcp-catalog, or the core's MCP server ids cannot be compared",
        "registry: the overlay has no keyring (lab/keyring/keyring.json): give --keyring, or "
        "the core's agent keys cannot be compared",
    ]
    assert not [n for n in doc["notes"] if "keyring is the repository's example" in n]
    assert "note: " in out.err  # JSON on stdout, what was not checked also on stderr


def test_an_overlay_with_its_own_catalog_and_keyring_uses_them(capsys, tmp_path):
    code, out = run(capsys, "--overlay", str(_overlay(tmp_path, mcp=True, keyring=True)), "--json")
    doc = json.loads(out.out)
    assert code == 0
    assert not [p for p in doc["problems"] if p.startswith("registry:")]
    assert not [n for n in doc["notes"] if "keyring" in n or "MCP catalog" in n]


def test_an_overlay_may_name_its_catalog_and_keyring_explicitly(capsys, tmp_path):
    cat = tmp_path / "elsewhere-mcp"
    cat.mkdir()
    keyring = tmp_path / "keyring.json"
    keyring.write_text('{"principals": []}')
    code, out = run(
        capsys,
        "--overlay",
        str(_overlay(tmp_path)),
        "--mcp-catalog",
        str(cat),
        "--keyring",
        str(keyring),
        "--json",
    )
    assert code == 0 and not json.loads(out.out)["problems"]


def test_a_keyring_that_is_a_fifo_a_directory_or_oversized_cannot_be_read(capsys, tmp_path):
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    big = tmp_path / "big.json"
    big.write_bytes(b'{"principals": [], "x": "' + b"a" * ld.MAX_BYTES + b'"}')
    for path, why in (
        (fifo, "not a regular file"),
        (tmp_path, "not a regular file"),
        (big, "over"),
    ):
        code, out = run(capsys, "--keyring", str(path))
        assert code == 2 and why in out.err, (path, out.err)


def test_a_provider_instance_that_takes_another_core_service_name_is_refused():
    tree, _ = examples()
    site = copy.deepcopy(SITES["small-lab"])
    site["slots"]["object-store"][0]["instance"] = "idp"  # the core's idp row, not an object store
    got = messages(check(tree, site=site))
    assert "site: instance idp takes the core service name of idp" in got
    assert not [m for m in messages(check(tree, site=SITES["small-lab"])) if "instance" in m]


@pytest.mark.parametrize(
    "body", [{"services": ["a"]}, {"services": None}, {"services": {"foo": "bar"}}, ["x"]]
)
def test_a_malformed_core_registry_is_a_named_problem(body):
    _, problems = ld.core_names(body)
    assert [p.where for p in problems] == ["registry"]


# ----------------------------------------------------------------------------- the site


def test_a_selection_that_breaks_its_schema_is_refused_before_the_site_rules():
    tree, _ = examples()
    site = {**SITES["small-lab"], "grants": {"publsh": []}}
    got = messages(check(tree, site=site))
    assert got and all(m.startswith("site: schema: ") for m in got), got


def test_a_fetched_module_without_a_lock_is_not_loadable(tmp_path):
    examples(tmp_path, without=("external-collector",))

    def fetched(doc):
        doc["origin"] = {
            "kind": "git",
            "url": "https://git.example.invalid/modules/external-collector",
            "commit": "0123456789abcdef0123456789abcdef01234567",
        }

    overlay, _ = overlay_module(tmp_path, "external-collector", fetched)
    tree, found = ld.discover(fixtures=tmp_path / "fixtures", overlay=overlay)
    assert found == []
    report = check(tree, (tmp_path / "fixtures",), site=SITES["small-lab"])
    assert "no lock file: every fetched module is refused" in report.notes
    assert (
        "lock: external-collector: fetched (git) but not pinned in the lock: not loadable"
        in messages(report)
    )


def test_an_in_tree_module_with_a_lock_entry_is_refused():
    tree, _ = examples()
    lock = {
        "schema_version": "1.0",
        "modules": {"external-collector": {"origin": {"kind": "in-tree"}, "tree": "x"}},
    }
    got = messages(check(tree, site=SITES["small-lab"], lock=lock))
    assert (
        "lock: external-collector: an in-tree module is reviewed by this repository; it is "
        "never locked" in got
    )


# ----------------------------------------------------------------------------- the CLI


def run(capsys, *argv, cmd="check"):
    code = mcli.main([cmd, "--root", str(ROOT), "--examples", *argv])
    return code, capsys.readouterr()


def test_the_cli_exits_0_clean_and_names_what_it_did_not_check(capsys):
    code, out = run(capsys, "--site", str(EXAMPLES / "sites" / "small-lab.yml"))
    assert code == 0
    assert "note: no inventory of what runs" in out.out
    assert "note: the core registry is the repository's example" in out.out
    assert "note: the public modules/ tree" in out.out
    assert out.out.rstrip().endswith("16 module(s), 0 problem(s)")


def test_the_cli_exits_1_on_a_problem_and_prints_json(capsys):
    code, out = run(
        capsys,
        "--site",
        str(EXAMPLES / "sites" / "small-lab.yml"),
        "--running",
        str(ROOT / "schemas/platform/negative/module_inventory.kind-missing.yml"),
        "--json",
    )
    assert code == 1
    doc = json.loads(out.out)
    assert doc["problems"] and all(p.startswith("running: schema:") for p in doc["problems"])


def test_the_cli_exits_1_on_a_malformed_core_registry(capsys, tmp_path):
    bad = tmp_path / "services.yml"
    bad.write_text("services: [a]\n")
    code, out = run(capsys, "--services", str(bad))
    assert code == 1 and "registry: services is not a mapping" in out.out


def test_the_cli_exits_2_on_an_unreadable_input(capsys, tmp_path):
    bad = tmp_path / "site.yml"
    bad.write_text("slots: [\n")
    code, out = run(capsys, "--site", str(bad))
    assert code == 2 and "not valid YAML" in out.err


@pytest.mark.parametrize(
    "flag",
    ["--overlay", "--services", "--keyring", "--mcp-catalog", "--site", "--running", "--roles"],
)
def test_a_path_given_that_does_not_exist_is_a_usage_error(capsys, tmp_path, flag):
    code, out = run(capsys, flag, str(tmp_path / "nonexistent"))
    assert code == 2 and "nonexistent" in out.err


def test_the_cli_exits_100_on_an_internal_failure(capsys, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("x")

    monkeypatch.setattr(ld, "check", boom)
    code, out = run(capsys)
    assert code == 100 and "internal error" in out.err


def test_render_into_a_file_is_a_usage_error(capsys, tmp_path):
    out = tmp_path / "out"
    out.write_text("x")
    site = str(EXAMPLES / "sites" / "full.yml")
    code, got = run(capsys, "--site", site, "--out", str(out), cmd="render")
    assert code == 2 and "not a directory" in got.err


def test_a_generator_refusal_is_a_json_error_with_exit_1(capsys, tmp_path, monkeypatch):
    from homelabnext.modules import limits

    def refuse(*_a, **_k):
        raise limits.LimitsError("planted")

    monkeypatch.setattr(limits, "render", refuse)
    site = str(EXAMPLES / "sites" / "full.yml")
    code, got = run(capsys, "--site", site, "--out", str(tmp_path / "o"), "--json", cmd="render")
    assert code == 1 and json.loads(got.out)["error"] == "planted"


def test_notes_name_a_path_under_the_root_relative_to_it(capsys):
    _, out = run(capsys)
    assert "note: the core registry is the repository's example (examples/services.yml)" in (
        out.out
    )


def test_render_writes_a_fresh_directory_only_for_a_clean_site(capsys, tmp_path):
    site = str(EXAMPLES / "sites" / "full.yml")
    out = tmp_path / "out"
    code, got = run(capsys, "--site", site, "--out", str(out), "--json", cmd="render")
    assert code == 0
    doc = json.loads(got.out)  # JSON only, nothing else on stdout
    assert doc["problems"] == [] and doc["written"]["limits"] and doc["written"]["egress"]
    assert any((out / "limits").iterdir()) and any((out / "egress").iterdir())
    code, got = run(capsys, "--site", site, "--out", str(out), cmd="render")
    assert code == 2 and "not empty" in got.err  # never mixed with an earlier render's files
    bad = tmp_path / "bad.yml"
    bad.write_text(yaml.safe_dump({**SITES["full"], "features": {}}))
    refused = tmp_path / "refused"
    code, _ = run(capsys, "--site", str(bad), "--out", str(refused), cmd="render")
    assert code == 1 and not refused.exists()
