# SPDX-License-Identifier: Apache-2.0
"""One record per file: the format, the loader, split/join, links blocks and the key tooling
(uids, ADR-0019)."""

import pathlib
import re
import shutil
import subprocess
import sys

import pytest
import yaml
from register_helpers import EXAMPLES, U, edit, f

from homelabnext.registers import RegisterError, build_all, load_register, records
from homelabnext.registers.__main__ import main as registers_main

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "register_ids.py"
KINDS = ("lessons", "runbooks")


def _git(cwd, *args, check=True):
    return subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@example.org",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
    )


def _tool(cwd, *args):
    return subprocess.run(
        [sys.executable, str(TOOL), *args], cwd=cwd, capture_output=True, text=True
    )


# --- split and join -----------------------------------------------------------------------------


def test_split_then_join_round_trips(tmp_path):
    for kind in KINDS:
        joined = records.join_register(REPO / "examples/registers" / kind, tmp_path / f"{kind}.yml")
        again = tmp_path / "split" / kind
        records.split_register(joined, again)
        committed = REPO / "examples/registers" / kind
        assert load_register(again) == load_register(committed)
        names = sorted(p.name for p in again.glob("*.md"))
        assert names == sorted(p.name for p in committed.glob("*.md"))  # <uid>.md each
        for name in names:  # the split writes exactly the committed record files
            assert (again / name).read_text() == (committed / name).read_text()


def test_split_refuses_a_lossy_or_invalid_register(tmp_path):
    src = tmp_path / "runbooks.yml"
    rb = {"runbooks": [dict(load_register(REPO / "examples/registers/runbooks")["runbooks"][0])]}
    rb["runbooks"][0]["steps"] = [{"do": "two\nlines", "verify": "exit 0"}]
    src.write_text(yaml.safe_dump(rb))
    with pytest.raises(RegisterError, match="round trip"):
        records.split_register(src, tmp_path / "out")
    assert not (tmp_path / "out").exists()
    src.write_text(f"runbooks:\n- uid: {U['RB-001']}\n  type: runbook\n  title: no steps at all\n")
    with pytest.raises(RegisterError, match="steps"):
        records.split_register(src, tmp_path / "out")


def test_a_joined_register_without_uids_is_refused(tmp_path):
    """A single-file register written before uids is migrated, not split: every entry needs its
    uid (``hnx records assign-uids``)."""
    doc = load_register(REPO / "examples/registers/lessons")
    for e in doc["lessons"]:
        e["id"] = "LL-00" + e.pop("uid")[-1]
    src = tmp_path / "lessons.yml"
    src.write_text(yaml.safe_dump(doc))
    with pytest.raises(RegisterError, match="numbered `id: LL-00"):
        records.split_register(src, tmp_path / "lessons")


# --- malformed records are fatal ------------------------------------------------------------------


@pytest.fixture
def src(tmp_path):
    d = tmp_path / "src"
    for kind in KINDS:
        shutil.copytree(REPO / "examples/registers" / kind, d / kind)
    shutil.copy(REPO / "examples/registers/invariants.yml", d / "invariants.yml")
    return d


_edit = edit


OTHER = "01a15e4e-0000-7000-8000-00000000000f"  # a valid uid no example record has


@pytest.mark.parametrize(
    "code, old, new, needle",
    [
        # a missing root cause section: the same schema error as a missing YAML field
        ("LL-001", "## Root cause\n", "## Notes\n", "root_cause"),
        ("LL-001", "uid: {u}", "uid: LL-1", "`uid` must be a canonical UUIDv7"),
        ("LL-001", "uid: {u}", "uid: {U}", "`uid` must be a canonical UUIDv7"),  # upper case
        ("LL-001", "uid: {u}", f"uid: {OTHER}", f"file name and front-matter uid {OTHER} disagree"),
        ("LL-001", "uid: {u}", "id: LL-001", "numbered `id: LL-001` and no `uid:`"),
        ("LL-001", "uid: {u}\n", "", "`uid` must be a canonical UUIDv7"),
        ("LL-001", "type: lesson", "type: runbook", "`type` must be lesson"),
        ("LL-001", "type: lesson", "type: lesson\nparent: {u}", "registers are flat"),
        ("LL-001", "## Symptom", "## Symtom", "unknown section `## Symtom`"),
        ("LL-001", "## Root cause", "## Symptom", "appears twice"),
        (
            "LL-001",
            "status: controlled",
            "status: controlled\nroot_cause: x",
            "belongs in the body",
        ),
        ("LL-001", "---\n\n## Symptom", "---\nstray prose\n\n## Symptom", "before the first"),
        ("LL-001", "systems: [proxy, tls]", "systems: [proxy, tls\n", "not YAML"),
        # a key set twice: the loader would keep the last value, a reader sees the first
        ("LL-001", "status: controlled", "status: retired\nstatus: controlled", "duplicate key"),
    ],
)
def test_malformed_records_fail_validation(src, tmp_path, code, old, new, needle):
    u = U[code]
    old, new = old.format(u=u, U=u.upper()), new.format(u=u, U=u.upper())
    _edit(src / "lessons" / f(code), old, new)
    with pytest.raises(RegisterError, match=re.escape(needle)):
        build_all(src, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_duplicate_uid_across_files_fails(src, tmp_path):
    shutil.copy(src / "lessons" / f("LL-001"), src / "lessons" / f("LL-002"))
    with pytest.raises(RegisterError) as ex:
        build_all(src, tmp_path / "out")
    assert f"file name and front-matter uid {U['LL-001']} disagree" in str(ex.value)
    # the schema's own duplicate check sees uids from any file
    texts = {p.name: p.read_text() for p in (src / "lessons").glob("*.md")}
    entries = records.load_texts({n: t for n, t in texts.items() if n != f("LL-002")}, "lessons")[
        "lessons"
    ]
    from homelabnext.registers.schema import validate_lessons

    with pytest.raises(RegisterError, match=f"duplicate uid {U['LL-001']}"):
        validate_lessons({"lessons": [*entries, entries[0]]})


def test_two_siblings_may_not_share_an_order(src, tmp_path):
    for code in ("LL-001", "LL-003"):
        _edit(src / "lessons" / f(code), "type: lesson", "type: lesson\norder: 1")
    with pytest.raises(RegisterError, match="LL 2: order 1 is also the order of its sibling LL 1"):
        build_all(src, tmp_path / "out")
    _edit(src / "lessons" / f("LL-003"), "order: 1", "order: 0.5")  # before LL-001 now
    build_all(src, tmp_path / "ok")
    from homelabnext.registers.schema import labels_of

    labels = labels_of(load_register(src / "lessons")["lessons"])
    assert labels[U["LL-003"]] == "LL 1" and labels[U["LL-001"]] == "LL 2"
    assert labels[U["LL-002"]] == "LL 3"  # unordered siblings follow, in creation order


def test_steps_section_grammar(src, tmp_path):
    rb = src / "runbooks" / f("RB-001")
    _edit(rb, "   - verify: the reload command", "   - verfy: the reload command")
    with pytest.raises(RegisterError, match="`## Steps` line 4"):
        build_all(src, tmp_path / "out")
    _edit(
        rb, "   - verfy: the reload command exits 0 and the proxy health endpoint returns 200\n", ""
    )
    with pytest.raises(RegisterError, match="every step needs its own `verify`"):
        build_all(src, tmp_path / "out")


def test_fenced_code_may_hold_heading_lines(src, tmp_path):
    _edit(
        src / "lessons" / f("LL-003"),
        "five weeks.\n",
        "five weeks.\n\n```text\n## not a heading\n```\n",
    )
    doc = load_register(src / "lessons")
    assert doc["lessons"][2]["symptom"].endswith("```text\n## not a heading\n```")


def test_a_record_directory_holds_records_only(src):
    (src / "lessons/README.md").write_text("# notes\n")
    with pytest.raises(RegisterError, match=r"README\.md"):
        load_register(src / "lessons")
    (src / "lessons/README.md").unlink()
    (src / "lessons/notes.txt").write_text("x")
    with pytest.raises(RegisterError, match="not a record file"):
        load_register(src / "lessons")


def test_both_forms_at_once_is_ambiguous(src, tmp_path):
    (src / "lessons.yml").write_text("lessons: []\n")
    with pytest.raises(RegisterError, match="keep one"):
        build_all(src, tmp_path / "out")


def test_related_uids_must_resolve(src, tmp_path):
    ll1, rb1 = src / "lessons" / f("LL-001"), U["RB-001"]
    _edit(ll1, "status: controlled", f"status: controlled\nrelated: [{rb1}]")
    records.stale_links(src / "lessons", write=True)
    assert f"- Related: [[{rb1}]]" in ll1.read_text()  # a uid, never a number or a title
    build_all(src, tmp_path / "ok")
    _edit(ll1, f"related: [{rb1}]", f"related: [{OTHER}]")
    with pytest.raises(RegisterError, match=f"related {OTHER} is not a lesson or runbook"):
        build_all(src, tmp_path / "bad")
    _edit(ll1, f"related: [{OTHER}]", "related: [RB-001]")
    with pytest.raises(RegisterError, match="related 'RB-001' is a legacy numbered code"):
        build_all(src, tmp_path / "bad")
    _edit(ll1, "related: [RB-001]", f"related: [{U['LL-001']}]")
    with pytest.raises(RegisterError, match="names the entry itself"):
        build_all(src, tmp_path / "bad")


def test_a_top_level_retired_block_is_refused_in_a_records_register():
    """A uid is never reused, so a lessons register has nothing to tombstone."""
    from homelabnext.registers.schema import validate_lessons

    doc = load_register(REPO / "examples/registers/lessons")
    with pytest.raises(RegisterError, match=r"unknown key\(s\) \['retired'\]"):
        validate_lessons({**doc, "retired": {"LL-007": {"reason": "merged into another"}}})


# --- the generated links block ---------------------------------------------------------------


def test_links_blocks_of_the_repository_are_current():
    dirs = [str(REPO / "examples/registers" / k) for k in KINDS]
    assert registers_main(["links", "--check", *dirs]) == 0


def test_links_block_is_regenerated_and_checked(src, capsys):
    rec = src / "runbooks" / f("RB-001")
    _edit(rec, "systems: [proxy, tls]", "systems: [proxy, tls, backup]")
    assert registers_main(["links", "--check", str(src / "runbooks")]) == 1
    assert "stale links block" in capsys.readouterr().out
    assert registers_main(["links", str(src / "runbooks")]) == 0
    assert "[[systems/backup|backup]]" in rec.read_text()
    assert registers_main(["links", "--check", str(src / "runbooks")]) == 0
    # a record written without the block gets one appended; hand edits inside it are replaced
    text = rec.read_text()
    rec.write_text(text[: text.index("## Links")])
    assert records.stale_links(src / "runbooks", write=True) == [rec]
    assert rec.read_text() == text
    _edit(rec, "- Systems:", "- my note\n- Systems:")
    assert records.stale_links(src / "runbooks", write=True) == [rec]
    assert rec.read_text() == text


# --- keys across a record directory -------------------------------------------------------------


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    shutil.copytree(REPO / "examples/registers/lessons", r / "reg/lessons")
    _git(r, "init")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "seed")
    return r


def test_a_new_record_needs_nothing_at_merge_time(repo):
    """Two branches that each add a lesson take a uid each: nothing to allocate or rename."""
    d = repo / "reg/lessons"
    for new in ("01a15e4e-0000-7000-8000-0000000000a1", "01a15e4e-0000-7000-8000-0000000000a2"):
        text = (d / f("LL-003")).read_text().replace(U["LL-003"], new)
        (d / f"{new}.md").write_text(text)
    for cmd in ("check-dupes", "check-uids", "check-lost"):
        r = _tool(repo, cmd)
        assert r.returncode == 0, (cmd, r.stderr)


def test_check_uids_flags_a_record_without_its_uid(repo):
    d = repo / "reg/lessons"
    text = (d / f("LL-003")).read_text().replace(f"uid: {U['LL-003']}", "id: LL-003")
    (d / "LL-003.md").write_text(text)
    (d / "LL-NEW-x.md").write_text(text.replace("id: LL-003", "id: LL-NEW"))
    r = _tool(repo, "check-uids", "reg/lessons")
    assert r.returncode == 1
    assert "reg/lessons/LL-003.md: no uid (still numbered LL-003)" in r.stderr
    assert "LL-NEW-x.md: no uid (still numbered LL-NEW)" in r.stderr
    assert "hnx records assign-uids" in r.stderr
    r = _tool(repo, "check-dupes", "reg/lessons")  # check-uids' to report, and only there
    assert r.returncode == 0 and "uid" not in r.stderr, r.stderr


def test_check_uids_runs_as_a_pre_commit_hook():
    """idcli's docstring says check-uids runs in pre-commit: the hook exists and runs it."""
    import yaml

    cfg = yaml.safe_load((REPO / ".pre-commit-config.yaml").read_text())
    hooks = {h["id"]: h for r in cfg["repos"] for h in r["hooks"]}
    assert hooks["register-ids-check-uids"]["entry"] == "python3 tools/register_ids.py check-uids"


def test_check_lost_catches_a_deleted_record_file(repo):
    assert _tool(repo, "check-lost").returncode == 0
    (repo / "reg/lessons" / f("LL-002")).unlink()
    r = _tool(repo, "check-lost")
    assert r.returncode == 1 and f"reg/lessons lost {U['LL-002']}" in r.stderr
    assert "git checkout HEAD -- reg/lessons/<uid>.md" in r.stderr
    for p in (repo / "reg/lessons").iterdir():  # the whole directory gone
        shutil.rmtree(p) if p.is_dir() else p.unlink()
    lost = ", ".join(sorted(U[f"LL-00{n}"] for n in range(1, 6)))
    assert f"lost {lost}" in _tool(repo, "check-lost").stderr


def test_check_lost_catches_a_deleted_event_file_and_a_deleted_sidecar(repo):
    d = repo / "reg/lessons"
    sidecar = d / f"{U['LL-001']}.events"
    [first, *rest] = sorted(sidecar.iterdir())
    first.unlink()  # one event gone, as a merge that kept one side's sidecar would leave it
    r = _tool(repo, "check-lost")
    assert r.returncode == 1, r.stderr
    assert f"lost {U['LL-001']}.events/{first.name}" in r.stderr
    assert "events are append-only" in r.stderr
    shutil.rmtree(sidecar)  # the whole sidecar gone, the record kept
    r = _tool(repo, "check-lost")
    lost = ", ".join(f"{U['LL-001']}.events/{p.name}" for p in [first, *rest])
    assert r.returncode == 1 and f"lost {lost}" in r.stderr, r.stderr
    _git(repo, "checkout", "HEAD", "--", f"reg/lessons/{sidecar.name}")
    assert _tool(repo, "check-lost").returncode == 0
    new = sidecar / "20261022T000000Z-review-agent-example-checker.yml"
    new.write_text((sidecar / rest[0].name).read_text())  # an added event is not a loss
    assert _tool(repo, "check-lost").returncode == 0


def test_a_deliberately_dropped_event_is_waived_by_name(repo, monkeypatch):
    sidecar = repo / "reg/lessons" / f"{U['LL-001']}.events"
    gone = sorted(sidecar.iterdir())[0]
    gone.unlink()
    monkeypatch.setenv("REGISTER_IDS_ALLOW_DROP", f"{U['LL-001']}.events/{gone.name}")
    assert _tool(repo, "check-lost").returncode == 0


def test_check_lost_reads_the_migration_commit_through_the_alias_map(tmp_path):
    """A base that still has LL-001.md: the migrated <uid>.md accounts for it through
    aliases.yml; a record dropped in the migration commit is reported by its old code."""
    r = tmp_path / "repo"
    d = r / "reg/lessons"
    d.mkdir(parents=True)
    for code in ("LL-001", "LL-003"):
        text = (EXAMPLES / "lessons" / f(code)).read_text()
        text = text.replace(f"uid: {U[code]}\ntype: lesson", f"id: {code}")
        (d / f"{code}.md").write_text(text)
    _git(r, "init")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "numbered")
    for code in ("LL-001", "LL-003"):
        text = (d / f"{code}.md").read_text().replace(f"id: {code}", f"uid: {U[code]}")
        (d / f(code)).write_text(text)
        (d / f"{code}.md").unlink()
    (r / "reg/aliases.yml").write_text(
        f"aliases:\n  LL-001: {U['LL-001']}\n  LL-003: {U['LL-003']}\n"
    )
    assert _tool(r, "check-lost").returncode == 0, _tool(r, "check-lost").stderr
    (d / f("LL-003")).unlink()
    out = _tool(r, "check-lost")
    assert out.returncode == 1 and "reg/lessons lost LL-003" in out.stderr


def test_check_lost_counts_a_code_the_migration_retired(tmp_path):
    """A pre-uid tombstone (LL-009) leaves the tree in the migration commit: its code is in
    aliases.yml's `retired:` block (homelabnext.identity's reader, the one the migration
    writes with), so it is accounted for; a malformed map is a FATAL line, not a traceback."""
    r = tmp_path / "repo"
    d = r / "reg/lessons"
    d.mkdir(parents=True)
    text = (EXAMPLES / "lessons" / f("LL-001")).read_text()
    (d / "LL-001.md").write_text(text.replace(f"uid: {U['LL-001']}\ntype: lesson", "id: LL-001"))
    (d / "LL-009.md").write_text("---\nid: LL-009\nretired:\n  reason: filed twice\n---\n")
    _git(r, "init")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "numbered")
    (d / f("LL-001")).write_text(text)
    (d / "LL-001.md").unlink()
    (d / "LL-009.md").unlink()
    aliases = r / "reg/aliases.yml"
    aliases.write_text(
        f"aliases:\n  LL-001: {U['LL-001']}\nretired:\n  LL-009:\n    reason: filed twice\n"
    )
    assert _tool(r, "check-lost").returncode == 0, _tool(r, "check-lost").stderr
    aliases.write_text(f"aliases:\n  LL-001: {U['LL-001']}\n")
    out = _tool(r, "check-lost")
    assert out.returncode == 1 and "reg/lessons lost LL-009" in out.stderr
    aliases.write_text("aliases:\n  LL-001: not-a-uid\n")
    out = _tool(r, "check-lost")
    assert out.returncode == 1 and "FATAL" in out.stderr and "Traceback" not in out.stderr


def test_check_lost_against_a_base_reads_the_single_file_before_a_split(repo):
    d = repo / "reg/lessons"
    records.join_register(d, repo / "reg/lessons.yml")
    shutil.rmtree(d)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "join back")
    base = _git(repo, "rev-parse", "HEAD").stdout.strip()
    records.split_register(repo / "reg/lessons.yml", d)
    (repo / "reg/lessons.yml").unlink()
    (d / f("LL-003")).unlink()  # lost in the conversion itself
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "split, dropping one")
    r = _tool(repo, "check-lost", "--base", base)
    assert r.returncode == 1 and f"lost {U['LL-003']}" in r.stderr


def test_check_dupes_flags_a_name_uid_mismatch_and_a_shared_uid(repo):
    d = repo / "reg/lessons"
    shutil.copy(d / f("LL-001"), d / f"{OTHER}.md")
    r = _tool(repo, "check-dupes", "reg/lessons")
    assert r.returncode == 1
    assert f"{OTHER}.md: file name and front-matter uid {U['LL-001']} disagree" in r.stderr
    assert f"{f('LL-001')}: uid {U['LL-001']} is also the uid of {OTHER}.md" in r.stderr
