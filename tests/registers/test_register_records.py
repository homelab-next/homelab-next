# SPDX-License-Identifier: Apache-2.0
"""One record per file: the format, the loader, split/join, links blocks and the id tooling."""

import pathlib
import re
import shutil
import subprocess
import sys

import pytest
import yaml

from homelabnext.registers import RegisterError, build_all, ids, load_register, records
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


# --- the conversion lost nothing ------------------------------------------------------------------


def _converted(kind):
    """(legacy YAML text, {record name: text}) on either side of the split, from git."""
    legacy, rdir = f"examples/registers/{kind}.yml", f"examples/registers/{kind}"
    if _git(REPO, "rev-parse", "--git-dir", check=False).returncode:
        pytest.skip("not a git checkout")
    head = _git(REPO, "show", f"HEAD:{legacy}", check=False)
    if head.returncode == 0:  # conversion not committed yet: HEAD's file vs the working tree
        texts = {p.name: p.read_text() for p in (REPO / rdir).glob("*.md")}
        return head.stdout, texts
    commit = _git(REPO, "rev-list", "-1", "HEAD", "--", legacy).stdout.strip()
    if not commit:
        pytest.skip("history without the single-file register (a shallow clone)")
    old = _git(REPO, "show", f"{commit}^:{legacy}", check=False)
    if old.returncode:
        pytest.skip("the conversion commit's parent is not in this clone")
    return old.stdout, ids._rev_dir_texts(REPO, commit, rdir)


@pytest.mark.parametrize("kind", KINDS)
def test_the_conversion_lost_nothing(kind, tmp_path):
    old_text, texts = _converted(kind)
    (tmp_path / f"{kind}.yml").write_text(old_text)
    old = load_register(tmp_path / f"{kind}.yml")
    new = records.load_texts(texts, kind)
    assert new == old  # every entry, every field, deep
    # and against the raw YAML: only surrounding whitespace of prose fields may differ
    prose = {f for f, _ in records.SECTIONS[kind] if f != "steps"}
    raw = yaml.safe_load(old_text)[kind]
    assert [
        {k: v.strip() if k in prose and isinstance(v, str) else v for k, v in e.items()}
        for e in raw
    ] == new[kind]
    assert sorted(texts) == sorted(f"{e['id']}.md" for e in raw)


def test_split_then_join_round_trips(tmp_path):
    for kind in KINDS:
        joined = records.join_register(REPO / "examples/registers" / kind, tmp_path / f"{kind}.yml")
        again = tmp_path / "split" / kind
        records.split_register(joined, again)
        assert load_register(again) == load_register(REPO / "examples/registers" / kind)
        for p in again.iterdir():  # the split writes exactly the committed files
            assert p.read_text() == (REPO / "examples/registers" / kind / p.name).read_text()


def test_split_refuses_a_lossy_or_invalid_register(tmp_path):
    src = tmp_path / "runbooks.yml"
    rb = {"runbooks": [dict(load_register(REPO / "examples/registers/runbooks")["runbooks"][0])]}
    rb["runbooks"][0]["steps"] = [{"do": "two\nlines", "verify": "exit 0"}]
    src.write_text(yaml.safe_dump(rb))
    with pytest.raises(RegisterError, match="round trip"):
        records.split_register(src, tmp_path / "out")
    assert not (tmp_path / "out").exists()
    src.write_text("runbooks:\n- id: RB-001\n  title: no steps at all\n")
    with pytest.raises(RegisterError, match="steps"):
        records.split_register(src, tmp_path / "out")


def test_split_names_placeholders_by_slug(tmp_path):
    doc = load_register(REPO / "examples/registers/lessons")
    for e, t in zip(doc["lessons"][:2], ("Same title", "Same title"), strict=True):
        e["id"], e["title"] = "LL-NEW", t
    src = tmp_path / "lessons.yml"
    src.write_text(yaml.safe_dump(doc))
    names = sorted(p.name for p in records.split_register(src, tmp_path / "lessons"))
    assert names == [
        *("LL-003.md", "LL-004.md", "LL-005.md"),
        *("LL-NEW-same-title-2.md", "LL-NEW-same-title.md"),
    ]


# --- malformed records are fatal ------------------------------------------------------------------


@pytest.fixture
def src(tmp_path):
    d = tmp_path / "src"
    for kind in KINDS:
        shutil.copytree(REPO / "examples/registers" / kind, d / kind)
    shutil.copy(REPO / "examples/registers/invariants.yml", d / "invariants.yml")
    return d


def _edit(path, old, new):
    text = path.read_text()
    assert old in text, old
    path.write_text(text.replace(old, new))


@pytest.mark.parametrize(
    "file, old, new, needle",
    [
        # a missing root cause section: the same schema error as a missing YAML field
        ("LL-001.md", "## Root cause\n", "## Notes\n", "root_cause"),
        ("LL-001.md", "id: LL-001", "id: LL-1", "front-matter has no `id:`"),
        ("LL-001.md", "id: LL-001", "id: LL-009", "file name and front-matter id LL-009 disagree"),
        ("LL-001.md", "## Symptom", "## Symtom", "unknown section `## Symtom`"),
        ("LL-001.md", "## Root cause", "## Symptom", "appears twice"),
        (
            "LL-001.md",
            "status: controlled",
            "status: controlled\nroot_cause: x",
            "belongs in the body",
        ),
        ("LL-001.md", "---\n\n## Symptom", "---\nstray prose\n\n## Symptom", "before the first"),
        ("LL-001.md", "id: LL-001\n", "", "front-matter has no `id:`"),
        ("LL-001.md", "systems: [proxy, tls]", "systems: [proxy, tls\n", "not YAML"),
    ],
)
def test_malformed_records_fail_validation(src, tmp_path, file, old, new, needle):
    _edit(src / "lessons" / file, old, new)
    with pytest.raises(RegisterError, match=re.escape(needle)):
        build_all(src, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_duplicate_id_across_files_fails(src, tmp_path):
    shutil.copy(src / "lessons/LL-001.md", src / "lessons/LL-002.md")
    with pytest.raises(RegisterError) as ex:
        build_all(src, tmp_path / "out")
    assert "duplicate id LL-001" in str(ex.value) or "disagree" in str(ex.value)
    # the schema's own duplicate check sees ids from different files (a placeholder name)
    shutil.copy(src / "lessons/LL-001.md", src / "lessons/LL-NEW-copy.md")
    _edit(src / "lessons/LL-002.md", "id: LL-001", "id: LL-002")
    texts = {p.name: p.read_text() for p in (src / "lessons").glob("*.md")}
    texts["LL-NEW-copy.md"] = texts["LL-NEW-copy.md"].replace("id: LL-001", "id: LL-NEW")
    texts["LL-004.md"] = texts["LL-001.md"]
    with pytest.raises(RegisterError, match=r"LL-004\.md: file name and front-matter id LL-001"):
        records.load_texts(texts, "lessons")


def test_steps_section_grammar(src, tmp_path):
    rb = src / "runbooks/RB-001.md"
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
        src / "lessons/LL-003.md",
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


def test_related_ids_must_resolve(src, tmp_path):
    _edit(src / "lessons/LL-001.md", "status: controlled", "status: controlled\nrelated: [RB-001]")
    records.stale_links(src / "lessons", write=True)
    assert "- Related: [[RB-001]]" in (src / "lessons/LL-001.md").read_text()
    build_all(src, tmp_path / "ok")
    _edit(src / "lessons/LL-001.md", "related: [RB-001]", "related: [RB-009]")
    with pytest.raises(RegisterError, match="related RB-009 is not a live"):
        build_all(src, tmp_path / "bad")
    _edit(src / "lessons/LL-001.md", "related: [RB-009]", "related: [LL-001]")
    with pytest.raises(RegisterError, match="names the entry itself"):
        build_all(src, tmp_path / "bad")


def test_tombstone_record(src):
    (src / "lessons/LL-007.md").write_text(
        records.render_record(
            {
                "id": "LL-007",
                "retired": {"reason": "merged into LL-001 on review", "replaced_by": "LL-001"},
            },
            "lessons",
        )
    )
    doc = load_register(src / "lessons")
    assert doc["retired"] == {
        "LL-007": {"reason": "merged into LL-001 on review", "replaced_by": "LL-001"}
    }
    assert "- Retired; replaced by [[LL-001]]" in (src / "lessons/LL-007.md").read_text()


# --- the generated links block ---------------------------------------------------------------


def test_links_blocks_of_the_repository_are_current():
    dirs = [str(REPO / "examples/registers" / k) for k in KINDS]
    assert registers_main(["links", "--check", *dirs]) == 0


def test_links_block_is_regenerated_and_checked(src, capsys):
    rec = src / "runbooks/RB-001.md"
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


# --- ids across a record directory -------------------------------------------------------------


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("HOMELABNEXT_IDS_STATE", str(tmp_path / "idstate"))
    r = tmp_path / "repo"
    shutil.copytree(REPO / "examples/registers/lessons", r / "reg/lessons")
    _git(r, "init")
    _git(r, "add", "-A")
    _git(r, "commit", "-m", "seed")
    return r


def test_new_record_is_allocated_renamed_and_rewritten(repo):
    d = repo / "reg/lessons"
    for slug in ("first", "second"):
        text = (d / "LL-003.md").read_text().replace("id: LL-003", "id: LL-NEW")
        (d / f"LL-NEW-{slug}.md").write_text(text + "\nSee LL-NEW for the follow-up.\n")
    assert _tool(repo, "check-dupes").returncode == 0  # placeholders may repeat
    r = _tool(repo, "check-placeholders", "reg/lessons/LL-NEW-first.md")
    assert r.returncode == 1 and "LL-NEW" in r.stderr
    r = _tool(repo, "resolve")
    assert r.returncode == 3, r.stderr
    assert "LL-NEW -> LL-006" in r.stdout and "LL-NEW -> LL-007" in r.stdout
    assert sorted(p.name for p in d.iterdir()) == [f"LL-00{n}.md" for n in range(1, 8)]
    first = (d / "LL-006.md").read_text()
    assert "id: LL-006" in first and "See LL-006 for" in first and "LL-NEW" not in first
    assert _tool(repo, "resolve").returncode == 0  # idempotent
    assert _tool(repo, "check-placeholders").returncode == 0
    assert _tool(repo, "check-dupes").returncode == 0


def test_check_lost_catches_a_deleted_record_file(repo):
    assert _tool(repo, "check-lost").returncode == 0
    (repo / "reg/lessons/LL-002.md").unlink()
    r = _tool(repo, "check-lost")
    assert r.returncode == 1 and "reg/lessons lost LL-002" in r.stderr
    assert "git checkout HEAD -- reg/lessons/<ID>.md" in r.stderr
    for p in (repo / "reg/lessons").iterdir():  # the whole directory gone
        p.unlink()
    assert "lost LL-001, LL-002, LL-003, LL-004, LL-005" in _tool(repo, "check-lost").stderr


def test_check_lost_counts_a_tombstone_file_as_present(repo):
    d = repo / "reg/lessons"
    (d / "LL-002.md").write_text(
        records.render_record(
            {"id": "LL-002", "retired": {"reason": "duplicate of LL-001 found in review"}},
            "lessons",
        )
    )
    assert _tool(repo, "check-lost").returncode == 0


def test_check_lost_against_a_base_reads_the_single_file_before_a_split(repo):
    d = repo / "reg/lessons"
    records.join_register(d, repo / "reg/lessons.yml")
    shutil.rmtree(d)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "join back")
    base = _git(repo, "rev-parse", "HEAD").stdout.strip()
    records.split_register(repo / "reg/lessons.yml", d)
    (repo / "reg/lessons.yml").unlink()
    (d / "LL-003.md").unlink()  # lost in the conversion itself
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "split, dropping one")
    r = _tool(repo, "check-lost", "--base", base)
    assert r.returncode == 1 and "lost LL-003" in r.stderr


def test_check_dupes_flags_a_name_id_mismatch_and_a_shared_id(repo):
    d = repo / "reg/lessons"
    shutil.copy(d / "LL-001.md", d / "LL-009.md")
    r = _tool(repo, "check-dupes", "reg/lessons")
    assert r.returncode == 1
    assert "LL-009.md: file name and front-matter id LL-001 disagree" in r.stderr
    assert "LL-009.md: id LL-001 is also the id of LL-001.md" in r.stderr


def test_allocation_floor_reads_the_directory(repo):
    assert ids.allocate(repo, "reg/lessons", "LL") == ["LL-006"]
