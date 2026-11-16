# SPDX-License-Identifier: Apache-2.0
"""The carried helper scripts' deletion logic, run for real on a scratch library (no systemd, no
network): the completed-downloads cleanup refuses a root that is a link or lies outside downloads/,
never follows a link while walking, removes only plain files inside downloads/ that are hardlinked
into the library and not held by a torrent, never deletes music, covers or books by filename, and the
rename helper refuses a name that leaves its folder."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "modules" / "media-automation" / "roles" / "media_automation" / "files"


def load(name: str, fname: str):
    sys.dont_write_bytecode = True  # the role's files/ directory stays source only
    spec = importlib.util.spec_from_file_location(name, FILES / fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def cd():
    return load("cleanup_downloads", "cleanup-downloads.py")


@pytest.fixture
def lib(tmp_path):
    root = tmp_path / "media"
    for d in ("movies", "music", "shows", "downloads/qbittorrent/completed"):
        (root / d).mkdir(parents=True)
    (root / "movies" / "film.mkv").write_text("film")
    (root / "music" / "song.flac").write_text("song")
    return root.resolve()


def completed(lib: Path) -> Path:
    return lib / "downloads" / "qbittorrent" / "completed"


# ----------------------------------------------------------------------------- the root


def test_a_real_completed_root_inside_downloads_is_accepted(cd, lib):
    assert cd.confine_root(str(completed(lib)), str(lib)) == str(completed(lib))


def test_a_symlinked_completed_root_is_refused_and_nothing_in_the_library_is_touched(cd, lib):
    """The reviewer's attack: completed -> ../../movies (the apps' uid can plant the link)."""
    c = completed(lib)
    c.rmdir()
    os.symlink(lib / "movies", c)
    (lib / "movies" / "hit.exe").write_text("x")  # a blacklisted name inside the library
    out = subprocess.run(
        [
            sys.executable,
            "-I",
            str(FILES / "cleanup-downloads.py"),
            "--media-root",
            str(lib),
            "--completed-root",
            str(c),
        ],
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"]},
    )
    assert out.returncode == 2 and "refusing to run" in out.stderr
    assert (lib / "movies" / "film.mkv").is_file() and (lib / "movies" / "hit.exe").is_file()
    with pytest.raises(cd.UnsafeRoot):
        cd.confine_root(str(c), str(lib))


def test_a_link_in_the_path_a_root_outside_downloads_and_a_missing_root_are_refused(
    cd, lib, tmp_path
):
    real = tmp_path / "elsewhere"
    real.mkdir()
    link = lib / "downloads" / "via"
    os.symlink(completed(lib), link)
    for root in (link / "x", lib / "movies", real, lib / "downloads" / "nothing"):
        with pytest.raises(cd.UnsafeRoot):
            cd.confine_root(str(root), str(lib))


# ----------------------------------------------------------------------------- the walk


def test_a_symlinked_subdirectory_or_file_is_never_entered_or_removed(cd, lib):
    c = completed(lib)
    (c / "rel").mkdir()
    os.symlink(lib / "music", c / "rel" / "linked-dir")
    os.symlink(lib / "movies" / "film.mkv", c / "linked-file.mkv")
    (lib / "music" / "tool.exe").write_text("x")
    cd.confine_root(str(c), str(lib))
    cd.remove_blacklisted_files(str(c), ["*.exe", "*.flac"], dry_run=False)
    index = cd.build_library_inode_index(str(lib), cd.LIBRARY_DIRS)
    cd.remove_safe_files(str(c), index, set(), dry_run=False)
    assert (lib / "music" / "tool.exe").is_file() and (lib / "music" / "song.flac").is_file()
    assert (lib / "movies" / "film.mkv").is_file()
    assert (c / "linked-file.mkv").is_symlink()  # offered to nothing
    assert [p for _d, _n, p in cd.iter_files(str(c))] == []


def test_only_a_hardlinked_file_not_held_by_a_torrent_is_removed(cd, lib):
    c = completed(lib)
    (c / "a").mkdir()
    os.link(lib / "movies" / "film.mkv", c / "a" / "imported.mkv")  # hardlinked: safe
    (c / "a" / "not-imported.mkv").write_text("new")  # no library copy: left alone
    os.link(lib / "music" / "song.flac", c / "seeding.flac")  # hardlinked but a torrent holds it
    cd.confine_root(str(c), str(lib))
    index = cd.build_library_inode_index(str(lib), cd.LIBRARY_DIRS)
    cd.remove_safe_files(str(c), index, {str(c / "seeding.flac")}, dry_run=False)
    assert not (c / "a" / "imported.mkv").exists()
    assert (c / "a" / "not-imported.mkv").is_file() and (c / "seeding.flac").is_file()
    assert (lib / "movies" / "film.mkv").is_file()  # the library copy is untouched
    cd.remove_safe_files(str(c), index, set(), dry_run=True)  # a dry run removes nothing
    assert (c / "seeding.flac").is_file()


def test_safe_remove_refuses_a_link_and_a_path_outside_downloads(cd, lib):
    c = completed(lib)
    cd.confine_root(str(c), str(lib))
    os.symlink(lib / "movies" / "film.mkv", c / "l.mkv")
    with pytest.raises(OSError):
        cd.safe_remove(str(c / "l.mkv"))
    with pytest.raises(OSError):
        cd.safe_remove(str(lib / "movies" / "film.mkv"))
    assert (lib / "movies" / "film.mkv").is_file()


# ----------------------------------------------------------------------------- the blacklist


def test_the_blacklist_never_deletes_music_covers_or_books(cd, lib, tmp_path):
    c = completed(lib)
    keep = [
        "a.flac",
        "b.mp3",
        "c.m4a",
        "d.jpg",
        "e.png",
        "f.cue",
        "g.pdf",
        "h.epub",
        "i.cbz",
        "j.log",
        "k.nfo",
    ]
    for n in keep:
        (c / n).write_text("x")
    (c / "payload.exe").write_text("x")
    (c / "movie.sample.mkv").write_text("x")
    pats = tmp_path / "list.txt"
    pats.write_text("\n".join(f"*.{n.split('.')[1]}" for n in keep) + "\n*.exe\n*sample.mkv\n")
    loaded = cd.load_blacklist_patterns(str(pats))
    assert sorted(loaded) == ["*.exe", "*sample.mkv"]  # protected patterns are dropped at load
    cd.confine_root(str(c), str(lib))
    # even a list that names them cannot delete them
    cd.remove_blacklisted_files(
        str(c), ["*.flac", "*.mp3", "*.jpg", "*.pdf", "*.exe", "*sample.mkv"], False
    )
    assert all((c / n).is_file() for n in keep)
    assert not (c / "payload.exe").exists() and not (c / "movie.sample.mkv").exists()


def test_the_shipped_blacklist_holds_no_protected_pattern(cd):
    shipped = (FILES / "qbittorrent-excluded-file-names.txt").read_text().splitlines()
    assert (
        shipped
        and cd.load_blacklist_patterns(str(FILES / "qbittorrent-excluded-file-names.txt"))
        == shipped
    )
    for ext in (".flac", ".mp3", ".m4a", ".jpg", ".png", ".cue", ".pdf", ".cbz", ".log"):
        assert f"*{ext}" not in [p.lower() for p in shipped]
    assert "*.exe" in [p.lower() for p in shipped]


def test_empty_directory_removal_never_follows_or_removes_a_link(cd, lib):
    c = completed(lib)
    cd.confine_root(str(c), str(lib))
    (c / "empty").mkdir()
    os.symlink(lib / "shows", c / "to-shows")
    old = 0
    os.utime(c / "empty", (old, old))
    dirs = cd.find_empty_dirs(str(c), 3600)
    assert str(c / "empty") in dirs and str(c / "to-shows") not in dirs
    cd.remove_empty_dirs([str(c / "to-shows")], dry_run=False)
    assert (lib / "shows").is_dir() and (c / "to-shows").is_symlink()


# ----------------------------------------------------------------------------- the rename helper


@pytest.fixture
def rn(lib, monkeypatch):
    mod = load("rename_cleanup", "rename_cleanup.py")
    monkeypatch.setattr(mod, "LIBRARY_ROOT", str(lib))
    return mod


def test_a_rename_stays_inside_its_folder(rn, lib):
    show = lib / "shows" / "S"
    show.mkdir()
    (show / "a.[x].mkv").write_text("x")
    assert rn.rename_on_disk(str(show), "a.[x].mkv", "a.mkv") is True
    assert (show / "a.mkv").is_file()


@pytest.mark.parametrize(
    "old, new",
    [
        ("a.mkv", "../../movies/stolen.mkv"),
        ("../../movies/film.mkv", "film.mkv"),
        ("/etc/passwd", "p"),
        ("a.mkv", "/tmp/out.mkv"),
    ],
)
def test_a_rename_that_leaves_the_folder_is_refused(rn, lib, old, new):
    show = lib / "shows" / "S"
    show.mkdir()
    (show / "a.mkv").write_text("x")
    assert rn.rename_on_disk(str(show), old, new) is False
    assert (lib / "movies" / "film.mkv").is_file() and (show / "a.mkv").is_file()


def test_a_rename_refuses_a_link_and_a_folder_that_resolves_outside_the_library(rn, lib, tmp_path):
    show = lib / "shows" / "S"
    show.mkdir()
    os.symlink(lib / "movies" / "film.mkv", show / "l.mkv")
    assert rn.rename_on_disk(str(show), "l.mkv", "m.mkv") is False
    outside = tmp_path / "out"
    outside.mkdir()
    os.symlink(outside, lib / "shows" / "esc")
    (outside / "a.mkv").write_text("x")
    assert rn.rename_on_disk(str(lib / "shows" / "esc"), "a.mkv", "b.mkv") is False
    assert (outside / "a.mkv").is_file()
