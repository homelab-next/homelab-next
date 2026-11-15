# SPDX-License-Identifier: Apache-2.0
"""tools/migrate/jellyfin.py against a fixture config/data directory built here (both schema
generations): the import keeps the server id, users, devices and watch state byte for byte in
meaning, rewrites only real library paths, resets hardware acceleration, keeps Quick Connect on,
and refuses a result whose counts differ from its source."""

from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "migrate_media", ROOT / "tools" / "migrate" / "jellyfin.py"
)
mm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mm)

SERVER_ID = "0123456789abcdef0123456789abcdef"


def make_source(root: Path, *, legacy: bool = False) -> Path:
    """A small config/data directory: 2 users, 3 devices, 2 libraries, 4 items, 3 watch rows."""
    (root / "data").mkdir(parents=True)
    (root / "config").mkdir()
    (root / "root" / "default" / "Movies").mkdir(parents=True)
    (root / "root" / "default" / "Shows").mkdir()
    (root / "cache").mkdir()
    (root / "cache" / "junk").write_text("x")
    (root / "log").mkdir()
    (root / "data" / "device.txt").write_text(SERVER_ID)
    (root / "root" / "default" / "Movies" / "movies.mblink").write_text("/media/movies")
    (root / "root" / "default" / "Movies" / "options.xml").write_text(
        "<LibraryOptions><PathInfos><MediaPathInfo><Path>/media/movies</Path></MediaPathInfo>"
        "</PathInfos></LibraryOptions>"
    )
    (root / "config" / "system.xml").write_text(
        "<ServerConfiguration>\n  <ServerName>homeflix</ServerName>\n"
        "  <QuickConnectAvailable>false</QuickConnectAvailable>\n</ServerConfiguration>\n"
    )
    (root / "config" / "encoding.xml").write_text(
        "<EncodingOptions>\n  <HardwareAccelerationType>nvenc</HardwareAccelerationType>\n"
        "  <EnableHardwareEncoding>true</EnableHardwareEncoding>\n</EncodingOptions>\n"
    )
    main = sqlite3.connect(root / "data" / "main.db")
    main.execute("CREATE TABLE Users (Id TEXT PRIMARY KEY, Username TEXT, Password TEXT)")
    main.execute(
        "CREATE TABLE Devices (Id INTEGER PRIMARY KEY, AccessToken TEXT, DeviceId TEXT, UserId TEXT)"
    )
    main.executemany(
        "INSERT INTO Users VALUES (?,?,?)",
        [("u1", "mum", "$pbkdf2$aa"), ("u2", "kid", "$pbkdf2$bb")],
    )
    main.executemany(
        "INSERT INTO Devices VALUES (?,?,?,?)",
        [
            (1, "tok-a", "firecube-1", "u1"),
            (2, "tok-b", "firecube-2", "u2"),
            (3, "tok-c", "phone", "u1"),
        ],
    )
    items = [
        ("i1", "Movie", "/media/movies/a/a.mkv", '{"Path":"/media/movies/a/a.mkv"}'),
        ("i2", "Movie", "/media/movies/b/b.mkv", '{"Path":"/media/movies/b/b.mkv"}'),
        ("i3", "Episode", "/media/shows/s/e1.mkv", '{"Path":"/media/shows/s/e1.mkv"}'),
        # a path that merely contains the prefix, and an indexer-style URL: neither is a library path
        ("i4", "Other", "/mydata/media/x", '{"Url":"http://idx.example.internal/media/feed"}'),
    ]
    if legacy:
        main.execute("CREATE TABLE UserDatas (key TEXT, userId TEXT, played INT)")
        main.executemany(
            "INSERT INTO UserDatas VALUES (?,?,?)",
            [("i1", "u1", 1), ("i2", "u1", 0), ("i3", "u2", 1)],
        )
        main.commit()
        main.close()
        lib = sqlite3.connect(root / "data" / "library.db")
        lib.execute("CREATE TABLE TypedBaseItems (guid TEXT, type TEXT, Path TEXT, data TEXT)")
        lib.executemany("INSERT INTO TypedBaseItems VALUES (?,?,?,?)", items)
        lib.commit()
        lib.close()
    else:
        main.execute("CREATE TABLE UserData (ItemId TEXT, UserId TEXT, Played INT)")
        main.execute("CREATE TABLE BaseItems (Id TEXT, Type TEXT, Path TEXT, Data TEXT)")
        main.executemany(
            "INSERT INTO UserData VALUES (?,?,?)",
            [("i1", "u1", 1), ("i2", "u1", 0), ("i3", "u2", 1)],
        )
        main.executemany("INSERT INTO BaseItems VALUES (?,?,?,?)", items)
        main.commit()
        main.close()
    return root


@pytest.fixture(params=[False, True], ids=["current", "legacy"])
def src(request, tmp_path):
    return make_source(tmp_path / "src", legacy=request.param)


def test_counts(src):
    assert mm.counts(src) == {
        "users": 2,
        "devices": 3,
        "libraries": 2,
        "items": 4,
        "watch_state": 3,
    }
    assert mm.server_id(src) == SERVER_ID
    assert mm.libraries(src) == ["Movies", "Shows"]


def test_counts_refuses_a_directory_that_is_not_a_config(tmp_path):
    with pytest.raises(mm.ImportFailed):
        mm.counts(tmp_path)


def test_import_keeps_identity_and_counts_and_maps_paths(src, tmp_path):
    dst = tmp_path / "dst"
    rep = mm.import_config(src, dst, {"/media": "/srv/media"})
    assert rep["source"] == rep["target"] == mm.counts(dst)
    assert mm.server_id(dst) == SERVER_ID
    assert (dst / "data" / "device.txt").read_bytes() == (src / "data" / "device.txt").read_bytes()
    # users and devices survive with their ids and tokens
    c = sqlite3.connect(dst / "data" / "main.db")
    assert c.execute("SELECT Username, Password FROM Users ORDER BY Id").fetchall() == [
        ("mum", "$pbkdf2$aa"), ("kid", "$pbkdf2$bb")]  # fmt: skip
    assert c.execute("SELECT AccessToken, DeviceId FROM Devices WHERE Id = 1").fetchone() == (
        "tok-a",
        "firecube-1",
    )
    c.close()
    # paths: the library moved, a lookalike and a URL did not
    db = "library.db" if (src / "data" / "library.db").exists() else "main.db"
    table, pcol, dcol = (
        ("TypedBaseItems", "Path", "data") if db == "library.db" else ("BaseItems", "Path", "Data")
    )
    c = sqlite3.connect(dst / "data" / db)
    got = dict(c.execute(f"SELECT {pcol}, {dcol} FROM {table}").fetchall())
    assert (
        "/srv/media/movies/a/a.mkv" in got
        and got["/srv/media/movies/a/a.mkv"] == '{"Path":"/srv/media/movies/a/a.mkv"}'
    )
    assert "/mydata/media/x" in got and "idx.example.internal/media/feed" in got["/mydata/media/x"]
    c.close()
    assert (
        dst / "root" / "default" / "Movies" / "movies.mblink"
    ).read_text() == "/srv/media/movies"
    assert (
        "<Path>/srv/media/movies</Path>"
        in (dst / "root" / "default" / "Movies" / "options.xml").read_text()
    )
    # the source is untouched
    assert (src / "root" / "default" / "Movies" / "movies.mblink").read_text() == "/media/movies"
    s = sqlite3.connect(src / "data" / db)
    assert s.execute(
        f"SELECT {pcol} FROM {table} WHERE guid_or_id = 'i1'".replace(
            "guid_or_id", "guid" if db == "library.db" else "Id"
        )
    ).fetchone() == ("/media/movies/a/a.mkv",)
    s.close()


def test_import_resets_acceleration_and_keeps_quick_connect_on(src, tmp_path):
    dst = tmp_path / "dst"
    rep = mm.import_config(src, dst)
    enc = (dst / "config" / "encoding.xml").read_text()
    assert "<HardwareAccelerationType>none</HardwareAccelerationType>" in enc
    assert "<EnableHardwareEncoding>true</EnableHardwareEncoding>" in enc  # nothing else touched
    sysx = (dst / "config" / "system.xml").read_text()
    assert "<QuickConnectAvailable>true</QuickConnectAvailable>" in sysx
    assert "<ServerName>homeflix</ServerName>" in sysx
    assert rep["changes"]["hardware_accel"] == "none" and rep["changes"]["quick_connect"] is True


def test_import_can_keep_the_old_acceleration(src, tmp_path):
    dst = tmp_path / "dst"
    mm.import_config(src, dst, hardware_accel=None)
    assert "nvenc" in (dst / "config" / "encoding.xml").read_text()


def test_import_creates_system_xml_with_quick_connect_when_absent(src, tmp_path):
    (src / "config" / "system.xml").unlink()
    dst = tmp_path / "dst"
    mm.import_config(src, dst)
    assert (
        "<QuickConnectAvailable>true</QuickConnectAvailable>"
        in (dst / "config" / "system.xml").read_text()
    )


def test_import_skips_caches_and_logs(src, tmp_path):
    dst = tmp_path / "dst"
    mm.import_config(src, dst)
    assert not (dst / "cache").exists() and not (dst / "log").exists()


def test_import_refuses_a_target_that_already_has_a_database(src, tmp_path):
    dst = tmp_path / "dst"
    mm.import_config(src, dst)
    with pytest.raises(mm.ImportFailed, match="already holds a database"):
        mm.import_config(src, dst)
    mm.import_config(src, dst, replace=True)  # explicit


def test_import_fails_when_the_counts_differ(src, tmp_path, monkeypatch):
    real = mm._copy_db

    def lossy(s, d):
        real(s, d)
        c = sqlite3.connect(d)
        for t in ("Users",):
            if c.execute("SELECT 1 FROM sqlite_master WHERE name = ?", (t,)).fetchone():
                c.execute(f"DELETE FROM {t} WHERE Id = 'u2'")
        c.commit()
        c.close()

    monkeypatch.setattr(mm, "_copy_db", lossy)
    with pytest.raises(mm.ImportFailed, match="counts differ"):
        mm.import_config(src, tmp_path / "dst")


def test_import_without_a_server_id_is_refused(src, tmp_path):
    (src / "data" / "device.txt").unlink()
    with pytest.raises(mm.ImportFailed, match="no server id"):
        mm.import_config(src, tmp_path / "dst")


def test_cli_counts_and_import(src, tmp_path, capsys):
    assert mm.main(["counts", str(src)]) == 0
    assert SERVER_ID in capsys.readouterr().out
    assert mm.main(["import", str(src), str(tmp_path / "dst"), "--map", "/media=/srv/media"]) == 0
    assert mm.counts(tmp_path / "dst")["users"] == 2
    assert (
        mm.main(["import", str(src), str(tmp_path / "dst")]) == 1
    )  # target already holds a database


def test_map_boundaries():
    rw = mm._rewriter({"/media": "/srv/media"})
    assert rw("/media") == "/srv/media"
    assert rw("/media/x") == "/srv/media/x"
    assert rw("<Path>/media</Path>") == "<Path>/srv/media</Path>"
    assert rw("/media2/x") == "/media2/x"
    assert rw("/mydata/media/x") == "/mydata/media/x"
    assert rw("http://h/media/x") == "http://h/media/x"
