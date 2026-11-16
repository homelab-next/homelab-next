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
    with pytest.raises(mm.ImportFailed, match="already holds a data root"):
        mm.import_config(src, dst)
    mm.import_config(src, dst, replace=True)  # explicit: the old root is moved aside, not deleted
    assert (tmp_path / "dst.before-import" / "data" / "device.txt").is_file()
    assert (dst / "data" / "device.txt").read_text() == SERVER_ID


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


# ----------------------------------------------------------------------------- review hardening


def test_replace_never_touches_the_source(src, tmp_path):
    before = sorted(str(p.relative_to(src)) for p in src.rglob("*"))
    with pytest.raises(mm.ImportFailed, match="the source, or inside or around it"):
        mm.import_config(src, src, replace=True)
    with pytest.raises(mm.ImportFailed, match="inside or around"):
        mm.import_config(src, src / "data" / "inner", replace=True)
    with pytest.raises(mm.ImportFailed, match="inside or around"):
        mm.import_config(src, src.parent, replace=True)
    assert sorted(str(p.relative_to(src)) for p in src.rglob("*")) == before


def test_replace_refuses_root_shallow_and_unrelated_directories(src, tmp_path):
    for bad in ("/", "/srv", "/srv/media"):
        with pytest.raises(mm.ImportFailed, match="too shallow"):
            mm.import_config(src, Path(bad), replace=True)
    other = tmp_path / "other" / "precious"
    other.mkdir(parents=True)
    (other / "keep.txt").write_text("keep")
    with pytest.raises(mm.ImportFailed, match="not a media server data root"):
        mm.import_config(src, other, replace=True)
    assert (other / "keep.txt").read_text() == "keep"
    assert not (tmp_path / "other" / "precious.partial").exists()


def test_a_target_outside_the_data_root_or_around_a_library_root_is_refused(src, tmp_path):
    with pytest.raises(mm.ImportFailed, match="outside the module's data root"):
        mm.import_config(src, tmp_path / "x" / "y" / "dst", data_root=tmp_path / "elsewhere")
    lib = tmp_path / "lib" / "media" / "movies"
    with pytest.raises(mm.ImportFailed, match="library root"):
        mm.import_config(src, tmp_path / "lib" / "media", {"/media": str(lib)})


def test_a_failed_import_leaves_the_previous_target_intact(src, tmp_path, monkeypatch):
    dst = tmp_path / "dst"
    mm.import_config(src, dst)
    marker = dst / "marker"
    marker.write_text("previous")

    real = mm._copy_db

    def lossy(s, d):
        real(s, d)
        c = sqlite3.connect(d)
        c.execute("DELETE FROM Users WHERE Id = 'u2'") if c.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'Users'"
        ).fetchone() else None
        c.commit()
        c.close()

    monkeypatch.setattr(mm, "_copy_db", lossy)
    with pytest.raises(mm.ImportFailed, match="counts differ"):
        mm.import_config(src, dst, replace=True)
    assert marker.read_text() == "previous" and (dst / "data" / "device.txt").exists()
    assert (tmp_path / "dst.partial").is_dir()  # kept for inspection
    with pytest.raises(mm.ImportFailed, match="left by an earlier import"):
        mm.import_config(src, dst, replace=True)


def test_an_unrecognised_schema_or_zero_users_is_not_verified(tmp_path):
    root = tmp_path / "s" / "a" / "src"
    (root / "data").mkdir(parents=True)
    (root / "data" / "device.txt").write_text(SERVER_ID)
    c = sqlite3.connect(root / "data" / "main.db")
    c.execute("CREATE TABLE Foo (x)")
    c.commit()
    c.close()
    with pytest.raises(mm.ImportFailed, match="unrecognised schema"):
        mm.import_config(root, tmp_path / "t" / "a" / "dst")
    c = sqlite3.connect(root / "data" / "main.db")
    c.execute("CREATE TABLE Users (Id TEXT)")
    c.execute("CREATE TABLE Devices (Id INTEGER)")
    c.commit()
    c.close()
    with pytest.raises(mm.ImportFailed, match="no users"):
        mm.import_config(root, tmp_path / "t" / "a" / "dst")
    mm.import_config(root, tmp_path / "t" / "a" / "dst", allow_empty=True)


def test_relative_and_missing_inputs_are_clean_refusals(src, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(src.parent)
    assert mm.counts(Path("src"))["users"] == 2  # a relative DIR is resolved
    assert mm.main(["counts", "nowhere"]) == 1
    assert "is this a config/data directory" in capsys.readouterr().err
    # a source with no config/ directory still imports; system.xml is created with Quick Connect
    import shutil

    shutil.rmtree(src / "config")
    mm.import_config(src, tmp_path / "t" / "a" / "dst")
    assert (
        "QuickConnectAvailable"
        in (tmp_path / "t" / "a" / "dst" / "config" / "system.xml").read_text()
    )


def test_host_paths_are_blanked_or_reported_and_symlinks_listed(src, tmp_path):
    (src / "config" / "system.xml").write_text(
        "<ServerConfiguration>\n  <MetadataPath>/mnt/bulk/metadata</MetadataPath>\n"
        "  <CachePath>/cache</CachePath>\n  <CertificatePath>/etc/ssl/old.pfx</CertificatePath>\n"
        "</ServerConfiguration>\n"
    )
    (src / "config" / "encoding.xml").write_text(
        "<EncodingOptions>\n  <EncoderAppPath>/usr/lib/old/ffmpeg</EncoderAppPath>\n"
        "  <HardwareAccelerationType>nvenc</HardwareAccelerationType>\n</EncodingOptions>\n"
    )
    bulk = src.parent / "bulk"
    bulk.mkdir()
    (src / "metadata").symlink_to(bulk, target_is_directory=True)
    (src / "config" / "link.xml").symlink_to(src / "config" / "system.xml")
    dst = tmp_path / "t" / "a" / "dst"
    rep = mm.import_config(src, dst)
    sysx = (dst / "config" / "system.xml").read_text()
    assert "<MetadataPath></MetadataPath>" in sysx and "<CachePath>/cache</CachePath>" in sysx
    assert "<EncoderAppPath></EncoderAppPath>" in (dst / "config" / "encoding.xml").read_text()
    assert any("MetadataPath=/mnt/bulk/metadata" in x for x in rep["changes"]["host_paths_blanked"])
    assert rep["host_paths"] == ["system.xml:CertificatePath=/etc/ssl/old.pfx"]
    assert sorted(rep["skipped_symlinks"]) == ["config/link.xml", "metadata"]
    with pytest.raises(mm.ImportFailed, match="may not have"):
        mm.import_config(src, tmp_path / "t" / "a" / "dst2", strict=True)


def test_map_rules_apply_in_one_pass_and_a_root_prefix_is_refused():
    rw = mm._rewriter({"/a": "/b", "/b": "/c"})
    assert rw("/a/x") == "/b/x" and rw("/b/y") == "/c/y"  # no chaining
    rw = mm._rewriter({"/media": "/srv/m", "/media/old": "/srv/o"})
    assert rw("/media/old/x") == "/srv/o/x"  # the longest prefix wins
    with pytest.raises(mm.ImportFailed, match="root prefix"):
        mm._rewriter({"/": "/srv"})
    with pytest.raises(mm.ImportFailed, match="root prefix"):
        mm._rewriter({"": "/srv"})


def test_blob_columns_are_rewritten_when_json_and_refused_when_binary(tmp_path):
    root = make_source(tmp_path / "src", legacy=True)
    c = sqlite3.connect(root / "data" / "library.db")
    c.execute("CREATE TABLE Blobs (id INT, data BLOB)")
    c.execute("INSERT INTO Blobs VALUES (1, ?)", (b'{"Path":"/media/movies/a/a.mkv"}',))
    c.commit()
    c.close()
    dst = tmp_path / "t" / "a" / "dst"
    mm.import_config(root, dst, {"/media": "/srv/media"})
    c = sqlite3.connect(dst / "data" / "library.db")
    (v,) = c.execute("SELECT data FROM Blobs").fetchone()
    assert isinstance(v, bytes) and v == b'{"Path":"/srv/media/movies/a/a.mkv"}'
    c.close()
    # a binary (non-JSON) blob that holds an old path is refused, listing where
    c = sqlite3.connect(root / "data" / "library.db")
    c.execute("UPDATE Blobs SET data = ?", (b"\x0a\x14/media/movies/a.mkv\x00",))
    c.commit()
    c.close()
    with pytest.raises(mm.ImportFailed, match=r"library\.db:Blobs\.data"):
        mm.import_config(root, tmp_path / "t" / "a" / "dst2", {"/media": "/srv/media"})


def test_crlf_survives_and_identity_bytes_and_tokens_are_kept(src, tmp_path):
    (src / "root" / "default" / "Movies" / "options.xml").write_bytes(
        b"<LibraryOptions>\r\n<Path>/media/movies</Path>\r\n</LibraryOptions>\r\n"
    )
    dst = tmp_path / "t" / "a" / "dst"
    mm.import_config(src, dst, {"/media": "/srv/media"})
    out = (dst / "root" / "default" / "Movies" / "options.xml").read_bytes()
    assert out == b"<LibraryOptions>\r\n<Path>/srv/media/movies</Path>\r\n</LibraryOptions>\r\n"
    assert (dst / "data" / "device.txt").read_bytes() == (src / "data" / "device.txt").read_bytes()
    assert mm._device_tokens(dst) == mm._device_tokens(src) == ["tok-a", "tok-b", "tok-c"]


def test_a_remaining_old_prefix_fails_the_import(src, tmp_path, monkeypatch):
    monkeypatch.setattr(mm, "_rewrite_db", lambda *a, **k: 0)  # a rewrite that silently did nothing
    with pytest.raises(mm.ImportFailed, match="old library prefix remains"):
        mm.import_config(src, tmp_path / "t" / "a" / "dst", {"/media": "/srv/media"})
