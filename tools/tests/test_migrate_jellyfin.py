# SPDX-License-Identifier: Apache-2.0
"""tools/migrate/jellyfin.py against a fixture config/data directory built here (both schema
generations): the import keeps the server id, users, devices and watch state byte for byte in
meaning, rewrites only real library paths, resets hardware acceleration, keeps Quick Connect on,
and refuses a result whose counts differ from its source. Both counts and import refuse a source a
newer server migrated (a downgrade), judged against modules/media/known-migrations.json, which is
checked here against the module's pin; its generator runs against a small git repository."""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "migrate_media", ROOT / "tools" / "migrate" / "jellyfin.py"
)
mm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mm)

SERVER_ID = "0123456789abcdef0123456789abcdef"


def v4(*parts: int) -> str:
    """A version as the history records a server's (four parts), built at run time."""
    return ".".join(map(str, parts))


RAW_KNOWN = json.loads((ROOT / "modules" / "media" / "known-migrations.json").read_text())
KNOWN = mm.load_known()
# a schema migration and a code migration the pinned version knows, as the server records them
HISTORY = [
    ("20200514181226_AddActivityLog", "9.0.11"),
    ("20260113233500_DropExtraIdsColumn", "10.0.11"),
    ("20250420090000_AddDefaultPluginRepository", v4(10, 11, 11, 0)),
    ("20260911120000_StripEmbeddedLinkedChildren", KNOWN["product_version"] + ".0.0"),
]
# what the release after the pinned one added: the target does not know it
NEWER = ("20260912120000_HarmonizeConflictingUserData", v4(12, 2, 0, 0))


def add_history(db: Path, rows) -> None:
    c = sqlite3.connect(db)
    c.execute(
        'CREATE TABLE IF NOT EXISTS "__EFMigrationsHistory" '
        "(MigrationId TEXT PRIMARY KEY, ProductVersion TEXT NOT NULL)"
    )
    c.executemany('INSERT INTO "__EFMigrationsHistory" VALUES (?, ?)', rows)
    c.commit()
    c.close()


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
    # the earlier layout's database knew schema migrations only
    add_history(root / "data" / "main.db", HISTORY[:1] if legacy else HISTORY)
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
    # no migration history: nothing proves the target can open it
    with pytest.raises(mm.ImportFailed, match="__EFMigrationsHistory rows"):
        mm.import_config(root, tmp_path / "t" / "a" / "dst", allow_empty=True)
    add_history(root / "data" / "main.db", HISTORY)
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


# ----------------------------------------------------------------------------- no downgrade


def test_the_known_migrations_are_the_pinned_versions():
    """The list the importer judges a source by is the one of the version the module pins."""
    manifest = yaml.safe_load((ROOT / "modules" / "media" / "module.yml").read_text())
    pinned = manifest["product"]["version"]
    assert isinstance(pinned, str)  # quoted: 12.10 must not read as 12.1
    image = yaml.safe_load(
        (ROOT / "modules" / "media" / "roles" / "media" / "defaults" / "main.yml").read_text()
    )["media_image"]
    assert image.split("@")[0].rsplit(":", 1)[1] == pinned == KNOWN["product_version"]
    assert mm.pinned_version() == pinned
    assert KNOWN["source"]["tag"] == "v" + pinned and len(KNOWN["source"]["commit"]) == 40
    assert KNOWN["source"]["releases"][-1] == "v" + pinned
    for kind in ("database", "code"):
        ids = KNOWN[kind]
        assert ids == sorted(set(ids)) and all(mm._MIGRATION_ID.fullmatch(i) for i in ids)
        # stored as [time, name] pairs, as the generator writes them
        assert ["_".join(x) for x in RAW_KNOWN[kind]] == ids
    assert (
        mm.dump_known(KNOWN) == (ROOT / "modules" / "media" / "known-migrations.json").read_text()
    )
    # the newest migration of the 2026-11-17 source is known; what the next release added is not
    assert "20260911120000_StripEmbeddedLinkedChildren" in KNOWN["code"]
    assert "20260113233500_DropExtraIdsColumn" in KNOWN["database"]
    assert NEWER[0] not in KNOWN["code"] + KNOWN["database"]


def test_a_list_for_another_version_than_the_pin_is_refused(tmp_path):
    other = tmp_path / "known.json"
    other.write_text(json.dumps({**RAW_KNOWN, "product_version": "12.0"}))
    with pytest.raises(
        mm.ImportFailed, match=r"lists the migrations of 12\.0 but the module pins 12\.1"
    ):
        mm.load_known(other, expect_version=mm.pinned_version())
    other.write_text(json.dumps({**RAW_KNOWN, "code": [["2026", "x y"]]}))
    with pytest.raises(mm.ImportFailed, match="malformed migration ids"):
        mm.load_known(other)
    other.write_text(json.dumps({"product_version": "12.1", "database": [], "code": []}))
    with pytest.raises(mm.ImportFailed, match="not a known-migrations list"):
        mm.load_known(other)


def test_a_source_a_newer_server_migrated_is_refused_by_import_and_counts(src, tmp_path, capsys):
    """2026-11-17: a source with migrations the pinned server did not know was imported; the server
    then failed to start on it ("no such column")."""
    add_history(src / "data" / "main.db", [NEWER])
    dst = tmp_path / "t" / "a" / "dst"
    with pytest.raises(mm.ImportFailed) as e:
        mm.import_config(src, dst, {"/media": "/srv/media"})
    msg = str(e.value)
    assert "1 migration(s) the target does not know" in msg
    assert f"20260912120000_HarmonizeConflictingUserData (recorded as {NEWER[1]})" in msg
    assert f"than the target {KNOWN['product_version']}" in msg and "downgrade" in msg
    assert not dst.exists() and not dst.with_name("dst.partial").exists()  # nothing was made
    assert mm.main(["counts", str(src)]) == 1
    assert "HarmonizeConflictingUserData" in capsys.readouterr().err
    assert mm.main(["import", str(src), str(dst)]) == 1
    assert "does not know" in capsys.readouterr().err


def test_a_known_migration_a_newer_server_wrote_is_refused(tmp_path):
    src = make_source(tmp_path / "src")
    c = sqlite3.connect(src / "data" / "main.db")
    c.execute(
        'UPDATE "__EFMigrationsHistory" SET ProductVersion = ? WHERE MigrationId = ?',
        (NEWER[1], "20250420090000_AddDefaultPluginRepository"),
    )
    c.commit()
    c.close()
    with pytest.raises(
        mm.ImportFailed, match=r"1 written by a newer version: .*\(written by 12\.2\.0\.0\)"
    ):
        mm.import_config(src, tmp_path / "t" / "a" / "dst")


def test_a_schema_rows_library_version_is_not_taken_for_the_server(tmp_path):
    """A schema migration's row carries the database library's version, not the server's; only
    code migrations say which server ran them. A library version above the target's is no refusal."""
    src = make_source(tmp_path / "src")
    c = sqlite3.connect(src / "data" / "main.db")
    c.execute(
        'UPDATE "__EFMigrationsHistory" SET ProductVersion = ? WHERE MigrationId = ?',
        ("99.0.1", "20200514181226_AddActivityLog"),
    )
    c.commit()
    c.close()
    got = mm.check_schema(src)
    assert got == {
        "target_version": KNOWN["product_version"],
        "migrations": len(HISTORY),
        "newest_migration": "20260911120000_StripEmbeddedLinkedChildren",
        "newest_server_version": KNOWN["product_version"] + ".0.0",
    }


def test_an_asserted_source_version_newer_than_the_target_is_refused(src, tmp_path, capsys):
    dst = tmp_path / "t" / "a" / "dst"
    with pytest.raises(mm.ImportFailed, match=r"the source server is 12\.4, newer than the target"):
        mm.import_config(src, dst, source_version="12.4")
    assert mm.main(["import", str(src), str(dst), "--source-version", "12.4"]) == 1
    assert (
        mm.main(["import", str(src), str(dst), "--source-version", KNOWN["product_version"]]) == 0
    )
    assert '"target_version"' in capsys.readouterr().out


def test_counts_prints_the_schema_and_the_id_without_the_byte_order_mark(src, capsys):
    """The server writes data/device.txt with a UTF-8 byte order mark."""
    (src / "data" / "device.txt").write_bytes(b"\xef\xbb\xbf" + SERVER_ID.encode())
    assert mm.server_id(src) == SERVER_ID
    assert mm.main(["counts", str(src)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["server_id"] == SERVER_ID and out["schema"]["migrations"] >= 1


def test_the_import_report_prints_the_id_without_the_mark_and_keeps_the_bytes(src, tmp_path):
    raw = b"\xef\xbb\xbf" + SERVER_ID.encode()
    (src / "data" / "device.txt").write_bytes(raw)
    dst = tmp_path / "t" / "a" / "dst"
    rep = mm.import_config(src, dst)
    assert rep["server_id"] == SERVER_ID
    assert (dst / "data" / "device.txt").read_bytes() == raw  # carried byte for byte


def test_a_taken_before_import_name_gets_the_next_free_one(src, tmp_path):
    """A second (or third) import over an imported target: the earlier aside is never touched."""
    dst = tmp_path / "t" / "a" / "dst"
    mm.import_config(src, dst)
    (dst / "first").write_text("1")
    mm.import_config(src, dst, replace=True)
    (dst / "second").write_text("2")
    (tmp_path / "t" / "a" / "dst.before-import.2").symlink_to(
        tmp_path / "nowhere"
    )  # dangling: taken
    rep = mm.import_config(src, dst, replace=True)
    assert (tmp_path / "t" / "a" / "dst.before-import" / "first").read_text() == "1"
    assert rep["previous_target"] == str(tmp_path / "t" / "a" / "dst.before-import.3")
    assert (tmp_path / "t" / "a" / "dst.before-import.3" / "second").read_text() == "2"
    assert (tmp_path / "t" / "a" / "dst.before-import.2").is_symlink()


def test_every_aside_name_taken_is_refused_before_anything_is_made(src, tmp_path, monkeypatch):
    dst = tmp_path / "t" / "a" / "dst"
    mm.import_config(src, dst)
    monkeypatch.setattr(mm, "ASIDE_MAX", 2)
    (tmp_path / "t" / "a" / "dst.before-import").mkdir()
    (tmp_path / "t" / "a" / "dst.before-import.2").mkdir()
    with pytest.raises(mm.ImportFailed, match="all exist"):
        mm.import_config(src, dst, replace=True)
    assert not (tmp_path / "t" / "a" / "dst.partial").exists()


# ----------------------------------------------------------------------------- the generator


def _git(repo: Path, *args: str, when: int = 0) -> None:
    stamp = f"@{1700000000 + when} +0000"
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.internal",
        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.internal",
        GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp,
    )  # fmt: skip
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def _release(repo: Path, tag: str, when: int, files: dict[str, str | None]) -> None:
    for rel, text in files.items():
        f = repo / rel
        if text is None:
            f.unlink()
            continue
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    _git(repo, "add", "-A", when=when)
    _git(repo, "commit", "-qm", tag, when=when)
    _git(repo, "tag", "-a", tag, "-m", tag, when=when)


def _ef(mid: str) -> str:
    return f'namespace X;\n[DbContext(typeof(Db))]\n[Migration("{mid}")]\npartial class M {{}}\n'


def _code(when: str, name: str, literal: bool = False) -> str:
    ref = f'"{name}"' if literal else f"nameof({name})"
    return f'[JellyfinMigration("{when}", {ref}, Stage = S.Core)]\npublic class {name} {{}}\n'


def test_the_generator_reads_every_release_up_to_the_version(tmp_path):
    repo = tmp_path / "src"
    repo.mkdir()
    _git(repo, "init", "-q")
    db, code = "src/Db/Migrations", "Server/Migrations/Routines"
    _release(repo, "v1.0", 0, {
        f"{db}/20200101000000_First.Designer.cs": _ef("20200101000000_First"),
        f"{code}/Old.cs": _code("2025-04-20T09:00:00", "Old"),
        "tests/Server.Tests/Migrations/Fake.cs": _code("2030-01-01T00:00:00", "TestOnly"),
    })  # fmt: skip
    _release(repo, "v2.0-rc1", 10, {f"{code}/Pre.cs": _code("2026-01-01T00:00:00", "Pre", True)})
    _release(repo, "v2.0", 20, {  # Old was removed: a database that ran it is still one 2.0 opens
        f"{code}/Old.cs": None,
        f"{db}/20260101000000_Second.Designer.cs": _ef("20260101000000_Second"),
    })  # fmt: skip
    # tagged after 2.0: a later patch of the older line, and the next release
    _release(repo, "v1.1", 30, {f"{code}/Patch.cs": _code("2026-06-01T00:00:00", "Patch")})
    _release(repo, "v2.1", 40, {f"{code}/Next.cs": _code("2026-09-12T12:00:00", "Next")})
    got = mm.known_migrations(repo, "2.0")
    assert got["product_version"] == "2.0" and got["source"]["tag"] == "v2.0"
    assert got["source"]["releases"] == ["v1.0", "v2.0-rc1", "v2.0"]
    assert got["database"] == ["20200101000000_First", "20260101000000_Second"]
    assert got["code"] == ["20250420090000_Old", "20260101000000_Pre"]
    out = tmp_path / "known.json"
    assert (
        mm.main(["known-migrations", "--repo", str(repo), "--version", "2.1", "--out", str(out)])
        == 0
    )
    assert "20260912120000_Next" in mm.load_known(out)["code"]
    with pytest.raises(mm.ImportFailed, match=r"no release tag v9\.9"):
        mm.known_migrations(repo, "9.9")
