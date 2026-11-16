# SPDX-License-Identifier: Apache-2.0
"""tools/migrate/media_automation.py against a fixture config root built here (no product's real
file is shipped): the import keeps every app's identity file byte for byte, rewrites library paths
and host names in databases, settings files and the torrent client's resume files, refuses an
unrecognised or empty source, never prints a secret, and every destructive-operation guard refuses.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "migrate_media_automation", ROOT / "tools" / "migrate" / "media_automation.py"
)
mm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mm)

SQL = list(mm.SQL_APPS)  # the apps that keep a SQLite database and a config.xml
CLIENT = "qbittorrent"
USENET = "nzbget"
REQUESTS = mm.ALL_APPS[-2]  # the request app
TRANSCODE = "tdarr"
# runtime-built values: nothing here looks like a key to a secret scanner
KEYS = {app: (app[0] * 32) for app in SQL}
PASSWORD = "pw-" + "z" * 12
OLD, NEW = "/media", "/srv/media"
IP_HOST = ".".join(str(n) for n in (192, 0, 2, 9))  # a documentation address, built here


def _db(path: Path, tables: tuple[str, ...], rows: dict[str, list[tuple]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    for t in tables:
        c.execute(
            f'CREATE TABLE "{t}" (Id INTEGER PRIMARY KEY, Path TEXT, Settings TEXT, Version INTEGER)'
        )
    for t, rs in rows.items():
        c.executemany(f'INSERT INTO "{t}" (Path, Settings, Version) VALUES (?,?,?)', rs)
    c.commit()
    c.close()


def build_source(root: Path, *, ip_host: bool = False) -> Path:
    for app in SQL:
        dbname, need, *_ = mm.SQL_APPS[app]
        base = root / app
        base.mkdir(parents=True)
        (base / "config.xml").write_text(f"<Config><ApiKey>{KEYS[app]}</ApiKey></Config>\n")
        (base / "logs").mkdir()
        (base / "logs" / "x.txt").write_text("noise")
        (base / "logs.db").write_text("not carried")
        (base / "MediaCover").mkdir()
        (base / "MediaCover" / "a.jpg").write_text("cover")
        (base / f"{dbname}.bak-20260101").write_text("not carried")
        host = IP_HOST if ip_host else "media-core-gluetun"
        client = json.dumps({"host": host, "port": 8080, "password": PASSWORD})
        idx = json.dumps({"baseUrl": "http://media-core-prowlarr/2/", "apiKey": "k" * 8})
        rows: dict[str, list[tuple]] = {"VersionInfo": [(None, None, 217)]}
        for t in need:
            if t == "VersionInfo":
                continue
            if t in ("DownloadClients",):
                rows[t] = [(None, client, None), (None, client, None)]
            elif t in ("Indexers", "Applications", "IndexerProxies"):
                rows[t] = [(f"{OLD}/idx", idx, None)]
            else:
                rows[t] = [(f"{OLD}/lib/{t}/{i}", None, None) for i in range(2)]
        _db(base / dbname, need, rows)
    qb = root / CLIENT / "qBittorrent"
    (qb / "BT_backup").mkdir(parents=True)
    (qb / "qBittorrent.conf").write_text(
        f"[BitTorrent]\nSession\\DefaultSavePath={OLD}/downloads/q/completed\n"
        f"Session\\TempPath={OLD}/downloads/q/incomplete\n"
    )
    resume = {
        b"save_path": f"{OLD}/downloads/q/completed".encode(),
        b"qBt-category": b"tv",
        b"pieces": b"\x00\x01\x02" + OLD.encode(),  # binary: must never be rewritten
    }
    (qb / "BT_backup" / ("a" * 40 + ".fastresume")).write_bytes(mm._bencode(resume))
    (qb / "BT_backup" / ("a" * 40 + ".torrent")).write_bytes(b"d4:infod4:name1:xee")
    nz = root / USENET
    nz.mkdir()
    (nz / "nzbget.conf").write_text(
        f"MainDir=/config\nDestDir={OLD}/downloads/n/completed\nCategory1.Name=Movies\n"
        "Server1.Host=news.example.internal\n"
    )
    rq = root / REQUESTS
    (rq / "db").mkdir(parents=True)
    (rq / "settings.json").write_text(
        json.dumps(
            {"radarr": [{"hostname": "media-core-radarr", "activeDirectory": f"{OLD}/films"}]}
        )
    )
    c = sqlite3.connect(rq / "db" / "db.sqlite3")
    for t in mm.REQUEST_TABLES:
        c.execute(f'CREATE TABLE "{t}" (id INTEGER PRIMARY KEY, name TEXT)')
        c.execute(f'INSERT INTO "{t}" (name) VALUES (?)', ("x",))
    c.commit()
    c.close()
    tr = root / TRANSCODE
    tr.mkdir()
    (tr / "Tdarr_Server_Config.json").write_text('{"serverPort": "8266"}')
    return root


@pytest.fixture
def src(tmp_path):
    return build_source(tmp_path / "source")


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(root)).encode() + p.read_bytes())
    return h.hexdigest()


def do_import(src, tmp_path, **kw):
    kw.setdefault("path_map", {OLD: NEW})
    kw.setdefault("host_map", {"media-core-gluetun": "gluetun"})
    kw.setdefault("strip_host_prefix", "media-core-")
    return mm.import_config(src, tmp_path / "data" / "mod" / "config", **kw)


# ----------------------------------------------------------------------------- counts


def test_counts_reads_every_app(src):
    out = mm.counts(src)
    assert sorted(out) == sorted(mm.ALL_APPS)
    first = SQL[0]
    assert out[first][mm.SQL_APPS[first][3][0].lower()] == 2
    assert out[CLIENT] == {"resume_files": 1, "torrent_files": 1}
    assert out[USENET] == {"categories": 1, "servers": 1}
    assert out[REQUESTS] == dict.fromkeys(mm.REQUEST_TABLES, 1)


def test_counts_reads_the_old_volume_layout(tmp_path, src):
    vols = tmp_path / "vols"
    for app in mm.ALL_APPS:
        name = "jelly" + REQUESTS if app == REQUESTS else app
        d = vols / f"old_{name}_config"
        d.mkdir(parents=True)
        os.rename(src / app, d / "_data")
    assert sorted(mm.counts(vols, "old_")) == sorted(mm.ALL_APPS)


def test_a_directory_with_no_app_is_an_error_not_an_empty_count(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(mm.ImportFailed, match="no app config directory"):
        mm.counts(tmp_path / "empty")


def test_an_unrecognised_schema_is_refused(src, tmp_path):
    app = SQL[0]
    c = sqlite3.connect(src / app / mm.SQL_APPS[app][0])
    c.execute(f'DROP TABLE "{mm.SQL_APPS[app][3][0]}"')
    c.commit()
    c.close()
    with pytest.raises(mm.ImportFailed, match="unrecognised schema"):
        do_import(src, tmp_path)
    assert not (tmp_path / "data").exists()


def test_an_empty_primary_table_is_not_verified(src, tmp_path):
    app = SQL[0]
    c = sqlite3.connect(src / app / mm.SQL_APPS[app][0])
    c.execute(f'DELETE FROM "{mm.SQL_APPS[app][3][0]}"')
    c.commit()
    c.close()
    with pytest.raises(mm.ImportFailed, match="no rows"):
        do_import(src, tmp_path)
    assert not (tmp_path / "data").exists()


def test_a_missing_required_app_is_refused_unless_chosen(src, tmp_path):
    import shutil

    shutil.rmtree(src / CLIENT)
    with pytest.raises(mm.ImportFailed, match=CLIENT):
        do_import(src, tmp_path)
    rep = do_import(src, tmp_path, only=tuple(a for a in mm.ALL_APPS if a != CLIENT))
    assert CLIENT not in rep["apps"]


def test_all_zero_counts_never_verify(src, tmp_path, monkeypatch):
    real = mm.app_counts
    monkeypatch.setattr(
        mm,
        "app_counts",
        lambda app, base: dict.fromkeys(real(app, base), 0) | {"schema_version": 3},
    )
    with pytest.raises(mm.ImportFailed, match="every count is zero"):
        do_import(src, tmp_path, allow_empty=True)
    assert not (tmp_path / "data" / "mod" / "config").exists()


# ----------------------------------------------------------------------------- import


def test_import_keeps_identity_and_counts_and_maps_paths_and_hosts(src, tmp_path):
    before = mm.counts(src)
    keys = {a: (src / a / "config.xml").read_bytes() for a in SQL}
    rep = do_import(src, tmp_path)
    dst = tmp_path / "data" / "mod" / "config"
    assert rep["target"] == rep["source"] == before
    for a in SQL:  # the identity file (the API key) is byte for byte the source's
        assert (dst / a / "config.xml").read_bytes() == keys[a]
        assert not (dst / a / "logs").exists() and not (dst / a / "logs.db").exists()
        assert not list((dst / a).glob("*.bak-*"))
    first = SQL[0]
    c = sqlite3.connect(dst / first / mm.SQL_APPS[first][0])
    paths = [r[0] for r in c.execute('SELECT Path FROM "' + mm.SQL_APPS[first][3][0] + '"')]
    assert paths and all(p.startswith(NEW + "/lib/") for p in paths)
    settings = json.loads(c.execute('SELECT Settings FROM "DownloadClients"').fetchone()[0])
    assert (
        settings["host"] == "gluetun" and settings["password"] == PASSWORD
    )  # carried, not dropped
    idx = json.loads(c.execute('SELECT Settings FROM "Indexers"').fetchone()[0])
    assert idx["baseUrl"] == "http://prowlarr/2/"
    conf = (dst / CLIENT / "qBittorrent" / "qBittorrent.conf").read_text()
    assert f"{NEW}/downloads/q/completed" in conf and f"={OLD}/" not in conf
    assert f"DestDir={NEW}/downloads/n/completed" in (dst / USENET / "nzbget.conf").read_text()
    s = json.loads((dst / REQUESTS / "settings.json").read_text())
    assert s["radarr"][0] == {"hostname": "radarr", "activeDirectory": f"{NEW}/films"}
    assert (dst / TRANSCODE / "configs" / "Tdarr_Server_Config.json").is_file()
    assert rep["changes"]["rewrite"]["resume_values"] >= 1


def test_the_resume_file_is_rewritten_as_bencode_and_binary_values_are_left_alone(src, tmp_path):
    do_import(src, tmp_path)
    f = (
        tmp_path
        / "data"
        / "mod"
        / "config"
        / CLIENT
        / "qBittorrent"
        / "BT_backup"
        / ("a" * 40 + ".fastresume")
    )
    doc, end = mm._bdecode(f.read_bytes())
    assert end == len(f.read_bytes())
    assert doc[b"save_path"] == f"{NEW}/downloads/q/completed".encode()
    assert doc[b"pieces"] == b"\x00\x01\x02" + OLD.encode()  # never a byte substitution
    assert mm._bencode(doc) == f.read_bytes()  # still canonical: the length prefixes are right


def test_a_resume_file_that_is_not_canonical_is_refused(src, tmp_path):
    f = src / CLIENT / "qBittorrent" / "BT_backup" / ("a" * 40 + ".fastresume")
    f.write_bytes(b"d1:bi1e1:ai2ee")  # keys out of order: re-encoding would change it
    with pytest.raises(mm.ImportFailed, match="byte for byte"):
        do_import(src, tmp_path)
    assert not (tmp_path / "data" / "mod" / "config").exists()


def test_the_report_never_carries_a_secret(src, tmp_path):
    rep = do_import(src, tmp_path)
    text = json.dumps(rep)
    assert PASSWORD not in text
    assert not any(k in text for k in KEYS.values())


def test_the_source_is_never_changed(src, tmp_path):
    before = tree_hash(src)
    do_import(src, tmp_path)
    assert tree_hash(src) == before


def test_an_ip_address_host_is_reported_and_refused_when_strict(tmp_path):
    s = build_source(tmp_path / "ip", ip_host=True)
    rep = do_import(s, tmp_path)
    assert rep["ip_hosts"] and "IP address" in rep["warnings"][0]
    s2 = build_source(tmp_path / "ip2", ip_host=True)
    with pytest.raises(mm.ImportFailed, match="IP address"):
        mm.import_config(s2, tmp_path / "x" / "y" / "cfg", {OLD: NEW}, strict=True)
    assert not (tmp_path / "x").exists() or not (tmp_path / "x" / "y" / "cfg").exists()


def test_a_remapped_ip_host_is_clean(tmp_path):
    s = build_source(tmp_path / "ip", ip_host=True)
    rep = do_import(s, tmp_path, host_map={IP_HOST: "gluetun"})
    assert "ip_hosts" not in rep


def test_cover_art_can_be_left_for_the_apps_to_download(src, tmp_path):
    do_import(src, tmp_path, skip_covers=True)
    assert not (tmp_path / "data" / "mod" / "config" / SQL[0] / "MediaCover").exists()
    other = tmp_path / "again"
    do_import(src, other)
    assert (other / "data" / "mod" / "config" / SQL[0] / "MediaCover" / "a.jpg").is_file()


def test_a_symlink_in_the_source_is_not_followed(src, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    os.symlink(outside, src / SQL[0] / "linked")
    rep = do_import(src, tmp_path)
    assert "linked" in rep["skipped_symlinks"]
    assert not (tmp_path / "data" / "mod" / "config" / SQL[0] / "linked").exists()


# ----------------------------------------------------------------------------- the path map


def test_map_rules_apply_in_one_pass_and_a_root_prefix_is_refused():
    rw = mm._rewriter({"/a": "/b", "/a/x": "/c"}, {})
    assert rw("/a/x/y /a/z") == "/c/y /b/z"  # the longest prefix wins
    assert rw("/b/q") == "/b/q"  # a rewritten path is not rewritten again
    for bad in ({"/": "/x"}, {"rel": "/x"}, {"/a": "rel"}):
        with pytest.raises(mm.ImportFailed):
            mm._rewriter(bad, {})
    assert mm._rewriter({"/a": "/b"}, {})("/alpha /a") == "/alpha /b"  # a whole component only
    assert (
        mm._rewriter({}, {"old": "new"})("old oldx x-old http://old/")
        == "new oldx x-old http://new/"
    )


def test_blob_columns_are_rewritten_when_json_and_refused_when_binary(tmp_path):
    for payload, ok in (
        (json.dumps({"p": f"{OLD}/x"}).encode(), True),
        (b"\x00\x05" + f"{OLD}/x".encode(), False),
    ):
        db = tmp_path / f"{ok}.db"
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE t (b BLOB)")
        c.execute("INSERT INTO t VALUES (?)", (payload,))
        c.commit()
        c.close()
        un: list[str] = []
        n = mm._rewrite_db(db, mm._rewriter({OLD: NEW}, {}), un)
        assert (n == 1 and not un) if ok else (n == 0 and un)


def test_a_remaining_old_prefix_fails_the_import(src, tmp_path, monkeypatch):
    monkeypatch.setattr(mm, "_rewrite_text_files", lambda root, rw: 0)
    monkeypatch.setattr(mm, "_rewrite_db", lambda *a, **k: 0)
    with pytest.raises(mm.ImportFailed, match="remains after the rewrite"):
        do_import(src, tmp_path)
    assert not (tmp_path / "data" / "mod" / "config").exists()


# ----------------------------------------------------------------------------- the guards


def test_a_shallow_or_nested_or_foreign_target_is_refused(src, tmp_path):
    for target, msg in (
        (Path("/"), "too shallow"),
        (Path("/tmp/x"), "too shallow"),
        (src, "source"),
        (src / SQL[0] / "inner", "source"),
        (tmp_path, "source"),
    ):
        with pytest.raises(mm.ImportFailed, match=msg):
            mm.import_config(src, target, {OLD: NEW})
    with pytest.raises(mm.ImportFailed, match="outside the module's data root"):
        mm.import_config(
            src, tmp_path / "elsewhere" / "a" / "cfg", {OLD: NEW}, data_root=tmp_path / "data"
        )


def test_a_target_that_is_or_holds_or_lies_in_the_library_is_refused(src, tmp_path):
    lib = tmp_path / "lib" / "srv" / "media"
    lib.mkdir(parents=True)
    for target in (lib, lib.parent, lib / "cfg"):
        with pytest.raises(mm.ImportFailed, match="library root"):
            mm.import_config(src, target, {OLD: str(lib)})


def test_an_existing_unrelated_directory_or_a_link_or_a_file_is_never_replaced(src, tmp_path):
    t = tmp_path / "data" / "mod" / "config"
    t.mkdir(parents=True)
    (t / "precious.txt").write_text("keep")
    with pytest.raises(mm.ImportFailed, match="not empty and not an app config root"):
        do_import(src, tmp_path, replace=True)
    assert (t / "precious.txt").read_text() == "keep"
    link = tmp_path / "data" / "mod" / "link"
    os.symlink(t, link)
    with pytest.raises(mm.ImportFailed, match="symbolic link"):
        mm.import_config(src, link, {OLD: NEW})
    f = tmp_path / "data" / "mod" / "file"
    f.write_text("x")
    with pytest.raises(mm.ImportFailed, match="not a directory"):
        mm.import_config(src, f, {OLD: NEW})


def test_an_existing_config_root_is_moved_aside_never_deleted(src, tmp_path):
    do_import(src, tmp_path)
    with pytest.raises(mm.ImportFailed, match="already holds a config root"):
        do_import(src, tmp_path)
    rep = do_import(src, tmp_path, replace=True)
    aside = Path(rep["previous_target"])
    assert aside.name == "config.before-import" and (aside / SQL[0] / "config.xml").is_file()
    with pytest.raises(mm.ImportFailed, match="before-import"):
        do_import(src, tmp_path, replace=True)  # the first aside copy is not overwritten


def test_a_leftover_partial_tree_stops_the_import(src, tmp_path):
    (tmp_path / "data" / "mod" / "config.partial").mkdir(parents=True)
    with pytest.raises(mm.ImportFailed, match="left by an earlier import"):
        do_import(src, tmp_path)


def test_a_failed_import_leaves_the_previous_target_intact(src, tmp_path, monkeypatch):
    do_import(src, tmp_path)
    dst = tmp_path / "data" / "mod" / "config"
    before = tree_hash(dst)
    real = mm.app_counts
    calls = {"n": 0}

    def flaky(app, base):
        calls["n"] += 1
        out = real(app, base)
        if base.is_relative_to(tmp_path / "data") and base.parent.name.endswith(".partial"):
            out = {**out, "schema_version": out.get("schema_version", 0) + 1}
        return out

    monkeypatch.setattr(mm, "app_counts", flaky)
    with pytest.raises(mm.ImportFailed, match="counts differ"):
        do_import(src, tmp_path, replace=True)
    assert tree_hash(dst) == before  # the target is untouched
    assert (tmp_path / "data" / "mod" / "config.partial").is_dir()  # kept for inspection


def test_a_changed_identity_file_fails_the_import(src, tmp_path, monkeypatch):
    real = mm._copy_tree

    def tamper(s, d, skipped, covers):
        real(s, d, skipped, covers)
        cfg = d / "config.xml"
        if cfg.is_file():
            cfg.write_text(cfg.read_text() + " ")

    monkeypatch.setattr(mm, "_copy_tree", tamper)
    with pytest.raises(mm.ImportFailed, match="changed in the copy"):
        do_import(src, tmp_path)
    assert not (tmp_path / "data" / "mod" / "config").exists()


def test_bad_maps_are_clean_refusals(src, tmp_path):
    with pytest.raises(mm.ImportFailed, match="plain host names"):
        do_import(src, tmp_path, host_map={"a b": "c"})
    with pytest.raises(mm.ImportFailed, match="no app config directory"):
        mm.import_config(tmp_path / "nothing", tmp_path / "a" / "b" / "c", {OLD: NEW})


# ----------------------------------------------------------------------------- the command line


def test_cli_counts_and_import(src, tmp_path, capsys):
    assert mm.main(["counts", str(src)]) == 0
    assert json.loads(capsys.readouterr().out)[CLIENT]["resume_files"] == 1
    dst = tmp_path / "data" / "m" / "config"
    code = mm.main(
        [
            "import",
            str(src),
            str(dst),
            "--map",
            f"{OLD}={NEW}",
            "--strip-host-prefix",
            "media-core-",
            "--data-root",
            str(tmp_path / "data"),
        ]
    )
    assert code == 0 and (dst / SQL[0] / "config.xml").is_file()
    out = capsys.readouterr().out
    assert PASSWORD not in out and not any(k in out for k in KEYS.values())
    assert mm.main(["import", str(src / "missing"), str(tmp_path / "q" / "r" / "s")]) == 1
    assert "media-automation import:" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        mm.main(["import", str(src), str(tmp_path / "q" / "r" / "s"), "--map", "rel=/x"])


def test_a_fifo_in_the_source_is_skipped_not_copied(src, tmp_path):
    os.mkfifo(src / SQL[0] / "pipe")
    rep = do_import(src, tmp_path)
    assert "pipe" in rep["skipped_symlinks"]
    assert not (tmp_path / "data" / "mod" / "config" / SQL[0] / "pipe").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root may chown")
def test_an_owner_without_root_is_refused_before_anything_is_written(src, tmp_path):
    with pytest.raises(mm.ImportFailed, match="need root"):
        do_import(src, tmp_path, owner=(1, 1))
    assert not (tmp_path / "data" / "mod" / "config.partial").exists()
