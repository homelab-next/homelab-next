#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: velociraptor-forensics
#   kind: job
#   purpose: Run the endpoint-forensics module's baseline hunt cycle (start one hunt over the allow-listed artifacts, collect it once into JSONL for the log pipeline, record the fleet's state), check its allow-list and hunt principal, and export or import its server state.
#   owner: platform
#   trigger: [timer:velociraptor_server/cycle, role:velociraptor_server]
#   inputs: the module's config file, the allow-list catalog, the forensics server's API (as the module's own hunt principal, through the server container) and the status and state directories
#   outputs: the status file, the hunt state, one JSONL file per finished hunt under the results directory, and listed exports
#   installs_to: /usr/local/libexec/homelabnext/hnx-velociraptor
#   exit:
#     "0": done
#     "1": the server could not be reached or refused, a catalog or definition was refused, or a tree check failed (the reason on stderr and in the status file)
#     "2": usage error
"""The host side of the ``velociraptor`` module.

It only ever asks the forensics server for what the module's hunt principal may do: collect the
artifacts of the allow-list catalog and read their results. It never defines, uploads or runs
anything, and the catalog check refuses a list (or a server definition) that would need more.
The server is reached through ``docker compose exec`` into its own container, where the API
listens on loopback only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import yaml

CATALOG_SCHEMA = "hnx-velociraptor-catalog/1"
STATUS_SCHEMA = "hnx-velociraptor-status/1"
#: the most the hunt principal may ever hold; a catalog that asks for more is refused
GRANTABLE = frozenset({"ANY_QUERY", "COLLECT_CLIENT", "READ_RESULTS", "START_HUNT"})
NAME = re.compile(r"[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9_]+)+\Z")
SOURCE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
HUNT_ID = re.compile(r"H\.[A-Za-z0-9]{4,32}\Z")
#: operations the gate allows; every other (upload, define, exec, write, admin) is refused
ALLOWED_OPS = frozenset({"collect", "hunt"})
MAX_STATE_HUNTS = 8


class CatalogError(Exception):
    pass


class TreeError(Exception):
    pass


# --- the catalog and the gate ----------------------------------------------------------------


def load_catalog(path) -> dict:
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise CatalogError(f"{p}: the catalog is not a regular file")
    doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != CATALOG_SCHEMA:
        raise CatalogError(f"the catalog's schema is {CATALOG_SCHEMA}")
    perms = (doc.get("principal") or {}).get("permissions")
    if not isinstance(perms, list) or not perms:
        raise CatalogError("principal.permissions is a list of permissions")
    for perm in perms:
        if perm not in GRANTABLE:
            raise CatalogError(
                f"principal permission {perm}: the hunt principal holds only {sorted(GRANTABLE)}"
            )
    arts = doc.get("artifacts")
    if not isinstance(arts, list) or not arts:
        raise CatalogError("artifacts is a non-empty list")
    seen = set()
    for a in arts:
        name = str(a.get("name", "")) if isinstance(a, dict) else ""
        if not NAME.fullmatch(name):
            raise CatalogError(f"artifact name {name!r} is not a plain artifact name")
        if name in seen:
            raise CatalogError(f"artifact {name} is listed twice")
        seen.add(name)
        for src in a.get("sources") or []:
            if not SOURCE.fullmatch(str(src)):
                raise CatalogError(f"artifact {name}: source {src!r} is not a plain source name")
        for perm in a.get("required_permissions") or []:
            if perm not in GRANTABLE:
                raise CatalogError(
                    f"artifact {name} needs {perm}, which the hunt principal never holds"
                )
    return doc


def gate(catalog: dict, artifact: str, op: str) -> tuple[bool, str]:
    """May the hunt principal do ``op`` with ``artifact``? Collect and hunt, on a listed artifact."""
    if op not in ALLOWED_OPS:
        return False, f"{op} is never the hunt principal's: it only collects and reads"
    if artifact not in {a["name"] for a in catalog["artifacts"]}:
        return False, f"{artifact} is not on the allow-list"
    return True, ""


def live_problems(catalog: dict, definitions: list[dict]) -> list[str]:
    """What the running server's definitions of the listed artifacts need beyond the principal."""
    if not definitions:
        return ["no definitions came back: the server's artifact list could not be read"]
    held = set(catalog["principal"]["permissions"])
    by_name = {d.get("name"): d for d in definitions}
    out = []
    for a in catalog["artifacts"]:
        d = by_name.get(a["name"])
        if d is None:
            out.append(f"{a['name']} is not defined on the server")
            continue
        need = set(d.get("required_permissions") or []) | set(d.get("implied_permissions") or [])
        extra = sorted(need - held)
        if extra:
            out.append(
                f"{a['name']} needs {', '.join(extra)}, which the hunt principal does not hold"
            )
    return out


# --- the fleet ---------------------------------------------------------------------------------


def summarize_clients(rows: list[dict], now: float, stale_s: float) -> dict:
    seen = [float(r.get("last_seen_at") or 0) / 1e6 for r in rows]
    seen = [s for s in seen if s > 0]
    return {
        "clients_total": len(rows),
        "clients_fresh": sum(1 for s in seen if now - s <= stale_s),
        "newest_seen_age_s": round(now - max(seen)) if seen else None,
    }


# --- talking to the server -----------------------------------------------------------------------


def docker_runner(argv):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
    return p.returncode, p.stdout, p.stderr


def _quote(text: str) -> str:
    return "'" + str(text).replace("\\", "\\\\").replace("'", "\\'") + "'"


def vql(cfg: dict, run, query: str, *, api: bool = True) -> list[dict]:
    argv = [
        cfg.get("docker_cli", "docker"), "compose", "-f", cfg["compose_file"], "exec", "-T",
        cfg["service"], "/bin/velociraptor",
    ]  # fmt: skip
    argv += ["--api_config", cfg["api_config"]] if api else ["--config", cfg["server_config"]]
    argv += ["query", query, "--format", "jsonl"]
    rc, out, err = run(argv)
    if rc != 0:
        raise RuntimeError((err or out or f"exit {rc}").strip().splitlines()[-1][:300])
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            rows.append(json.loads(line))
    return rows


# --- files -------------------------------------------------------------------------------------


def atomic_write(path, text: str, mode: int = 0o640) -> None:
    p = Path(path)
    if p.is_symlink():
        raise OSError(f"{p}: refusing to write through a link")
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.parent / f".{p.name}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, p)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_state(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"hunts": []}
    hunts = doc.get("hunts") if isinstance(doc, dict) else None
    return {"hunts": hunts if isinstance(hunts, list) else []}


# --- the cycle ---------------------------------------------------------------------------------


def start_hunt(cfg, run, catalog, now) -> str:
    names = [a["name"] for a in catalog["artifacts"]]
    for n in names:
        ok, why = gate(catalog, n, "hunt")
        if not ok:
            raise RuntimeError(why)
    listing = ", ".join(_quote(n) for n in names)
    rows = vql(cfg, run, f"SELECT hunt(description={_quote('hnx-baseline ' + _iso(now))}, "
               f"artifacts=[{listing}]) AS r FROM scope()")  # fmt: skip
    hunt_id = str(((rows[0].get("r") or {}) if rows else {}).get("HuntId", ""))
    if not HUNT_ID.fullmatch(hunt_id):
        raise RuntimeError(
            "the server started no hunt (the principal may not, or the list is refused)"
        )
    return hunt_id


def collect_hunt(cfg, run, catalog, hunt_id, now) -> int:
    out = []
    for a in catalog["artifacts"]:
        for src in a.get("sources") or [None]:
            q = f"SELECT * FROM hunt_results(hunt_id={_quote(hunt_id)}, artifact={_quote(a['name'])}"
            q += f", source={_quote(src)})" if src else ")"
            for row in vql(cfg, run, q):
                out.append({
                    "time": _iso(now), "hunt_id": hunt_id, "artifact": a["name"],
                    "source": src or "", "category": a.get("category", ""),
                    "client_id": row.get("ClientId") or row.get("client_id") or "",
                    "hostname": row.get("Fqdn") or row.get("Hostname") or "",
                    "row": row,
                })  # fmt: skip
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in out)
    atomic_write(Path(cfg["results_dir"]) / f"hunts-{hunt_id}.jsonl", text, 0o640)
    return len(out)


def cycle(cfg: dict, run, now: float) -> int:
    """One run: the fleet's state, then (when due) a hunt, then (when ready) its collection."""
    status = {"schema": STATUS_SCHEMA, "checked_at": now, "service_up": False,
              "clients_total": None, "clients_fresh": None, "newest_seen_age_s": None,
              "problems": [], "stale_after_s": int(cfg["stale_after_minutes"]) * 60,
              "min_clients": int(cfg["min_clients"]),
              "max_age_s": int(cfg.get("max_age_minutes", 30)) * 60}  # fmt: skip
    rc = 0
    try:
        catalog = load_catalog(cfg["catalog"])
        rows = vql(cfg, run, "SELECT client_id, last_seen_at FROM clients()")
        status["service_up"] = True
        status.update(summarize_clients(rows, now, status["stale_after_s"]))
        defs = vql(cfg, run, "SELECT name, required_permissions, implied_permissions FROM "
                   "artifact_definitions(names=[" + ", ".join(
                       _quote(a["name"]) for a in catalog["artifacts"]) + "])")  # fmt: skip
        status["problems"] = live_problems(catalog, defs)
        rc = 1 if status["problems"] else _hunts(cfg, run, catalog, now, status)
    except (CatalogError, OSError, RuntimeError, ValueError) as e:
        status["problems"].append(str(e))
        rc = 1
    try:
        atomic_write(cfg["status_file"], json.dumps(status, sort_keys=True) + "\n", 0o644)
    except OSError as e:
        print(f"status not written: {e}", file=sys.stderr)
        rc = 1
    for p in status["problems"]:
        print(p, file=sys.stderr)
    return rc


def _hunts(cfg, run, catalog, now, status) -> int:
    state_path = Path(cfg["state_dir"]) / "hunts.json"
    state = _load_state(state_path)
    hunts = state["hunts"]
    due = not hunts or now - max(float(h.get("started", 0)) for h in hunts) >= \
        float(cfg["hunt_interval_hours"]) * 3600  # fmt: skip
    if due:
        hunts.append(
            {"hunt_id": start_hunt(cfg, run, catalog, now), "started": now, "collected": False}
        )
    for h in hunts:
        if (
            not h.get("collected")
            and now - float(h["started"]) >= float(cfg["collect_after_minutes"]) * 60
        ):
            collect_hunt(cfg, run, catalog, h["hunt_id"], now)
            h["collected"] = True
    state["hunts"] = hunts[-MAX_STATE_HUNTS:]
    atomic_write(state_path, json.dumps(state, sort_keys=True) + "\n", 0o600)
    return 0


# --- the probes the health hook runs -------------------------------------------------------------


def probe(cfg: dict, run) -> list[str]:
    """What is wrong with the server's two listeners, probed from inside its container against
    its own certificate authority: the clients' port serves its certificate, the GUI port asks
    for a sign-in."""
    out = []
    ca = "config.Client.ca_certificate"
    try:
        r = vql(cfg, run, f"SELECT Response, Content FROM http_client(url='https://localhost:"
                f"{int(cfg.get('frontend_port', 8000))}/server.pem', root_ca={ca})", api=False)  # fmt: skip
        if (
            not r
            or r[0].get("Response") != 200
            or "BEGIN CERTIFICATE" not in str(r[0].get("Content"))
        ):
            out.append("the clients' port does not serve the server's certificate")
        g = vql(cfg, run, f"SELECT Response FROM http_client(url='https://localhost:"
                f"{int(cfg.get('gui_port', 8889))}/', root_ca={ca})", api=False)  # fmt: skip
        if not g or g[0].get("Response") != 401:
            out.append("the GUI port does not ask for a sign-in")
    except RuntimeError as e:
        out.append(f"a listener could not be probed: {e}")
    return out


def principal_problems(cfg: dict, run, catalog: dict) -> list[str]:
    """The hunt principal holds exactly the catalog's permissions and is refused to run a command
    and to define an artifact; it still reads."""
    out = []
    try:
        vql(cfg, run, "SELECT client_id FROM clients() LIMIT 1")
    except RuntimeError as e:
        return [f"the hunt principal cannot read the fleet: {e}"]
    users = vql(
        cfg,
        run,
        f"SELECT name, effective_policy FROM gui_users() WHERE name = {_quote(cfg['principal'])}",
    )
    want = {p.lower() for p in catalog["principal"]["permissions"]}
    got = {
        k
        for k, v in ((users[0].get("effective_policy") or {}) if users else {}).items()
        if v is True
    }
    if got != want:
        out.append(f"the principal's permissions are {sorted(got)}, not {sorted(want)}")
    if vql(cfg, run, "SELECT * FROM execve(argv=['/bin/true'])"):
        out.append("the hunt principal ran a command")
    r = vql(cfg, run, "SELECT artifact_set(definition='name: Custom.Hnx.Probe\\ntype: CLIENT\\n"
            "sources:\\n- query: SELECT 1 FROM scope()') AS r FROM scope()")  # fmt: skip
    if r and r[0].get("r"):
        out.append("the hunt principal defined an artifact")
    return out


# --- export and import ---------------------------------------------------------------------------


def safe_path(path) -> Path:
    s = str(path)
    p = Path(s)
    if not p.is_absolute() or ".." in p.parts or "." in p.parts[1:] or len(p.parts) < 4:
        raise TreeError(f"{s}: not an absolute, canonical path of four or more components")
    if os.path.normpath(s) != s:
        raise TreeError(f"{s}: not canonical")
    return p


def _walk(root: Path):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise TreeError(f"{root}: not a directory (or a link)")
    for cur, dirs, files in os.walk(root, followlinks=False):
        for d in list(dirs):
            if (Path(cur) / d).is_symlink():
                raise TreeError(f"{Path(cur) / d}: a link in a tree")
        for f in sorted(files):
            p = Path(cur) / f
            st = p.lstat()
            if p.is_symlink() or not p.is_file() or st.st_nlink != 1:
                raise TreeError(f"{p}: not a single-link regular file")
            yield p.relative_to(root).as_posix(), p


def _sha(path: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def _write_listing(root: Path, rows: list[dict]) -> None:
    lst = root / "listing.jsonl"
    lst.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    os.chmod(lst, 0o600)


def export_tree(sources: dict[str, Path], dest) -> list[dict]:
    """Copy each source tree to ``dest/<name>/`` and list every file (key, size, sha256). Built
    beside ``dest`` and renamed into place whole; an existing ``dest`` is never touched."""
    dest = Path(dest)
    if dest.exists() or dest.is_symlink():
        raise TreeError(f"{dest}: an export already exists there")
    part = dest.parent / f".{dest.name}.partial"
    if part.exists():
        raise TreeError(f"{part}: a partial export is in the way (remove it by hand)")
    rows = []
    part.mkdir(parents=True, mode=0o700)
    for name, src in sorted(sources.items()):
        (part / name).mkdir(mode=0o700)  # a source with no file is still a directory of the export
        for rel, p in _walk(src):
            out = part / name / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "rb") as a, open(out, "xb") as b:
                b.write(a.read())
            os.chmod(out, 0o600)
            digest, size = _sha(out)
            rows.append({"key": f"{name}/{rel}", "size": size, "sha256": digest})
    if not rows:
        raise TreeError("the sources hold no file: an export of nothing is refused")
    _write_listing(part, rows)
    os.rename(part, dest)
    return rows


def check_export(src, names) -> list[dict]:
    src = Path(src)
    if src.is_symlink() or not src.is_dir():
        raise TreeError(f"{src}: not a directory")
    lst = src / "listing.jsonl"
    if lst.is_symlink() or not lst.is_file():
        raise TreeError("the export has no listing.jsonl")
    rows = [json.loads(x) for x in lst.read_text(encoding="utf-8").splitlines() if x.strip()]
    if not rows:
        raise TreeError("the listing names no file")
    listed = {}
    for r in rows:
        key = r.get("key", "")
        if key in listed or key.split("/", 1)[0] not in names or ".." in key.split("/"):
            raise TreeError(f"the listing names an unknown or repeated key: {key!r}")
        listed[key] = r
    found = {}
    for name in names:
        if (src / name).exists():
            for rel, p in _walk(src / name):
                found[f"{name}/{rel}"] = p
    if set(found) != set(listed):
        raise TreeError("the export holds files the listing does not name, or misses one it does")
    for key, p in found.items():
        digest, size = _sha(p)
        if (digest, size) != (listed[key]["sha256"], listed[key]["size"]):
            raise TreeError(f"{key}: differs from the listing")
    return rows


def import_tree(src, targets: dict[str, Path], uid: int, gid: int, stamp: str) -> None:
    """Install a checked export. Each target is built as a sibling and renamed into place; a
    populated target is renamed aside (``<target>.replaced-<stamp>``), never deleted."""
    src = Path(src)
    check_export(src, tuple(targets))
    resolved = {n: safe_path(t) for n, t in targets.items()}
    if not re.fullmatch(r"[A-Za-z0-9]{1,32}", stamp):
        raise TreeError("the stamp is letters and digits")
    for t in resolved.values():
        if t.is_symlink() or Path(f"{t}.restore").exists():
            raise TreeError(f"{t}: a link, or a restore is already staged beside it")
    for name, t in resolved.items():
        stage = Path(f"{t}.restore")
        stage.mkdir(mode=0o700, parents=True)
        for rel, p in _walk(src / name):
            out = stage / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "rb") as a, open(out, "xb") as b:
                b.write(a.read())
            os.chmod(out, 0o600)
        for cur, dirs, files in os.walk(stage):
            for x in dirs + files:
                os.chown(Path(cur) / x, uid, gid)
        os.chown(stage, uid, gid)
        os.chmod(stage, 0o700)
    for t in resolved.values():
        if t.exists() and any(t.iterdir()):
            os.rename(t, Path(f"{t}.replaced-{stamp}"))
        elif t.exists():
            t.rmdir()
        os.rename(Path(f"{t}.restore"), t)


# --- command line --------------------------------------------------------------------------------


def _cfg(path) -> dict:
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise SystemExit(f"{p}: the config is not a regular file")
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default="/etc/homelabnext/velociraptor.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("cycle")
    sub.add_parser("probe")
    sub.add_parser("catalog-check")
    sub.add_parser("principal-check")
    g = sub.add_parser("gate")
    g.add_argument("artifact")
    g.add_argument("op")
    e = sub.add_parser("export")
    e.add_argument("--etc", required=True)
    e.add_argument("--datastore", required=True)
    e.add_argument("--dest", required=True)
    c = sub.add_parser("check-export")
    c.add_argument("--src", required=True)
    i = sub.add_parser("import")
    i.add_argument("--src", required=True)
    i.add_argument("--etc", required=True)
    i.add_argument("--datastore", required=True)
    i.add_argument("--uid", type=int, required=True)
    i.add_argument("--gid", type=int, required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd in ("export", "check-export", "import"):
            if a.cmd == "export":
                rows = export_tree(
                    {"etc": safe_path(a.etc), "datastore": safe_path(a.datastore)},
                    safe_path(a.dest),
                )
                print(json.dumps(rows))
            elif a.cmd == "check-export":
                print(json.dumps(check_export(safe_path(a.src), ("etc", "datastore"))))
            else:
                import_tree(safe_path(a.src), {"etc": safe_path(a.etc), "datastore": safe_path(a.datastore)},
                            a.uid, a.gid, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))  # fmt: skip
            return 0
        cfg = _cfg(a.config)
        if a.cmd == "cycle":
            return cycle(cfg, docker_runner, time.time())
        catalog = load_catalog(cfg["catalog"])
        if a.cmd == "gate":
            ok, why = gate(catalog, a.artifact, a.op)
            print("allowed" if ok else f"refused: {why}")
            return 0 if ok else 1
        if a.cmd == "catalog-check":
            names = ", ".join(_quote(x["name"]) for x in catalog["artifacts"])
            problems = live_problems(catalog, vql(cfg, docker_runner, "SELECT name, required_permissions, "
                                                  f"implied_permissions FROM artifact_definitions(names=[{names}])"))  # fmt: skip
        elif a.cmd == "probe":
            problems = probe(cfg, docker_runner)
        else:
            problems = principal_problems(cfg, docker_runner, catalog)
        for p in problems:
            print(p, file=sys.stderr)
        return 1 if problems else 0
    except (CatalogError, TreeError, RuntimeError, OSError, ValueError) as ex:
        print(f"refused: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
