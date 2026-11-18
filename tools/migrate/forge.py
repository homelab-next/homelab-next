#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: forge-migrate
#   kind: tool
#   purpose: Copy a forge instance (repositories, accounts, packages) from one place to another as a verified export, over ssh pipes, and prove the target holds exactly what the source held.
#   owner: maintainers
#   trigger: [manual]
#   inputs: two endpoints named on the command line (an ssh destination and a container name, never a literal in this file); for stage and verify, an export directory written by dump
#   outputs: an export directory (dump.zip, manifest.json, repos.tsv, listing.jsonl) for dump; JSON facts for the other commands
#   exit:
#     "0": done (for verify, the target equals the export)
#     "1": the target differs from the export, or the source or the export is not intact
#     "2": usage error or a command on an endpoint failed
"""Migrate a forge instance by freeze, dump, stage, restore (the provider's role) and verify
(docs of the provider: its module's README.md, "Migrating in").

Generic: an *endpoint* is an ssh destination (or ``None`` for this host) plus the name of the
container that runs the instance; nothing here names a host, an address or a lab.

* :func:`dump` -- **read-only on the source**: the product's own dump is streamed over the ssh pipe into a
  file of a directory the caller names (never a temporary directory: the dump holds every
  account's password hash), then ``repos.tsv`` records every repository's refs digest and
  ``git fsck`` verdict, ``manifest.json`` the product version, the database's row counts and
  content fingerprint (read from the dump itself) and whether the source was stopped for the
  whole run (``frozen``/``quiescent``), and ``listing.jsonl`` the sha256 of the files.  The export
  is the format the provider's role restores (the role's ``restore_source``).  The product's dump
  carries the configuration file, which holds the three application secrets: the export is made
  WITHOUT it, and the manifest records an HMAC-SHA256 fingerprint of each secret instead (never a
  value).  A source whose ``SECRET_KEY`` was never set runs on the product's built-in default key,
  which cannot be carried: the dump then counts the rows of every table the product encrypts with
  that key (read from the dump's own database), refuses when there is one, and otherwise records
  the key's source as ``builtin-default`` and the proof (``secret_key_unused_proof``), so the
  target may take a fresh generated key.  It never makes up a key that pretends to be the
  source's.  The files are 0600 in a 0700 directory all the same: the database inside holds every
  account's password hash, and the repositories are the data.
* :func:`stage` -- copy an export into a new directory under the target's data root over ssh
  (mode 0700, nothing overwritten); the role's restore reads it from there.
* :func:`verify` -- on the target, **independently of the restore's own checks**: the database's
  counts and fingerprint read from the target's database file, and every repository's refs digest
  and fsck verdict, against the export; zero accounts or repositories where the export has some is
  an error.  The application secrets: the source's (by fingerprint), except a ``SECRET_KEY`` the
  export proved was the built-in default with nothing encrypted under it, which must then be a set,
  fresh one.
* :func:`freeze` / :func:`unfreeze` -- stop / start the instance's container (a *write*, done only
  in the cutover window, only to stop and start).  ``freeze`` first sets the restart policy to
  ``no`` (a container with ``always`` would come back with the host: split brain) and reports the
  policy it had; ``unfreeze --restart <policy>`` puts it back.  Never ``unfreeze`` the source after
  the cutover.

**The final delta.** A copy taken while people push is already stale: the cutover is ``freeze``,
``dump`` again (refused while the source runs, unless ``--allow-live``), ``stage``, the role's
restore, ``verify --require-quiescent``.

**Destructive paths.** The tool deletes exactly one kind of thing: the single temporary database
file it created (``O_EXCL``) in the export directory while verifying, and only after resolving that
it is a regular file of that name inside that directory.  It never removes a directory, and
``stage`` refuses a destination that exists, is shallow (under three components), is not canonical,
lies outside the target's data root or is the export itself on the same host.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol

import yaml

__all__ = [
    "Endpoint",
    "MigrateError",
    "VerifyMismatch",
    "dump",
    "freeze",
    "inventory",
    "stage",
    "unfreeze",
    "verify",
]

ROOT = Path(__file__).resolve().parents[2]


def _module_for(slot: str) -> tuple[str, str]:
    """(module id, product name) of the module that fills ``slot``.  This tool speaks the product's
    own commands and layout, and takes their names from the module's manifest rather than spelling
    them (the product-name lint's rule: name the slot)."""
    found = []
    for d in sorted((ROOT / "modules").iterdir()):
        m = d / "module.yml"
        if m.is_file():
            doc = yaml.safe_load(m.read_text())
            if slot in ((doc.get("provides") or {}).get("slots") or {}):
                found.append((d.name, doc["product"]["name"]))
    if len(found) != 1:
        raise RuntimeError(f"expected one module filling {slot!r}, found {found}")
    return found[0]


MID, PRODUCT = _module_for("forge")
ROLE = ROOT / "modules" / MID / "roles" / MID
DUMP, MANIFEST, REPOS, LISTING = "dump.zip", "manifest.json", "repos.tsv", "listing.jsonl"
FILES = (DUMP, MANIFEST, REPOS, LISTING)
#: places an export must never be staged: world-writable scratch space (it holds every account's
#: password hash)
SCRATCH_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
_CHUNK = 1 << 20
_VERSION = re.compile(r"\b(\d+\.\d+\.\d+)\b")


class MigrateError(RuntimeError):
    """A command on an endpoint failed, or an input is not usable."""


class VerifyMismatch(MigrateError):
    """The target is not what the export says."""


def _load_helper():
    """The role's own helper (one implementation of the database facts, not a copy)."""
    sys.dont_write_bytecode = True  # no __pycache__ beside the role's files
    spec = importlib.util.spec_from_file_location(
        "hnx_forge_helper", ROLE / "files" / f"hnx_{MID}.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


#: where each application secret lives in the instance's configuration file: name -> (section, key)
SECRET_KEYS = {
    "secret_key": ("security", "SECRET_KEY"),
    "internal_token": ("security", "INTERNAL_TOKEN"),
    "jwt_secret": ("oauth2", "JWT_SECRET"),
}
_RESTART_POLICIES = ("no", "always", "unless-stopped", "on-failure")


def repos_script() -> str:
    """The role's repositories-manifest script (one text, run against both ends)."""
    return yaml.safe_load((ROLE / "vars" / "main.yml").read_text())[f"{MID}_repos_script"]


def guard_dir(path: str, *, root: str | None = None, min_components: int = 3) -> str:
    """Lexical checks for a directory something is created in; returns it unchanged.

    Absolute, canonical (no ``..``, ``.``, ``//`` or trailing ``/``), at least three components
    (``/var/x/y``: never ``/``, ``/var``, ``/var/lib``), and strictly inside ``root`` when given."""
    p = PurePosixPath(path)
    if not path.startswith("/") or str(p) != path or ".." in p.parts or "." in p.parts:
        raise MigrateError(f"{path!r}: not an absolute canonical path")
    if len(p.parts) < min_components + 1:  # "/" counts as a part
        raise MigrateError(f"{path!r}: refusing a path of fewer than {min_components} components")
    if root is not None:
        r = PurePosixPath(guard_dir(root, min_components=2))
        if r not in p.parents:
            raise MigrateError(f"{path!r}: not inside the data root {root!r}")
    return path


@dataclass(frozen=True)
class Endpoint:
    """Where an instance runs.  ``ssh`` is a destination (``user@host``) or ``None`` for this
    host; commands run as ``[ssh dest] [sudo -n] docker ...``.

    ``container`` runs the instance.  The defaults are the provider's rootless image; a source on
    the older root image names ``exec_user`` (the account the product runs as, which its dump
    command requires), ``config``, ``work_dir``, ``repos_root`` and ``db_path`` of its own."""

    container: str
    ssh: str | None = None
    sudo: bool = True
    exec_user: str | None = None
    config: str = f"/etc/{PRODUCT}/app.ini"
    work_dir: str | None = None
    repos_root: str = f"/var/lib/{PRODUCT}/git/repositories"
    db_path: str = f"/var/lib/{PRODUCT}/{PRODUCT}.db"
    data_root: str | None = None

    def __post_init__(self) -> None:
        for p in (self.config, self.repos_root, self.db_path):
            guard_dir(p, min_components=2)


class Runner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        stdin: BinaryIO | None = None,
        stdout: BinaryIO | None = None,
    ) -> tuple[int, bytes, bytes]:
        """Run argv; stdout goes to ``stdout`` if given, else is returned.  -> (rc, out, err)."""


def _subprocess_runner(argv, *, stdin=None, stdout=None):
    p = subprocess.run(
        list(argv),
        stdin=stdin if stdin is not None else subprocess.DEVNULL,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return p.returncode, p.stdout or b"", p.stderr or b""


@dataclass
class _Ctx:
    runner: Runner | None = None
    log: list[list[str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.runner is None:  # looked up at call time, so a test can replace the module's
            self.runner = _subprocess_runner


def _wrap(ep: Endpoint, inner: Sequence[str], *, has_stdin: bool = False) -> list[str]:
    """The argv that runs ``inner`` on the endpoint: through ssh (one quoted command string, as
    ssh joins it; ``-n`` when nothing is piped in) and sudo when asked."""
    cmd = (["sudo", "-n"] if ep.sudo else []) + list(inner)
    if ep.ssh is None:
        return cmd
    return ["ssh", *([] if has_stdin else ["-n"]), "-o", "BatchMode=yes", ep.ssh, shlex.join(cmd)]


def _run(ctx: _Ctx, ep: Endpoint, inner: Sequence[str], *, stdin=None, stdout=None) -> bytes:
    argv = _wrap(ep, inner, has_stdin=stdin is not None)
    ctx.log.append(list(argv))
    rc, out, err = ctx.runner(argv, stdin=stdin, stdout=stdout)
    if rc != 0:
        tail = err.decode("utf-8", "replace").strip().splitlines()[-3:]
        raise MigrateError(f"{' '.join(inner[:6])} ... failed ({rc}): {' | '.join(tail)}")
    return out


def _running(ctx: _Ctx, ep: Endpoint) -> bool:
    out = _run(ctx, ep, ["docker", "inspect", "--format", "{{.State.Running}}", ep.container])
    return out.decode().strip() == "true"


def _image(ctx: _Ctx, ep: Endpoint) -> str:
    out = _run(ctx, ep, ["docker", "inspect", "--format", "{{.Config.Image}}", ep.container])
    return out.decode().strip()


def _in(ctx: _Ctx, ep: Endpoint, cmd: Sequence[str], *, stdout=None) -> bytes:
    """Run ``cmd`` where the instance's files are: in the container when it runs, else in a
    one-off container of the same image over the same volumes (nothing is started or changed)."""
    user = ["-u", ep.exec_user] if ep.exec_user else []
    if _running(ctx, ep):
        return _run(ctx, ep, ["docker", "exec", *user, ep.container, *cmd], stdout=stdout)
    var = PRODUCT.upper()
    env = (
        ["-e", f"{var}_WORK_DIR={ep.work_dir}", "-e", f"{var}_CUSTOM={ep.work_dir}"]
        if ep.work_dir
        else []
    )
    return _run(
        ctx, ep,
        ["docker", "run", "--rm", "--volumes-from", ep.container, *user, *env,
         "--entrypoint", cmd[0], _image(ctx, ep), *cmd[1:]],
        stdout=stdout,
    )  # fmt: skip


def _version(ctx: _Ctx, ep: Endpoint) -> str:
    out = _in(ctx, ep, [PRODUCT, "--version"]).decode("utf-8", "replace")
    m = _VERSION.search(out)
    if not m:
        raise MigrateError(f"cannot read the version from {out.strip()[:80]!r}")
    return m.group(1)


def _repo_lines(ctx: _Ctx, ep: Endpoint) -> list[str]:
    out = _in(ctx, ep, ["sh", "-c", repos_script(), "sh", ep.repos_root]).decode("utf-8", "replace")
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


_TOP_LEVEL = "forge-migrate:top-level"  # never a section of the product's


def _key_values(ctx: _Ctx, ep: Endpoint, helper) -> tuple[dict, str]:
    """The endpoint's three application secrets, read from its configuration file in memory (never
    printed, never written), and where its ``SECRET_KEY`` comes from: ``configured``, or
    ``builtin-default`` when the file sets none (no ``SECRET_KEY`` and no ``SECRET_KEY_URI``: the
    product then falls back to its built-in key) or sets that very key; the value is then ``None``.
    Any other secret the file does not hold in plain text (a ``*_URI`` file reference, say) is an
    error, not a skipped check."""
    text = _in(ctx, ep, ["cat", ep.config]).decode("utf-8", "replace")
    ini = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
    ini.optionxform = str  # type: ignore[assignment]  # the product's keys are case-sensitive
    try:
        # the product's app.ini opens with section-less keys (APP_NAME, RUN_MODE, WORK_PATH: go-ini's
        # default section), which configparser refuses without a header: read them into a section of
        # their own (not configparser's DEFAULT, whose keys would answer for every section)
        ini.read_string(f"[{_TOP_LEVEL}]\n" + text)
    except configparser.Error as exc:
        raise MigrateError(
            f"{ep.config}: not readable as a configuration ({type(exc).__name__})"
        ) from None
    values: dict = {}
    source = helper.KEY_CONFIGURED
    for name, (section, key) in SECRET_KEYS.items():
        raw = ini.get(section, key, fallback=None)
        value = (raw or "").strip().strip("`\"'")
        uri = (ini.get(section, f"{key}_URI", fallback=None) or "").strip()
        if name == "secret_key" and not uri and value in ("", helper.BUILTIN_APP_KEY):
            source, value = helper.KEY_BUILTIN, None
        elif not value:
            raise MigrateError(
                f"{ep.config}: no {key} in [{section}] in plain text: cannot prove the secret is "
                "the same on both sides (a *_URI or file reference is not supported)"
            )
        values[name] = value
    return values, source


def _key_fingerprints(values: dict, source: str, helper) -> dict:
    """HMAC fingerprints of the secrets the export carries: all three, or, for a built-in
    ``SECRET_KEY`` (not carried), the other two."""
    names = helper.SECRET_NAMES if source == helper.KEY_CONFIGURED else helper.OTHER_SECRET_NAMES
    try:
        return helper.secret_fingerprints(values, names)
    except helper.HelperError as exc:
        raise MigrateError(str(exc)) from None


def inventory(ep: Endpoint, *, _ctx: _Ctx | None = None) -> dict:
    """The repositories' manifest of a live endpoint (a read)."""
    ctx = _ctx or _Ctx()
    lines = _repo_lines(ctx, ep)
    return {"repositories": lines, "running": _running(ctx, ep)}


def _sha256(path: Path) -> tuple[int, str]:
    h, n = hashlib.sha256(), 0
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
            n += len(chunk)
    return n, h.hexdigest()


def _refuse_scratch(out_dir: Path, scratch_dirs: Sequence[str]) -> None:
    resolved = out_dir.resolve()
    for s in scratch_dirs:
        base = Path(s).resolve()
        if resolved == base or base in resolved.parents:
            raise MigrateError(
                f"{out_dir}: inside {base}: an export holds every account's password hash"
            )


def _check_instance(lines: Sequence[str], facts: Mapping, allow_empty: bool) -> None:
    """An export that proves nothing is an error, not a pass; so is a source that disagrees with
    itself (a database row with no repository on disk, or the reverse) or fails its integrity."""
    c = facts["counts"]
    failing = [ln.split("\t")[0] for ln in lines if ln.split("\t")[-1] != "ok"]
    if failing:
        raise VerifyMismatch(
            f"git fsck fails for: {', '.join(failing)}: the instance is damaged, nothing is copied"
        )
    if not allow_empty and (c["users"] == 0 or c["repos"] == 0 or not lines):
        raise VerifyMismatch(
            f"the instance has {c['users']} accounts, {c['repos']} repositories and {len(lines)} "
            "repositories on disk: refusing a vacuous export (wrong container? --allow-empty if it is empty)"
        )
    on_disk = [ln for ln in lines if ".wiki.git\t" not in ln]
    if len(on_disk) != c["repos"]:
        raise VerifyMismatch(
            f"the database lists {c['repos']} repositories but {len(on_disk)} are on disk: the instance disagrees with itself"
        )


def dump(
    source: Endpoint,
    out_dir: str | os.PathLike,
    *,
    allow_live: bool = False,
    allow_empty: bool = False,
    scratch_dirs: Sequence[str] = (*SCRATCH_DIRS, tempfile.gettempdir()),
    _ctx: _Ctx | None = None,
) -> dict:
    """Dump ``source`` into ``out_dir`` (created, mode 0700, must be empty) and return the manifest.

    Read-only on the source (``docker inspect``, the dump command, ``git for-each-ref``/``fsck``).
    A running source is refused unless ``allow_live``: the manifest then says it was not frozen."""
    ctx = _ctx or _Ctx()
    out = Path(out_dir)
    _refuse_scratch(out, scratch_dirs)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    out.chmod(0o700)
    if any(out.iterdir()):
        raise MigrateError(f"{out}: not empty")
    running = _running(ctx, source)
    if running and not allow_live:
        raise MigrateError(
            f"{source.container} is running: freeze it first (writes would be missed), or pass --allow-live for a rehearsal copy"
        )
    before = _repo_lines(ctx, source)
    version = _version(ctx, source)
    zpath = out / DUMP
    raw = out / ".dump.raw"  # the product's own dump, with its configuration: never an export file
    try:
        with os.fdopen(os.open(raw, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            _in(
                ctx,
                source,
                [
                    PRODUCT,
                    "--config",
                    source.config,
                    "dump",
                    "--type",
                    "zip",
                    "--skip-log",
                    "--file",
                    "-",
                ],
                stdout=f,
            )
        helper = _load_helper()
        # the dump holds the configuration, which holds the application secrets: the export is
        # without it (the restore rebuilds the configuration from the secret store) and records
        # only a fingerprint of them, which verify compares with the target's
        key_values, key_source = _key_values(ctx, source, helper)
        key_fps = _key_fingerprints(key_values, key_source, helper)
        helper.strip_config(str(raw), str(zpath))
        try:
            facts = helper.dbcounts({"zip": str(zpath)})
        except helper.HelperError as exc:
            raise VerifyMismatch(f"the dump's database is not an instance's: {exc}") from exc
        key_proof = None
        if key_source == helper.KEY_BUILTIN:
            # the key cannot be carried: prove, from the very database this export holds, that
            # nothing is encrypted under it (a refusal names every table that holds such rows)
            try:
                key_proof = helper.unused_key_proof(
                    helper.from_dump(str(zpath), helper.app_key_uses)
                )
            except helper.HelperError as exc:
                raise VerifyMismatch(str(exc)) from exc
        after = _repo_lines(ctx, source)
        _check_instance(after, facts, allow_empty)
    except BaseException:
        zpath.unlink(missing_ok=True)  # the files this run created
        raise
    finally:
        raw.unlink(missing_ok=True)
    frozen = not running and not _running(ctx, source)
    (out / REPOS).write_text("\n".join(after) + "\n")
    manifest = {
        "format": 1,
        "product_version": version,
        "image": _image(ctx, source),
        "counts": facts["counts"],
        "fingerprint": facts["fingerprint"],
        "app_key_fingerprints": key_fps,
        "secret_key_source": key_source,
        **({"secret_key_unused_proof": key_proof} if key_proof is not None else {}),
        "config_included": False,
        "repositories": len(after),
        "source": {"frozen": frozen, "quiescent": frozen and before == after},
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    rows = []
    for name in (DUMP, MANIFEST, REPOS):
        size, digest = _sha256(out / name)
        rows.append(json.dumps({"key": name, "size": size, "sha256": digest}, sort_keys=True))
    (out / LISTING).write_text("\n".join(rows) + "\n")
    for name in FILES:
        (out / name).chmod(0o600)
    return manifest


def _read_export(src: Path) -> tuple[dict, list[str]]:
    """The manifest and repositories of an export, after checking every file against its listing."""
    try:
        listed = {
            r["key"]: r for r in map(json.loads, (src / LISTING).read_text().splitlines()) if r
        }
    except (OSError, ValueError, KeyError) as exc:
        raise VerifyMismatch(f"{src}: no readable {LISTING}: {exc}") from exc
    if sorted(listed) != sorted([DUMP, MANIFEST, REPOS]):
        raise VerifyMismatch(f"{src}: {LISTING} must name exactly {DUMP}, {MANIFEST} and {REPOS}")
    for name, row in listed.items():
        path = src / name
        if path.is_symlink() or not path.is_file():
            raise VerifyMismatch(f"{path}: not a regular file")
        if _sha256(path) != (int(row["size"]), row["sha256"]):
            raise VerifyMismatch(f"{path}: differs from its listing (size or sha256)")
    manifest = json.loads((src / MANIFEST).read_text())
    if manifest.get("format") != 1:
        raise VerifyMismatch(f"{src}: manifest format {manifest.get('format')!r}, expected 1")
    lines = [ln for ln in (src / REPOS).read_text().splitlines() if ln.strip()]
    return manifest, lines


def verify(
    target: Endpoint,
    dump_dir: str | os.PathLike,
    *,
    require_quiescent: bool = False,
    allow_empty: bool = False,
    _ctx: _Ctx | None = None,
) -> dict:
    """Compare the target with the export, independently of the restore: the database file's counts
    and fingerprint, and every repository's refs digest and fsck verdict.  Returns the facts."""
    ctx = _ctx or _Ctx()
    src = Path(dump_dir)
    manifest, want_lines = _read_export(src)
    if require_quiescent and not manifest.get("source", {}).get("quiescent"):
        raise MigrateError(
            f"{src}: not dumped from a frozen source (it ran, or its repositories moved during the dump)"
        )
    if not allow_empty and (
        manifest["counts"]["users"] == 0 or manifest["counts"]["repos"] == 0 or not want_lines
    ):
        raise MigrateError(
            f"{src}: the export holds no account or no repository: refusing to call anything verified"
        )
    got_lines = _repo_lines(ctx, target)
    helper = _load_helper()
    tmp = src / ".verify.db"
    try:
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            _in(ctx, target, ["cat", target.db_path], stdout=f)
        try:
            facts = helper.dbcounts({"db": str(tmp)})
        except helper.HelperError as exc:
            raise VerifyMismatch(f"the target's database is not an instance's: {exc}") from exc
    finally:
        if tmp.is_file() and not tmp.is_symlink() and tmp.parent.resolve() == src.resolve():
            tmp.unlink()
    problems = []
    values, target_source = _key_values(ctx, target, helper)
    # the target always has a SECRET_KEY of its own: the source's, or (only for an export that
    # proved the source's was the built-in one with nothing under it) a fresh one
    builtin = manifest.get("secret_key_source") == helper.KEY_BUILTIN
    if target_source == helper.KEY_BUILTIN:
        problems.append("the target runs on the built-in default SECRET_KEY: set one")
    else:
        try:
            helper.check_app_key(
                {
                    "values": values,
                    "origin": "generated" if builtin else "source",
                    "manifest": manifest,
                    "zip": str(src / DUMP),
                }
            )
        except helper.HelperError as exc:
            problems.append(str(exc))
    if facts["counts"] != manifest["counts"]:
        diff = {
            k: (manifest["counts"].get(k), facts["counts"].get(k))
            for k in facts["counts"]
            if manifest["counts"].get(k) != facts["counts"][k]
        }
        problems.append(f"counts differ (export, target): {diff}")
    moved = sorted(
        k for k in facts["fingerprint"] if facts["fingerprint"][k] != manifest["fingerprint"].get(k)
    )
    if moved:
        problems.append(f"the content of {', '.join(moved)} differs")
    if sorted(got_lines) != sorted(want_lines):
        want, got = (
            {ln.split("\t")[0]: ln for ln in want_lines},
            {ln.split("\t")[0]: ln for ln in got_lines},
        )
        names = sorted({*want, *got})
        bad = [n for n in names if want.get(n) != got.get(n)]
        problems.append(
            f"repositories differ (missing, extra, other refs or fsck): {', '.join(bad[:20])}"
        )
    if problems:
        raise VerifyMismatch("; ".join(problems))
    return {"verified": True, "counts": facts["counts"], "repositories": len(got_lines)}


def stage(
    target: Endpoint,
    dump_dir: str | os.PathLike,
    dest: str,
    *,
    source_dir: str | None = None,
    _ctx: _Ctx | None = None,
) -> str:
    """Copy the export into ``dest`` (a new directory under the target's data root) and return it.

    ``dest`` must not exist (``mkdir`` without ``-p``), each file is written with no-clobber and
    its sha256 is read back; nothing is ever overwritten or removed."""
    ctx = _ctx or _Ctx()
    src = Path(dump_dir)
    _read_export(src)
    if not target.data_root:
        raise MigrateError(
            "stage needs the target's data root (--data-root): the directory dest must lie in"
        )
    guard_dir(dest, root=target.data_root)
    if target.ssh is None and source_dir is not None and os.path.realpath(source_dir) == dest:
        raise MigrateError("the destination is the export itself")
    _run(ctx, target, ["mkdir", "-m", "0700", "--", dest])
    for name in FILES:
        remote = f"{dest}/{name}"
        with (src / name).open("rb") as f:
            _run(ctx, target, ["sh", "-c", 'set -C; umask 077; cat > "$1"', "sh", remote], stdin=f)
        got = _run(ctx, target, ["sha256sum", "--", remote]).decode().split()[0]
        if got != _sha256(src / name)[1]:
            raise MigrateError(f"{remote}: sha256 differs after the copy")
    return dest


def freeze(source: Endpoint, *, _ctx: _Ctx | None = None) -> dict:
    """Stop the instance (a write: only in the cutover window, only to stop).

    A container whose restart policy is ``always`` or ``unless-stopped`` would come back with its
    host (two live instances: split brain), so the policy is set to ``no`` first and the one it had
    is returned: pass it to :func:`unfreeze` (``--restart``) to put it back."""
    ctx = _ctx or _Ctx()
    was = (
        _run(
            ctx,
            source,
            [
                "docker",
                "inspect",
                "--format",
                "{{.HostConfig.RestartPolicy.Name}}",
                source.container,
            ],
        )
        .decode()
        .strip()
        or "no"
    )
    if was != "no":
        _run(ctx, source, ["docker", "update", "--restart=no", source.container])
    _run(ctx, source, ["docker", "stop", source.container])
    return {
        "stopped": source.container,
        "running": _running(ctx, source),
        "restart_policy_was": was,
    }


def unfreeze(source: Endpoint, *, restart: str | None = None, _ctx: _Ctx | None = None) -> dict:
    """Start the instance again, first putting back the restart policy ``freeze`` reported.

    Never do this after the cutover: the source and the target would both serve."""
    ctx = _ctx or _Ctx()
    if restart is not None:
        if restart not in _RESTART_POLICIES:
            raise MigrateError(f"--restart: one of {', '.join(_RESTART_POLICIES)}")
        _run(ctx, source, ["docker", "update", f"--restart={restart}", source.container])
    _run(ctx, source, ["docker", "start", source.container])
    return {"started": source.container, "running": _running(ctx, source)}


def _endpoint(a: argparse.Namespace) -> Endpoint:
    kw = {k: v for k, v in {"exec_user": a.exec_user, "config": a.config, "work_dir": a.work_dir,
                                "repos_root": a.repos_root, "db_path": a.db_path}.items() if v}  # fmt: skip
    return Endpoint(
        container=a.container, ssh=a.ssh, sudo=not a.no_sudo, data_root=a.data_root, **kw
    )


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "command", choices=["dump", "stage", "verify", "inventory", "freeze", "unfreeze"]
    )
    ap.add_argument("--ssh", help="user@host (default: this host)")
    ap.add_argument("--no-sudo", action="store_true")
    ap.add_argument("--container", required=True, help="the container that runs the instance")
    ap.add_argument(
        "--exec-user", help="the account the product runs as, when the image is the root one (git)"
    )
    ap.add_argument("--config", help="app.ini in the container (default: the rootless image's)")
    ap.add_argument(
        "--work-dir",
        help="the product's work directory, for a one-off run over a stopped container (the root image's data directory)",
    )
    ap.add_argument("--repos-root", help="the repositories' root in the container")
    ap.add_argument("--db-path", help="the SQLite database file in the container")
    ap.add_argument("--data-root", help="stage: the target's data root the destination must lie in")
    ap.add_argument(
        "--dir", help="dump: the (empty) directory to write; stage and verify: the export to read"
    )
    ap.add_argument("--dest", help="stage: the new directory on the target (under --data-root)")
    ap.add_argument(
        "--allow-live", action="store_true", help="dump: accept a running source (a rehearsal copy)"
    )
    ap.add_argument(
        "--allow-empty",
        action="store_true",
        help="accept an instance with no account or repository",
    )
    ap.add_argument(
        "--restart",
        choices=_RESTART_POLICIES,
        help="unfreeze: the restart policy freeze reported (restart_policy_was), put back before the start",
    )
    ap.add_argument(
        "--require-quiescent",
        action="store_true",
        help="verify: refuse an export not taken from a frozen source",
    )
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    try:
        ep = _endpoint(a)
        if a.command in ("dump", "stage", "verify") and not a.dir:
            raise MigrateError(f"{a.command} needs --dir")
        if a.command == "dump":
            result = dump(ep, a.dir, allow_live=a.allow_live, allow_empty=a.allow_empty)
        elif a.command == "stage":
            if not a.dest:
                raise MigrateError("stage needs --dest")
            result = {"staged": stage(ep, a.dir, a.dest, source_dir=a.dir)}
        elif a.command == "verify":
            result = verify(
                ep, a.dir, require_quiescent=a.require_quiescent, allow_empty=a.allow_empty
            )
        elif a.command == "inventory":
            result = inventory(ep)
        elif a.command == "freeze":
            result = freeze(ep)
        else:
            result = unfreeze(ep, restart=a.restart)
    except VerifyMismatch as e:
        print(f"forge-migrate: {e}", file=sys.stderr)
        return 1
    except MigrateError as e:
        print(f"forge-migrate: {e}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
