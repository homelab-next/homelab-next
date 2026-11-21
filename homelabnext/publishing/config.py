# SPDX-License-Identifier: Apache-2.0
"""The run's configuration (a JSON file the role renders; no secret in it) and the credentials.

Credentials are read by name at run time from a directory (systemd ``LoadCredential``): one file
per name, which must not be readable by group or others (0600 or tighter), never empty, never
cached in the config.  ``stage`` mode reads only the deny-list: it needs no hosting credential
and makes no network call.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from homelabnext import tlp
from homelabnext.publishing import feed as fd
from homelabnext.publishing import gate as gt
from homelabnext.publishing.pages import PagesConfig

MODES = ("stage", "dry-run", "live")
CRED_PAGES_TOKEN = "cloudflare-api-token"
CRED_R2_KEY_ID = "r2-access-key-id"
CRED_R2_SECRET = "r2-secret-access-key"
CRED_DENY_LIST = "deny-list"
CRED_NOTIFY = "notify-token"


class ConfigError(ValueError):
    pass


def read_credential(directory: Path, name: str) -> str:
    """The value of credential ``name``; refuses a missing, empty, linked or too-open file."""
    path = directory / name
    try:
        st = path.lstat()
    except OSError as exc:
        raise ConfigError(f"credential {name!r} is not readable ({type(exc).__name__})") from exc
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"credential {name!r} is not a regular file")
    if st.st_uid not in (0, os.geteuid()):
        raise ConfigError(f"credential {name!r} is owned by neither root nor this user")
    if st.st_mode & 0o077:
        raise ConfigError(
            f"credential {name!r} is readable by group or others (mode {st.st_mode & 0o777:04o}); 0600 or tighter"
        )
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ConfigError(f"credential {name!r} is empty")
    return value


@dataclass(frozen=True)
class R2Config:
    account_id: str
    bucket: str
    endpoint: str  # https://<account>.<object-store host>, derived unless given


LANE_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_LANE_KEYS = {"lane", "dir"}


@dataclass(frozen=True)
class LaneSource:
    """A producer lane's output directory (``<dir>/<kind>/<id>/`` items, the same contract as the
    publishable area).  Always **stage-only**: whatever the run's mode, its items are gated and
    staged under ``<staging>/lane-<lane>/`` and nothing is ever deployed or uploaded from it, so a
    shadow lane cannot reach the network through this module.  Its snapshots and staged items are
    kept apart from every other lane's and from the publishable area's."""

    lane: str
    dir: Path


_LIVE_KEYS = {"lane", "dir", "root"}
# the lanes that may be live: a positive list (a name deny-list is evaded by `shadows`, `shdw`, ...)
LIVE_LANES = ("real",)
_SHADOW_RE = re.compile(r"(^|[-_.])shadow($|[-_.])", re.IGNORECASE)


@dataclass(frozen=True)
class LiveSource:
    """The ONE directory whose items are the live source (it replaces ``publishable_dir`` as what
    the run gates, stages, deploys and uploads).  It names a lane only so the site says which
    producer lane it is; the shadow lane can never be it (by name, or by any ``shadow`` component of
    the real path), and no ``lane_sources`` entry may be or nest with it."""

    lane: str
    dir: Path


@dataclass(frozen=True)
class Config:
    mode: str
    publishable_dir: Path
    staging_dir: Path
    state_dir: Path
    credentials_dir: Path
    ceiling: tlp.Label
    audience: str
    access_control: str
    posture_rules: bool
    pages: PagesConfig | None
    pages_account_id: str
    r2: R2Config | None
    feed: fd.FeedConfig | None
    notify_url: str
    notify_topic: str
    snapshots_keep: int = 5
    snapshots_min_age_s: float = 3600.0
    legacy_exceptions: dict[str, str] | None = None
    staging_keep: int = 48
    staging_min_age_s: float = 172800.0
    lane_sources: tuple[LaneSource, ...] = ()
    live_source: LiveSource | None = None
    posture_rules_disabled: tuple[str, ...] = ()


def _posture_disabled(names: object) -> tuple[str, ...]:
    try:
        return tuple(sorted(gt.check_posture_rules_disabled(names)))
    except gt.GateError as exc:
        raise ConfigError(str(exc)) from exc


def _abs(doc: dict, key: str) -> Path:
    v = doc.get(key)
    if not isinstance(v, str) or not os.path.isabs(v) or ".." in Path(v).parts:
        raise ConfigError(f"{key} is an absolute path without ..")
    return Path(v)


def _legacy(items: object) -> dict[str, str]:
    """``[{key, sha256}]`` -> {key: sha256}: reviewed, already-public legacy metadata objects."""
    out: dict[str, str] = {}
    if not isinstance(items, list):
        raise ConfigError("legacy_exceptions is a list of {key, sha256}")
    for it in items:
        if (
            not isinstance(it, dict)
            or not re.fullmatch(
                r"episodes/[a-z0-9][a-z0-9-]{0,63}_\d{4}-\d{2}-\d{2}\.json", str(it.get("key", ""))
            )
            or not re.fullmatch(r"[0-9a-f]{64}", str(it.get("sha256", "")))
        ):
            raise ConfigError("a legacy exception needs an episode metadata key and its sha256")
        out[it["key"]] = it["sha256"]
    return out


def _nested(a: str, b: str) -> bool:
    return a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")


def _lanes(items: object, others: list[Path]) -> tuple[LaneSource, ...]:
    """``[{lane, dir}]``: stage-only producer lanes (see :class:`LaneSource`)."""
    if not isinstance(items, list):
        raise ConfigError("lane_sources is a list of {lane, dir}")
    out: list[LaneSource] = []
    for it in items:
        if not isinstance(it, dict) or set(it) != _LANE_KEYS:
            raise ConfigError(
                "a lane source is {lane, dir} and nothing else (it is always stage-only)"
            )
        lane = it["lane"]
        if not isinstance(lane, str) or not LANE_RE.match(lane) or len(lane) > 32:
            raise ConfigError("a lane source's lane is a short slug")
        d = _abs(it, "dir")
        if any(x.lane == lane for x in out):
            raise ConfigError(f"lane source {lane!r} is listed twice")
        real = os.path.realpath(d)  # a link or a doubled slash is the same directory
        taken = [os.path.realpath(x.dir) for x in out] + [os.path.realpath(o) for o in others]
        if any(_nested(real, t) for t in taken):
            raise ConfigError(
                "a lane source's dir is its own: not nested with another lane's, publishable_dir, "
                "staging_dir, state_dir or credentials_dir"
            )
        out.append(LaneSource(lane, d))
    return tuple(out)


def _same_inode(a: str, b: str) -> bool:
    """True when two paths are one directory on disk (a bind mount has another path, the same
    ``(st_dev, st_ino)``, which realpath cannot see).  A path that does not exist is nobody's."""
    try:
        x, y = os.stat(a), os.stat(b)
    except OSError:
        return False
    return (x.st_dev, x.st_ino) == (y.st_dev, y.st_ino)


def _not_lane_writable(path: str) -> None:
    """A live source's root and its parent are the producer's trust anchor: a lane user who could
    write either could swap what the parents resolve to after validation.  Owned by root (or this
    user) and not group- or world-writable; an absent one is not yet installed and is skipped."""
    for p in (path, os.path.dirname(path)):
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
            raise ConfigError(
                f"the live source's root {path!r} and its parent must be owned by root and not "
                "writable by group or others (a lane user must not be able to repoint them)"
            )


def _live(item: object, others: list[Path], lanes: tuple[LaneSource, ...]) -> LiveSource:
    """``{lane, dir, root}``: the single live source (see :class:`LiveSource`)."""
    if not isinstance(item, dict) or set(item) != _LIVE_KEYS:
        raise ConfigError("live_source is {lane, dir, root} and nothing else")
    lane = item["lane"]
    if not isinstance(lane, str) or not LANE_RE.match(lane) or len(lane) > 32:
        raise ConfigError("the live source's lane is a short slug")
    if _SHADOW_RE.search(lane):
        raise ConfigError("the shadow lane can never be the live source")
    d = _abs(item, "dir")
    real = os.path.realpath(
        d
    )  # a link, a doubled slash or a bind-style alias is judged by what it is
    if any(_SHADOW_RE.search(part) for part in Path(real).parts[1:]) or any(
        _SHADOW_RE.search(part) for part in d.parts[1:]
    ):
        raise ConfigError("the live source's dir is under a shadow path: refused")
    # POSITIVE check: the live dir is exactly <root>/<lane> (by real path) for an allowed lane that
    # is no stage-only lane, and is not the same directory on disk (st_dev, st_ino) as any lane source
    if lane not in LIVE_LANES:
        raise ConfigError(f"the live source's lane is one of {', '.join(LIVE_LANES)}")
    root = _abs(item, "root")
    if real != os.path.realpath(root / lane):
        raise ConfigError("the live source's dir is not exactly <root>/<lane> (by real path)")
    if any(x.lane == lane for x in lanes):
        raise ConfigError(f"lane {lane!r} is a stage-only lane source: it cannot also be live")
    for x in lanes:
        if _same_inode(str(d), str(x.dir)):
            raise ConfigError("the live source's dir is the same directory as a lane source's")
    if _same_inode(str(d), str(root / "shadow")):
        raise ConfigError("the live source's dir is the shadow lane's directory")
    _not_lane_writable(os.path.realpath(root))
    if any(_nested(real, os.path.realpath(o)) for o in others):
        raise ConfigError(
            "the live source's dir is its own: not nested with a lane source, staging_dir, "
            "state_dir or credentials_dir"
        )
    return LiveSource(lane, d)


def load(path: Path, mode_override: str | None = None) -> Config:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"config {path}: {type(exc).__name__}") from exc
    if not isinstance(doc, dict):
        raise ConfigError("the config is not an object")
    mode = mode_override or doc.get("mode", "stage")
    if mode not in MODES:
        raise ConfigError(f"mode is one of {', '.join(MODES)}")
    try:
        ceiling = tlp.parse(doc.get("tlp_allowed", "clear"))
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    pages = None
    if isinstance(doc.get("pages"), dict):
        p = doc["pages"]
        pages = PagesConfig(
            project=p.get("project", ""),
            branch=p.get("branch", ""),
            wrangler_version=p.get("wrangler_version", ""),
            lock_sha256=p.get("lock_sha256", ""),
            install_dir=_abs(p, "install_dir"),
            node=_abs(p, "node") if "node" in p else Path("/usr/bin/node"),
        )
    r2 = feed = None
    if isinstance(doc.get("r2"), dict):
        r = doc["r2"]
        acct, bucket = r.get("account_id", ""), r.get("bucket", "")
        if not acct or not bucket:
            raise ConfigError("r2 needs account_id and bucket")
        r2 = R2Config(acct, bucket, r.get("endpoint") or f"https://{acct}.r2.cloudflarestorage.com")
        feed = fd.FeedConfig(
            **{
                k: doc.get("feed", {}).get(k, "")
                for k in ("public_base_url", "title", "description", "author", "owner_email")
            },
            category=doc.get("feed", {}).get("category", "Technology"),
        )
    notify = doc.get("notify") or {}
    publishable = _abs(doc, "publishable_dir")
    staging, state, creds = (
        _abs(doc, "staging_dir"),
        _abs(doc, "state_dir"),
        _abs(doc, "credentials_dir"),
    )
    lanes = _lanes(doc.get("lane_sources", []), [publishable, staging, state, creds])
    live = None
    if doc.get("live_source") is not None:
        live = _live(doc["live_source"], [*(x.dir for x in lanes), staging, state, creds], lanes)
        if _nested(os.path.realpath(live.dir), os.path.realpath(publishable)) and os.path.realpath(
            live.dir
        ) != os.path.realpath(publishable):
            raise ConfigError("the live source's dir may not nest with publishable_dir")
    return Config(
        mode=mode,
        publishable_dir=live.dir if live else publishable,
        staging_dir=staging,
        state_dir=state,
        credentials_dir=creds,
        ceiling=ceiling,
        audience=doc.get("audience", "public"),
        access_control=doc.get("access_control", ""),
        posture_rules=bool(doc.get("posture_rules", True)),
        pages=pages,
        pages_account_id=(doc.get("pages") or {}).get("account_id", ""),
        r2=r2,
        feed=feed,
        notify_url=notify.get("url", ""),
        notify_topic=notify.get("topic", ""),
        snapshots_keep=int(doc.get("snapshots_keep", 5)),
        snapshots_min_age_s=float(doc.get("snapshots_min_age_s", 3600)),
        legacy_exceptions=_legacy(doc.get("legacy_exceptions", [])),
        staging_keep=int(doc.get("staging_keep", 48)),
        staging_min_age_s=float(doc.get("staging_min_age_s", 172800)),
        lane_sources=lanes,
        live_source=live,
        posture_rules_disabled=_posture_disabled(doc.get("posture_rules_disabled", [])),
    )
