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
import stat
from dataclasses import dataclass
from pathlib import Path

from homelabnext import tlp
from homelabnext.publishing import feed as fd
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


def _abs(doc: dict, key: str) -> Path:
    v = doc.get(key)
    if not isinstance(v, str) or not os.path.isabs(v) or ".." in Path(v).parts:
        raise ConfigError(f"{key} is an absolute path without ..")
    return Path(v)


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
    return Config(
        mode=mode,
        publishable_dir=_abs(doc, "publishable_dir"),
        staging_dir=_abs(doc, "staging_dir"),
        state_dir=_abs(doc, "state_dir"),
        credentials_dir=_abs(doc, "credentials_dir"),
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
    )
