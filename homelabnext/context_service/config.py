# SPDX-License-Identifier: Apache-2.0
"""The service's configuration: one JSON file (rendered by the module's role) plus secrets by env.

Everything is checked here, before anything starts, so a malformed source, caller or judge setting
is refused by name and never half-applied.  Secrets never appear in the file: a caller is the sha256
of its token, the admin token, the gateway key and each source's credential are read from the
environment variables the file names (the role writes them to an owner-only env file).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from homelabnext import tlp as _tlp

__all__ = [
    "ADMIN_ENV",
    "FORMATS",
    "SCOPES",
    "Caller",
    "Config",
    "ConfigError",
    "HealthQuery",
    "JudgeConfig",
    "Source",
    "load",
    "parse",
]

#: the admin caller's token (scopes reindex and health): the timer, the role's health hook
ADMIN_ENV = "CONTEXT_ADMIN_TOKEN"
#: what a configured caller may be given; ``health`` is the admin's alone
SCOPES = frozenset({"query", "reindex"})
#: how a source's files become documents
FORMATS = ("files", "yaml-records")

_NAME = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")
_KIND = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_ENV = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_REF = re.compile(r"(?:[0-9a-f]{40}|[A-Za-z0-9][A-Za-z0-9._/-]{0,199})\Z")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}\Z")
_URL = re.compile(r"(https?)://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/%+-]*)?\Z")
_ROLE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class ConfigError(ValueError):
    """The configuration is malformed; the message names the field, never a secret."""


@dataclass(frozen=True)
class Caller:
    name: str
    sha256: str  # of the token; the token itself never reaches the configuration
    ceiling: _tlp.Label
    scopes: frozenset[str]


@dataclass(frozen=True)
class Source:
    """One git repository read at ``ref`` (a branch or tag, tracked; or a 40-hex commit, pinned)."""

    name: str
    url: str
    ref: str
    kind: str
    label: _tlp.Label  # the declared TLP of everything the source holds
    paths: tuple[str, ...]  # globs, relative to the repository root
    format: str = "files"
    records_key: str = ""  # yaml-records: the top-level key of the list ("" = the root list)
    id_field: str = "id"
    title_field: str = "title"
    honour_item_labels: bool = False  # an item's own looser label is kept (ADR-0033 decision 3)
    credential_env: str = ""  # the variable holding the git credential ("" = none)
    credential_scheme: str = "bearer"  # bearer: the value is a token; basic: user:password
    max_documents: int = 20000


@dataclass(frozen=True)
class JudgeConfig:
    url: str  # the gateway's base URL; the decision role answers on POST /v1/systemone
    key_env: str
    role: str = "fast-classifier"
    threshold: float = 0.10
    workers: int = 2
    top_k: int = 5
    ceiling: _tlp.Label = _tlp.Label.AMBER  # the most restrictive label a passage sent may carry
    on_error: str = "fallback"
    tag: str = "context"
    allow_plaintext: bool = False
    timeout: float = 30.0


@dataclass(frozen=True)
class HealthQuery:
    """The canned query: ``text`` must find ``expect`` in the top hits, read at ``ceiling``."""

    text: str
    expect: str
    ceiling: _tlp.Label
    top: int = 5


@dataclass(frozen=True)
class Config:
    port: int
    model_dir: Path
    data_dir: Path
    sources: tuple[Source, ...]
    callers: tuple[Caller, ...]
    health: HealthQuery
    judge: JudgeConfig | None = None
    bind: str = ""  # "" = every address of the container (the host publishes one)
    dense_weight: float = 0.5
    min_similarity: float = 0.36
    min_score: float = 0.0
    allow_file_sources: bool = False  # file:// and absolute paths: tests and a local mirror only
    allow_plain_http: bool = False
    git: str = "git"
    git_timeout: float = 600.0
    max_body_bytes: int = 65536
    reindex_min_interval_s: float = 60.0  # a caller's reindex sooner than this after the last: 429


def _need(raw: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in raw:
        raise ConfigError(f"{where}.{key} is required")
    return raw[key]


def _str(value: Any, where: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where} must be a non-empty string")
    if pattern is not None and not pattern.match(value):
        raise ConfigError(f"{where} is malformed")
    return value


def _num(value: Any, where: str, lo: float, hi: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not lo <= value <= hi:
        raise ConfigError(f"{where} must be a number in [{lo}, {hi}]")
    return float(value)


def _int(value: Any, where: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise ConfigError(f"{where} must be an integer in [{lo}, {hi}]")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be true or false")
    return value


def _label(value: Any, where: str) -> _tlp.Label:
    try:
        return _tlp.parse(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{where} is not a TLP label") from exc


def _only(raw: Mapping[str, Any], allowed: set[str], where: str) -> None:
    extra = sorted(set(raw) - allowed)
    if extra:
        raise ConfigError(f"{where}: unknown key(s) {extra}")


def _glob(value: Any, where: str) -> str:
    g = _str(value, where)
    p = PurePosixPath(g)
    if p.is_absolute() or ".." in p.parts or "\\" in g or any(c.isspace() for c in g):
        raise ConfigError(f"{where} must be a relative glob inside the repository")
    return g


def _source_url(url: str, where: str, *, allow_file: bool, allow_http: bool) -> str:
    if url.startswith("file://") or url.startswith("/"):
        if not allow_file:
            raise ConfigError(f"{where}: a local repository needs allow_file_sources")
        if ".." in PurePosixPath(url.removeprefix("file://")).parts:
            raise ConfigError(f"{where}: a local repository path is canonical")
        return url
    m = _URL.match(url)
    if not m:
        raise ConfigError(f"{where} must be an https URL with no credential in it")
    if m[1] == "http" and not allow_http:
        raise ConfigError(f"{where}: plain http needs allow_plain_http")
    return url


_SOURCE_KEYS = set(Source.__dataclass_fields__) - {"label"} | {"tlp"}


def _source(raw: Any, i: int, *, allow_file: bool, allow_http: bool) -> Source:
    where = f"sources[{i}]"
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{where} must be a mapping")
    _only(raw, _SOURCE_KEYS, where)
    fmt = raw.get("format", "files")
    if fmt not in FORMATS:
        raise ConfigError(f"{where}.format must be one of {FORMATS}")
    paths = _need(raw, "paths", where)
    if not isinstance(paths, list) or not paths or len(paths) > 64:
        raise ConfigError(f"{where}.paths must list 1 to 64 globs")
    scheme = raw.get("credential_scheme", "bearer")
    if scheme not in ("bearer", "basic"):
        raise ConfigError(f"{where}.credential_scheme must be bearer or basic")
    cred = raw.get("credential_env", "")
    if cred != "":
        _str(cred, f"{where}.credential_env", _ENV)
    ref = _str(_need(raw, "ref", where), f"{where}.ref", _REF)
    if ".." in ref or ref.endswith(("/", ".lock")) or "//" in ref:
        raise ConfigError(f"{where}.ref is malformed")
    return Source(
        name=_str(_need(raw, "name", where), f"{where}.name", _NAME),
        url=_source_url(
            _str(_need(raw, "url", where), f"{where}.url"),
            f"{where}.url",
            allow_file=allow_file,
            allow_http=allow_http,
        ),
        ref=ref,
        kind=_str(_need(raw, "kind", where), f"{where}.kind", _KIND),
        label=_label(_need(raw, "tlp", where), f"{where}.tlp"),
        paths=tuple(_glob(g, f"{where}.paths[{j}]") for j, g in enumerate(paths)),
        format=fmt,
        records_key=raw.get("records_key", "")
        and _str(raw["records_key"], f"{where}.records_key", _FIELD),
        id_field=_str(raw.get("id_field", "id"), f"{where}.id_field", _FIELD),
        title_field=_str(raw.get("title_field", "title"), f"{where}.title_field", _FIELD),
        honour_item_labels=_bool(
            raw.get("honour_item_labels", False), f"{where}.honour_item_labels"
        ),
        credential_env=cred,
        credential_scheme=scheme,
        max_documents=_int(raw.get("max_documents", 20000), f"{where}.max_documents", 1, 200000),
    )


def _caller(raw: Any, i: int) -> Caller:
    where = f"callers[{i}]"
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{where} must be a mapping")
    _only(raw, {"name", "sha256", "ceiling", "scopes"}, where)
    scopes = _need(raw, "scopes", where)
    if (
        not isinstance(scopes, list)
        or not scopes
        or not all(isinstance(s, str) for s in scopes)
        or not set(scopes) <= SCOPES
    ):
        raise ConfigError(f"{where}.scopes must list some of {sorted(SCOPES)}")
    return Caller(
        name=_str(_need(raw, "name", where), f"{where}.name", _NAME),
        sha256=_str(_need(raw, "sha256", where), f"{where}.sha256", _HEX64),
        ceiling=_label(_need(raw, "ceiling", where), f"{where}.ceiling"),
        scopes=frozenset(scopes),
    )


def _judge(raw: Any, *, allow_http: bool) -> JudgeConfig | None:
    if raw is None:
        return None
    where = "judge"
    if not isinstance(raw, Mapping):
        raise ConfigError("judge must be a mapping or null")
    _only(raw, set(JudgeConfig.__dataclass_fields__), where)
    url = _str(_need(raw, "url", where), "judge.url", _URL)
    plain = _bool(raw.get("allow_plaintext", False), "judge.allow_plaintext")
    if url.startswith("http://") and not (plain and allow_http):
        raise ConfigError("judge.url: plain http needs allow_plaintext and allow_plain_http")
    on_error = raw.get("on_error", "fallback")
    if on_error not in ("fallback", "abstain"):
        raise ConfigError("judge.on_error must be fallback or abstain")
    return JudgeConfig(
        url=url,
        key_env=_str(_need(raw, "key_env", where), "judge.key_env", _ENV),
        role=_str(raw.get("role", "fast-classifier"), "judge.role", _ROLE),
        threshold=_num(raw.get("threshold", 0.10), "judge.threshold", 0.0, 1.0),
        workers=_int(raw.get("workers", 2), "judge.workers", 1, 16),
        top_k=_int(raw.get("top_k", 5), "judge.top_k", 1, 50),
        ceiling=_label(raw.get("ceiling", "amber"), "judge.ceiling"),
        on_error=on_error,
        tag=_str(raw.get("tag", "context"), "judge.tag", re.compile(r"[A-Za-z0-9._/-]{1,64}\Z")),
        allow_plaintext=plain,
        timeout=_num(raw.get("timeout", 30.0), "judge.timeout", 1.0, 600.0),
    )


def _health(raw: Any) -> HealthQuery:
    if not isinstance(raw, Mapping):
        raise ConfigError("health must be a mapping")
    _only(raw, {"text", "expect", "ceiling", "top"}, "health")
    text = _str(_need(raw, "text", "health"), "health.text")
    expect = _str(_need(raw, "expect", "health"), "health.expect")
    if ":" not in expect or any(c.isspace() for c in expect):
        raise ConfigError("health.expect must be a document id (<kind>:<source>/<name>)")
    return HealthQuery(
        text=text,
        expect=expect,
        ceiling=_label(_need(raw, "ceiling", "health"), "health.ceiling"),
        top=_int(raw.get("top", 5), "health.top", 1, 50),
    )


_TOP = set(Config.__dataclass_fields__)


def parse(raw: Any) -> Config:
    """A :class:`Config` from the decoded JSON, or :class:`ConfigError`."""
    if not isinstance(raw, Mapping):
        raise ConfigError("the configuration must be a mapping")
    _only(raw, _TOP, "configuration")
    allow_file = _bool(raw.get("allow_file_sources", False), "allow_file_sources")
    allow_http = _bool(raw.get("allow_plain_http", False), "allow_plain_http")
    srcs = _need(raw, "sources", "configuration")
    if not isinstance(srcs, list) or not srcs:
        raise ConfigError("sources must list at least one source")
    sources = tuple(
        _source(s, i, allow_file=allow_file, allow_http=allow_http) for i, s in enumerate(srcs)
    )
    names = [s.name for s in sources]
    if len(set(names)) != len(names):
        raise ConfigError("sources: every name is distinct")
    callers_raw = raw.get("callers", [])
    if not isinstance(callers_raw, list):
        raise ConfigError("callers must be a list")
    callers = tuple(_caller(c, i) for i, c in enumerate(callers_raw))
    if len({c.name for c in callers}) != len(callers) or "admin" in {c.name for c in callers}:
        raise ConfigError("callers: every name is distinct and none is admin (the role's own)")
    if len({c.sha256 for c in callers}) != len(callers):
        raise ConfigError("callers: two callers share a token")
    for key in ("model_dir", "data_dir"):
        p = PurePosixPath(_str(_need(raw, key, "configuration"), key))
        if not p.is_absolute() or ".." in p.parts:
            raise ConfigError(f"{key} must be an absolute canonical path")
    health = _health(_need(raw, "health", "configuration"))
    if not any(health.expect.startswith(f"{s.kind}:{s.name}/") for s in sources):
        raise ConfigError("health.expect names no configured source")
    bind = raw.get("bind", "")
    if not isinstance(bind, str):
        raise ConfigError("bind must be a string")
    return Config(
        port=_int(_need(raw, "port", "configuration"), "port", 1024, 65535),
        model_dir=Path(raw["model_dir"]),
        data_dir=Path(raw["data_dir"]),
        sources=sources,
        callers=callers,
        health=health,
        judge=_judge(raw.get("judge"), allow_http=allow_http),
        bind=bind,
        dense_weight=_num(raw.get("dense_weight", 0.5), "dense_weight", 0.0, 1.0),
        min_similarity=_num(raw.get("min_similarity", 0.36), "min_similarity", 0.0, 1.0),
        min_score=_num(raw.get("min_score", 0.0), "min_score", 0.0, 1.0),
        allow_file_sources=allow_file,
        allow_plain_http=allow_http,
        git=_str(raw.get("git", "git"), "git"),
        git_timeout=_num(raw.get("git_timeout", 600.0), "git_timeout", 5.0, 7200.0),
        max_body_bytes=_int(raw.get("max_body_bytes", 65536), "max_body_bytes", 1024, 1 << 22),
        reindex_min_interval_s=_num(
            raw.get("reindex_min_interval_s", 60.0), "reindex_min_interval_s", 0.0, 86400.0
        ),
    )


def load(path: str | Path) -> Config:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read the configuration ({type(exc).__name__})") from exc
    return parse(raw)
