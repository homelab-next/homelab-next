# SPDX-License-Identifier: Apache-2.0
"""``agents.yml``: the activity store, retention, caps, stuck thresholds, the private tier's front
door, the push ingest's senders and the broker Approvals page (``schemas/status/agents.schema.json``).

Secrets are referenced by their secret-store name (``secret:status/ingest/cloud-token``), never held in
the file.  At run time a reference is read from the environment variable
:func:`homelabnext.registry.model.secret_env_name` derives from it (``HNX_SECRET_STATUS_INGEST_CLOUD_TOKEN``,
what a systemd ``LoadCredential``/env file or the secret-store agent provides) or from a file of
that name under ``secrets_dir``.  An unresolvable reference **disables what it guards** -- the
private tier, or that one sender -- and says so; it never falls back to "open".
"""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths
from homelabnext._yaml import UniqueKeyLoader
from homelabnext.registry.model import (
    Registry,
    secret_env_name,
    secret_ref_problems,
    service_secret_refs,
)

from .model import DEFAULT_STUCK_AFTER_S, Thresholds
from .store import DEFAULT_CAPS, ActivityStore, Redactor

SecretLookup = Callable[[str], "str | None"]


class AgentsConfigError(ValueError):
    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


def secret_lookup(
    env: Mapping[str, str] | None = None, secrets_dir: str | Path | None = None
) -> SecretLookup:
    """``secret:<name>`` -> its value from the environment or ``secrets_dir``, else None."""
    environ = os.environ if env is None else env

    def lookup(ref: str) -> str | None:
        value = environ.get(secret_env_name(ref), "")
        if not value and secrets_dir is not None:
            name = ref.removeprefix("secret:")
            p = Path(secrets_dir) / name
            if ".." not in Path(name).parts and p.is_file():
                value = p.read_text(encoding="utf-8").strip()
        return value or None

    return lookup


@dataclass(frozen=True)
class FrontDoor:
    """What a request must carry to see the private tier (see :mod:`.auth`)."""

    trusted: frozenset[str]  # proxy addresses (canonical text)
    header: str
    secret: str
    identity_header: str
    groups_header: str
    viewer_group: str
    access_log: Path


@dataclass(frozen=True)
class Sender:
    """One push sender: its token, whether it may send the detail tier, and the runtimes it may
    report (empty: any).  Its events are stored ``via push:<name>``, and it may only add to
    sessions it started (``homelabnext.status.agents.ingest.check_batch``)."""

    name: str
    token: str
    detail: bool = True
    runtimes: tuple[str, ...] = ()


@dataclass(frozen=True)
class IngestSettings:
    senders: tuple[Sender, ...]
    max_body_bytes: int = 262144
    max_events: int = 200
    rate_per_min: int = 120

    def __post_init__(self) -> None:
        # a token names its sender (sender_for): two senders with one token are one sender
        # with two sets of rights, whichever matched last
        by_token: dict[str, str] = {}
        for s in self.senders:
            other = by_token.setdefault(s.token, s.name)
            if other != s.name:
                raise ValueError(f"ingest senders {other} and {s.name} have the same token")


@dataclass(frozen=True)
class ApprovalsSettings:
    """The Approvals page (:mod:`homelabnext.status.approvals`): the broker socket the hub
    relays through, the SSO issuer it vouches for, and the group allowed to decide."""

    socket: Path
    issuer: str
    approver_group: str
    timeout_s: float = 10.0


@dataclass
class AgentsConfig:
    store: Path
    retention_days: int = 14
    keep_detail: bool = True
    redact_personal_data: bool = False
    caps: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_CAPS))
    thresholds: Thresholds = field(default_factory=Thresholds)
    front_door: FrontDoor | None = None
    ingest: IngestSettings | None = None
    approvals: ApprovalsSettings | None = None
    warnings: list[str] = field(default_factory=list)

    def open_store(self, clock: Callable[[], float]) -> ActivityStore:
        return ActivityStore(
            self.store,
            clock=clock,
            retention_days=self.retention_days,
            redactor=Redactor(personal=self.redact_personal_data, caps=self.caps),
            keep_detail=self.keep_detail,
            thresholds=self.thresholds,
        )


@cache
def _validator():
    import jsonschema

    schema = json.loads(paths.schema_file("status", "agents.schema.json").read_text("utf-8"))
    return jsonschema.Draft202012Validator(schema)


def config_problems(doc: Any) -> list[str]:
    errs = sorted(_validator().iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    return [f"{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message[:200]}" for e in errs]


def _proxies(registry: Registry, names: list[str] | None) -> tuple[frozenset[str], list[str]]:
    problems: list[str] = []
    if names is None:  # default: every host that runs an edge proxy
        names = sorted({s.host for s in registry.services.values() if s.capability == "edge-proxy"})
    out = set()
    for n in names:
        host = registry.hosts.get(n)
        if host is None:
            problems.append(f"private.trusted_proxies: {n!r} is not a registry host")
        else:
            out.add(str(ipaddress.ip_address(host.address)))
    return frozenset(out), problems


def build_config(
    doc: Mapping[str, Any], registry: Registry, secrets: SecretLookup, *, base: Path = Path(".")
) -> AgentsConfig:
    problems = config_problems(doc)
    if problems:
        raise AgentsConfigError("invalid agents config", problems)
    stuck = doc.get("stuck_after_s") or {}
    cfg = AgentsConfig(
        store=base / doc["store"],
        retention_days=doc.get("retention_days", 14),
        keep_detail=doc.get("detail", True),
        redact_personal_data=doc.get("redact_personal_data", False),
        caps={**DEFAULT_CAPS, **(doc.get("caps") or {})},
        thresholds=Thresholds(
            default=stuck.get("default", DEFAULT_STUCK_AFTER_S),
            runtimes=dict(stuck.get("runtimes") or {}),
            models=dict(stuck.get("models") or {}),
        ),
    )
    priv = doc.get("private")
    if priv:
        svc = registry.services.get(priv["service"])
        if svc is None or not svc.front_door:
            raise AgentsConfigError(
                "invalid agents config",
                [
                    f"private.service {priv['service']!r} is not a registry service with a front_door"
                ],
            )
        trusted, probs = _proxies(registry, priv.get("trusted_proxies"))
        if probs:
            raise AgentsConfigError("invalid agents config", probs)
        secret = secrets(svc.front_door["secret"])
        if not secret:
            # the message names where the setting lives, never anything read from the secret store
            cfg.warnings.append(
                f"private tier disabled: the front-door secret of service {svc.name} is not set "
                "(see its front_door entry in the registry)"
            )
        elif not trusted:
            cfg.warnings.append("private tier disabled: no trusted proxy address")
        else:
            cfg.front_door = FrontDoor(
                trusted=trusted,
                header=svc.front_door["header"],
                secret=secret,
                identity_header=priv.get("identity_header", "X-Authentik-Username"),
                groups_header=priv.get("groups_header", "X-Authentik-Groups"),
                viewer_group=priv["viewer_group"],
                access_log=base / priv["access_log"],
            )
    appr = doc.get("approvals")
    if appr:
        if not priv:
            raise AgentsConfigError(
                "invalid agents config",
                [
                    "approvals needs private: the page is served behind the private tier's front door"
                ],
            )
        if appr["approver_group"] == priv["viewer_group"]:
            # a viewer may read the queue; deciding is a separate grant, never the same group
            raise AgentsConfigError(
                "invalid agents config",
                ["approvals.approver_group must differ from private.viewer_group"],
            )
        if cfg.front_door is None:
            cfg.warnings.append("approvals page disabled: the private tier's front door is off")
        else:
            cfg.approvals = ApprovalsSettings(
                socket=Path(appr["socket"]),
                issuer=appr["issuer"],
                approver_group=appr["approver_group"],
                timeout_s=float(appr.get("timeout_s", 10)),
            )
    ing = doc.get("ingest")
    if ing:
        refs = service_secret_refs(registry.services)
        refs += [(f"ingest sender {s['name']}: token", s["token"]) for s in ing["senders"]]
        problems = secret_ref_problems(refs)
        if problems:
            raise AgentsConfigError("invalid agents config", problems)
        senders = []
        for s in ing["senders"]:
            token = secrets(s["token"])
            if token:
                senders.append(
                    Sender(s["name"], token, s.get("detail", True), tuple(s.get("runtimes", ())))
                )
            else:
                cfg.warnings.append(
                    f"ingest sender {s['name']} disabled: its token is not set "
                    "(see its entry under ingest.senders)"
                )
        try:
            cfg.ingest = IngestSettings(
                senders=tuple(senders),
                max_body_bytes=ing.get("max_body_bytes", 262144),
                max_events=ing.get("max_events", 200),
                rate_per_min=ing.get("rate_per_min", 120),
            )
        except ValueError as exc:  # names senders, never a token
            raise AgentsConfigError("invalid agents config", [str(exc)]) from None
    return cfg


def load_config(
    path: str | Path,
    registry: Registry,
    secrets: SecretLookup | None = None,
    *,
    base: Path = Path("."),
) -> AgentsConfig:
    try:
        doc = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise AgentsConfigError(f"cannot read agents config {path}: {exc}") from None
    return build_config(doc, registry, secrets or secret_lookup(), base=base)
