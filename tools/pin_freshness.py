#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: pin-freshness
#   kind: tool
#   purpose: Report the version pins dependabot cannot parse against their upstream's newest release past the 14-day cooldown.
#   owner: maintainers
#   trigger: [ci:pin-freshness/report, manual]
#   inputs: the tree (role defaults, the public modules' role defaults, workflow env, the Terraform provider block, the Makefile); upstream release lists over HTTPS (report only)
#   outputs: inventory - the pins found, as JSON; report - a Markdown report for the tracking issue
#   exit:
#     "0": inventory listed, or report written (pins that are behind are reported, never a failure)
#     "1": inventory --check found a pin with no upstream source, or a source with no pin
#     "2": usage error, an unreadable tree or an unwritable --out file
"""Which pins are behind upstream, for the ones dependabot cannot see.

    python tools/pin_freshness.py inventory [--check]
    python tools/pin_freshness.py report [--out FILE] [--cooldown-days 14] [--now ISO]

Dependabot updates actions, the hashed constraints, compose images, Dockerfiles and pre-commit
hooks.  It cannot parse these, so they drift unseen:

* an Ansible role's ``*_version`` and ``*_image`` defaults (``ansible/roles/*/defaults/main.yml``
  and a public module's ``modules/*/roles/*/defaults/main.yml``), including an empty version that
  installs whatever the vendor repository serves;
* a workflow's ``*_VERSION`` env (``.github/workflows/*.yml``), usually beside the checksum that
  must move with it (``*_SHA256``, ``*_SHA512``, ``*_SUM_SHA256``), and ``GO_VERSION``;
* the Terraform provider constraint the compute generator writes;
* uv, which ``make constraints`` runs at whatever version is installed.

``inventory`` finds them offline; ``--check`` fails when one has no upstream in :data:`SOURCES`
(or a source names a pin that is gone), so a new pin is never silently unwatched.  ``report``
asks each upstream for its releases and, honouring the same cooldown as dependabot and ``make
constraints`` (a release younger than 14 days is held back, and listed as such), writes one
Markdown report: for each pin the newest release on its own line (same major.minor) and the
newest overall.  Being behind is reported, never an exit status: the scheduled workflow puts the
report in one tracking issue, and an upstream release never turns a pull request red.  A source
that cannot be read is reported as not checked.

The GitHub token (``GH_TOKEN`` or ``GITHUB_TOKEN``) is sent to the GitHub API only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MARKER = "<!-- hnx:pin-freshness -->"
COOLDOWN_DAYS = 14
GITHUB_HOST = "api.github.com"
GITHUB_API = f"https://{GITHUB_HOST}"
PYPI = "https://pypi.org/pypi"
GO_PROXY = "https://proxy.golang.org"
TIMEOUT = 30
MAX_BYTES = 20 * 1024 * 1024  # the largest answer read; the PyPI JSON of a big project is ~5 MB
MAX_ERROR = 200  # characters of an upstream error shown in the issue

# Where each pin's releases are published: ("github", "owner/repo") for GitHub releases,
# ("pypi", "name"), ("go-toolchain", "") or ("none", "why it is not compared").
SOURCES: dict[str, tuple[str, str]] = {
    "ci:GO_VERSION": ("go-toolchain", ""),
    "ci:ACTIONLINT_VERSION": ("github", "rhysd/actionlint"),
    "ci:NATS_SERVER_VERSION": ("github", "nats-io/nats-server"),
    "ci:ZIZMOR_VERSION": ("pypi", "zizmor"),
    "ci:CADDY_VERSION": ("github", "caddyserver/caddy"),
    "ci:GITLEAKS_VERSION": ("github", "gitleaks/gitleaks"),
    "role:docker_engine/docker_engine_version": (
        "none",
        "moby/moby tags engine releases docker-vX.Y.Z, which the github source does not parse: "
        "compare with its releases page by hand",
    ),
    "role:caddy/caddy_image": ("github", "caddyserver/caddy"),
    "role:caddy/caddy_lego_version": ("github", "go-acme/lego"),
    "role:caddy_auth_proxy/caddy_auth_proxy_image": ("github", "oauth2-proxy/oauth2-proxy"),
    "role:docker_engine/docker_engine_containerd_version": ("github", "containerd/containerd"),
    "role:docker_engine/docker_engine_buildx_version": ("github", "docker/buildx"),
    "role:docker_engine/docker_engine_compose_version": ("github", "docker/compose"),
    "role:events_bus/events_bus_version": ("github", "nats-io/nats-server"),
    "role:example_service/example_service_version": ("none", "a fictitious example package"),
    "role:keycloak/keycloak_image": ("github", "keycloak/keycloak"),
    "role:keycloak/keycloak_postgres_image": (
        "none",
        "the Docker official image (docker.io/library/postgres): compare its tags with the "
        "PostgreSQL release page by hand, within the pinned major version",
    ),
    "role:ntfy/ntfy_image": ("github", "binwiederhier/ntfy"),
    "role:open_webui/open_webui_image": ("github", "open-webui/open-webui"),
    "role:openbao/openbao_version": ("github", "openbao/openbao"),
    "role:openbao/openbao_lego_version": ("github", "go-acme/lego"),
    "role:tailscale_node/tailscale_node_version": ("github", "tailscale/tailscale"),
    "role:trivy/trivy_version": ("github", "aquasecurity/trivy"),
    "role:vllm_server/vllm_server_version": ("pypi", "vllm"),
    "role:wazuh_agent/wazuh_agent_version": ("github", "wazuh/wazuh"),
    "terraform:bpg/proxmox": ("github", "bpg/terraform-provider-proxmox"),
    "tool:uv": ("pypi", "uv"),
}

# A note shown beside a pin in the report: what else moves with it.
NOTES: dict[str, str] = {
    "ci:NATS_SERVER_VERSION": "moves with the lab-in-a-box NATS image (dependabot raises that one)",
    "ci:CADDY_VERSION": "the example registries' `impl: caddy` version moves with it",
    "ci:ZIZMOR_VERSION": "docs/private-overlay.md names it",
    "role:wazuh_agent/wazuh_agent_version": "never newer than the manager it reports to",
    "role:docker_engine/docker_engine_version": "docker-ce and docker-ce-cli move with it",
    "role:open_webui/open_webui_image": "an image: bump the tag and its digest together",
    "role:caddy/caddy_image": (
        "an image (modules/caddy): bump the tag and its digest together, with product.version in "
        "modules/caddy/module.yml, the lab registry's version and the CI CADDY_VERSION/CADDY_SHA512"
    ),
    "role:caddy/caddy_lego_version": (
        "moves with caddy_lego_checksums and caddy_lego_checksums_release, and with role openbao's "
        "lego pin (tools/tests/test_pin_consistency.py holds them equal)"
    ),
    "role:caddy_auth_proxy/caddy_auth_proxy_image": (
        "an image (modules/caddy, the -alpine variant): bump the tag and its digest together, with "
        "the lab registry's auth-proxy version"
    ),
    "role:keycloak/keycloak_image": (
        "an image (modules/keycloak): bump the tag and its digest together, with product.version "
        "in modules/keycloak/module.yml and the lab registry's version"
    ),
    "role:keycloak/keycloak_postgres_image": (
        "an image (modules/keycloak): the tag and its digest together, a minor version only "
        "(a major one is a dump and a restore)"
    ),
    "role:ntfy/ntfy_image": (
        "an image (modules/ntfy): bump the tag and its digest together, with product.version in "
        "modules/ntfy/module.yml and the lab registry's version"
    ),
    "role:openbao/openbao_lego_version": (
        "moves with openbao_lego_checksums and openbao_lego_checksums_release, taken from the "
        "release's lego_<version>_checksums.txt"
    ),
    "role:openbao/openbao_version": (
        "moves with the lab-in-a-box `secrets` image (dependabot raises that one) and with "
        "openbao_checksums, taken from the release's signed checksums.txt"
    ),
}

_VERSION = re.compile(r"^v?(\d+(?:\.\d+){0,3})$")


@dataclass(frozen=True)
class Pin:
    id: str
    path: str
    line: int
    value: str  # as written: a version, an image reference, a constraint, or "" when unpinned
    checksum: str | None = None  # the env key that must move with it, if any
    kind: str = "version"  # version | image | constraint | unpinned


@dataclass(frozen=True)
class Release:
    version: tuple[int, ...]
    tag: str
    published: datetime


@dataclass
class Finding:
    pin: Pin
    current: tuple[int, ...] | None
    line_latest: Release | None = None
    newest: Release | None = None
    held: list[Release] = field(default_factory=list)  # newer, but inside the cooldown
    status: str = ""
    error: str | None = None


def parse_version(text: str) -> tuple[int, ...] | None:
    """``1.26.10`` / ``v1.7.12`` -> ints; a pre-release, a constraint or a word -> None."""
    m = _VERSION.match(text.strip())
    return tuple(int(p) for p in m.group(1).split(".")) if m else None


def _fmt(v: tuple[int, ...] | None) -> str:
    return ".".join(map(str, v)) if v else "-"


# --- inventory: offline --------------------------------------------------------------------


_ROLE_KEY = re.compile(
    r'^(?P<key>[a-z0-9_]+_(?:version|image)):\s*(?P<q>"?)(?P<val>[^"\s#]*)(?P=q)'
)
_ENV_KEY = re.compile(
    r'^\s+(?P<key>[A-Z0-9_]+_VERSION):\s*(?P<q>"?)(?P<val>[^"\s#]+)(?P=q)\s*(?:#.*)?$'
)
_CHECKSUM = ("_SUM_SHA256", "_SHA256", "_SHA512")
_TF = re.compile(
    r'source\s*=\s*"(?P<src>[a-z0-9-]+/[a-z0-9-]+)"\s*\n\s*version\s*=\s*"(?P<val>[^"]+)"'
)


def _lineno(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def inventory(root: Path = ROOT) -> list[Pin]:
    pins: list[Pin] = []
    # the core's roles, then the public modules' roles (modules/<id>/roles/<role>/): one role
    # namespace, so a module role is watched under its own name like a core one
    role_defaults = sorted((root / "ansible" / "roles").glob("*/defaults/main.yml")) + sorted(
        (root / "modules").glob("*/roles/*/defaults/main.yml")
    )
    for f in role_defaults:
        role = f.parent.parent.name
        for n, line in enumerate(f.read_text().splitlines(), 1):
            m = _ROLE_KEY.match(line)
            if not m:
                continue
            key, val = m["key"], m["val"]
            kind = "image" if key.endswith("_image") else ("version" if val else "unpinned")
            pins.append(
                Pin(f"role:{role}/{key}", f.relative_to(root).as_posix(), n, val, None, kind)
            )
    for f in sorted((root / ".github" / "workflows").glob("*.yml")):
        lines = f.read_text().splitlines()
        for n, line in enumerate(lines, 1):
            m = _ENV_KEY.match(line)
            if not m:
                continue
            prefix = m["key"].removesuffix("_VERSION")
            near = "\n".join(lines[max(0, n - 4) : n + 4])
            checksum = next(
                (prefix + s for s in _CHECKSUM if re.search(rf"^\s+{prefix}{s}:", near, re.M)),
                None,
            )
            pins.append(
                Pin(f"ci:{m['key']}", f.relative_to(root).as_posix(), n, m["val"], checksum)
            )
    gen = root / "homelabnext" / "compute" / "gen" / "terraform_proxmox.py"
    if gen.is_file():
        text = gen.read_text()
        for m in _TF.finditer(text):
            pins.append(
                Pin(
                    f"terraform:{m['src']}",
                    gen.relative_to(root).as_posix(),
                    _lineno(text, m.start("val")),
                    m["val"],
                    kind="constraint",
                )
            )
    make = root / "Makefile"
    if make.is_file():
        for n, line in enumerate(make.read_text().splitlines(), 1):
            if re.match(r"^\s+uv pip compile\b", line):
                pins.append(Pin("tool:uv", "Makefile", n, "", kind="unpinned"))
                break
    return pins


def check_inventory(
    pins: list[Pin], sources: dict[str, tuple[str, str]] | None = None
) -> list[str]:
    sources = SOURCES if sources is None else sources
    ids = [p.id for p in pins]
    out = [
        f"{p.path}:{p.line}: {p.id} has no upstream in SOURCES" for p in pins if p.id not in sources
    ]
    out += [f"SOURCES names {i}, which the tree no longer pins" for i in sources if i not in ids]
    out += [f"{i} is pinned twice" for i in sorted({i for i in ids if ids.count(i) > 1})]
    return out


# --- upstream: report only -----------------------------------------------------------------


Fetch = Callable[[str], Any]


class _GitHubOnlyAuth(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to https, and carry the token only to the GitHub API host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https":
            raise urllib.error.HTTPError(
                newurl, code, "redirect away from https refused", headers, fp
            )
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and target.hostname != GITHUB_HOST:
            new.remove_header("Authorization")
        return new


def opener(*handlers: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_GitHubOnlyAuth, *handlers)


def http_fetch(url: str, open_with: urllib.request.OpenerDirector | None = None) -> Any:
    """GET ``url`` as JSON (or text, for a plain-text response).

    The token goes to the GitHub API only, and not along a redirect to another host; an answer
    over :data:`MAX_BYTES` is refused."""
    headers = {"User-Agent": "homelabnext-pin-freshness", "Accept": "application/json"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(GITHUB_API + "/"):
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
    req = urllib.request.Request(url, headers=headers)
    with (open_with or opener()).open(req, timeout=TIMEOUT) as r:  # only the https URLs above
        raw = r.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError(f"answer larger than {MAX_BYTES // (1024 * 1024)} MB refused")
        body = raw.decode()
        return json.loads(body) if "json" in r.headers.get("Content-Type", "") else body


def describe(exc: BaseException) -> str:
    """An upstream failure as one short line safe to put in the issue: the exception type and,
    for HTTP, the status; any other message capped and stripped of what Markdown would act on."""
    if isinstance(exc, urllib.error.HTTPError):
        return f"{type(exc).__name__} {exc.code}"
    text = " ".join(str(exc).split())
    text = re.sub(r"[`|<>\[\]@]", "", text)[:MAX_ERROR]
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _when(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def releases(source: tuple[str, str], fetch: Fetch) -> list[Release]:
    kind, name = source
    out: list[Release] = []
    if kind == "github":
        for r in fetch(f"{GITHUB_API}/repos/{name}/releases?per_page=100"):
            v = parse_version(r.get("tag_name", ""))
            if v and not r.get("draft") and not r.get("prerelease") and r.get("published_at"):
                out.append(Release(v, r["tag_name"], _when(r["published_at"])))
    elif kind == "pypi":
        for ver, files in fetch(f"{PYPI}/{name}/json")["releases"].items():
            v = parse_version(ver)
            live = [f for f in files if not f.get("yanked")]
            if v and live:
                out.append(Release(v, ver, min(_when(f["upload_time_iso_8601"]) for f in live)))
    elif kind == "go-toolchain":
        listing = fetch(f"{GO_PROXY}/golang.org/toolchain/@v/list")
        tags = {
            m.group(1)
            for m in re.finditer(r"^v0\.0\.1-go(\d+\.\d+\.\d+)\.linux-amd64$", listing, re.M)
        }
        # newest first, dated one by one: only the head of the list is ever needed
        for tag in sorted(tags, key=lambda t: tuple(map(int, t.split("."))), reverse=True)[:12]:
            info = fetch(f"{GO_PROXY}/golang.org/toolchain/@v/v0.0.1-go{tag}.linux-amd64.info")
            out.append(Release(tuple(map(int, tag.split("."))), tag, _when(info["Time"])))
    else:
        raise ValueError(f"unknown source kind {kind!r}")
    return sorted(out, key=lambda r: r.version)


def current_version(pin: Pin) -> tuple[int, ...] | None:
    if pin.kind == "image":
        ref = pin.value.split("@", 1)[0]
        return parse_version(ref.rsplit(":", 1)[1]) if ":" in ref else None
    if pin.kind == "constraint":
        m = re.match(r"^\s*(?:~>|>=|=)?\s*v?(\d+(?:\.\d+)*)", pin.value)
        return tuple(int(p) for p in m.group(1).split(".")) if m else None
    return parse_version(pin.value)


def _line(v: tuple[int, ...]) -> tuple[int, ...]:
    return v[:2]


def assess(pin: Pin, rels: list[Release], now: datetime, cooldown: int = COOLDOWN_DAYS) -> Finding:
    cur = current_version(pin)
    cutoff = now - timedelta(days=cooldown)
    ripe = [r for r in rels if r.published <= cutoff]
    f = Finding(pin, cur)
    f.newest = ripe[-1] if ripe else None
    if cur:
        same = [r for r in ripe if _line(r.version) == _line(cur)]
        f.line_latest = same[-1] if same else None
        f.held = [r for r in rels if r.published > cutoff and r.version > cur]
    else:
        f.held = [r for r in rels if r.published > cutoff]
    newest = f.newest.version if f.newest else None
    if pin.kind == "unpinned":
        f.status = "unpinned"
    elif pin.kind == "constraint" and pin.value.strip().startswith("~>") and len(cur or ()) < 3:
        # "~> 0.60" allows every later 0.x: for a 0.x provider any minor may break
        f.status = "loose constraint"
    elif cur is None:
        f.status = "unreadable pin"
    elif newest is None or newest <= cur:
        f.status = "current"
    elif newest[0] != cur[0]:
        f.status = "behind (major)"
    elif cur[0] == 0 and newest[1] != cur[1]:
        f.status = "behind (0.x minor)"  # semver: a 0.x minor may break, like a major
    elif newest[1] != cur[1]:
        f.status = "behind (minor)"
    else:
        f.status = "behind (patch)"
    return f


def build(
    pins: list[Pin],
    fetch: Fetch,
    now: datetime,
    cooldown: int = COOLDOWN_DAYS,
    sources: dict[str, tuple[str, str]] | None = None,
) -> list[Finding]:
    sources = SOURCES if sources is None else sources
    out: list[Finding] = []
    cache: dict[tuple[str, str], list[Release] | Exception] = {}
    for pin in pins:
        source = sources.get(pin.id)
        if source is None:
            out.append(
                Finding(
                    pin, current_version(pin), status="no source", error="no upstream in SOURCES"
                )
            )
            continue
        if source[0] == "none":
            out.append(Finding(pin, current_version(pin), status="not compared", error=source[1]))
            continue
        if source not in cache:
            try:
                cache[source] = releases(source, fetch)
            except Exception as exc:  # one unreadable upstream must not hide the rest
                cache[source] = exc
        got = cache[source]
        if isinstance(got, Exception):
            f = assess(pin, [], now, cooldown)  # unpinned and loose stay so; the rest is unknown
            if f.status.startswith(("current", "behind")):
                f.status = "not checked"
            f.error = describe(got)
            out.append(f)
        else:
            out.append(assess(pin, got, now, cooldown))
    return out


ORDER = ["behind (major)", "behind (0.x minor)", "behind (minor)", "behind (patch)", "unpinned", "loose constraint",
         "unreadable pin", "not checked", "no source", "current", "not compared"]  # fmt: skip


def render(findings: list[Finding], now: datetime, cooldown: int = COOLDOWN_DAYS) -> str:
    def rel(r: Release | None) -> str:
        return f"{r.tag} ({r.published:%Y-%m-%d})" if r else "-"

    rows = sorted(
        findings, key=lambda f: (ORDER.index(f.status) if f.status in ORDER else 99, f.pin.id)
    )
    counts = {s: sum(f.status == s for f in findings) for s in ORDER}
    out = [
        MARKER,
        "# Pin freshness",
        "",
        f"Generated {now:%Y-%m-%d %H:%M} UTC by `tools/pin_freshness.py report` (the "
        "`pin-freshness` workflow). These are the pins dependabot cannot parse; it raises the "
        f"rest. A release younger than {cooldown} days is held back, as dependabot's cooldown and "
        "`make constraints` hold it, and listed under *held*. Being behind never fails a check: "
        "bump a version and its checksum together, in a pull request.",
        "",
        "Summary: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n),
        "",
        "| Pin | Where | Pinned | Status | Newest on its line | Newest | Held (cooldown) | Note |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for f in rows:
        p = f.pin
        note = "; ".join(
            x
            for x in (
                f"bump `{p.checksum}` with it" if p.checksum else "",
                NOTES.get(p.id, ""),
                f"`{f.error.replace('`', '')}`" if f.error else "",
            )
            if x
        )
        held = ", ".join(r.tag for r in f.held[-3:]) or "-"
        shown = re.sub(r"@sha256:([0-9a-f]{12})[0-9a-f]+", r"@sha256:\1…", p.value)
        pinned = f"`{shown}`" if p.value else "(unpinned)"
        out.append(
            f"| `{p.id}` | `{p.path}:{p.line}` | {pinned} | {f.status} | {rel(f.line_latest)} | "
            f"{rel(f.newest)} | {held} | {note.replace('|', '/')} |"
        )
    return "\n".join(out) + "\n"


# --- command line --------------------------------------------------------------------------


def main(
    argv: list[str] | None = None,
    fetch: Fetch = http_fetch,
    root: Path = ROOT,
    now: datetime | None = None,
) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("inventory", help="list the pins found in the tree (offline)")
    inv.add_argument("--check", action="store_true", help="fail on a pin with no upstream source")
    rep = sub.add_parser("report", help="compare each pin with its upstream (network)")
    rep.add_argument("--out", type=Path, help="write the Markdown here (default: stdout)")
    rep.add_argument("--cooldown-days", type=int, default=COOLDOWN_DAYS)
    rep.add_argument("--now", help="ISO 8601 time to judge the cooldown from (default: now)")
    args = ap.parse_args(argv)
    try:
        pins = inventory(root)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"pin_freshness: cannot read the tree: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "inventory":
        print(json.dumps([p.__dict__ for p in pins], indent=2))
        if args.check:
            problems = check_inventory(pins)
            for line in problems:
                print(f"pin_freshness: {line}", file=sys.stderr)
            return 1 if problems else 0
        return 0
    if args.cooldown_days < 0:
        print("pin_freshness: --cooldown-days must be >= 0", file=sys.stderr)
        return 2
    if args.now:
        try:
            now = _when(args.now)
        except ValueError:
            print(f"pin_freshness: --now is not an ISO 8601 time: {args.now}", file=sys.stderr)
            return 2
    now = now or _utcnow()
    text = render(build(pins, fetch, now, args.cooldown_days), now, args.cooldown_days)
    if args.out:
        try:
            args.out.write_text(text)
        except OSError as exc:
            print(f"pin_freshness: cannot write {args.out}: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
