# SPDX-License-Identifier: Apache-2.0
"""Native detection rules (ADR-0006 decision 4, amended by ADR-0049 decision 2).

A detection is Sigma unless Sigma cannot carry it; a native rule states why, from a closed list.
This module is the public lint and the engine run for them, written for the SIEM adapter's rule
format (rule and decoder XML) and tested through the engine's own rule tester.

Layout, in a detections root (the module's, or the overlay module's for the lab's own rules)::

    native/index.yml                         the registry (below)
    native/rules/<name>.xml, native/decoders/<name>.xml
    native/native.baseline.json              {"count": N, "stock-override": M}: the ratchet
    fixtures/<slug>/{must_fire,must_not_fire}/*.json   raw engine input, one event per file

``index.yml``::

    schema: homelabnext.detections.native/v1
    engine: <the engine's name>
    range: [100000, 119999]          # the module's reserved engine numbers
    rules:
      - slug: ssh-offbaseline        # = the fixtures directory and the det id
        det: det:ssh-offbaseline
        kind: rules                  # rules | decoders: the directory the file is in
        file: ssh-offbaseline.xml
        native_reason: engine-correlation   # engine-correlation | decoder | list-lookup | stock-override
        why: one sentence on what Sigma cannot say here
        rule_ids: [100200, 100201]   # exactly the ids the file declares (decoders: [])
        overrides: [5710]            # stock-override only: the stock rule ids it changes

A fixture is ``{"event": "<the raw line>", "location": "/var/log/auth.log", "format": "syslog",
"rule_id": 100200}``; for ``must_fire`` the engine must match that rule, for ``must_not_fire`` it
must not.  ``lint_native`` fails on a missing reason, a reason outside the list, a rule number
outside the range or declared twice, a det id a Sigma rule also has, a missing fixture kind, a
``<location>`` with regular-expression characters and no ``type="pcre2"`` (such a rule loads clean
and never matches), and a count above the baseline.  ``run_native`` sends each fixture through the
engine's tester (an injectable callable, so the check is hermetic; ``ManagerLogtest`` is the real
one, the manager API's ``PUT /logtest``).
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

REASONS = ("engine-correlation", "decoder", "list-lookup", "stock-override")
KINDS = ("rules", "decoders")
SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*\Z")
FILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\.xml\Z")
REGEX_CHARS = re.compile(r"[\\.*+?()\[\]|^$]")
SCHEMA = "homelabnext.detections.native/v1"
FIXTURE_KINDS = ("must_fire", "must_not_fire")


@dataclass(frozen=True)
class Fixture:
    slug: str
    kind: str
    path: Path
    event: str
    location: str
    format: str
    rule_id: int


def load_index(root: Path) -> dict | None:
    path = Path(root) / "native" / "index.yml"
    if not path.is_file():
        return None
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return doc if isinstance(doc, dict) else {}


def _declared_ids(xml_file: Path) -> list[int]:
    tree = ET.parse(xml_file)
    return [int(r.get("id")) for r in tree.iter("rule") if r.get("id", "").isdigit()]


def _location_problems(xml_file: Path) -> list[str]:
    out = []
    for loc in ET.parse(xml_file).iter("location"):
        text = (loc.text or "").strip()
        if REGEX_CHARS.search(text) and loc.get("type") != "pcre2":
            out.append(
                f"<location>{text}</location> has regular-expression characters and no "
                'type="pcre2": it loads clean and never matches'
            )
    return out


def load_fixtures(root: Path, slug: str) -> list[Fixture]:
    out = []
    for kind in FIXTURE_KINDS:
        d = Path(root) / "fixtures" / slug / kind
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.json")):
            doc = json.loads(f.read_text(encoding="utf-8"))
            for key in ("event", "rule_id"):
                if key not in doc:
                    raise ValueError(f"{f}: missing {key!r}")
            out.append(
                Fixture(slug, kind, f, str(doc["event"]), str(doc.get("location", "")),
                        str(doc.get("format", "syslog")), int(doc["rule_id"]))
            )  # fmt: skip
    return out


def lint_native(root: Path, sigma_det_ids: set[str] | None = None) -> list[str]:
    """Problems with the native rules under ``root`` (empty: none, or no native rules at all)."""
    root = Path(root)
    doc = load_index(root)
    if doc is None:
        return []
    problems: list[str] = []
    if doc.get("schema") != SCHEMA:
        problems.append(f"native/index.yml: schema must be {SCHEMA}")
    rng = doc.get("range")
    if not (
        isinstance(rng, list)
        and len(rng) == 2
        and all(isinstance(n, int) for n in rng)
        and rng[0] <= rng[1]
    ):
        problems.append("native/index.yml: range must be [low, high] integers")
        rng = None
    entries = doc.get("rules") or []
    seen_slugs: set[str] = set()
    seen_dets: set[str] = set()
    seen_ids: dict[int, str] = {}
    overrides = 0
    for e in entries:
        slug = e.get("slug", "?")
        pre = f"native {slug}"
        if not isinstance(e.get("slug"), str) or not SLUG_RE.match(e["slug"]):
            problems.append(f"{pre}: slug must be lower-case words joined by hyphens")
        if slug in seen_slugs:
            problems.append(f"{pre}: slug declared twice")
        seen_slugs.add(slug)
        det = e.get("det")
        if det != f"det:{slug}":
            problems.append(f"{pre}: det must be det:{slug}")
        if det in seen_dets or (sigma_det_ids and det in sigma_det_ids):
            problems.append(
                f"{pre}: {det} is also another rule's id (a Sigma rule or a second native one)"
            )
        seen_dets.add(det)
        reason = e.get("native_reason")
        if reason not in REASONS:
            problems.append(f"{pre}: native_reason {reason!r} is not one of {', '.join(REASONS)}")
        if not isinstance(e.get("why"), str) or len(e["why"].strip()) < 20:
            problems.append(f"{pre}: why must say in a sentence what Sigma cannot express")
        if reason == "stock-override":
            overrides += 1
            if not e.get("overrides"):
                problems.append(
                    f"{pre}: a stock-override names the stock rule ids it changes (overrides)"
                )
        kind, fname = e.get("kind"), e.get("file", "")
        if kind not in KINDS or not FILE_RE.match(str(fname)):
            problems.append(f"{pre}: kind must be rules or decoders and file a plain name.xml")
            continue
        xml_file = root / "native" / kind / fname
        if not xml_file.is_file():
            problems.append(f"{pre}: native/{kind}/{fname} does not exist")
            continue
        try:
            declared = _declared_ids(xml_file) if kind == "rules" else []
            problems += [f"{pre}: {p}" for p in _location_problems(xml_file)]
        except ET.ParseError as exc:
            problems.append(f"{pre}: native/{kind}/{fname} is not well-formed XML ({exc})")
            continue
        listed = e.get("rule_ids") or []
        if sorted(declared) != sorted(listed):
            problems.append(
                f"{pre}: rule_ids {sorted(listed)} differ from the ids the file declares {sorted(declared)}"
            )
        for n in declared:
            if rng and not rng[0] <= n <= rng[1]:
                problems.append(f"{pre}: rule {n} is outside the module's range {rng[0]}-{rng[1]}")
            if n in seen_ids:
                problems.append(f"{pre}: rule {n} is also declared by {seen_ids[n]}")
            seen_ids[n] = slug
        try:
            fixtures = load_fixtures(root, slug)
        except (ValueError, json.JSONDecodeError) as exc:
            problems.append(f"{pre}: {exc}")
            continue
        kinds = {f.kind for f in fixtures}
        for need in FIXTURE_KINDS:
            if need not in kinds:
                problems.append(
                    f"{pre}: no {need} fixture (a native rule without both kinds fails)"
                )
    base = root / "native" / "native.baseline.json"
    if base.is_file():
        limit = json.loads(base.read_text(encoding="utf-8"))
        if len(entries) > int(limit.get("count", 0)):
            problems.append(
                f"native rules: {len(entries)} exceed the baseline {limit.get('count')} (a reviewed change raises it)"
            )
        if overrides > int(limit.get("stock-override", 0)):
            problems.append(
                f"stock overrides: {overrides} exceed the baseline {limit.get('stock-override')}"
            )
    else:
        problems.append(
            'native/native.baseline.json is missing (the ratchet: {"count": N, "stock-override": M})'
        )
    return problems


Tester = Callable[[Fixture], int | None]  # the id of the rule the engine matched, or None


def run_native(root: Path, tester: Tester) -> tuple[list[str], int]:
    """Send every fixture through ``tester``; (problems, fixtures run)."""
    doc = load_index(root) or {}
    problems, ran = [], 0
    for e in doc.get("rules") or []:
        for fx in load_fixtures(Path(root), e["slug"]):
            ran += 1
            fired = tester(fx)
            label = f"{e['slug']}/{fx.kind}/{fx.path.name}"
            if fx.kind == "must_fire" and fired != fx.rule_id:
                problems.append(f"{label}: expected rule {fx.rule_id}, the engine matched {fired}")
            if fx.kind == "must_not_fire" and fired == fx.rule_id:
                problems.append(f"{label}: rule {fx.rule_id} fired and must not")
    return problems, ran


class ManagerLogtest:
    """The manager API's rule tester (``PUT /logtest``), verified against ``ca_file`` (the manager's
    own certificate); one session token is kept, the credential is the caller's."""

    def __init__(
        self, base_url: str, user: str, password: str, ca_file: str, timeout: float = 30.0
    ):
        self._base = base_url.rstrip("/")
        self._basic = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        ctx = ssl.create_default_context(cafile=ca_file) if self._base.startswith("https") else None
        handlers = [urllib.request.ProxyHandler({})]
        if ctx:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)
        self._timeout = timeout
        self._jwt: str | None = None
        self._session: str | None = None

    def _call(
        self, method: str, path: str, body: dict | None = None, auth: str | None = None
    ) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self._base + path, data=data, method=method,
                                     headers={"Authorization": auth or f"Bearer {self._jwt}",
                                              "Content-Type": "application/json"})  # fmt: skip
        try:
            with self._opener.open(req, timeout=self._timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{method} {path} answered {exc.code}") from exc

    def __call__(self, fx: Fixture) -> int | None:
        if self._jwt is None:
            req = urllib.request.Request(self._base + "/security/user/authenticate?raw=true", method="POST",
                                         headers={"Authorization": self._basic})  # fmt: skip
            with self._opener.open(req, timeout=self._timeout) as r:
                self._jwt = r.read().decode().strip()
        body = {
            "event": fx.event,
            "log_format": fx.format,
            "location": fx.location or "hnx-fixture",
        }
        if self._session:
            body["token"] = self._session
        reply = self._call("PUT", "/logtest", body)
        data = reply.get("data", {})
        self._session = data.get("token", self._session)
        rule = (data.get("output") or {}).get("rule") or {}
        return int(rule["id"]) if str(rule.get("id", "")).isdigit() else None
