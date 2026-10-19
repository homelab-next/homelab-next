# SPDX-License-Identifier: Apache-2.0
"""The offline workflow runner: one fixture event through one pack, deterministically.

Nothing here touches a network, a model or a clock.  Deterministic steps are computed for real
(``pick``, ``extract-iocs``; ``lookup`` computes its key and reads the row from the fixture's
``lookups``).  Model steps return the fixture's ``model`` output for that step, checked against
what the step may answer (a decide step's label must be one its decision spec can return).
Action steps become broker requests and go through an :class:`Executor`; the reference
:class:`BrokerExecutor` asks :func:`homelabnext.broker.decide`, so a risky action (tier
``execute``/``privileged`` or ``requires_approval``) runs only when the fixture presents an
approval bound to the digest of exactly that request (R-04).

References: a string value starting with ``$`` is ``$event.<path>`` or ``$steps.<id>.<path>``
(a numeric path part indexes a list; a missing part is ``null``); ``$$`` escapes a literal ``$``.
A step whose ``when`` does not hold is skipped and its output is ``null``.

Step outputs: ``pick`` -> ``{values, first, count}``; ``lookup`` -> ``{key, found, row}``;
``extract-iocs`` -> ``{urls, domains, ipv4, sha256, count}`` (sorted, unique, defanged forms
refanged); ``decide`` -> ``{label, confidence}``; ``prompt`` -> the fixture's object.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from homelabnext import broker
from homelabnext.agent.digest import digest_of

MODEL_KINDS = ("decide", "prompt")
RISKY_TIERS = ("execute", "privileged")


# ---------------------------------------------------------------- references and conditions
def is_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("$") and not value.startswith("$$")


def ref_root(ref: str) -> tuple[str, str | None]:
    """``("event", None)`` or ``("steps", <step id>)``; ``("", None)`` for an unknown root."""
    parts = ref[1:].split(".")
    if parts[0] == "event":
        return "event", None
    if parts[0] == "steps" and len(parts) > 1:
        return "steps", parts[1]
    return "", None


def refs_in(value: Any) -> list[str]:
    """Every reference inside ``value`` (strings, lists and mappings, recursively)."""
    if is_ref(value):
        return [value]
    if isinstance(value, Mapping):
        return [r for v in value.values() for r in refs_in(v)]
    if isinstance(value, list):
        return [r for v in value for r in refs_in(v)]
    return []


def step_refs(step: Mapping[str, Any]) -> list[str]:
    """The references a step reads, in its ``when`` and its inputs."""
    out = [c["ref"] for c in step.get("when", [])]
    for key in ("from", "key", "input", "slots", "params"):
        if key in step:
            out += refs_in(step[key])
    return out


def resolve(ref: str, scope: Mapping[str, Any]) -> Any:
    parts = ref[1:].split(".")
    if parts[0] == "event":
        cur: Any = scope["event"]
        rest = parts[1:]
    elif parts[0] == "steps" and len(parts) > 1:
        cur = scope["steps"].get(parts[1])
        rest = parts[2:]
    else:
        return None
    for p in rest:
        if isinstance(cur, Mapping):
            cur = cur.get(p)
        elif isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
            cur = cur[int(p)]
        else:
            return None
    return copy.deepcopy(cur)


def render(value: Any, scope: Mapping[str, Any]) -> Any:
    if isinstance(value, str):
        if value.startswith("$$"):
            return value[1:]
        return resolve(value, scope) if value.startswith("$") else value
    if isinstance(value, Mapping):
        return {k: render(v, scope) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, scope) for v in value]
    return value


def holds(conditions: Sequence[Mapping[str, Any]] | None, scope: Mapping[str, Any]) -> bool:
    for c in conditions or ():
        v = resolve(c["ref"], scope)
        if "equals" in c and v != c["equals"]:
            return False
        if "in" in c and v not in c["in"]:
            return False
        if "exists" in c and (v is not None) != c["exists"]:
            return False
    return True


# ---------------------------------------------------------------- deterministic operations
_URL = re.compile(r"\bhttps?://[^\s<>\"'()\[\]{}]+", re.I)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SHA256 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_DEFANG = ((re.compile(r"hxxp", re.I), "http"), (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."))
_DEFANG += ((re.compile(r"\[:\]"), ":"),)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def refang(text: str) -> str:
    for rx, repl in _DEFANG:
        text = rx.sub(repl, text)
    return text


def extract_iocs(texts: Sequence[str]) -> dict[str, Any]:
    """URLs, their host names, IPv4 addresses and sha256 hashes in ``texts``; nothing invented."""
    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    hashes: set[str] = set()
    for raw in texts:
        text = refang(raw)
        for m in _URL.finditer(text):
            url = m.group(0).rstrip(".,;:!?")
            urls.add(url)
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
            if host and not _is_ipv4(host):
                domains.add(host)
        ips.update(m.group(0) for m in _IPV4.finditer(text) if _is_ipv4(m.group(0)))
        hashes.update(m.group(0).lower() for m in _SHA256.finditer(text))
    out = {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ipv4": sorted(ips, key=lambda a: tuple(int(o) for o in a.split("."))),
        "sha256": sorted(hashes),
    }
    out["count"] = sum(len(v) for v in out.values())
    return out


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


def _enrich(step: Mapping[str, Any], scope: Mapping[str, Any], lookups: Mapping) -> Any:
    op = step["op"]
    if op == "pick":
        src = resolve(step["from"], scope)
        items = [i for i in src if isinstance(i, Mapping)] if isinstance(src, list) else []
        match = step.get("match", {})
        vals = [
            i.get(step["field"])
            for i in items
            if all(i.get(k) == v for k, v in match.items()) and i.get(step["field"]) is not None
        ]
        return {"values": vals, "first": vals[0] if vals else None, "count": len(vals)}
    if op == "lookup":
        key = resolve(step["key"], scope)
        table = lookups.get(step["table"], {})
        row = table.get(str(key)) if isinstance(key, (str, int)) else None
        return {"key": key, "found": row is not None, "row": copy.deepcopy(row)}
    if op == "extract-iocs":
        refs = step["from"] if isinstance(step["from"], list) else [step["from"]]
        return extract_iocs([s for r in refs for s in _strings(resolve(r, scope))])
    raise ValueError(f"unknown enrich op {op!r}")  # pragma: no cover - the schema closes it


# ---------------------------------------------------------------- executing actions
@dataclass(frozen=True)
class Outcome:
    """What happened to one action request.  ``result``: executed | held | denied | shadow."""

    result: str
    reason: str
    decision: Mapping[str, Any] = field(default_factory=dict)


class Executor(Protocol):
    def execute(
        self, request: Mapping[str, Any], approval: Mapping[str, Any] | None
    ) -> Outcome: ...


def action_entry(manifest: Mapping[str, Any], action: str) -> Mapping[str, Any] | None:
    return next((a for a in manifest.get("actions", []) if a["action"] == action), None)


def is_risky(manifest: Mapping[str, Any], action: str) -> bool:
    """Risky = the broker manifest gives it an ``execute``/``privileged`` tier or demands approval.
    An action the manifest does not list is treated as risky (and the broker denies it anyway)."""
    entry = action_entry(manifest, action)
    return entry is None or entry["tier"] in RISKY_TIERS or bool(entry["requires_approval"])


class BrokerExecutor:
    """The reference executor: the broker decides, and only an enforced ``allow`` runs.

    ``ran`` lists every request whose (fake) handler executed - the evidence a test inspects.
    """

    def __init__(
        self,
        manifest: Mapping[str, Any],
        *,
        now: str,
        store: broker.ApprovalStore | None = None,
    ):
        self.manifest = manifest
        self.now = now
        self.store = store if store is not None else broker.MemoryApprovalStore()
        self.ran: list[dict[str, Any]] = []

    def execute(self, request: Mapping[str, Any], approval: Mapping[str, Any] | None) -> Outcome:
        d = broker.decide(self.manifest, request, approval, now=self.now, store=self.store)
        if d["verdict"] == "allow" and d["enforced"]:
            self.ran.append(dict(request))
            return Outcome("executed", d["reason"], d)
        if not d["enforced"]:
            return Outcome("shadow", d["reason"], d)
        if d["verdict"] == "needs-approval":
            return Outcome("held", d["reason"], d)
        return Outcome("denied", d["reason"], d)


ExecutorFactory = Callable[..., Executor]
Tamper = Callable[[Mapping[str, Any], dict[str, Any]], dict[str, Any]]


# ---------------------------------------------------------------- the run
@dataclass(frozen=True)
class Call:
    step: str
    action: str
    target: str | None
    params: Any
    result: str
    reason: str
    request_id: str
    request_digest: str

    def to_dict(self) -> dict[str, Any]:
        out = {
            "step": self.step,
            "action": self.action,
            "params": self.params,
            "result": self.result,
            "reason": self.reason,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
        }
        if self.target is not None:
            out["target"] = self.target
        return out


@dataclass
class RunResult:
    triggered: bool
    calls: list[Call] = field(default_factory=list)
    outputs: dict[str, Any] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # the fixture itself is incomplete or stale


def request_id(pack: str, event_id: Any, step_id: str) -> str:
    """Deterministic broker request id for one action step of one event."""
    h = digest_of({"pack": pack, "event": event_id, "step": step_id})
    return f"{step_id}-{h.split(':', 1)[1][:12]}"


def triggered(pack: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    trig = pack["trigger"]
    return event.get("type") == trig["event"] and holds(trig.get("where"), {"event": event})


def run_fixture(
    pack: Mapping[str, Any],
    fixture: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    spec_labels: Mapping[str, Sequence[str]] | None = None,
    executor_factory: ExecutorFactory = BrokerExecutor,
    approvals: Sequence[Mapping[str, Any]] | None = None,
    tamper: Tamper | None = None,
) -> RunResult:
    """Run ``fixture`` through ``pack``.

    ``spec_labels`` maps a decision spec id to the labels it can return (unknown ids are not
    checked here; the validator reports them).  ``approvals`` overrides the fixture's own;
    ``tamper(step, request)`` may alter a request after it is built and before the broker sees it
    (how the validator proves an approval does not survive a changed payload).
    """
    event = fixture["event"]
    if not triggered(pack, event):
        return RunResult(False)
    now = fixture.get("now") or event.get("time")
    executor = executor_factory(manifest, now=now)
    model = fixture.get("model", {})
    lookups = fixture.get("lookups", {})
    given = list(fixture.get("approvals", []) if approvals is None else approvals)
    by_request = {a["request_id"]: a for a in given}
    res = RunResult(True)
    scope: dict[str, Any] = {"event": event, "steps": res.outputs}
    used_model: set[str] = set()
    used_approvals: set[str] = set()
    for step in pack["steps"]:
        sid, kind = step["id"], step["kind"]
        if not holds(step.get("when"), scope):
            res.outputs[sid] = None
            res.skipped.append(sid)
            continue
        if kind == "enrich":
            res.outputs[sid] = _enrich(step, scope, lookups)
        elif kind in MODEL_KINDS:
            res.outputs[sid] = _model(step, model, spec_labels or {}, res.problems)
            used_model.add(sid)
        else:
            req = {
                "request_id": request_id(pack["pack"], event.get("id"), sid),
                "action": step["action"],
                "actor": pack["actor"],
                "params": render(step["params"], scope),
                "created": event.get("time"),
            }
            if "target" in step:
                req["target"] = step["target"]
            if tamper is not None:
                req = tamper(step, req)
            req["digest"] = broker.request_digest(req)
            approval = by_request.get(req["request_id"])
            if approval is not None:
                used_approvals.add(req["request_id"])
            out = executor.execute(req, approval)
            res.outputs[sid] = {"result": out.result, "reason": out.reason}
            res.calls.append(
                Call(
                    sid,
                    req["action"],
                    req.get("target"),
                    req["params"],
                    out.result,
                    out.reason,
                    req["request_id"],
                    req["digest"],
                )
            )
    for sid in sorted(set(model) - used_model):
        res.problems.append(f"model output for {sid!r}, but no such model step ran")
    for rid in sorted(set(by_request) - used_approvals):
        res.problems.append(f"approval for request {rid!r}, which this run never made")
    return res


def _model(step, model, spec_labels, problems: list[str]) -> Any:
    sid = step["id"]
    if sid not in model:
        problems.append(f"model step {sid!r} ran but the fixture gives no model output for it")
        return None
    out = copy.deepcopy(model[sid])
    if step["kind"] == "decide":
        labels = spec_labels.get(step["spec"])
        label = out.get("label")
        if labels is not None and label not in labels:
            problems.append(
                f"model output for {sid!r}: label {label!r} is not one spec "
                f"{step['spec']!r} can return {sorted(labels)}"
            )
        conf = out.get("confidence")
        if conf is not None and not (isinstance(conf, (int, float)) and 0 <= conf <= 1):
            problems.append(f"model output for {sid!r}: confidence must be within 0..1")
        out = {"label": label, "confidence": conf}
    return out
