# SPDX-License-Identifier: Apache-2.0
"""Reviews: who validated an artefact, in which role, against exactly which content.

One model for every reviewed artefact: lesson and runbook records
(``examples/registers/lessons/<uid>.md``), the per-service SOP pages (``docs/systems/``) and the
strategy-to-task records (``examples/strategy/``, :mod:`homelabnext.strategy`) and the MCP
catalog's server records (``examples/mcp/<id>.yml``, inline ``reviews:``; :mod:`homelabnext.mcp.servers`).
An artefact carries ``author:`` and its reviews: append-only event files in the sidecar
directory beside it (``<uid>.events/``, ``docs/systems/dns.events/``; see
:mod:`homelabnext.registers.events`), each one review entry, or (the older form, still read) an
inline ``reviews:`` list::

    reviews:
      - by: agent:j8-lead        # issuer:subject, compared like the broker's approvals
        kind: agent              # agent | human
        role: check              # check | audit | approve
        date: 2026-10-19
        verdict: pass            # pass | changes | reject
        digest: sha256:3f9a...   # the content reviewed (`hnx reviews digest FILE`); prefix >= 12
        note: optional one line or a link to the evidence

Identity rules (always fatal):

* identities are ``issuer:subject``, normalized with the broker's
  :func:`homelabnext.broker.qualified_identity`, so ``agent:J8_Lead`` and ``agent:j8-lead`` are
  one reviewer;
* the ``author`` never reviews their own artefact, in any role;
* an ``audit`` review (an independent agent audit that looks for what is wrong, missing or
  unproven) comes from an agent identity other than every ``check`` reviewer;
* a review's ``kind`` must match the identity: an identity is an agent when the policy's
  ``reviewers`` allowlist says ``kind: agent`` or its issuer is ``agent`` (the broker's rule: an
  allowlisted agent, or an identity naming an agent profile); a ``human`` review must come from a
  ``kind: human`` allowlist entry (fail closed, like broker approvers).

Staleness is by content, not by date: a review counts only while its ``digest`` is a prefix of
the artefact's current digest, so editing the content drops it back to needing review, and
regenerating machine facts (the Links block of a record, the ``hnx:gen`` blocks of a system
page) does not.  Only ``verdict: pass`` reviews count toward a requirement.

The policy (one YAML file, ``examples/review-policy.yml``) says, per artefact kind and state,
which reviews are required; :func:`load_policy` validates it fatally.  ``last_reviewed`` is
derived (:attr:`Evaluation.last_reviewed`, the latest current passing review), never stored.

``challenge`` is the deprecated spelling of ``audit`` (the role's earlier name): a file that
still says it is read as ``audit`` by :func:`normalize_role` and draws a
:class:`DeprecatedReviewRole` warning, never a failure, so older review files and policies keep
validating while they are renamed.

This is a consistency check over what the files claim, not authentication: anyone with write
access can type a review.  Authenticated sign-off is the broker's approval flow.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import warnings
from dataclasses import dataclass, field

import yaml

from homelabnext.agent.digest import digest_of
from homelabnext.broker import qualified_identity

__all__ = [
    "ARTEFACT_STATES",
    "DeprecatedReviewRole",
    "Evaluation",
    "Policy",
    "Requirement",
    "ReviewError",
    "content_digest",
    "evaluate",
    "identity",
    "load_policy",
    "main",
    "normalize_role",
    "validate_policy",
]

KINDS = ("agent", "human")
ROLES = ("check", "audit", "approve")
#: deprecated role spellings -> the role they mean; read (with a warning), never written
ROLE_ALIASES = {"challenge": "audit"}
VERDICTS = ("pass", "changes", "reject")
FIELDS = frozenset({"by", "kind", "role", "date", "verdict", "digest", "note"})
REQUIRED_FIELDS = ("by", "kind", "role", "date", "verdict", "digest")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{12,64}$")
# every state of every reviewed artefact kind; a policy must name each one (fail closed)
ARTEFACT_STATES: dict[str, tuple[str, ...]] = {
    "lesson.pitfall": ("open", "partial", "controlled", "retired"),
    "lesson.practice": ("active", "incorporated", "superseded", "retired"),
    "runbook": ("active", "superseded"),
    "system-page": ("draft", "reviewed"),
    # the strategy-to-task records (homelabnext.strategy, docs/strategy.md)
    "strategy": ("active",),
    "objective": ("active", "achieved", "retired"),
    "measure": ("active", "retired"),
    "requirement": ("active", "answered", "expired", "retired"),
    "rfi": ("open", "answered", "expired", "no-find"),
    # the MCP catalog's server records (homelabnext.mcp.servers, docs/mcp-catalog.md)
    "mcp-server": ("draft", "active", "deprecated", "retired"),
}
UNKNOWN_AUTHOR = "unknown"


class ReviewError(ValueError):
    def __init__(self, what: str, problems: list[str]):
        self.problems = problems
        super().__init__(f"{what}: {len(problems)} problem(s)\n  - " + "\n  - ".join(problems))


class DeprecatedReviewRole(FutureWarning):
    """A review or a policy still spells a role the deprecated way (``challenge``)."""


def normalize_role(role, where: str = ""):
    """The role ``role`` means: a deprecated alias (``challenge``) becomes its current name
    (``audit``) with a :class:`DeprecatedReviewRole` warning; anything else is returned as is
    (an unknown role is the caller's validation problem, not this helper's)."""
    if isinstance(role, str) and role in ROLE_ALIASES:
        new = ROLE_ALIASES[role]
        at = f"{where}: " if where else ""
        warnings.warn(
            f"{at}review role {role!r} is deprecated; write {new!r}",
            DeprecatedReviewRole,
            stacklevel=2,
        )
        return new
    return role


def content_digest(obj) -> str:
    """``sha256:<hex>`` of the canonical JSON of ``obj`` (dates as ISO strings)."""
    return digest_of(json.loads(json.dumps(obj, default=str)))


def identity(value) -> tuple[str, str] | None:
    """``issuer:subject`` -> the broker's normalized (issuer, subject), or None if malformed."""
    if not isinstance(value, str) or ":" not in value:
        return None
    issuer, subject = qualified_identity(*value.split(":", 1))
    return (issuer, subject) if issuer and subject else None


def _show(ident: tuple[str, str]) -> str:
    return f"{ident[0]}:{ident[1]}"


@dataclass(frozen=True)
class Requirement:
    role: str
    kind: str
    min: int = 1

    def label(self) -> str:
        return f"{self.kind} {self.role}" + (f" x{self.min}" if self.min > 1 else "")


@dataclass
class Policy:
    reviewers: dict[tuple[str, str], str] = field(default_factory=dict)
    requirements: dict[str, dict[str, tuple[Requirement, ...]]] = field(default_factory=dict)

    def required(self, artefact: str, state: str) -> tuple[Requirement, ...]:
        return self.requirements.get(artefact, {}).get(state, ())

    def kind_of(self, ident: tuple[str, str]) -> str | None:
        if ident in self.reviewers:
            return self.reviewers[ident]
        return "agent" if ident[0] == "agent" else None


def validate_policy(data) -> list[str]:
    """Every problem with a policy document (empty list = valid)."""
    if not isinstance(data, dict):
        return ["the policy must be a mapping with `version`, `reviewers` and `requirements`"]
    problems = []
    extra = set(data) - {"version", "reviewers", "requirements"}
    if extra:
        problems.append(f"unknown top-level key(s) {sorted(extra)}")
    if data.get("version") != 1:
        problems.append("`version` must be 1")
    seen = set()
    for n, r in enumerate(data.get("reviewers") or [], 1):
        if not isinstance(r, dict) or set(r) - {"issuer", "subject", "kind"}:
            problems.append(f"reviewers #{n}: a mapping of issuer, subject, kind")
            continue
        ident = identity(f"{r.get('issuer', '')}:{r.get('subject', '')}")
        if ident is None:
            problems.append(f"reviewers #{n}: needs a non-empty `issuer` and `subject`")
        elif ident in seen:
            problems.append(f"reviewers #{n}: {_show(ident)} is listed twice")
        seen.add(ident)
        if r.get("kind") not in KINDS:
            problems.append(f"reviewers #{n}: `kind` must be one of {KINDS}")
        elif ident and ident[0] == "agent" and r["kind"] != "agent":
            problems.append(f"reviewers #{n}: an `agent:` identity cannot be kind human")
    reqs = data.get("requirements")
    if not isinstance(reqs, dict):
        return [*problems, "`requirements` must map artefact kind -> state -> [requirement]"]
    for art in sorted(set(reqs) - set(ARTEFACT_STATES)):
        problems.append(f"requirements: unknown artefact kind {art!r} ({sorted(ARTEFACT_STATES)})")
    for art, states in ARTEFACT_STATES.items():
        got = reqs.get(art)
        if not isinstance(got, dict):
            problems.append(f"requirements.{art}: missing (list every state: {list(states)})")
            continue
        for st in sorted(set(got) - set(states)):
            problems.append(f"requirements.{art}: unknown state {st!r}")
        for st in states:
            if st not in got:
                problems.append(f"requirements.{art}.{st}: missing (write [] for none)")
                continue
            if not isinstance(got[st], list):
                problems.append(f"requirements.{art}.{st}: must be a list")
                continue
            for n, q in enumerate(got[st], 1):
                where = f"requirements.{art}.{st} #{n}"
                if not isinstance(q, dict) or set(q) - {"role", "kind", "min"}:
                    problems.append(f"{where}: a mapping of role, kind (and min)")
                    continue
                if normalize_role(q.get("role"), where) not in ROLES:
                    problems.append(f"{where}: `role` must be one of {ROLES}")
                if q.get("kind") not in KINDS:
                    problems.append(f"{where}: `kind` must be one of {KINDS}")
                m = q.get("min", 1)
                if not (isinstance(m, int) and not isinstance(m, bool) and m >= 1):
                    problems.append(f"{where}: `min` must be an integer >= 1")
    return problems


def policy_from(data) -> Policy:
    problems = validate_policy(data)
    if problems:
        raise ReviewError("review policy", problems)
    reviewers = {
        identity(f"{r['issuer']}:{r['subject']}"): r["kind"] for r in data.get("reviewers") or []
    }
    reqs = {
        art: {
            st: tuple(
                Requirement(ROLE_ALIASES.get(q["role"], q["role"]), q["kind"], q.get("min", 1))
                for q in lst
            )
            for st, lst in states.items()
        }
        for art, states in data["requirements"].items()
    }
    return Policy(reviewers, reqs)  # type: ignore[arg-type]


def load_policy(path) -> Policy:
    p = pathlib.Path(path)
    try:
        data = yaml.safe_load(p.read_text())
    except (OSError, yaml.YAMLError) as ex:
        raise ReviewError(str(p), [f"cannot read the policy ({ex})"]) from ex
    try:
        return policy_from(data)
    except ReviewError as ex:
        raise ReviewError(str(p), ex.problems) from None


@dataclass
class Evaluation:
    problems: list[str] = field(default_factory=list)  # fatal, whatever the state
    current: list[dict] = field(default_factory=list)  # passing reviews of this content
    stale: list[dict] = field(default_factory=list)  # reviews of an earlier content
    missing: list[str] = field(default_factory=list)  # requirement labels not met

    @property
    def last_reviewed(self) -> dt.date | None:
        dates = [_date(r.get("date")) for r in self.current]
        return max((d for d in dates if d), default=None)


def _date(v) -> dt.date | None:
    if isinstance(v, dt.date):
        return v
    try:
        return dt.date.fromisoformat(str(v))
    except ValueError:
        return None


def evaluate(
    reviews,
    *,
    author,
    digest: str,
    artefact: str,
    state: str,
    policy: Policy | None = None,
    who: str = "",
) -> Evaluation:
    """Check ``reviews`` of one artefact whose current content digest is ``digest``.

    Without a policy only the rules that need none run (shape, self-review, audit
    independence, an ``agent:`` identity in a human slot); with one, the allowlist and the
    requirement for (``artefact``, ``state``) apply too.
    """
    ev = Evaluation()
    pre = f"{who}: " if who else ""
    if author is None:
        ev.problems.append(f"{pre}`author` is required (issuer:subject, or `unknown`)")
        author_id = None
    elif author == UNKNOWN_AUTHOR:
        author_id = None
    else:
        author_id = identity(author)
        if author_id is None:
            ev.problems.append(f"{pre}`author` {author!r} is not issuer:subject or `unknown`")
    if reviews is None:
        reviews = []
    if not isinstance(reviews, list):
        ev.problems.append(f"{pre}`reviews` must be a list")
        reviews = []
    checks: list[tuple[str, str]] = []
    audits: list[tuple[int, tuple[str, str]]] = []
    for n, r in enumerate(reviews, 1):
        at = f"{pre}review #{n}"
        if not isinstance(r, dict):
            ev.problems.append(f"{at}: must be a mapping")
            continue
        extra = set(r) - FIELDS
        missing = [k for k in REQUIRED_FIELDS if k not in r]
        if extra:
            ev.problems.append(f"{at}: unknown field(s) {sorted(extra)}")
        if missing:
            ev.problems.append(f"{at}: missing {', '.join(missing)}")
        ident = identity(r.get("by"))
        if ident is None:
            ev.problems.append(f"{at}: `by` must be an issuer-qualified identity (agent:name)")
            continue
        role = normalize_role(r.get("role"), at)
        if role != r.get("role"):
            r = {**r, "role": role}
        kind = r.get("kind")
        bad = False
        if kind not in KINDS:
            ev.problems.append(f"{at}: `kind` must be one of {KINDS}")
            bad = True
        if role not in ROLES:
            ev.problems.append(f"{at}: `role` must be one of {ROLES}")
            bad = True
        if r.get("verdict") not in VERDICTS:
            ev.problems.append(f"{at}: `verdict` must be one of {VERDICTS}")
            bad = True
        if _date(r.get("date")) is None:
            ev.problems.append(f"{at}: `date` must be ISO YYYY-MM-DD")
            bad = True
        if not (isinstance(r.get("digest"), str) and DIGEST_RE.match(r["digest"])):
            ev.problems.append(f"{at}: `digest` must be sha256:<hex, >= 12 chars>")
            bad = True
        if author_id is not None and ident == author_id:
            ev.problems.append(f"{at}: {_show(ident)} is the author; nobody reviews their own work")
            bad = True
        classified = policy.kind_of(ident) if policy else ("agent" if ident[0] == "agent" else None)
        if kind == "human" and classified == "agent":
            ev.problems.append(f"{at}: {_show(ident)} is an agent identity in a human review")
            bad = True
        elif kind == "human" and policy is not None and classified is None:
            ev.problems.append(
                f"{at}: {_show(ident)} is not a `kind: human` reviewer in the policy allowlist"
            )
            bad = True
        elif kind == "agent" and classified == "human":
            ev.problems.append(f"{at}: {_show(ident)} is a human identity in an agent review")
            bad = True
        elif kind == "agent" and policy is not None and classified is None:
            ev.problems.append(
                f"{at}: {_show(ident)} is not an agent identity (`agent:` issuer or a "
                "`kind: agent` allowlist entry)"
            )
            bad = True
        if role == "check":
            checks.append(ident)
        elif role == "audit":
            audits.append((n, ident))
        if bad:
            continue
        if r["verdict"] == "pass" and digest.startswith(r["digest"]):
            ev.current.append(r)
        elif not digest.startswith(r["digest"]):
            ev.stale.append(r)
    for n, ident in audits:
        if ident in checks:
            ev.problems.append(
                f"{pre}review #{n}: the audit review comes from {_show(ident)}, who also "
                "made a check review; it must be a different agent"
            )
            ev.current = [r for r in ev.current if identity(r.get("by")) != ident]
    if policy is not None:
        for q in policy.required(artefact, state):
            # distinct reviewers: one identity reviewing twice is still one review
            got = len(
                {
                    identity(r.get("by"))
                    for r in ev.current
                    if r["role"] == q.role and r["kind"] == q.kind
                }
            )
            if got < q.min:
                ev.missing.append(q.label())
    return ev


def missing_message(who: str, state: str, ev: Evaluation, digest: str) -> str:
    stale = f"; {len(ev.stale)} review(s) are of an earlier content" if ev.stale else ""
    return (
        f"{who}: status {state} needs {', '.join(ev.missing)} review(s) of the current content "
        f"({digest[:19]}){stale}"
    )


# --- hnx reviews digest -----------------------------------------------------------------------


def file_digest(path) -> str:
    """The digest a reviewer stamps for ``path``: a register or strategy record, an MCP catalog
    record (``<catalog>/mcp/<id>.yml``), or a docs/systems page."""
    p = pathlib.Path(path)
    text = p.read_text(encoding="utf-8")
    from homelabnext.strategy.records import file_digest as strategy_digest

    if (got := strategy_digest(p, text)) is not None:
        return got
    if p.suffix == ".yml" and p.parent.name == "mcp":
        from homelabnext.mcp.servers import file_digest as mcp_digest

        return mcp_digest(p)
    if p.parent.name in ("lessons", "runbooks"):
        from homelabnext.registers import events as ev
        from homelabnext.registers.records import record_digest
        from homelabnext.registers.schema import RegisterError

        problems: list[str] = []
        events = ev.read_events(ev.events_dir(p), problems, p.name)
        if problems:
            raise RegisterError(p.parent.name, problems)
        return record_digest(text, p.name, p.parent.name, events)
    from homelabnext.sop.pages import page_digest

    return page_digest(text)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hnx reviews", description="the shared review model")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("digest", help="the content digest a review of FILE must carry")
    d.add_argument("files", nargs="+")
    ns = ap.parse_args(argv)
    rc = 0
    for f in ns.files:
        try:
            print(f"{file_digest(f)}  {f}")
        except (OSError, ValueError) as ex:
            print(f"[reviews] FATAL: {f}: {ex}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
