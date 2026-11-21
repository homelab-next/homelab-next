# SPDX-License-Identifier: Apache-2.0
"""One publishing run: discover items, gate them, then stage, plan or push by mode.

* ``stage``: the gate, then each passing item written under the staging directory with the plan
  it would have had.  No credential but the deny-list is read; the transport is :class:`NoNetwork`.
* ``dry-run``: the gate, then reads only (the bucket listing, the remote feed), the plan, no write.
* ``live``: the gate, then the pushes.  A blocked item is never pushed, and does not stop the others.

Every gate decision is appended to ``gate.jsonl`` in the state directory (rule and file, never the
matched text); every push to ``published-manifest.jsonl``.  Exit code 0: nothing blocked or failed.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from homelabnext.notify import Message, Notifier, default_sender
from homelabnext.publishing import config as cf
from homelabnext.publishing import gate as gt
from homelabnext.publishing import pages as pg
from homelabnext.publishing import r2, snapshots, stage
from homelabnext.publishing.transport import NoNetwork, ReadOnly, Transport, Urllib
from homelabnext.state import StateStore

PROBLEM = "Publishing: an item was blocked by the gate"
RECOVERY = "Publishing: the gate passes every item again"
NOTIFY_KEY = "publishing-gate"


@dataclass
class Report:
    mode: str
    blocked: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    done: list[dict] = field(default_factory=list)

    @property
    def code(self) -> int:
        return 1 if (self.blocked or self.failed) else 0


def _append(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, sort_keys=True) + "\n")


def _last_site_digest(manifest: Path, project: str) -> str | None:
    if not manifest.exists():
        return None
    last = None
    for line in manifest.read_text(encoding="utf-8").splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("adapter") == "pages" and d.get("target") == project:
            last = d.get("digest")
    return last


def discover(publishable: Path) -> list[tuple[str, Path]]:
    out = []
    for kind in gt.KINDS:
        base = publishable / kind
        if base.is_symlink():  # a symlinked kind directory is refused by name, not followed
            out.append((kind, base))
        elif base.is_dir():
            out += [
                (kind, p)
                for p in sorted(base.iterdir())
                if (p.is_dir() or p.is_symlink()) and not p.name.startswith(".")
            ]
    return out


def _no_runner(*_a, **_k):  # a lane source never deploys: a runner call there is a defect
    raise pg.PagesError("a producer lane's items are staged only; nothing is deployed from it")


def _prune(
    cfg: cf.Config,
    entries: list[tuple[str, Path]],
    manifest: Path,
    snapshots_dir: Path,
    staging_dir: Path,
    clock: Callable[[], float],
    gate_log: Path,
) -> None:
    try:  # snapshots go by age: the newest few per kind, what is current, what was last published
        snapshots.prune(
            snapshots_dir,
            keep=cfg.snapshots_keep,
            min_age_s=cfg.snapshots_min_age_s,
            protect_ids={p.name for _k, p in entries} | snapshots.referenced_ids(manifest),
            now=clock(),
        )
        if staging_dir.is_dir():  # shadow output: by age, but what is current is never pruned
            snapshots.prune(
                staging_dir,
                keep=cfg.staging_keep,
                min_age_s=cfg.staging_min_age_s,
                protect_ids={p.name for _k, p in entries},
                now=clock(),
                digest_len=12,
            )
    except OSError as exc:
        _append(gate_log, {"ts": clock(), "prune_failed": type(exc).__name__})


def _gate_source(
    cfg: cf.Config,
    entries: list[tuple[str, Path]],
    *,
    net: Transport,
    runner: pg.Runner,
    policy: gt.Policy,
    report: Report,
    clock: Callable[[], float],
    snapshots_dir: Path,
    lane: str | None,
    anchor: Path | None = None,
) -> None:
    """Gate and handle one source's items: the publishable area (``lane`` None) or one producer
    lane's output.  A lane's items are tagged with it everywhere: the report (``<lane>:<id>``),
    the gate log and ``plan.json``; the lanes never share a snapshot or staging directory."""
    gate_log = cfg.state_dir / "gate.jsonl"
    # a lane publishes nothing (stage only), so it has no manifest: it never sees the real one
    manifest = cfg.state_dir / (
        "published-manifest.jsonl" if lane is None else f"no-manifest-{lane}.jsonl"
    )

    def tag(name: str) -> str:
        return name if lane is None else f"{lane}:{name}"

    def log(doc: dict) -> None:
        _append(gate_log, doc if lane is None else {**doc, "lane": lane})

    sites = [e for e in entries if e[0] == "site"]
    superseded = {p.name for _, p in sites[:-1]}  # only the newest site build is the site
    for kind, root in entries:
        if root.name in superseded:
            done = {"item": tag(root.name), "kind": kind, "result": "superseded"}
            report.done.append(done if lane is None else {**done, "lane": lane})
            continue
        try:
            # what is gated and published is a private copy: every byte read once, hashed as read
            item = gt.snapshot_item(root, kind, snapshots_dir, anchor)
            verdict = gt.evaluate(item, policy)
        except (gt.GateError, OSError) as exc:
            report.blocked.append(tag(root.name))
            log(
                {
                    "ts": clock(),
                    "item": root.name,
                    "kind": kind,
                    "ok": False,
                    "reasons": [{"rule": "item-unreadable", "path": "", "detail": str(exc)}],
                }
            )
            continue
        log(
            {
                "ts": clock(),
                "item": item.id,
                "kind": kind,
                "ok": verdict.ok,
                "label": verdict.label,
                "reasons": [r.as_dict() for r in verdict.reasons],
            }
        )
        if not verdict.ok:
            report.blocked.append(tag(item.id))
            continue
        try:
            out = _handle(cfg, item, verdict, net, runner, manifest, clock, policy, lane)
            report.done.append(out if lane is None else {**out, "lane": lane, "item": tag(item.id)})
        except r2.FeedBlocked as exc:
            report.blocked.append(tag(item.id))
            log(
                {
                    "ts": clock(),
                    "item": item.id,
                    "kind": kind,
                    "ok": False,
                    "reasons": [{"rule": "feed-blocked", "path": "feed.xml", "detail": str(exc)}],
                }
            )
        except (r2.R2Error, pg.PagesError, cf.ConfigError, stage.StageError, OSError) as exc:
            report.failed.append(tag(item.id))
            log(
                {
                    "ts": clock(),
                    "item": item.id,
                    "kind": kind,
                    "ok": True,
                    "failed": f"{type(exc).__name__}: {exc}",
                }
            )
    _prune(
        cfg,
        entries,
        manifest,
        snapshots_dir,
        cfg.staging_dir,
        clock,
        gate_log,
    )


def run(
    cfg: cf.Config,
    *,
    transport: Transport | None = None,
    runner: pg.Runner = pg.subprocess_runner,
    notifier: Notifier | None = None,
    clock: Callable[[], float] = time.time,
) -> Report:
    report = Report(cfg.mode)
    policy = gt.Policy(
        gt.DenyList.parse(cf.read_credential(cfg.credentials_dir, cf.CRED_DENY_LIST)),
        cfg.ceiling,
        cfg.audience,
        cfg.access_control,
        cfg.posture_rules,
        frozenset(cfg.posture_rules_disabled),
    )
    gate_log = cfg.state_dir / "gate.jsonl"
    net: Transport = NoNetwork()  # stage: whatever a caller passes, no call is possible
    if cfg.mode == "dry-run":
        net = ReadOnly(transport or Urllib())
    elif cfg.mode == "live":
        net = transport or Urllib()
    live_entries: list[tuple[str, Path]] | None = []
    if cfg.live_source is not None:
        # the live source is a producer's handoff directory: an unreadable one (the read group not
        # joined yet) is reported, never silently "nothing to publish"
        try:
            os.listdir(cfg.live_source.dir)
            live_entries = discover(cfg.live_source.dir)
        except FileNotFoundError:
            live_entries = []
        except OSError as exc:
            live_entries = None
            report.failed.append("live:unreadable")
            _append(
                gate_log,
                {
                    "ts": clock(),
                    "lane": cfg.live_source.lane,
                    "item": "live-source",
                    "kind": "live",
                    "ok": True,
                    "failed": f"live-unreadable: {type(exc).__name__}",
                },
            )
    else:
        live_entries = discover(cfg.publishable_dir)
    if live_entries is not None:
        _gate_source(
            cfg,
            live_entries,
            net=net,
            runner=runner,
            policy=policy,
            report=report,
            clock=clock,
            snapshots_dir=cfg.state_dir / "snapshots",
            lane=None,
            anchor=cfg.live_source.dir if cfg.live_source else None,
        )
    for src in cfg.lane_sources:
        # a producer lane's items: gated like any other, then STAGED ONLY, whatever the run's mode
        # (no transport, no runner, no hosting credential): its own snapshots and staging area
        try:
            os.listdir(
                src.dir
            )  # absent: nothing handed off yet.  Anything else is reported, never silent
            lane_entries = discover(src.dir)
        except FileNotFoundError:
            continue
        except OSError as exc:  # no read access yet (the read group), a file in its place, ...
            report.failed.append(f"{src.lane}:unreadable")
            _append(
                cfg.state_dir / "gate.jsonl",
                {
                    "ts": clock(),
                    "lane": src.lane,
                    "item": f"lane-{src.lane}",
                    "kind": "lane",
                    "ok": True,
                    "failed": f"lane-unreadable: {type(exc).__name__}",
                },
            )
            continue
        _gate_source(
            dataclasses.replace(
                cfg,
                mode="stage",
                publishable_dir=src.dir,
                staging_dir=cfg.staging_dir / f"lane-{src.lane}",
            ),
            lane_entries,
            net=NoNetwork(),
            runner=_no_runner,
            policy=policy,
            report=report,
            clock=clock,
            snapshots_dir=cfg.state_dir / f"snapshots-{src.lane}",
            lane=src.lane,
            anchor=src.dir,
        )
    # stage mode makes no network call at all, a notification included; and a notification that
    # cannot be sent never takes the run down (the verdicts are already logged and returned)
    if notifier is not None and cfg.mode != "stage":
        bad = report.blocked
        try:
            notifier.report(
                NOTIFY_KEY,
                "blocked" if bad else "ok",
                Message(
                    NOTIFY_KEY,
                    PROBLEM,
                    "blocked: " + ", ".join(bad) if bad else RECOVERY,
                    level="warn",
                    tlp="amber",
                ),
            )
        except Exception as exc:
            _append(gate_log, {"ts": clock(), "notify_failed": type(exc).__name__})
            print(f"publishing: notification not sent ({type(exc).__name__})", file=sys.stderr)
    return report


def _handle(cfg, item, verdict, net, runner, manifest, clock, policy, lane=None) -> dict:
    out: dict = {"item": item.id, "kind": item.kind, "mode": cfg.mode}
    digest = gt.tree_digest(item)
    plan: dict
    if item.kind == "site":
        if cfg.pages is None:
            raise cf.ConfigError("a site item needs the pages settings")
        same = _last_site_digest(manifest, cfg.pages.project) == digest
        plan = {
            "adapter": "pages",
            "project": cfg.pages.project,
            "branch": cfg.pages.branch,
            "wrangler": cfg.pages.wrangler_version,
            "digest": digest,
            "unchanged": same,
            "files": dict(item.sidecar["sha256s"]),
        }
        if cfg.mode == "live" and not same:
            home = cfg.state_dir / "home"
            home.mkdir(parents=True, exist_ok=True)
            pg.deploy(
                cfg.pages,
                item.root,
                token=cf.read_credential(cfg.credentials_dir, cf.CRED_PAGES_TOKEN),
                account_id=cfg.pages_account_id,
                home=home,
                runner=runner,
            )
            _append(
                manifest,
                {
                    "ts": clock(),
                    "adapter": "pages",
                    "target": cfg.pages.project,
                    "item": item.id,
                    "digest": digest,
                    "tlp": verdict.label,
                    "sha256s": item.sidecar["sha256s"],
                },
            )
            out["result"] = "deployed"
        else:
            out["result"] = "unchanged" if same else "would-deploy"
    else:
        if cfg.r2 is None or cfg.feed is None:
            raise cf.ConfigError("a podcast item needs the r2 and feed settings")
        if cfg.mode == "stage":
            stem, _date, _m, _mp3 = r2.episode_files(item)
            plan = {
                "adapter": "r2-feed",
                "bucket": cfg.r2.bucket,
                "keys": [f"episodes/{stem}.mp3", f"episodes/{stem}.json"],
                "feed": r2.FEED_KEY,
                "files": dict(item.sidecar["sha256s"]),
            }
            out["result"] = "staged"
        else:
            client = r2.R2Client(
                cfg.r2.endpoint,
                cfg.r2.bucket,
                cf.read_credential(cfg.credentials_dir, cf.CRED_R2_KEY_ID),
                cf.read_credential(cfg.credentials_dir, cf.CRED_R2_SECRET),
                net,
            )
            p = r2.plan_episode(client, item, cfg.feed, policy, cfg.legacy_exceptions)
            plan = {
                "adapter": "r2-feed",
                "bucket": cfg.r2.bucket,
                "uploads": [u.key for u in p.uploads],
                "unchanged": list(p.unchanged),
                "feed_changes": p.feed_changes,
                "episodes": p.episodes,
                "unverified_by_size_only": list(p.unverified),
                "excused_legacy": list(p.excused),
            }
            if cfg.mode == "live":
                try:
                    written = r2.apply_plan(client, p)
                except r2.PreconditionFailed:  # the feed moved under us: read it again, once
                    p = r2.plan_episode(client, item, cfg.feed, policy, cfg.legacy_exceptions)
                    written = r2.apply_plan(client, p)
                if written:
                    _append(
                        manifest,
                        {
                            "ts": clock(),
                            "adapter": "r2-feed",
                            "target": cfg.r2.bucket,
                            "item": item.id,
                            "digest": digest,
                            "tlp": verdict.label,
                            "written": written,
                        },
                    )
                out["result"] = "published" if written else "unchanged"
            else:
                out["result"] = "would-publish" if (p.uploads or p.feed_changes) else "unchanged"
    out["plan"] = plan
    if cfg.mode == "stage":
        out["result"] = "staged"
        out["staged"] = str(
            stage.stage_item(item, verdict, plan, cfg.staging_dir, cfg.publishable_dir, lane)
        )
    return out


def build_notifier(cfg: cf.Config, opener=None) -> Notifier | None:
    if not cfg.notify_url:
        return None
    extra = {"opener": opener} if opener is not None else {}
    n = Notifier(
        default_sender(
            endpoint=lambda: cfg.notify_url,
            default_topic=cfg.notify_topic or None,
            auth=lambda: "Bearer " + cf.read_credential(cfg.credentials_dir, cf.CRED_NOTIFY),
            **extra,
        ),
        StateStore(cfg.state_dir / "notify.json"),
    )
    n.register_module_pairs([(PROBLEM, RECOVERY)], module="publishing")
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="publishing", description="gate and publish the lab's publishable items"
    )
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--mode", choices=cf.MODES, help="override the config's mode")
    args = ap.parse_args(argv)
    try:
        cfg = cf.load(args.config, args.mode)
        notifier = None
        if cfg.mode != "stage":  # stage makes no network call: no notifier is even built
            try:
                notifier = build_notifier(cfg)
            except Exception as exc:
                print(f"publishing: notifier not built ({type(exc).__name__})", file=sys.stderr)
        rep = run(cfg, notifier=notifier)
    except (cf.ConfigError, gt.GateError, pg.PagesError) as exc:
        print(f"publishing: {exc}", file=sys.stderr)
        return 2
    json.dump(
        {"mode": rep.mode, "blocked": rep.blocked, "failed": rep.failed, "done": rep.done},
        sys.stdout,
        indent=2,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return rep.code
