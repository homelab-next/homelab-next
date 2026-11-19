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
import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from homelabnext.notify import Message, Notifier, default_sender
from homelabnext.publishing import config as cf
from homelabnext.publishing import gate as gt
from homelabnext.publishing import pages as pg
from homelabnext.publishing import r2, stage
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
        if base.is_dir():
            out += [
                (kind, p)
                for p in sorted(base.iterdir())
                if p.is_dir() and not p.name.startswith(".")
            ]
    return out


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
    )
    net: Transport = NoNetwork()  # stage: whatever a caller passes, no call is possible
    if cfg.mode == "dry-run":
        net = ReadOnly(transport or Urllib())
    elif cfg.mode == "live":
        net = transport or Urllib()
    gate_log, manifest = cfg.state_dir / "gate.jsonl", cfg.state_dir / "published-manifest.jsonl"

    entries = discover(cfg.publishable_dir)
    sites = [e for e in entries if e[0] == "site"]
    superseded = {p.name for _, p in sites[:-1]}  # only the newest site build is the site
    for kind, root in entries:
        if root.name in superseded:
            report.done.append({"item": root.name, "kind": kind, "result": "superseded"})
            continue
        try:
            item = gt.load_item(root, kind)
            verdict = gt.evaluate(item, policy)
        except gt.GateError as exc:
            report.blocked.append(root.name)
            _append(
                gate_log,
                {
                    "ts": clock(),
                    "item": root.name,
                    "kind": kind,
                    "ok": False,
                    "reasons": [{"rule": "item-unreadable", "path": "", "detail": str(exc)}],
                },
            )
            continue
        _append(
            gate_log,
            {
                "ts": clock(),
                "item": item.id,
                "kind": kind,
                "ok": verdict.ok,
                "label": verdict.label,
                "reasons": [r.as_dict() for r in verdict.reasons],
            },
        )
        if not verdict.ok:
            report.blocked.append(item.id)
            continue
        try:
            report.done.append(_handle(cfg, item, verdict, net, runner, manifest, clock))
        except (r2.R2Error, pg.PagesError, cf.ConfigError, stage.StageError, OSError) as exc:
            report.failed.append(item.id)
            _append(
                gate_log,
                {
                    "ts": clock(),
                    "item": item.id,
                    "kind": kind,
                    "ok": True,
                    "failed": f"{type(exc).__name__}: {exc}",
                },
            )
    if notifier is not None:
        bad = report.blocked
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
    return report


def _handle(cfg, item, verdict, net, runner, manifest, clock) -> dict:
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
            p = r2.plan_episode(client, item, cfg.feed)
            plan = {
                "adapter": "r2-feed",
                "bucket": cfg.r2.bucket,
                "uploads": [u.key for u in p.uploads],
                "unchanged": list(p.unchanged),
                "feed_changes": p.feed_changes,
                "episodes": p.episodes,
            }
            if cfg.mode == "live":
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
            stage.stage_item(item, verdict, plan, cfg.staging_dir, cfg.publishable_dir)
        )
    return out


def build_notifier(cfg: cf.Config) -> Notifier | None:
    if not cfg.notify_url:
        return None
    n = Notifier(
        default_sender(
            cfg.notify_url,
            default_topic=cfg.notify_topic or None,
            auth=lambda: "Bearer " + cf.read_credential(cfg.credentials_dir, cf.CRED_NOTIFY),
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
        rep = run(cfg, notifier=build_notifier(cfg))
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
