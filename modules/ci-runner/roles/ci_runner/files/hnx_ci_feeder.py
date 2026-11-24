#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: ci-runner-feeder
#   kind: service
#   purpose: Keep the CI runner host's spool supplied with single-use runner registrations minted with a repository-admin credential that never leaves the trusted side, remove registrations that were orphaned, and turn the repository's pool switch on only while the pool answers.
#   owner: platform
#   trigger: [manual, role:ci_runner]
#   inputs: --repo, --host, --ssh-key, --labels; the forge token from HNX_CI_FORGE_TOKEN, or the forge CLI's own stored login (--token-command)
#   outputs: registrations pushed over SSH to the host's forced command; deleted orphan registrations; the runner-selection variable
#   exit:
#     "0": stopped, or with --once one round done
#     "1": a round failed and --once was given
#     "2": usage error
"""The registration feeder for the ephemeral CI runner pool (modules/ci-runner README).

The runner host holds no forge credential at all. This loop, on a trusted machine that holds one,
mints one single-use ("just in time") runner registration per idle slot through the forge's REST
API and pushes it to the host's spool through an SSH key whose only command is the slot script's
``feed``. A registration is good for one job: the runner it registers deletes itself when its job
ends.

Every ``--reap-every`` rounds it lists the repository's runners and deletes the ones that carry
the pool's name prefix, are offline and not busy, and are neither spooled nor held by a slot
(a registration whose VM died before it connected). With ``--selection-var`` it sets that
repository variable (the workflow's switch) to ``--on-value`` while the host answers with a golden
image and slots, and to ``--off-value`` after ``--down-after`` seconds without that, so new workflow
runs are never routed to a pool that is gone.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
PREFIX = "hnx-ci-"
LIVE = {"booting", "running"}
IDLE = {"waiting", "done"}


class Forge:
    """The few REST calls the feeder makes, with a token it never prints."""

    def __init__(self, repo: str, token: str, api: str = API, opener=urllib.request.urlopen):
        self.repo, self._token, self.api, self._open = repo, token, api, opener

    def call(self, method: str, path: str, body: dict | None = None) -> dict | None:
        req = urllib.request.Request(
            f"{self.api}/repos/{self.repo}{path}",
            method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "hnx-ci-feeder",
            },
        )
        with self._open(req, timeout=30) as r:
            raw = r.read()
        return json.loads(raw) if raw else None

    def mint(self, name: str, labels: list[str], group: int = 1) -> str:
        out = self.call(
            "POST",
            "/actions/runners/generate-jitconfig",
            {"name": name, "runner_group_id": group, "labels": labels, "work_folder": "_work"},
        )
        return out["encoded_jit_config"]

    def runners(self) -> list[dict]:
        out, page = [], 1
        while True:
            doc = self.call("GET", f"/actions/runners?per_page=100&page={page}") or {}
            got = doc.get("runners", [])
            out += got
            if len(got) < 100:
                return out
            page += 1

    def queued_jobs(self, labels: list[str]) -> int:
        """Jobs of this repository waiting for a runner that carries all of ``labels``."""
        want, n = set(labels), 0
        for state in ("queued", "in_progress"):
            doc = self.call("GET", f"/actions/runs?status={state}&per_page=100") or {}
            for run in doc.get("workflow_runs", []):
                jobs = self.call("GET", f"/actions/runs/{int(run['id'])}/jobs?per_page=100") or {}
                n += sum(
                    1
                    for j in jobs.get("jobs", [])
                    if j.get("status") == "queued" and want <= set(j.get("labels", []))
                )
        return n

    def delete_runner(self, rid: int) -> None:
        self.call("DELETE", f"/actions/runners/{int(rid)}")

    def get_var(self, name: str) -> str | None:
        try:
            return (self.call("GET", f"/actions/variables/{name}") or {}).get("value")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def set_var(self, name: str, value: str) -> None:
        if self.get_var(name) is None:
            self.call("POST", "/actions/variables", {"name": name, "value": value})
        else:
            self.call("PATCH", f"/actions/variables/{name}", {"name": name, "value": value})


class Host:
    """The runner host's forced command over SSH: ``status`` and ``put <name>``."""

    def __init__(self, target: str, key: str, known_hosts: str | None, run=subprocess.run):
        self._run = run
        self.base = ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                     "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15"]  # fmt: skip
        if known_hosts:
            self.base += [
                "-o",
                f"UserKnownHostsFile={known_hosts}",
                "-o",
                "StrictHostKeyChecking=yes",
            ]
        self.base.append(target)

    def status(self) -> dict:
        r = self._run([*self.base, "status"], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"status: exit {r.returncode}: {r.stderr.strip()[:200]}")
        return json.loads(r.stdout)

    def put(self, name: str, jit: str) -> None:
        r = self._run(
            [*self.base, "put", name], input=jit, capture_output=True, text=True, timeout=60
        )
        if r.returncode != 0:
            raise RuntimeError(f"put {name}: exit {r.returncode}: {r.stderr.strip()[:200]}")


def wanted(status: dict, buffer: int) -> int:
    """How many registrations to mint now: one per slot waiting for one, plus a small buffer,
    less what is already spooled; never more than the slots in total."""
    states = [s.get("state") for s in status.get("slots", {}).values()]
    # only a slot that says it waits (or just finished) is idle: one whose state cannot be read is
    # never counted, so an unreadable slot directory cannot make the feeder mint for every slot
    idle = sum(1 for s in states if s in IDLE)
    target = min(status.get("slots_total", 0), idle + buffer)
    return max(0, target - len(status.get("spooled", [])))


def held(status: dict) -> set[str]:
    names = set(status.get("spooled", []))
    for s in status.get("slots", {}).values():
        if s.get("runner") and s.get("state") in LIVE:
            names.add(s["runner"])
    return names


def orphans(runners: list[dict], keep: set[str], prefix: str = PREFIX) -> list[dict]:
    return [
        r
        for r in runners
        if str(r.get("name", "")).startswith(prefix)
        and r.get("status") == "offline"
        and not r.get("busy")
        and r.get("name") not in keep
    ]


def supply(status: dict, tag: str) -> int:
    """Registrations of one ``--also`` repository already spooled or held by a slot that has not
    yet started a job (a booting VM): they will take its queued jobs."""
    mark = f"{PREFIX}{tag}-"
    n = sum(1 for x in status.get("spooled", []) if str(x).startswith(mark))
    for s in status.get("slots", {}).values():
        if s.get("state") == "booting" and str(s.get("runner", "")).startswith(mark):
            n += 1
    return n


def idle_runners(runners: list[dict], prefix: str = PREFIX) -> list[dict]:
    """Pool runners that are connected and run no job: a VM holding a slot for work that is not
    coming (or whose job another runner took)."""
    return [
        r
        for r in runners
        if str(r.get("name", "")).startswith(prefix)
        and r.get("status") == "online"
        and not r.get("busy")
    ]


def booting(status: dict, tag: str) -> int:
    """Slots of one ``--also`` repository whose VM is up and has not started a job yet."""
    mark = f"{PREFIX}{tag}-"
    return sum(
        1
        for s in status.get("slots", {}).values()
        if s.get("state") == "booting" and str(s.get("runner", "")).startswith(mark)
    )


def new_name(tag: str) -> str:
    return f"{PREFIX}{tag}-{time.strftime('%m%d%H%M%S', time.gmtime())}-{secrets.token_hex(3)}"


class Feeder:
    def __init__(self, forge: Forge, host: Host, args, clock=time.monotonic):
        self.forge, self.host, self.args, self.clock = forge, host, args, clock
        self.extras = list(getattr(args, "extras", []) or [])  # [(Forge, labels, tag)]
        self.seen: dict[int, float] = {}  # runner id -> when this process first saw it idle
        self.last_live = clock()
        self.rounds = 0
        self.routed: str | None = None

    def route(self, value: str) -> None:
        if not self.args.selection_var or value == self.routed:
            return
        if self.forge.get_var(self.args.selection_var) != value:
            self.forge.set_var(self.args.selection_var, value)
            print(f"feeder: {self.args.selection_var} = {value}", flush=True)
        self.routed = value

    def round(self) -> None:
        self.rounds += 1
        try:
            st = self.host.status()
        except Exception as e:  # unreachable, refused, garbled: the pool is not answering
            print(f"feeder: host status failed: {e}", flush=True)
            if self.clock() - self.last_live > self.args.down_after:
                self.route(self.args.off_value)
            raise
        if st.get("golden") and st.get("slots_total", 0) > 0:
            self.last_live = self.clock()
            self.route(self.args.on_value)
        elif self.clock() - self.last_live > self.args.down_after:
            self.route(self.args.off_value)
        if st.get("golden"):
            room = wanted(st, self.args.buffer)
            unmet = 0  # queued jobs of the other repositories no registration covers yet
            # another repository's registrations only against its queued jobs, first: its jobs
            # wait for them, where the main repository's buffer is only a head start
            for forge, labels, tag in self.extras:
                try:
                    queued = forge.queued_jobs(labels)
                    need = queued - supply(st, tag)
                except Exception as e:  # its API failing must not stop the main repository's feed
                    print(
                        f"feeder: {tag} demand failed: {type(e).__name__}: {str(e)[:200]}",
                        flush=True,
                    )
                    continue
                # spooled registrations only cover a queue once a slot takes them
                unmet += max(0, queued - booting(st, tag))
                for _ in range(
                    max(0, min(need, st.get("slots_total", 0) - len(st.get("spooled", []))))
                ):
                    name = new_name(tag)
                    self.host.put(name, forge.mint(name, labels))
                    st.setdefault("spooled", []).append(name)
                    room = max(0, room - 1)
            for _ in range(room):
                name = new_name(self.args.tag)
                self.host.put(name, self.forge.mint(name, self.args.labels))
                st.setdefault("spooled", []).append(name)
            self.reclaim(st, unmet)
        if self.rounds % self.args.reap_every == 1 or self.args.reap_every == 1:
            for forge in [self.forge, *(e[0] for e in self.extras)]:
                for r in orphans(forge.runners(), held(st)):
                    forge.delete_runner(r["id"])
                    print(f"feeder: removed orphan registration {r['name']}", flush=True)

    def reclaim(self, st: dict, unmet: int) -> None:
        """Free slots held by idle runners, so a repository's idle VMs never starve another's
        queued jobs: when queued jobs of an ``--also`` repository wait and no slot is free, the
        main repository's idle runners are deleted (their VMs power off) one for one; and every
        repository's runners idle longer than ``--idle-ttl`` go too (all but ``--buffer`` of the
        main repository's, which are its head start)."""
        now = self.clock()
        free = sum(1 for s in st.get("slots", {}).values() if s.get("state") in IDLE)
        ttl = getattr(self.args, "idle_ttl", 0)
        due = ttl > 0 and self.rounds % self.args.reap_every == 2 % self.args.reap_every
        if not ((unmet > 0 and free == 0) or due):
            return
        for forge, keep, starving in [(self.forge, self.args.buffer, unmet)] + [
            (e[0], 0, 0) for e in self.extras
        ]:
            idle = idle_runners(forge.runners())
            ids = {r["id"] for r in idle}
            for rid in [k for k in self.seen if k not in ids]:
                del self.seen[rid]
            for r in idle:
                self.seen.setdefault(r["id"], now)
            idle.sort(key=lambda r: self.seen[r["id"]])  # oldest first
            kill = []
            if starving > 0 and free == 0:
                kill = idle[:starving]
            if due:
                old = [r for r in idle if now - self.seen[r["id"]] >= ttl]
                kill += [r for r in old[: max(0, len(idle) - keep)] if r not in kill]
            for r in kill:
                forge.delete_runner(r["id"])
                self.seen.pop(r["id"], None)
                print(f"feeder: released idle runner {r['name']}", flush=True)


def token_from(args) -> str:
    tok = os.environ.get("HNX_CI_FORGE_TOKEN", "")
    if not tok and args.token_command:
        tok = subprocess.run(args.token_command, capture_output=True, text=True, check=True).stdout
    tok = tok.strip()
    if not tok:
        raise SystemExit("hnx-ci-feeder: no forge token (HNX_CI_FORGE_TOKEN or --token-command)")
    return tok


def parse(argv: list[str]):
    p = argparse.ArgumentParser(prog="hnx-ci-feeder")
    p.add_argument("--repo", required=True, help="owner/name")
    p.add_argument(
        "--host",
        required=True,
        help="the slots' account on the runner host (its key is forced to feed): user@address",
    )
    p.add_argument("--ssh-key", required=True)
    p.add_argument("--known-hosts")
    p.add_argument("--labels", default="self-hosted,linux,x64,hnx-ci")
    p.add_argument("--on-value", default="on", help="the variable's value while the pool answers")
    p.add_argument(
        "--off-value",
        default="off",
        help="its value once the pool has not answered for --down-after",
    )
    p.add_argument(
        "--selection-var",
        default="",
        help="the repository variable the workflow reads as the pool's on/off switch",
    )
    p.add_argument("--tag", default="pool", help="a short word in every runner name")
    p.add_argument("--buffer", type=int, default=2)
    p.add_argument("--interval", type=float, default=15.0)
    p.add_argument("--reap-every", type=int, default=20)
    p.add_argument(
        "--idle-ttl",
        type=float,
        default=900.0,
        help="seconds a connected runner may sit without a job before its registration is "
        "deleted and its slot freed (0: never); its first sight is this process's own clock",
    )
    p.add_argument("--down-after", type=float, default=180.0)
    p.add_argument(
        "--also",
        action="append",
        default=[],
        metavar="OWNER/NAME=LABELS=TAG",
        help="a further repository the same slots serve (repeatable): registrations for it are "
        "minted only against its queued jobs that carry LABELS (comma separated), named with TAG",
    )
    p.add_argument("--token-command", nargs="+", default=["gh", "auth", "token"])
    p.add_argument("--once", action="store_true")
    a = p.parse_args(argv)
    a.labels = [x for x in a.labels.split(",") if x]
    a.extras = []
    for spec in a.also:
        parts = spec.split("=")
        if len(parts) != 3 or "/" not in parts[0] or not parts[2].isalnum():
            p.error(f"bad --also {spec!r}: OWNER/NAME=LABEL,LABEL=TAG")
        a.extras.append((parts[0], [x for x in parts[1].split(",") if x], parts[2]))
    if not a.labels or a.buffer < 0 or a.reap_every < 1 or not a.tag.isalnum():
        p.error("bad --labels, --buffer, --reap-every or --tag")
    return a


def main(argv: list[str]) -> int:
    args = parse(argv)
    token = token_from(args)
    args.extras = [(Forge(repo, token), labels, tag) for repo, labels, tag in args.extras]
    feeder = Feeder(Forge(args.repo, token), Host(args.host, args.ssh_key, args.known_hosts), args)
    while True:
        try:
            feeder.round()
        except Exception as e:
            print(f"feeder: round failed: {type(e).__name__}: {str(e)[:300]}", flush=True)
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
