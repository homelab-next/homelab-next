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
    idle = sum(1 for s in states if s not in LIVE)
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


def new_name(tag: str) -> str:
    return f"{PREFIX}{tag}-{time.strftime('%m%d%H%M%S', time.gmtime())}-{secrets.token_hex(3)}"


class Feeder:
    def __init__(self, forge: Forge, host: Host, args, clock=time.monotonic):
        self.forge, self.host, self.args, self.clock = forge, host, args, clock
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
            for _ in range(wanted(st, self.args.buffer)):
                name = new_name(self.args.tag)
                self.host.put(name, self.forge.mint(name, self.args.labels))
                st.setdefault("spooled", []).append(name)
        if self.rounds % self.args.reap_every == 1 or self.args.reap_every == 1:
            for r in orphans(self.forge.runners(), held(st)):
                self.forge.delete_runner(r["id"])
                print(f"feeder: removed orphan registration {r['name']}", flush=True)


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
        "--host", required=True, help="the feed account on the runner host: user@address"
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
    p.add_argument("--down-after", type=float, default=180.0)
    p.add_argument("--token-command", nargs="+", default=["gh", "auth", "token"])
    p.add_argument("--once", action="store_true")
    a = p.parse_args(argv)
    a.labels = [x for x in a.labels.split(",") if x]
    if not a.labels or a.buffer < 0 or a.reap_every < 1 or not a.tag.isalnum():
        p.error("bad --labels, --buffer, --reap-every or --tag")
    return a


def main(argv: list[str]) -> int:
    args = parse(argv)
    feeder = Feeder(
        Forge(args.repo, token_from(args)), Host(args.host, args.ssh_key, args.known_hosts), args
    )
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
