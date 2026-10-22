#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: last-run-writer
#   kind: job
#   purpose: Write a scheduled job's last-run record (schemas/status/last_run.schema.json) when its service starts and again when it stops, whatever the outcome.
#   owner: platform
#   trigger: [role:last_run, timer:aide/scan, timer:clamav/scan, timer:lynis/scan, timer:needrestart/check, timer:rkhunter/scan, timer:trivy/scan]
#   inputs: the job's id, unit, schedule and record directory (arguments); systemd's SERVICE_RESULT, EXIT_CODE and EXIT_STATUS (finish)
#   outputs: <dir>/<job id as a file name>.json, mode 0640, group-readable by --group
#   installs_to: /usr/local/libexec/homelabnext/hnx-last-run
#   exit:
#     "0": the record was written
#     "1": it could not be written (the units ignore it, with the - prefix)
#     "2": bad arguments
"""Managed by homelabnext (role last_run); local changes are overwritten.

A timer's service runs this twice (docs/role-interface.md section 8):

    ExecStartPre=-hnx-last-run start  --dir D --group G --job timer:<role>/<unit> --unit %n --calendar "<OnCalendar>" --delay <s>
    ExecStopPost=-hnx-last-run finish (the same arguments)

``start`` writes the record with ``running: true``; ``finish`` (systemd runs ExecStopPost after
a success, a failure, a timeout or a kill alike) adds the end time and systemd's own verdict.
The record carries the schedule the host actually runs, so the status hub's ``job-last-run``
mapping (docs/status.md) judges lateness without the repository.  The write is atomic (a
temporary file renamed over the record), mode 0640, group ``--group``, so a shipping account in
that group can read it and nobody else can."""

import argparse
import datetime
import grp
import json
import os
import re
import socket
import sys
import tempfile

SCHEMA = "homelabnext.status.last-run/1"
JOB = re.compile(r"^(?:timer|fleet-unit):[A-Za-z0-9_.-]{1,64}(?:/[A-Za-z0-9_.-]{1,64})?\Z")
CALENDAR = re.compile(r"^[A-Za-z0-9*:,./~ -]{1,128}\Z")


def now():
    # timezone.utc, not datetime.UTC (3.11+): the writer runs on the guest's own Python 3
    utc = datetime.timezone.utc  # noqa: UP017
    return datetime.datetime.now(utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_path(directory, job):
    # injective: JOB allows only [A-Za-z0-9_.-:/] and no '%', so percent-encoding ':' and '/'
    # keeps `timer:lynis/scan` and `timer:lynis-scan` apart (a '-' for both made them one file)
    return os.path.join(directory, job.replace(":", "%3A").replace("/", "%2F") + ".json")


def env(name, pattern):
    value = os.environ.get(name, "")
    return value if re.fullmatch(pattern, value) else None


def build(args, previous):
    host = socket.gethostname().split(".")[0][:63] or "unknown"
    rec = {
        "schema": SCHEMA,
        "job": args.job,
        "unit": args.unit,
        "host": host,
        "on_calendar": args.calendar,
        "started_at": now(),
        "finished_at": None,
        "running": True,
        "result": None,
        "exit_code": None,
        "exit_status": None,
    }
    if args.delay:
        rec["randomized_delay_s"] = args.delay
    if args.action == "finish":
        # the start time is the one start wrote; without it (start never ran) the run is dated
        # by its end
        started = previous.get("started_at") if previous.get("running") else None
        rec.update(
            started_at=started or now(),
            finished_at=now(),
            running=False,
            result=env("SERVICE_RESULT", r"[a-z][a-z-]{0,31}") or "unknown",
            exit_code=env("EXIT_CODE", r"[a-z]{1,16}"),
            exit_status=env("EXIT_STATUS", r"[A-Z0-9]{1,16}"),
        )
    return rec


def write(path, rec, gid):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".last-run.")
    try:
        os.fchmod(fd, 0o640)
        if gid is not None:
            os.fchown(fd, -1, gid)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=1, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv=None):
    p = argparse.ArgumentParser(prog="hnx-last-run")
    p.add_argument("action", choices=["start", "finish"])
    p.add_argument("--dir", required=True)
    p.add_argument("--group", required=True)
    p.add_argument("--job", required=True)
    p.add_argument("--unit", required=True)
    p.add_argument("--calendar", required=True)
    p.add_argument("--delay", type=int, default=0)
    args = p.parse_args(argv)
    if not JOB.match(args.job) or not CALENDAR.match(args.calendar) or args.delay < 0:
        print("hnx-last-run: bad --job, --calendar or --delay", file=sys.stderr)
        return 2
    path = record_path(args.dir, args.job)
    try:
        with open(path, encoding="utf-8") as f:
            previous = json.load(f)
        previous = previous if isinstance(previous, dict) else {}
    except (OSError, ValueError):
        previous = {}
    try:
        gid = grp.getgrnam(args.group).gr_gid
    except KeyError:
        print(
            f"hnx-last-run: no group {args.group}; the record keeps its default group",
            file=sys.stderr,
        )
        gid = None
    try:
        write(path, build(args, previous), gid)
    except OSError as exc:
        print(f"hnx-last-run: {path}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
