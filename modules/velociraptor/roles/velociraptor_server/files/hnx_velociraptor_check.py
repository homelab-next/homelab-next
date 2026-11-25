#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: velociraptor-check
#   kind: tool
#   purpose: Decide whether the endpoint-forensics server is up, has clients enrolled and has heard from one recently, from the status file the hunt cycle writes.
#   owner: platform
#   trigger: [role:velociraptor_server]
#   inputs: the status file written by the module's hunt cycle (the criterion's name and, optionally, a path)
#   outputs: one line of evidence
#   installs_to: /usr/local/libexec/homelabnext/hnx-velociraptor-check
#   exit:
#     "0": the property holds
#     "1": the property does not hold
#     "2": usage error (an unknown criterion)
#     "100": "could not measure (no status file, an unknown schema, or one older than its own bound: the cycle that writes it has stopped)"
"""The module's capture-health criteria. Pure: it reads one file and never contacts the server."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

STATUS_SCHEMA = "hnx-velociraptor-status/1"
DEFAULT_STATUS = "/var/lib/hnx-modules/velociraptor/status/fleet.json"
CRITERIA = ("service-up", "clients-enrolled", "clients-fresh")


def criterion(name: str, path, now: float) -> tuple[int, str]:
    if name not in CRITERIA:
        return 2, f"unknown criterion {name!r}: one of {', '.join(CRITERIA)}"
    try:
        s = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return 100, f"cannot read the status file {path}: {e}"
    if not isinstance(s, dict) or s.get("schema") != STATUS_SCHEMA:
        return 100, "the status file is not a velociraptor status document"
    try:
        age = now - float(s["checked_at"])
        limit = float(s.get("max_age_s", 1800))
    except (KeyError, TypeError, ValueError):
        return 100, "the status file has no usable checked_at"
    if age > limit:
        return (
            100,
            f"the status is {int(age)}s old (bound {int(limit)}s): the hunt cycle has stopped",
        )
    if name == "service-up":
        if s.get("service_up") is True and not s.get("problems"):
            return 0, "the server answers and its definitions are within the principal's rights"
        return 1, "the server is down or refused: " + "; ".join(
            map(str, s.get("problems") or ["no answer"])
        )
    total = s.get("clients_total")
    if not isinstance(total, int):
        return 100, "the fleet could not be read (clients_total is unknown)"
    if name == "clients-enrolled":
        need = int(s.get("min_clients", 1))
        if total >= max(need, 1):
            return 0, f"{total} clients enrolled"
        return 1, f"{total} clients enrolled, need {max(need, 1)}"
    seen = s.get("newest_seen_age_s")
    bound = int(s.get("stale_after_s", 900))
    if isinstance(seen, int) and seen <= bound:
        return (
            0,
            f"the newest client was heard {seen}s ago ({s.get('clients_fresh')} of {total} within {bound}s)",
        )
    return (
        1,
        f"no client heard within {bound}s (newest: {seen}s)"
        if seen is not None
        else "no client has ever been heard",
    )


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or len(argv) > 2:
        print(
            "usage: hnx-velociraptor-check <service-up|clients-enrolled|clients-fresh> [status-file]",
            file=sys.stderr,
        )
        return 2
    rc, text = criterion(argv[0], argv[1] if len(argv) > 1 else DEFAULT_STATUS, time.time())
    print(text)
    return rc


if __name__ == "__main__":
    sys.exit(main())
