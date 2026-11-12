#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: events-provision
#   kind: tool
#   purpose: Create a standing events stream and its DLQ, bounded, when missing (the operator's one-time step).
#   owner: platform
#   trigger: [role:events_bus]
#   inputs: the bus URL, the admin user, its password in HNX_EVENTS_ADMIN_PASSWORD, the stream, its subject prefix and size
#   outputs: "one JSON line: the streams it created, under the key created"
#   installs_to: /usr/local/libexec/homelabnext/hnx-events-provision
#   exit:
#     "0": the stream and its DLQ exist
#     "1": the bus refused or could not be reached
#     "2": usage error
"""Provision one standing stream (role events_bus) through the project's own adapter,
``homelabnext.conform.adapters.nats_jetstream.provision_streams``, as the admin user: the relay
and every other client connect with ``provision=False`` and may not create streams.

Usage: hnx-events-provision URL USER STREAM SUBJECT_PREFIX MAX_BYTES  (password in the
environment, never in argv)."""

import json
import os
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 5 or not argv[4].isdigit():
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    url, user, stream, prefix, max_bytes = argv
    password = os.environ.get("HNX_EVENTS_ADMIN_PASSWORD", "")
    if not password:
        print("hnx-events-provision: HNX_EVENTS_ADMIN_PASSWORD is not set", file=sys.stderr)
        return 2
    from homelabnext.conform.adapters import nats_jetstream as nj

    try:
        wire = nj.NatsPyWire(
            url, name=f"{user}-provision", user=user, password=lambda: password,
            inbox_prefix=f"_INBOX.{user}",
        )  # fmt: skip
        try:
            created = nj.provision_streams(
                wire, stream=stream, subject_prefix=prefix, max_bytes=int(max_bytes)
            )
        finally:
            wire.close()
    except Exception as exc:  # the class only: never a body or a credential
        print(f"hnx-events-provision: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"created": created}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
