#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: events-provision
#   kind: tool
#   purpose: Create the standing events streams (each with its DLQ, bounded) and the pull durables clients bind to, when missing.
#   owner: platform
#   trigger: [role:events_bus]
#   inputs: the bus URL and the admin user as arguments, its password in HNX_EVENTS_ADMIN_PASSWORD, the streams and durables as JSON on stdin
#   outputs: "one JSON line: the streams and durables (stream/durable) it created, under the key created"
#   installs_to: /usr/local/libexec/homelabnext/hnx-events-provision
#   exit:
#     "0": every stream, its DLQ and every durable exist (each durable a pull durable on its filter)
#     "1": the bus refused or could not be reached, or an existing durable is not one a client may bind to
#     "2": usage error
"""Provision the standing streams and the durables (role events_bus) through the project's own
adapter, ``homelabnext.conform.adapters.nats_jetstream.provision_streams`` and
``provision_consumers``, as the admin user: the relay, the bridge and every other client connect
with ``provision=False`` and may create neither a stream nor a consumer.  A consumer create takes
any configuration, a push ``deliver_subject`` included, which the server delivers as itself
whatever the creator may publish to; so only this step creates durables, and only pull ones.

Usage: hnx-events-provision URL USER < SPEC  (password in the environment, never in argv; SPEC is
{"streams": [{name, subject_prefix, max_bytes}], "durables": [{stream, durable, filter, ...}]})."""

import json
import os
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: hnx-events-provision URL USER < SPEC", file=sys.stderr)
        return 2
    url, user = argv
    password = os.environ.get("HNX_EVENTS_ADMIN_PASSWORD", "")
    if not password:
        print("hnx-events-provision: HNX_EVENTS_ADMIN_PASSWORD is not set", file=sys.stderr)
        return 2
    try:
        spec = json.loads(sys.stdin.read() or "{}")
        streams, durables = list(spec.get("streams", [])), list(spec.get("durables", []))
        for s in streams:
            if not str(s["max_bytes"]).isdigit():
                raise ValueError("max_bytes is a positive integer")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"hnx-events-provision: the spec on stdin: {exc}", file=sys.stderr)
        return 2
    from homelabnext.conform.adapters import nats_jetstream as nj

    created: list[str] = []
    try:
        wire = nj.NatsPyWire(
            url, name=f"{user}-provision", user=user, password=lambda: password,
            inbox_prefix=f"_INBOX.{user}",
        )  # fmt: skip
        try:
            for s in streams:
                created += nj.provision_streams(
                    wire,
                    stream=s["name"],
                    subject_prefix=s["subject_prefix"],
                    max_bytes=int(s["max_bytes"]),
                )
            by_stream: dict[str, list[dict]] = {}
            for d in durables:
                by_stream.setdefault(str(d["stream"]), []).append(d)
            for stream, ds in by_stream.items():
                made = nj.provision_consumers(wire, stream=stream, durables=ds)
                created += [f"{stream}/{name}" for name in made]
        finally:
            wire.close()
    except Exception as exc:  # the class only: never a body or a credential
        print(f"hnx-events-provision: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"created": created}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
