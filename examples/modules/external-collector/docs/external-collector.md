<!-- SPDX-License-Identifier: Apache-2.0 -->
# External data collector (fictional example module)

The example feature module of [docs/modules.md](../../../../docs/modules.md). It collects
connection attempts and dropped files on a host outside the lab, lands sessions in the lake,
offers the files to a sandbox through the `sample-handoff` interface, and keeps one agent,
`external-collector-analyst`, that reports on them in a real and a shadow lane.

Everything it adds to the platform is listed under `contributes` in
[module.yml](../module.yml); the decommission audit's `contributions` plane (specified, not implemented yet) is meant to
show anything left behind after removal.
