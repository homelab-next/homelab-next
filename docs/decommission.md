---
summary: 'The read-only decommission audit: hnx decommission check, its statuses, the planes it inspects, adapters and fakes, and a positive control.'
---
# Decommission audit

Building a guest has a path; tearing one down needs one too, or each remnant (a dead firewall
file, a playbook still targeting the host, a monitoring target, a secret name, a DHCP lease)
lives until somebody trips on it. `hnx decommission` is the read-only audit that answers
"what of this retired guest is still lying around?" across every plane.

```
hnx decommission check old-core --vmid 170 --ip 192.0.2.99 --root . --snapshot state.json
hnx decommission plan  old-core --vmid 170 --root . --snapshot state.json   # ordered teardown list
hnx decommission planes                                                    # list the planes
```

Exit codes: `0` clean, `1` remnants (or nothing could be measured), `2` usage error.
`--strict` also fails on REVIEW and SKIP. `--json` is machine readable.

## Statuses

| Status | Meaning |
|---|---|
| `CLEAN` | measured; nothing left |
| `REMNANT` | measured; something is still there (fails the audit) |
| `INFO` | worth knowing, not a failure (for example the vmid is now another live resource's) |
| `REVIEW` | a human decides (a code comment or narrative doc still mentions the guest) |
| `SKIP` | could not be measured. **Never counted as clean**; a run where nothing could be measured is `UNMEASURED` and exits 1 |

## Planes

A plane is a function `(Target, Adapters) -> Result` registered with `@plane("name")` in
`homelabnext/decommission/planes.py`. Add a plane by registering one; nothing else changes.

| Plane | Looks at | Source |
|---|---|---|
| `inventory` | inventory files and `host_vars/<name>` | source tree |
| `playbooks` | plays targeting the host, `import_playbook` chain, broken imports | source tree |
| `iac` | IaC definitions by name; a vmid now owned by another resource is `INFO`, so never delete by id alone | source tree |
| `live-refs` | any other mention; live config is a remnant, comments and narrative docs are `REVIEW` | source tree |
| `hv-config`, `hv-firewall`, `hv-volumes`, `hv-backup`, `hv-ha` | guest config, per-guest firewall file, disks and volumes, backup-job and HA membership | hypervisor adapter |
| `siem-roster`, `monitoring` | telemetry agent roster, scrape/probe targets | adapters |
| `secret-names` | secret-store variable **names** only; values are never requested | adapter |
| `dns`, `proxy`, `dhcp` | records and aliases, edge routes, reservations | adapters |

Word-bounded matching: `app-core` does not match `app-core-2` or `x.app-core`. A path already
reported by `inventory`, `playbooks` or `iac` is not repeated by `live-refs`.

## Adapters and fakes

Probes never call `subprocess` or open sockets. They read through `Adapters`
(`homelabnext/decommission/adapters.py`): a source `Tree` (`DirTree`, `MemTree`) and snapshot-backed
sections for the hypervisor and the rosters. A snapshot is a JSON file your own exporter writes:

```json
{"hypervisor": {"guest_configs": {"180": "..."}, "firewall_files": ["180.fw"], "volumes": ["pool:vm-180-disk-0"],
                "backup_jobs": [{"id": "daily", "vmids": [180]}], "ha": ["vm:180"]},
 "siem": {"agents": [{"name": "app-core"}]}, "monitoring": {"targets": ["app-core:9100"]},
 "secrets": {"names": ["app_core_db_password"]}, "dns": {"records": []},
 "proxy": {"routes": []}, "dhcp": {"reservations": []},
 "dns_note": "a section may be {\"unreachable\": \"why\"} to model an outage"}
```

A missing section means "no adapter configured" and a section of `{"unreachable": "..."}` means the
source could not be reached; both give `SKIP`. A live adapter implements the same few methods.

## Positive control

A clean answer on a live guest means the audit is broken. `--control LIVE_NAME` runs the same
planes for a guest you know is live and exits 1 if it comes back clean. The test-suite does the
same end to end: `tests/decommission/` wires a fictional live guest into every plane (all flagged)
and a retired guest that is clean on every measured plane.

## Relation to `tools/decommission_check.py`

That tool is the service-swap scanner (step 8 of the swap procedure: does anything still point at
the retired *product*). It is unchanged and still gates `hnx swap`. Use this audit when a whole
guest is retired.
