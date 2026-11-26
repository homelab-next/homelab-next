<!-- SPDX-License-Identifier: Apache-2.0 -->
# prowler: scheduled read-only cloud-posture scan

A feature module ([module manifest](../../docs/modules.md)) for security audit and assessment: a weekly,
read-only cloud-posture audit that writes what it finds as JSON lines to a file.

**Scope: a lab-internal cloud-posture audit of the lab's own honeypot AWS account, with the same
read-only permissions the old lab used. Use outside the lab requires explicit permission.** It is not a
slot provider: it listens on nothing, has no web page and no public route, and has no registry row.
Which account, which regions, which exposures the site accepts, the credential's value and the guest it
runs on are the overlay's; the module holds none of them.

```
 secret store --(deploy time)--> root-only credential file (0600)
                                          |
 timer (weekly, Tue 03:00) --> scan unit: hnx-prowler-export --> prowler aws (read-only API calls, every region)
                                          |                         |  json-ocsf report (output/, replaced each run)
                                          v                         v
                          /var/log/prowler-findings.json  <-- summary line + one flat line per FAILING check
                                          |
                      SIEM agent localfile / log pipeline --> lake writer --> the lake's compliance-finding table
```

## What it installs (role `prowler`, host role `scanner`)

| Piece | What it does |
|---|---|
| virtualenv | `prowler_venv` (default `/opt/hnx-modules/<id>/venv`), owned by the module. The scanner is installed there at the exact `prowler_version` pin (never "latest"); a system-wide `pip install` is refused by a distribution's externally-managed Python and breaking that for one tool is not a trade worth making. |
| exporter | `/usr/local/libexec/homelabnext/hnx-prowler-export` (standard library only). Runs the scanner, parses its report, replaces the findings file whole. |
| credential file | `<config>/credentials/aws.env`, root-only 0600, written by a task with `no_log: true`. systemd reads it as root and gives the scan its environment; the scan's own user cannot open it. |
| settings and mutelist | `<config>/scan.env` (no secret) and `<config>/mutelist.yaml`, rendered from `prowler_mutelist`. |
| unit and timer | `hnx-<id>-scan.service` (hardened, `Nice=10`, idle IO, 2 G cap, the module's slice) and `hnx-<id>-scan.timer` (`OnCalendar`, `Persistent=true`, a 15 minute random delay; never an interval). |

## The findings file

`prowler_findings_path` (default `/var/log/prowler-findings.json`) holds JSON lines, replaced whole and
atomically by every scan:

1. one `pw_kind: summary` line: `pw_passed`, `pw_failed`, `pw_muted`, `pw_total`, `pw_score` (over the
   verdicts acted on: muted findings are on neither side), `pw_version`, `pw_account`, `pw_scanned_at`;
2. one `pw_kind: check` line per **failing** check: check id, title, severity, service, region, account,
   resource id and type, risk and remediation text (cut at 500 characters).

Every field is flat and `pw_`-prefixed on purpose. The scanner's native output is deeply nested, a SIEM's
generic JSON decoder flattens nested objects into dotted names, and an ordinary leaf (`status`,
`severity`, `region`) can collide with a reserved field and take down the rule engine. A prefix removes
that by construction. Passes are counted in the summary and not emitted; the scanner's full report stays
in `output/` until the next scan.

Two behaviours that are easy to get wrong, both covered by `tests/modules/test_prowler_script.py`:

* **The scanner's exit code 3 means "a check failed", which is the normal outcome of a real scan.** Only a
  code outside {0, 3} is a tool error.
* **A muted finding keeps `status_code: FAIL`** and is marked `status: Suppressed`. Filtering on the status
  code alone makes the mutelist look as if it works while changing nothing in the file; the exporter
  reads the suppression first and reports the muted count in the summary, so a mutelist that grows
  without a reason is visible.

A failed scan, or a report with no findings at all, writes **nothing**: truncating the last findings to
zero would make a broken scanner look like an account where everything got fixed. The previous file stays
and health goes red once it is older than `prowler_scan_max_age_h` (default 192 h: the weekly period plus a
day; a staleness of days is the weekly cadence working, a staleness of more than a week is the signal).

## How the findings reach the lake

The module writes the file; it does not hold a lake client. The log pipeline (`cap:log-pipeline`, preferred)
tails the file, labels each event and stages the compliance-finding batch, and the lake writer module
commits it to the lake's compliance table. If no pipeline is selected the findings still land in the file
(and the SIEM agent can tail it as a local JSON file); nothing reaches the lake and the table's own
freshness check reports it. Mapping `pw_` lines to the compliance-finding class is the pipeline's
route, not this module's.

## Secrets it needs

One: `secret:prowler/aws-credentials` (`prowler_login_ref`), one line, `<access key id>:<secret access key>`,
for a **read-only principal** (the provider's `SecurityAudit` and `ViewOnlyAccess` policies; nothing that
writes). The form is checked in readiness, before anything is written. Run the scan as a scoped principal
on purpose: with a narrower one most of the ~300 checks fail with AccessDenied, which the scanner reports as
FAILURES, and "the scanner could not look" is indistinguishable at a glance from "the account is
misconfigured", the reading people act on. Rotating the credential is a new secret value and a re-run of the
install; no code changes.

## Egress it needs

`internet` from the `scanner` role, declared in the manifest and granted by the overlay
(`grants.egress.prowler.scanner: [internet]`): https to the provider's API endpoints (`amazonaws.com`)
at scan time, and the package index at install and upgrade. The generated network policy can allow
`internet` but cannot name hosts, so the site's firewall should limit the guest to those names (and to
DNS). Nothing else leaves; nothing is accepted inbound.

## Placement: why NOT on the honeypot instance

Put the `scanner` role on an ordinary lab guest (a small one: 1 vCPU, 2 GB, 10 GB). **Never on a decoy.** A
honeypot is hostile ground by design: it exists to be found and attacked. A credential that can enumerate
the whole account, even read-only, belongs on the host *least* likely to be compromised, not the most.
The module itself therefore has no placement constraint to enforce that; the README and the host role's
purpose say it, and the site's selection is where it holds.

## Mutelist

`prowler_mutelist` is for findings that are **true and intended** (a decoy's exposed ports) and nothing
else. Each entry needs an account (12 digits or `*`), a check id, pinned resources, a reason of at least ten
characters, and optionally regions. Pin the resource, never the whole check: if a second instance appears
the mute must not silently cover it. An entry with `review: YYYY-MM` is a **deferred** gap (true, not
wanted, accepted until a stated month against a stated blocker): the health hook fails once that month has
passed, because the scanner has no native expiry and an accepted risk that outlives its date is how it
turns into a forgotten one. A blanket `'.*'` resource is only accepted on a deferred entry. The
module ships an empty mutelist; the overlay carries its own (the old lab's two deferred root-MFA entries
and its decoy's five port entries are site facts, not module facts).

## Running it one-off

```
sudo systemctl start hnx-<id>-scan.service          # the full scan, as the timer would
journalctl -u hnx-<id>-scan.service -n 50            # one line: "prowler <ver>: N failed / M passed / K muted of T checks"
sudo head -n1 /var/log/prowler-findings.json        # the summary line
sudo cat /var/lib/hnx-modules/<id>/state/last-run.json
```

A single region while testing: set `prowler_regions: [eu-west-1]` for the run, then put it back; a
scanner that looks at one region is the blind spot the default avoids.

## Lifecycle hooks

`main` (install), `validate` (inputs, mutelist entries), `readiness` (systemd, a virtualenv-capable Python,
the credential in its form; nothing written), `health` (files, the credential file is 0600 root, the pinned
version, the timer armed, the last scan succeeded within `prowler_scan_max_age_h` and the findings file is no
older, no deferred mutelist entry past its review month), `backup`, `restore` (the findings file from an
export, checked to be a scan's), `upgrade` (raise `prowler_version` and converge), `export`.

## Data and retention

Local state is small: `state/last-run.json`, the scanner's last report under `output/` (replaced every run,
it enumerates the account, so the directory is 0750) and exports under `export/<stamp>/` (JSON). The
findings file is replaced weekly; **the lake is the retained history** (the compliance table's own
retention). The state dataset is exported before a removal; the virtualenv, the data root and the findings
file are kept on remove for the operator to archive. The account is never touched, so revoking the
credential there is the operator's.

## Host precondition

Python 3 with `venv` and `ensurepip` (on Debian, the `python3-venv` package) and systemd. The readiness hook
proves both and says what to install; no module provides them.
