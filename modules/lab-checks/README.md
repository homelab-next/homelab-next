<!-- SPDX-License-Identifier: Apache-2.0 -->
# lab-checks: the lab's continuous checks

A feature module that answers one question every hour: **do the lab's invariants still hold?** It runs the
site's invariants register with `hnx invariants run` from a systemd timer, keeps each criterion's last status,
and **pages the operators once when a criterion turns newly red** (and once when it recovers), through the
notify slot. A standing red is never re-paged; a page that could not be delivered is retried next run
([ADR-0049](../../docs/adr/0049-the-soc-data-plane-and-the-lab-checks-move-as-modules.md) decision 7, the runner's
`page_changes`).

The register is the **site's** (the overlay's `lab/registers/invariants.yml`: real names, owners, thresholds). The
module ships the mechanism and the read-only probes the criteria are written with.

## What it installs (host role `runner`)

| Path | What |
|---|---|
| `<bin dir>/hnx-lab-probe` | probes: `http`, `tcp`, `dns`, `prom`, `lastrun`; exit 0 pass, 1 fail, 100 could not measure |
| `<bin dir>/hnx-lab-notify` | the pager (`--notify-cmd` of the runner): one POST to the notify topic with the token from an owner-only file |
| `<config dir>/invariants.yml` | the register, validated on the host before it replaces the live one |
| `<config dir>/credentials/notify-token` | the publish token, 0400 |
| `<config dir>/ca.pem` | optional (`lab_checks_ca_ref`): the lab CA the probes pass as `--ca` to verify internal TLS services |
| `hnx-<id>.service` / `.timer` | one run of the register, hourly on a calendar (`*-*-* *:07:00 UTC`), never an interval |
| `<data root>/results/<id>.hourly.json`, `state/<id>.hourly.json` | the results document and the paging state (derived) |

The unit runs as root with **one capability** (`CAP_DAC_READ_SEARCH`, so a criterion can read a lane's run records
that an unprivileged account owns), a read-only system, no new privileges and writes only to its results and state.
The runner exits 1 when a criterion is red and 100 when one could not be measured; the unit accepts both
(`SuccessExitStatus=1 100`), because the page is the signal.

## Using it in a site

1. Select it in `lab/modules.yml`: `hosts: {<guest>: ...}` and a placement of its `runner` role on a guest that
   carries `hnx` (`/opt/hnx/bin/hnx`, installed by the module that runs it there).
2. Write the register (the central register schema, `docs/registers.md`): a pillar for the lab, and one criterion per
   observable, each `evidence: auto` with an `observable` that is a command, an `expected` text, a `remediation` and an
   `owner` (the module or area that owns the check). Use the probes:

   ```yaml
   - id: N-01
     owner: metrics
     statement: Every metrics target answers its scrape.
     evidence: auto
     observable: hnx-lab-probe prom "$METRICS_URL" 'count(up == 0)' --eq 0 --empty zero
     expected: no target is down
     remediation: find the target (`up == 0` in the metrics UI) and restart or fix it
   ```
3. Seed `secret:lab-checks/notify-token` (a copy of the notify provider's publisher token) and set the group
   variables `lab_checks_logical_id`, `lab_checks_register_src` (and `lab_checks_notify_allow_plain_http` for a LAN
   endpoint with no TLS).
4. Run the install twice (the second `changed=0`), then the hooks.

**Letting another module read the results (opt-in).** By default the results document is root's alone (0600).
`lab_checks_results_group: <group>` makes the role create that system group and the results directory
`root:<group> 02750`, so the document is `root:<group> 0640` (the unit's umask becomes 0027; a document an earlier run
wrote is set by the role). Nothing else of the module is shared: the state, the credentials and the configuration keep
their owner. The workflow engine's lookup steps use it: mount `<data root>/results` into its action runner with that
group (the automation module's `stackstorm_table_mounts`, docs/stackstorm.md, "Tables").

## Proving it pages

Add a criterion whose observable fails (for example `exit 1`), run `systemctl start hnx-<id>.service`: one page
arrives. Start it again: no page (a standing red). Make it pass and start it: one "recovered" page. Remove the
criterion. This is the module's positive control; the same sequence is in `tests/modules/test_lab_checks_scripts.py`
against the runner itself.

## Hooks

* **readiness**: systemd, `hnx` and the register are present, the token has its form.
* **health**: the files are in place, the timer is armed and the last results document is younger than
  `lab_checks_results_max_age_s`. A red criterion is **not** unhealthy: that is the page's job. A checker that
  stopped running is the failure nobody is paged for, which is what health catches.

## Not here

* The criteria of the SOC data plane (source census, manager errors) arrive with the modules that own them
  (ADR-0049 decision 8). Until then a criterion is written in the site's register with the probes above.
* The generated `checks/<module>.yml` playbooks (every module's readiness and health hooks) are an operator-side
  gate that needs the deploy host's secrets; they are not run from this unit.
