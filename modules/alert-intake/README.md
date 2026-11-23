<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `alert-intake`: the SIEM's alerts into the case store

A feature module ([module manifest](../../docs/modules.md), draft; ADR-0049 decision 5 names it
`alert-intake`). It replaces the old SOAR flow (SIEM alert at a level, to the SOAR product, to the case
store and a page). The SIEM's integration posts each alert it raises as one `homelabnext.alert.created`
event; this service validates it, records an **alert** (never a case, unless the site's policy says so)
through the `cases` contract, and pages for a new high-severity one.

| | |
|---|---|
| Needs | `cap:case-management` (provisional), `cap:notify`, `cap:secrets` |
| Host role | `server`: kind `vm`, baseline `base`, 1 vCPU, 512 MB. Place it where the SIEM, the case store and the notifier all answer |
| Role | `alert_intake`: a stdlib script and one systemd service. No container, no runtime release |
| Config secrets | the webhook token, the case store's key and CA, the notification token (names in `module.yml`) |
| Egress | none declared: the case store and the notifier are slots the module requires |

## The webhook

`POST /v1/alerts` on `alert_intake_listen_address:alert_intake_port`, `Authorization: Bearer <token>`,
body one `homelabnext.alert.created` 1.2 event (CloudEvents structured JSON, `schemas/events/alert.created`).
`GET /healthz` answers `{"status":"ok"}` with no credential.

| Answer | Meaning |
|---|---|
| 202 | handled: `{alert, count, paged, case, duplicate}` |
| 400 | malformed (the schema's checks, spelled out in the script) |
| 401 | missing or wrong token |
| 403 | the event's `source` is not `alert_intake_allowed_source` (the SIEM's): only the SIEM may raise an alert |
| 409 | this event id was handled with a different body |
| 413 | body over 256 KiB |
| 502 | the case store or the notifier failed: **retry the same event**; progress is kept, so nothing is double-counted or re-paged |

## What it does with an event

1. **Idempotent by event id** (the shared state store, newest 5000; a corrupt file stops the service rather than starting empty): a redelivery is answered from the state and runs nothing.
2. **Dedup key** = `detection` plus the sorted `entities` (ADR-0049); `create_alert(..., dedup_key=)` collapses a
   repeat into the open alert's `count` (the contract's rule, done by the case store). A repeat never pages.
3. **Promotion** only if `alert_intake_promote_min` names a severity (default empty: alerts, not cases).
4. **Paging**: a NEW alert (count 1) at or above `alert_intake_page_min` (default `high`; the old lab paged only
   its top tier, so a SIEM level mapped below `high` never pages) is sent once to `alert_intake_notify_url`
   (the shared notification sender: bearer token, no redirect, topic `alert_intake_notify_topic`). `info` is recorded as `low`.
5. **Canary**: a detection id under `alert_intake_canary_prefix` (default `det:canary`) is recorded, dismissed with the
   reason `canary` and never pages (ADR-0049's E-01 canary starts here; the daily criterion is the SIEM
   module's to schedule).

## The adapter is the site's

The service names no product. `alert_intake_cases_adapter` (`module:factory`) is the case store's `cases` adapter and
`alert_intake_adapter_file` its one source file on the control host (the module is the file's basename), which the
role copies to the guest beside the contract file (`conformance/protocols/cases.py`, vendored in
`files/cases_contract.txt`; a test keeps it equal to the repo's). The service also imports the shared libraries `homelabnext.notify` and `homelabnext.state` (a fixed set of 12 files the role copies from
`alert_intake_homelabnext_dir`; a test computes the set from the script's real imports). The adapter must use only the standard library
and that contract file; the repository's `homelabnext/conform/adapters/cases_iris.py` is such an adapter (DFIR-IRIS
2.4.29, passing the `cases` suite with `--strict`: `hnx conform run cases --strict --target cases-iris`).
The role writes its settings
(`base_url`, `credential` as a secret reference, `ca_file`, plus `alert_intake_cases_settings`) to `cases.json`
and the key itself to a root-only environment file under the variable the reference names.

## What the overlay adds

- the guest and the `server` placement; the instance; the group variables `alert_intake_logical_id`,
  `alert_intake_listen_address`, `alert_intake_allowed_source`, `alert_intake_cases_adapter`,
  `alert_intake_adapter_file`, `alert_intake_homelabnext_dir`, `alert_intake_cases_url`, `alert_intake_notify_url`,
  `alert_intake_notify_topic` (and `alert_intake_notify_plaintext: true` for a notifier reached over plain http);
- firewall rules: the webhook port from the SIEM only; the case store's port and the notifier's out;
- the four secrets in the secret store (webhook token, case store key and CA, notification token); the case store
  key may be the provider's own, by the overlay's grant;
- the SIEM's integration: its URL and token (the SIEM module's README has the contract it posts).

## Install, health, backup

`ansible-playbook -i <inventory with --selection> modules/alert-intake/playbooks/install.yml`, or the apply path.
`health` proves the files, the unit, `/healthz` and that the webhook refuses a call with no token; it does not call
the case store or the notifier. `export` writes `state.json` (the per-event progress) under `export/<stamp>/`;
`restore` replaces the live state from one (the form is checked first). The alerts are the case store's data.
