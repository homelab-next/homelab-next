<!-- SPDX-License-Identifier: Apache-2.0 -->
# wazuh: the SIEM provider

Fills the `siem-source` and `hot-index` slots (both provisional: neither has a contract yet) with
the Wazuh manager, its indexer and its dashboard, as three `compose_app` containers in the module's
slice on one guest (ADR-0049 decision 2, ADR-0027). The manager receives the agents' events and
runs the rules; the indexer holds the hot index (30 days); the dashboard reads both. Real values
(the guest, names, secrets, rules) are the site's: the overlay's `lab/modules.yml`,
`lab/services.yml`, group variables and secret store. **This page is also the API contract the
agent control, the log pipeline and the alert intake build against.**

## The contract (what other modules rely on)

All ports are published on the guest's own address (`wazuh_bind`, never all interfaces); the
hypervisor's per-VM firewall is the control that decides who reaches them.

| What | Port | Protocol | Who | Notes |
|---|---|---|---|---|
| Agent events | 1514 | tcp | agents, sensors' agents | the registry row `siem-source` (host and port); the siem-agent control resolves the manager by the instance's logical id |
| Agent enrolment | 1515 | tcp (TLS) | agents, once | refused without the **enrolment password** (below); the siem-agent control passes it to `agent-auth` |
| Manager API | 55000 | https | the dashboard, health, census | account `wazuh-wui`, password `secret:wazuh/api-password`; a token from `POST /security/user/authenticate` |
| Indexer API | 9200 | https | the manager, the dashboard, the export; the `hot-index` slot (no row of its own: the module is one instance for both slots) | account `admin`; the certificate is from the module's private CA and names the guest's address |
| Dashboard | 5601 | http | the edge only | no TLS of its own: the edge terminates it and signs people in (below) |
| Syslog input | 5514 | udp | the log pipeline on the guest | only when `wazuh_syslog_allowed_ips` is set; the manager sees the sender as one of those addresses |

**Enrolment endpoint.** An agent enrols with `agent-auth -m <manager host> -p 1515 -P <password>`
(the `wazuh_agent` role does this). The password is the secret `secret:wazuh/enrollment-password`
(the role default `wazuh_agent_enrollment_ref` of the `siem-agent` control points at the same
name in the module's own namespace). A request without it is answered `Invalid password` and no
agent is created. Re-enrolment after the manager lost its keys is a deadlock the old lab recorded
(LL-113): the module's restore brings the keys back (`manager-state.tar`), so restore before
re-enrolling anyone. Agents of this release (4.14.9) and older may connect; a newer agent may not.

**Secrets (by name; values are the site's, in OpenBao).** `secret:wazuh/enrollment-password`
(consumers: every agent), `secret:wazuh/indexer-admin-password`, `secret:wazuh/dashboard-password`,
`secret:wazuh/api-password`, and, only with the alert integration on,
`secret:wazuh/alert-forwarder-auth` (the whole `Authorization` header value). Forms are enforced
before any container sees them: 16 to 64 of `A-Z a-z 0-9 . _ ~ -`, all different; the API
password also needs a lower, an upper, a digit and one of `. ~ -` (the manager API's policy).

**The streams (for the log pipeline on the same guest).** The manager writes JSON, one object per
line, under the data root (`/var/lib/hnx-modules/wazuh` by default):

| File | Content |
|---|---|
| `manager/logs/alerts/alerts.json` | every alert (level 3 and up): `timestamp`, `rule` {`id`, `level`, `description`, `groups`, `mitre`}, `agent`, `manager`, `id`, `full_log`, `decoder`, `data`, `location` |
| `manager/logs/archives/archives.json` | every event the manager received, decoded or not (`logall_json`); large, rotated daily |

Both are rotated daily by the manager and compressed under `manager/logs/{alerts,archives}/<year>/<month>/`;
the manager keeps `wazuh_logs_keep_days` (14) days of them. The files belong to the manager's service
group, **gid 999** (`wazuh_manager_gid`), mode 0640: a reader joins that group (`group_add: [999]`)
and mounts `manager/logs` read-only. A reader never writes there, and follows the file across the
daily rotation (a tail by inode, not by name). Nothing under `manager/` is a place to put a file: the
product's own init owns it.

**The syslog input.** Set `wazuh_syslog_allowed_ips` and the manager listens for syslog on UDP 5514 of
the guest's address (container port 514). The log pipeline forwards the router's and the appliances'
syslog to it after it has set the labels (ADR-0049 decision 3), so the product's decoders and rules
keep working on them. The allowed addresses are the sender as the manager sees it (the pipeline's
container network); the control that decides who may send is the guest's firewall, which admits no
one else to this port.

### The alert webhook

**Target: the alert-intake module** (`POST /v1/alerts` on its port, 8480 by default; its README is the
other half of this contract). Set `wazuh_alert_forward_url` to `http://<intake host>:8480/v1/alerts`
(the overlay's value). The intake authenticates the caller with `Authorization: Bearer <webhook
token>`: this module's `secret:wazuh/alert-forwarder-auth` must hold exactly `Bearer ` followed by the
value of the intake's webhook-token secret (the overlay seeds both from one value). The intake pins the
`source` per sender: `wazuh_alert_source` (default `svc:<instance id>`, `svc:siem`) must equal the
intake's `alert_intake_allowed_source`, or every post is answered 403 (permanent: the integration drops
it and logs it). Answers: 202 handled (the intake dedups on detection plus entities and is idempotent
per event id); 400/403/409 permanent; 401 or 5xx (502: the case store or notifier failed) are held in the
outbox and the same event id is retried.


With `wazuh_alert_forward_url` set, the manager's integration `custom-hnx-alert` posts each alert at
or above `wazuh_alert_forward_level` (default 12) to that URL as **one CloudEvents event, type
`homelabnext.alert.created` 1.2** (ADR-0009; `schemas/events/alert.created.schema.json`):

```
POST <wazuh_alert_forward_url>
Content-Type: application/cloudevents+json
Idempotency-Key: evt-<32 hex>
Authorization: <the whole value of the forwarder-auth secret>

{
  "specversion": "1.0",
  "id": "evt-<first 32 hex of sha256 of [type, source, "", alert_id]>",   (homelabnext.events.derive_event_id)
  "source": "svc:<instance id>",                       (wazuh_alert_source)
  "type": "homelabnext.alert.created",
  "time": "2026-11-22T10:00:00Z",
  "severity": "high",                                  (info | low | medium | high | critical)
  "datacontenttype": "application/json",
  "dataschema": "https://schemas.example.internal/homelabnext/events/alert.created/1.2",
  "tlp": "red",                                        (the source's declaration, wazuh_alert_tlp; never taken from the event)
  "data": {
    "alert_id": "1700000000.123456",                   (the manager's alert id)
    "detection": "det:ssh-offbaseline",                (wazuh_detection_ids[rule number], else det:wazuh-rule-<number>)
    "title": "<the rule's description, 200 characters at most>",
    "severity": "high",
    "observed_at": "2026-11-22T10:00:00.000+00:00",
    "entities": [{"kind": "host", "value": "hnx-agents-01"}, {"kind": "ip", "value": "<address>"}]
  }
}
```

The level maps to the severity as 15 critical, 12 to 14 high, 8 to 11 medium, 5 to 7 low, below that
info. `entities` come from the agent name (host), the decoded source and destination addresses (ip), the
source and destination users (user), the DNS query (domain), the file's SHA-256 (hash) and the process
image (process), at most 50. The event id is a pure function of the source and the alert id, so a
redelivery is the same event and the forwarder answers *duplicate*. A response of 200, 201, 202 or 204
is delivery; 401, 403, 404, 408, 421, 425, 429, any 5xx and a 3xx (redirects are never followed) keep
the event in the manager's outbox (`manager/logs/hnx-alert-outbox/`, at most 500, flushed in order at
the next alert); any other 4xx is permanent and dropped with a line in the integration log. **Only
this module's bus user may publish `alert.>`** (ADR-0049 decision 5): the forwarder authenticates the
caller with the header above, and `alert-intake` also refuses an event whose `source` is not this
instance's. The canary rule's alerts carry `det:` canary ids; the intake closes those itself and
they never page.

## Native rules

ADR-0006 decision 4 and ADR-0049 decision 2: a detection is Sigma unless Sigma cannot carry it, and a
native rule states why. The reason is one of `engine-correlation` (frequency, timeframe, same-field or
parent-rule chains), `decoder` (it reads a field only the engine's own decoder produces),
`list-lookup` (an engine-side list) or `stock-override` (it changes the level of, or silences, a rule
the product ships: the riskiest class, human-approve). The public lint
`python -m homelabnext.detections lint --native` enforces the format; the engine run
`python -m homelabnext.detections run --native` sends every fixture through the manager's own rule
tester (`PUT /logtest`) and fails on a missed must-fire or a fired must-not-fire (`docs/detections.md`,
"Native rules").

The role loads a site's native files from `wazuh_native_dir` (a directory on the controller with
`rules/*.xml` and `decoders/*.xml`): each is installed as `hnx-<name>.xml` into the manager's
`etc/rules` or `etc/decoders`. Only `hnx-*.xml` files are ever written or removed; the product's own
files and `local_rules.xml` are not touched. **The native range is 100000 to 119999** (the product's
own range for a site's custom rules); the Sigma bundle's numbers are 900000 and up. A load is safe by construction
(checklist D-03): the manager's configuration test (`wazuh-analysisd -t`) runs in the container before
the restart, the daemons' liveness is checked after it, and a failure of either puts the previous set
back and restarts it. The role restarts the manager's daemons once per run, only when something
changed (the rule set, the integration, the internal options). Things the old lab learned and the role
keeps: a rule change needs a restart (the configuration test alone is not enough); a `<location>` with
regular-expression characters needs `type="pcre2"` (an element without it loads clean and never
matches); a custom field name must be prefixed; the log collector drops lines over 64 KiB; the
configuration must not reset `logall_json`.

## The Sigma lane

The site's Sigma rules (ADR-0006; `docs/detections.md`, "The Sigma lane on the engine") reach the
manager through `wazuh_sigma_roots`: detection roots on the controller, each with `sigma/`, its
fixtures, `engine_fixtures/`, `det_map.yml` and `mappings/wazuh.yml`, whose `logsources:` bindings
name, per Sigma logsource, the engine base its rules chain from and the decoder's field names. On
every run the role, on the controller and with the controller's `hnx` (`wazuh_hnx_cli`), lints each
root, runs its fixtures (the reference evaluator and the compiled form), checks its det map, and
compiles its bundle; any failure, including a rule the bindings cannot carry, stops the deploy before
the manager sees anything. The bundle is installed as `hnx-zz-sigma-<n>.xml`, which sorts after
every native file, so a rule's parent (a native base such as the sensors' HTTP classifier) is
always loaded first, and it goes through the same configuration test, liveness check and rollback.
A rule marked `hnx_source: awaiting-source` is compiled (a port the engine cannot take shows now)
but not shipped. The site's `wazuh_detection_ids` carries the det map's numbers too, so an alert
from a Sigma rule reaches the alert webhook under its `det:` id. After the load,
`python -m homelabnext.detections run --engine` sends each deployed rule's engine fixtures (raw
lines) through `PUT /logtest` and fails on a miss, a false positive, or a deployed rule with none.

`wazuh_json_decoder_excluded` (default false) makes the manager skip the product's generic JSON decoder file
(`0006-json_decoders.xml`). A site whose JSON logs (the Zeek sensors') have their own decoders needs it: otherwise the generic
decoder claims every line that starts with `{`, answers rule 1002, and no rule keyed on the site's decoder fires. The file also
holds the `json` and `json-msgraph` decoders other stock rules rely on, so the site ships identical replacements in its native
decoders (the overlay's `zeek-zjson-*.xml`). The exclusion is rendered only once the manager holds a native decoder that
defines `<decoder name="json">`: on a first install the stack starts without it, the site's decoders are installed once the
manager answers, and the role then renders the exclusion and restarts the manager once (a second run changes nothing). A
site that asks for the exclusion and ships no such decoder is refused.

`wazuh/rule-drift` compares the digest of what the manager has loaded
(`hnx_wazuh_rules.py digest --etc`) with the digest of what the site wants (`--stage`): the health
hook runs both and refuses a difference.

## The manager acts on no host

Active response is off in the manager's configuration (`<active-response><disabled>yes`), the
manager's own host-monitoring modules (file integrity, rootcheck, configuration assessment,
vulnerability detection) are off (the guest has its own agent), and the internal options carry
`logcollector.remote_commands=0` and `wazuh_command.remote_commands=0`. The agent role sets the same
on every agent. A response that changes a host is a `remote-admin` broker action behind approval
(ADR-0017, ADR-0030). A role test asserts these settings.

## TLS

The stack's internal TLS (indexer HTTP and transport, the security plugin's administrator client
certificate, the manager's client certificate for the indexer) comes from a private CA the role
generates once under `certs/` of the data root: create-only, so a re-run (and a restore) never
rotates it; the CA's key stays root's and is mounted into no container. The indexer's certificate
carries `indexer`, `localhost` and the names in `wazuh_indexer_cert_names` (the guest's address by
default), so a consumer of the `hot-index` row verifies it against `certs/root-ca.pem`; it is
reissued, under the same CA, when those names change. The manager's API has the product's own
self-signed certificate (the health hook verifies it against itself).

## Dashboard

Plain http on the guest at `wazuh_dashboard_port` (5601), **reached through the edge only**: the
site publishes it with an edge route (forward-auth through the identity provider) and the guest's
firewall admits the edge host alone on that port. The dashboard signs people in against the indexer's
accounts (`admin`, `kibanaserver`); the product's demo accounts and their published passwords are not
created.

## Data and the hot index

Under the data root: `manager/` (the manager's state, owned by the product's init), `indexer/` (the hot
index), `certs/`, `config/` (what the role renders; the staged native files) and `export/` (0700).
The indexer's heap is `wazuh_indexer_heap` (8g by default, half its container's limit; the product's 1
GiB default starved it on a big host: LL-155) and the guest needs `vm.max_map_count` of 262144 (the
readiness hook refuses to go on without it). The role installs an index-lifecycle policy that deletes
an alerts or archives index after `wazuh_index_retention_days` (30): the lake holds the history, and
an indexer disk that fills is the failure this prevents.

## Health

The health hook proves: the three containers are running and healthy; **every manager daemon is a live
process** (the product's own status command reads pid files and reports a daemon that died hours
ago as running, LL-105: it is never asked); the enrolment service answers a wrong
password with `Invalid password`; the manager's API accepts its account; the indexer refuses a caller
with no account, answers the administrator and is not red; the dashboard serves its sign-in page; and
the loaded rules are the site's. The compose healthchecks are the same real-process checks.

The manager's alert stream is also checked: `alerts/alerts.json` must have been written within
`wazuh_alerts_max_age_seconds` (default 900; the stream advances many times a minute, so quarter of an hour of
silence is an outage), so a manager that is up with nothing running fails health.

## Pid files

The manager's pid files (`/var/ossec/var/run`) are a **tmpfs**: they live in RAM and are empty at every container
start. On a hard reset the container's writable layer kept the old files; the product's start reads a pid file,
finds the recycled pid alive and skips that daemon ("Process N not used by Wazuh, removing..."), so the
container came back with no daemon running and nothing alerted (2026-11-25, 45 minutes blind). Nothing other than
`*.pid` and `*.state` files ever lives there.

## Liveness and the stale-stream alert

A timer (`hnx-wazuh-liveness.timer`, every minute, role task `liveness.yml`) runs `hnx_wazuh_liveness.py`, which
writes `siem_manager.prom` into `wazuh_textfile_dir` (default `/var/lib/homelabnext-textfile`; empty turns the
timer off): `siem_manager_daemon_up{daemon}`, `siem_manager_daemons_running`/`_expected`,
`siem_alerts_file_age_seconds`, `siem_alerts_file_present` and `siem_manager_check_timestamp_seconds`. The host's
node exporter must serve that directory (the overlay's `node_exporter_textfile_dir`). The monitoring module's
rules page on `SiemManagerDaemonsDown` (a daemon missing for 5 minutes), `SiemAlertStreamStale` (no write for 15
minutes, 5 minutes sustained) and `SiemLivenessCheckStale` (the writer itself stopped).

## Export and restore

`export` writes `export/{manager-state.tar, index/<name>.jsonl, version.txt, listing.jsonl}` (key,
size, sha256): the manager's state (the agents' keys, the rule files, the agent database) and the hot
index in a neutral format through the indexer's API. `restore` (`wazuh_restore_source`) checks the
listing, the sizes and the hashes and refuses a source taken from a newer product than the pinned one
before anything is written; takes a `pre-restore-*` safety export; unpacks the state with the manager
and the dashboard stopped; converges; and loads the index back by document id (a second run changes
nothing). The CA and the certificates are not part of an export. The export directory holds the agents'
keys: 0700.

## Placement and what the overlay adds

One host role, `server`: 8 vCPU, 24 GiB, 300 GB at least (the module's footprint; the lab's guest is
12 vCPU, 32 GiB, 400 GB). The overlay adds: the module row in `lab/modules.yml` (one instance for both slots) and the registry
row as bound in `lab/services.yml`; the guest's firewall (1514/1515 from the agents' subnets, the
dashboard from the edge host only, 5514 from the pipeline's host only, the two APIs from the named
consumers); the guest's sysctl (`vm.max_map_count`); the five secrets; the edge route for the
dashboard; and group variables (`wazuh_logical_id`, `wazuh_syslog_allowed_ips`, `wazuh_native_dir`,
`wazuh_detection_ids`, `wazuh_alert_forward_url`, the images when the pin moves).

## Upgrade, removal

`upgrade` validates a pinned bump of one image (same repository, not older than the running one) and
records it; the playbook exports first, then converges. The three images are one release: set all
three in the overlay. `remove` exports first, stops and removes the containers and deletes the
env_files; the data root and the export stay for the operator.
