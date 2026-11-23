<!-- SPDX-License-Identifier: Apache-2.0 -->
# source-census

The daily check that **every log source is still arriving**, judged by its own cadence, and that the
lake is **not dark**. It replaces the old lab's daily ingest audit (ADR-0049 decisions 8 and 9; step 8
of the build order) as two generic criteria over the `lake-query` slot, plus the burst clusterer that
the SIEM module's `manager-errors` criterion calls. It is a feature module: it names slots, never a
product, and holds no copy of any event (it reads counts and hours only).

## What it does

| Criterion | Question | Fails when |
|---|---|---|
| `source-census/sources-flowing` | Is every source of the raw-archive table arriving within a multiple of its own learned cadence? | a source is silent past `multiple` x its cadence (`STALE`), a declared source never arrived (`MISSING`), or a learning source that arrived 3 times is silent past the floor (`LEARNING-STALE`), and no unexpired acknowledgement covers it. Nothing at all arriving also fails. |
| `source-census/all-classes-dark` | Did any event of any class arrive in the window? | none of the configured tables has one row in the last 24 hours. It never learns: an empty young lake is dark. |

`hnx lake source-census` runs both. The daily unit (`source-census-run`, 07:15 UTC) runs it with
the settings file the role writes and pages through the `notify` slot; the criteria's observable runs
it with `--no-notify`, so an ad-hoc run never pages and never touches the paging state.

### How a source's cadence is learned

The census groups the table by its **source columns** (default `location`, `decoder_name`) and the UTC hour
over the window (`window_days`, default **8**): one query through the portable SQL subset plus the
hour bucket of `homelabnext/lake/dialect.py`. For each source it takes the gaps between the hours it
arrived in; its cadence is the 90th-percentile gap (at least 1 hour). A source is flagged when its
silence exceeds `multiple` (default 3) x cadence **and** `min_silence_hours` (default 2). A weekly
scan is not stale on Tuesday; an hourly source is stale after ten hours. A source seen in fewer than
two hours has no cadence: it is judged against the floor.

**Declared sources** (`expected`) are the old audit's per-source table, as data: a `match` on the
source columns (a text, or a mapping of `equals`, `prefix`, `suffix`, `contains`), a `cadence_hours`
and a `grace`. They never learn, and a declared source that never arrived is `MISSING`. Match on what a
producer's restructuring preserves (a file name and a path fragment), not one exact path: the old
audit read `STALE` for days each time a producer moved its directory while the data kept flowing.

### The learning window (it is visible, and it has a floor)

A source whose first arrival is later than the window start (plus one cadence) has less history than
the window: it is `LEARNING`. A learning source **passes** and the criterion reads **`WARN`** with the
source named in the evidence, so a young lake is visible, not silently green. But while learning, a
source that has arrived at least 3 times (`learning_min_arrivals`) and is then silent past an absolute
floor (`floor_hours`, 24 by default, overlay-settable) **fails** (`LEARNING-STALE`), so the cutover
period is not blind. `all-classes-dark` never learns.

### Acknowledged-quiet

`acknowledged` is a list of `{name | match, owner, reason, expires}`. A source that would fail and is
covered by an unexpired entry reads `ACKNOWLEDGED` and passes, with the owner and expiry in the
evidence. An expired entry covers nothing: the source fails again and the evidence says the
acknowledgement expired. An entry without an owner or a reason, or one naming a source nobody
declared, is refused when the settings load.

## Paging (state-diffed, never a standing set twice)

The run compares the set of flagged items (a source, or the dark state) with the last run's. A message
goes out only when the set **gains** a member (the body marks the new ones), one more when it
empties, and a standing set is never sent again. State is saved after a successful send, so a failed
page is retried the next run (exit 100 on a send failure: an undelivered verdict is never a pass).
The titles are constant and carry no counts (`Source census: source(s) flagged` / `Source census:
all sources flowing`; the pair is the module's `notify_pairs`); the counts are in the body. A page
carries source names, which are lab data, so it goes through the channel's declared TLP ceiling
(`notify_ceiling`, red by default); below red it arrives as the fixed withheld notice.

## The burst clusterer and the manager-errors criterion input

`hnx logbursts` (`homelabnext/logbursts.py`) clusters error lines in time into bursts (a gap over 10
minutes starts a new one), collapses each burst to its distinct message shapes (numbers, addresses and
long hex ids masked, one real example kept per shape), and gives a verdict:

* **ONGOING (needs attention)**: the last line is no older than the quiet period (120 minutes), or a
  shape came back on 3 or more distinct UTC days in the lookback (a fault that recurs daily is one
  standing fault, not three recoveries). Exit 1.
* **RECOVERED (no action)**: lines, all stopped, nothing recurs. Exit 0.
* **CLEAN**: no line. Exit 0. A log that cannot be read is exit 100 (could not measure).

Fifteen errors inside one 38-second network blip, 14 hours ago, read `RECOVERED`; a
`Agent key already in use` storm across eight agents within seconds is one shape (a reconnection storm
after a restart, not cloned keys), `RECOVERED` once it stops. Both are fixtures
(`tests/logbursts/fixtures/`).

`data/manager-benign.yml` is the old audit's filter list as reviewed data: each entry is `{match,
reason}`, a literal substring, with `{names}` for site values (`--var scanner_address=...`: the address of
the site's own scanner is the site's). A list that cannot be read, an entry without a reason, a
duplicate, a match under 8 characters or a missing variable is refused whole: a list that cannot be
read is never one that hides nothing. The list only grows by a reviewed change
(`tests/logbursts/test_benign_ratchet.py` pins its length).

The criterion itself, `wazuh/manager-errors`, belongs to the SIEM module (a criterion's id starts with
its owner's id). This module ships what it calls. The SIEM module's criteria file declares:

```yaml
- id: wazuh/manager-errors
  evidence: auto
  observable: /opt/hnx/bin/hnx logbursts --log <manager log> --log <rotated logs> --benign <benign list> --var scanner_address=<site value>
```

with the manager log (24 hours verdict window, 7 days lookback for recurrence) as its input.

## What the overlay adds

* A guest for the `checker` host role with the runtime release (`hnx_runtime`) applied, in the site's
  `modules.yml` selection, plus `config.lake_domain`, `lake_warehouse` and `lake_catalog` (and, if they differ from
  `soc` and `raw_archive`, `lake_namespace` and `census_table`).
* The reader `analyzer:source-census` in the site's `tlp_readers`: it reads **red** (it counts every
  source), and its login in the engine's password file. A reader may read the census table only.
* Secrets, created by the seeding, never changed by it: `secret:source-census/reader-password` and
  `secret:source-census/notify-token`.
* The notify channel's declared ceiling (`config.notify_ceiling`), the acknowledged-quiet list, the
  declared sources (`source_census_expected`) and the site's values for the benign list.
* Nothing for the cron: the unit is the module's `scheduler_jobs`, rendered by the fleet scheduler.

## Interface assumptions (agreed with the log-pipeline modules)

The census reads one table: `soc.raw_archive` by default (the `soc` namespace is fresh and new, never
a migrated one), with a UTC `time` timestamp column and the source columns `location` and `decoder_name`
(the decoded format of the line). The lake writer's raw-archive table owns those names (its schema is checked by a test); if it names
them otherwise, only `census_table`, `source_columns` and `time_column` change. Nothing else is
assumed of it.

## Hooks

`health` (settings and 0600 credential files present, the command answers), `readiness` (the runtime
release carries the census; every credential is set), `backup` (the paging state; credentials are not
listed), `export`/`restore` (the state with its sha256; restore never over a flagged set), `upgrade`
(proves the installed release answers the census command and records it: there is no version of its own
to bump).
