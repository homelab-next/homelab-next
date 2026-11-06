---
summary: 'Module manifest reference: TLP labels on module data, model-role ceilings, labelled model requests and the ceilings of agent profiles and MCP servers.'
summary_of: outline:sha256:d3f95c56a1c68f08
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: TLP labels

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## TLP labels (ADR-0033)

Data is labelled with TLP 2.0 ([ADR-0033](../adr/0033-data-carries-tlp-every-reader-has-a-ceiling.md)):
`clear` < `green` < `amber` < `amber+strict` < `red`, and a reader with ceiling X receives labels at
or below X. `homelabnext.tlp` is the one implementation every component uses. `read()` is for a
label on data (a record, a sidecar, a stored row) and never raises: anything but an accepted
spelling, including a missing label, is `red`. `parse()` is for a declaration (a source's label, a
reader's ceiling) and raises on anything else, so an authored mistake is refused rather than
silently read as `red`. `strictest()` is the label of derived data (`red` when an input is
unreadable or there are none), and `allows(ceiling, label)` takes only a parsed ceiling. Accepted
spellings: the five labels, optionally `tlp:`-prefixed, in any ASCII case, with surrounding spaces,
tabs, CR and LF ignored; `white` is `clear`. A `Label` compares only with another `Label`, and a
`str` subclass is read through `str`'s own methods. The publishing sidecar's enum is held equal to `tlp.LABELS`.
`item_label(declared, item, honour_item_labels=...)` is the label of one item from a declared
source; datasets declare theirs under [`data:`](data.md#data-and-lifecycle-safety). The lake stores the
label per row: every core OCSF table has a `tlp` column from 1.1, a write without a canonical label
is refused, and `homelabnext.lake.tables.row_label` reads a stored row's label (`red` unless it
is one of the canonical spellings). The log pipeline tags each event from its source's declaration
(`homelabnext.logpipeline.tlp_labels`, the `hnx_tlp` label), and `hnx modules tlp-backfill`
(`homelabnext.lake.backfill`) writes the statements that label rows stored before the column;
running them, and loading the generated `lake-access.json` into the query engine, are the
operator's steps on a real lab. Readers read at their ceiling: the query
engine through the generated row filters ([`tlp_readers`](selection.md#site-selection-platformmodule_selection-10-a-draft-schema)),
and code in this repository through `homelabnext.lake.ceiling.CeilingReader`, which builds its own
filtered `SELECT` from a table, columns and equality filters, checks each row's label again, and
refuses raw SQL below `red` (raw SQL could alias a constant as `tlp`). `reader_for(lake, reader,
tlp_readers, schemas)` gives a consumer its reader at the ceiling its `tlp_readers` entry declares
and refuses a reader with none; a read at `red` always names a `RedGrant` (a `red` reader's comes
from its declaration's `why`; the swap and parity tools, which copy and compare every row, hold
their own and read through `raw_query`), and `tests/lake/test_lake_read_boundary.py` fails on a
module outside `homelabnext/lake/` that imports the lake library and calls a client's `query` or
`named` itself. The status hub's views and
exports declare their TLP ceilings, and its public view and exports serve only what its release
transforms keep ([status](../status.md#tlp-ceilings-and-release-transforms)). Model roles, model
requests, agent profiles and MCP servers carry their ceilings and labels (below).

### Engine sign-in

The engine's row filters are keyed on the session user, so they hold only when that user is
authenticated: a reader named by a bare `X-Trino-User` header would let any process that reaches
the port read as a `red` reader. Every reader therefore signs in to the engine with its own
password (the engine's password authenticator, one entry per reader in its password file).
`homelabnext.conform.adapters.lake.make_lake(..., credential=)` takes the reader's password as a
secret reference (`secret:<name>`, conventionally the secret `lake-query/readers/<login>`, delivered
in `HNX_SECRET_LAKE_QUERY_READERS_<LOGIN>`) and sends it as HTTP Basic on every request, with no
redirect followed and no proxy used (`catalog_credential=` does the same for the catalog's bearer
token, `ca_file=` names a private CA). A `lake-query` endpoint that is not loopback is refused
without a credential, with no override; only the loopback-bound lab-in-a-box runs without one.

HTTP Basic cannot carry a colon in the user part, so a reader signs in with its id's first `:`
written as `.` (`analyzer:novelty` signs in as `analyzer.novelty`;
`homelabnext.lake.trino_http.engine_login`), and the engine maps the login back to the reader id
with a user-mapping rules file (the engine's single-pattern setting keeps only the first group, so
it cannot rebuild the id): first the pattern `(profile|module|analyzer|user)\.(.+)`, user `$1:$2`,
so the session user `lake-access.json` names is the whole reader id, then the pattern `(.*)`,
user `$1`, so a login with no prefix stays itself (a login no rule matches is refused). The
conformance and swap-rehearsal runs sign in as such a login, `hnx-conform` by default (the
rehearsal's `--user`), with the secret `lake-query/readers/hnx-conform` (`--credential`). `hnx
novelty` signs in as `analyzer:novelty`.

Signing in is not enough on its own: the client still names its session user in a header, and a
signed-in reader that names another (a `red` reader) would get that reader's row filters. So
`lake-access.json` denies impersonation to everyone (`impersonation`: nobody may act as another
user), and the operator adds no rule that allows it. A credential goes over https only (except to
loopback), whatever `allow_plaintext` says. The catalog is a second way to the rows: one reachable
off loopback must require its token and hand storage credentials to the engine alone, or a reader
reads the data files and skips every filter (an operator step, `TODO.md` §4).

### Model-role ceilings (ADR-0033 decision 10)

Every model role has a TLP ceiling, `homelabnext.modules.rules.role_ceiling(roles, role)` (and
`role_ceilings(roles)` for the table). A role no prompt can leave the lab through is `red`. A role
whose prompts can leave it, as `cloud_roles` reads it (a binding marked `leaves_lab` on the role
or anywhere down its fallback chain, so a local primary with a cloud fallback counts), is `clear`.
The overlay raises it to `green` only by recording the provider's terms in the role table
(`platform/model_roles` 1.4): `provider_terms: {retention: none, training: none, ref: ...}` on
each `leaves_lab` binding, and `tlp_ceiling: green` on the role. Every role on the chain that
leaves the lab must be raised, and every `leaves_lab` binding on it must record the terms, since a
request may be served by any of them. `amber` and above are never a ceiling of a role that leaves
the lab.

The terms sit in the role table because they describe the provider behind one binding, which the
table already names (with `leaves_lab` beside it): a swap that rebinds a role to another provider
changes the binding the terms are on, and the swap gate reads both as a trust change of the role
(`bindings[].provider_terms`, `tlp_ceiling`), which needs a record naming it. The selection's
grants are per module, not per role or provider, so a ceiling there could differ by module for the
same prompt path. The whole role table is already human-approve in both review tiers
(`hnx modules review-tier`, `hnx site review-tier`), so raising a ceiling is too.

`rules.role_ceiling_problems(roles)` refuses, in the site rules and when the gateway config is
generated: a `tlp_ceiling` that is not `clear` or `green` in its canonical spelling; one on a role
that does not leave the lab (its ceiling is `red`); `green` without the terms on every
`leaves_lab` binding of the chain, or with a role down the chain that is not raised; and
`provider_terms` on a binding that does not leave the lab. The ceiling is in addition to
`grants.cloud_models`: a raised role still needs the grant.

### Model requests (ADR-0033 decision 11)

`homelabnext.registry.model_tlp.admit(roles, role, claimed, sender=...)` is the rule a request
meets: `claimed` is the caller's label of everything it assembled (left out when the request
carries none or `null`, which is `red`; a value that is not a label is `red` too), and `sender` the sending
profile's ceiling (`send_ceiling(tlp_ceiling, data_tier)`: its declared ceiling, else `clear` for
`cloud-allowed` and `red` for anything else). For a role that leaves the lab the request is judged
at the higher of the two; it is refused when above the role's ceiling, and a role the table does not
hold, or any role while the table has a malformed entry, is refused. The `Admission` it returns
carries `reason` (`within-ceiling`, `above-ceiling`, `unlabelled`, `unknown-role`,
`invalid-role-table`), a `message` and a `record()` the caller logs. Only the canonical
`tlp_ceiling: green` raises a role: another spelling (`TLP:GREEN`) is refused by validation and
raises nothing. Where it runs, and what
the gateway itself enforces, is in [the LLM gateway](../llm-gateway.md#tlp-labels-on-model-requests).

### Agent profiles and MCP servers (ADR-0033 decision 12)

`data_tier` is derived from a TLP value, not a second axis: `local-only` is above the cloud-role
ceiling (`clear`), `cloud-allowed` is at or below it. The ceiling policy attests a profile's
`tlp_ceiling` where it attests `data_tier` ([agent profiles](../agent.md#profile-compiler)), and an MCP
server record declares `tlp`, the label of what it returns ([MCP catalog](../mcp-catalog.md#a-record)).
Validation refuses an entry whose `data_tier` and TLP value disagree, and a profile is granted a
server only when the server's `tlp` is at or below the profile's ceiling. A record or entry that
states no TLP value is read from its `data_tier` (a server: `clear` for `cloud-allowed`, `red` for
`local-only`; a profile: it receives what its tier already let it receive and sends to a model at
`clear` only when `cloud-allowed`), and the catalog check and the policy say so in a note.
