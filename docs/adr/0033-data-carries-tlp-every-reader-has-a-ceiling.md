---
summary: Every source and record carries a TLP 2.0 label (unlabelled is red); derived data takes its strictest input; every view, export and model has a ceiling.
summary_of: outline:sha256:1d653fdecf0ac92a
---
# ADR-0033: Data carries a TLP label from its source; every reader has a ceiling

- **Status:** proposed
- **Date:** 2026-10-30
- **Related:** ADR-0001 (additive schemas), ADR-0011 (what is public) and ADR-0021 (public and
  private repositories), which classify code and configuration, not data; ADR-0022 (LLM gateway),
  ADR-0027 (modules), [modules](../modules.md) (the publishing gate, model roles `leaves_lab`),
  [status](../status.md) (the public view and the private tier)

## Context

The lab holds data with very different sharing terms in the same places: open feeds anyone may
republish, community feeds shared on terms, licensed API results that may not leave the
organisation, and the lab's own logs, inventory, findings and agent activity. Today that is
expressed in two unrelated ways:

- The **publishing gate** already speaks TLP 2.0. A producer's item carries a claimed TLP
  (`clear`, `green`, `amber`, `amber+strict`, `red`); the gate verifies the claim against the
  content and lets out only what its `tlp_allowed` permits (red and amber never pass).
- **Displays** use a binary split. The status hub has a public view and a private tier unlocked
  by the trusted front door; the links page marks a service `public` or `lab only`. Nothing says
  *which data* a view may show, only *who* may open it.

So a label exists only at the last step out of the lab, and nothing carries it from the source
through the lake, the SIEM, enrichment and model calls to that step. Two failures follow. A
display or a cloud model can be handed data whose terms forbid it, and nothing notices, because
the binary split cannot say "community-shareable but not public". And a derived item (a summary,
an enrichment, a rollup) has no label of its own, so the gate has to guess from the text.

The standard for this already exists and the lab's threat-intel sources already use it: TLP 2.0
(FIRST, 2022), carried as tags, sidecar fields or STIX markings.

## Decision

1. **The label set is TLP 2.0, exactly.** Five labels, ordered from least to most restrictive:
   `clear` < `green` < `amber` < `amber+strict` < `red`. No other label is defined. A value that is
   not one of these five is treated as `red` wherever it is read.
2. **The default is red.** Any source, record or stored row without a label is `red`. Data the lab
   generates about itself (logs, alerts, telemetry, inventory, configuration, findings, agent
   activity) is `red` unless its source declaration says otherwise. Lowering this default is a
   declaration a human reviews, never a fallback.
3. **Every source declares its label.** A module's data source declares `tlp`: the label of any
   item that arrives without one, taken from the provider's terms (a feed's licence, a licensed
   API's redistribution terms), never from the processing stage. An item that carries its own
   label from the source (a tag, a sidecar field, a STIX marking) keeps it when it is **stricter**
   than the declaration. It may be **looser** only when the source also declares
   `honour_item_labels: true`, a human-tier field, because that trusts the provider's labelling.
4. **Derived data takes its strictest input.** An enrichment, correlation, summary, rollup or model
   output is labelled the most restrictive label among everything that went into it, including
   the model prompt's context. An open item enriched from an open source stays as it was; the same
   item enriched with a licensed result takes that result's label. A label is never lowered
   automatically: a downgrade is an explicit, recorded human decision on one item or one source.
5. **Storage carries the label.** Every lake table has a `tlp` column and a table-level default; a
   row with no value reads as the table default, and a table with no default reads as `red`. The
   log pipeline sets the label on each event before it reaches the SIEM or the lake, from the
   source's declaration. Adding the column is an additive schema change (ADR-0001).
6. **Every reader declares a ceiling, and readers get only data at or below it.** A reader is
   anything that shows or sends data on: a status or generated page, a dashboard, an export, the
   publishing gate, an agent profile, a model role. The filter is applied in the shared read path
   (the client library or the view the reader queries), not in each page, so a new page cannot
   forget it. A reader with no declared ceiling is refused by validation; it does not default to
   showing everything.
7. **Viewers are granted a ceiling, and a view is reachable only at or below it.** The initial
   mapping keeps what exists working:
   - anonymous, internet-facing: `clear`;
   - the status hub's public view: `clear`;
   - the private tier behind the trusted front door (the operator): `red`.
   Intermediate grants (`green` for a community audience, `amber` or `amber+strict` for named
   partners) are added per site when a real audience exists.
8. **`green` is not public.** TLP:GREEN allows sharing within a community, not publication on the
   open internet. The publishing gate keeps `clear` as its default; an overlay may set
   `tlp_allowed: green` only when the static host is restricted to that community, and validation
   says so.
9. **Model roles have a ceiling.** A local model role's ceiling is `red`. A role whose prompts leave
   the lab (`leaves_lab`) defaults to `green`; raising it is a human-tier change. The gateway refuses
   a request whose context is labelled above the role's ceiling and records the refusal, and the
   label of the response is the strictest label in its context (rule 4).
10. **Secrets are not labelled data.** Keys, passwords and tokens are never stored in the lake or
    the SIEM and are never shown at any ceiling; they live only in the secrets slot. The existing
    screeners and leak scans enforce this, and a secret found in labelled data is a defect, not a
    `red` record.
11. **Claims are verified at every egress, not only at publishing.** The publishing gate's checks
    (TLP markers in the body, the deny-list) run wherever data leaves the lab: exports and cloud
    model requests as well as publishing. A marker stricter than the claimed label wins.

## Consequences

- Every display, export, agent profile and model role gains a declared ceiling. Existing displays
  migrate by mapping, not by redesign: the public view becomes a `clear` ceiling and the private
  tier a `red` one, so nothing they show changes on day one.
- The binary `public` / `lab only` on the links page describes **network reachability** and stays;
  it is no longer read as a data classification.
- Source declarations become reviewable: a source marked looser than `red`, or one that honours its
  items' own labels, goes through the human review tier like other trust-widening fields.
- The lake, the SIEM's event schema and the log pipeline each gain a `tlp` field. Old rows have no
  value and read as `red`, which hides data from looser views until a source declaration backfills
  its table default. That is the intended failure direction.
- Rollups for wider audiences become possible without a separate pipeline: the same data rendered
  at a lower ceiling simply omits what it may not show.
- Cloud models see less by default. Work that needs `amber` context on a cloud model needs a human
  to raise that role's ceiling, deliberately and on the record.
- The label describes sharing terms, not sensitivity in general. Data that is sensitive for other
  reasons (personal data, legal holds) still needs its own handling; this ADR does not cover it.
- Delivery is incremental, in this order: the label type and validation; source declarations in
  module manifests; the storage column and pipeline tagging; reader ceilings and the shared filter;
  the model-role ceiling at the gateway; egress verification beyond publishing.

## Alternatives

- **Keep the binary public / private split.** Rejected: it cannot express "shareable with a
  community but not public" or "licensed, organisation only", which are exactly the cases where a
  wrong display is a breach of someone else's terms.
- **A home-grown scale, or extra levels beyond TLP 2.0.** Rejected: a label partners and sources do
  not recognise has to be translated at every boundary, and the lab's sources already speak TLP 2.0.
  Secrets are handled by rule 10 instead of a sixth label.
- **Label by processing stage (raw is open, enriched is amber).** Rejected as a rule, though it is
  often the outcome: the source's terms decide, and an open item enriched from another open source
  is still open (rule 4).
- **Default unlabelled internal data to `amber+strict`.** Rejected for now: `red` (named recipients
  only) is the fail-closed choice for a lab with one operator. A site with a wider internal audience
  can declare its sources `amber+strict` explicitly.
- **Filter in each page or dashboard.** Rejected: every new page would have to remember to do it.
  Filtering in the shared read path, with validation refusing a reader that declares no ceiling,
  makes the safe behaviour the only behaviour.
- **Per-column labels.** Deferred: row labels with a table default cover the cases known today, and
  per-column labels can be added later without breaking rows.
