---
summary: Every source and record carries a TLP 2.0 label (unlabelled is red); derived data takes its strictest input; every view, export and model has a TLP ceiling.
summary_of: outline:sha256:91c8e47d3eaaa755
---
# ADR-0033: Data carries a TLP label from its source; every reader has a TLP ceiling

- **Status:** proposed
- **Date:** 2026-10-30
- **Related:** ADR-0001 (additive schemas); ADR-0011 and ADR-0021, which classify repositories
  and files and are unchanged by this ADR (a file in the public repository is `clear` by
  ADR-0011); ADR-0022 (LLM gateway, role locality); ADR-0024 and ADR-0030 (the ceiling policy,
  `data_tier`, agents act through the broker); ADR-0027 (modules, review tiers);
  [modules](../modules.md) (the publishing gate, model roles and `leaves_lab`);
  [status](../status.md) (the public view, the exports, the private tier);
  [agent profiles](../agent.md), [MCP catalog](../mcp-catalog.md)

## Context

The lab holds data with very different sharing terms in the same places: open feeds anyone may
republish, community feeds shared on terms, third-party enrichment, licensed API results that
may not leave the organisation, and the lab's own logs, inventory, findings and agent activity.
Today that is expressed in three unrelated ways:

- The **publishing gate** already speaks TLP 2.0. A producer's item carries a claimed TLP
  (`clear`, `green`, `amber`, `amber+strict`, `red`). The gate treats it as a claim, re-derives
  the marking from the content (TLP markers and deny-listed names override the claim), and lets
  out only what `tlp_allowed` permits (`clear` by default, `green` at most).
- **Displays** use a binary split. The status hub has a public view (with public exports) and a
  private tier unlocked by the trusted front door; the links page marks a service `public` or
  `lab only`. That says *who* may open a page, not *which data* it may show.
- **Agents and MCP servers** carry `data_tier: local-only | cloud-allowed`, attested by the
  ceiling policy: where data may *go*, in two values.

So a label exists only at the last step out of the lab, and nothing carries it from the source
through the lake, the SIEM, enrichment and model calls to that step. A display or a cloud model
can be handed data whose terms forbid it and nothing notices, because neither binary can say
"community-shareable but not public" or "licensed, organisation only". A derived item (a
summary, an enrichment, a rollup) has no label of its own, so the gate can only re-derive one
from the text.

The standard for this already exists and the lab's threat-intel sources already use it: TLP 2.0
(FIRST, 2022), carried as tags, sidecar fields or STIX markings.

## Decision

1. **The label set is TLP 2.0, exactly.** Five labels, ordered by restriction, and what each
   permits:

   | Label | May be shared with |
   |---|---|
   | `clear` | anyone; no restriction |
   | `green` | the recipient's community; not public channels |
   | `amber` | the recipient's organisation and its clients, on a need-to-know basis |
   | `amber+strict` | the recipient's organisation only |
   | `red` | the named recipients only |

   `clear` < `green` < `amber` < `amber+strict` < `red`. A reader with TLP ceiling X receives
   labels at or below X; a `red` ceiling means every label is visible to that reader, not that
   the reader may share it on, which `red` forbids. No other label is defined. Accepted
   spellings: `clear`, `green`, `amber`, `amber+strict`, `red`, each with an optional `tlp:`
   prefix, in any case, surrounding whitespace ignored; TLP 1.0 `white` is `clear`. Anything else
   (including `amber-strict`, `amber strict` and an empty string), and a missing value, reads as
   `red` wherever it is read.
2. **The default is red.** Any source or record without a label is `red`. Data the lab generates
   about itself (logs, alerts, telemetry, inventory, configuration, findings, agent activity) is
   `red` unless a source declaration says otherwise. Lowering this default is a declaration a
   human reviews, never a fallback. Fictional example data in the public repository's `examples/`
   is declared `clear`, since it is published already (ADR-0011).
3. **Every source declares its label, from the provider's terms.** `tlp` is a field of each
   `data:` entry in a module manifest (an additive manifest version, ADR-0001): the label of any
   item that arrives without one. It comes from the provider's terms (a feed's licence, an API's
   redistribution terms), never from the processing stage. Reference declarations:

   | Source | Label |
   |---|---|
   | open feeds with no sharing restriction | `clear` |
   | free, open enrichment lookups with no sharing restriction | `clear` |
   | community or consented feeds | `green` |
   | third-party enrichment whose terms allow organisation-and-clients sharing | `amber` |
   | licensed or non-redistributable results (paid APIs) | `amber+strict` |
   | the lab's own data | `red` |

   Cost and processing stage are not the test: a free source whose terms restrict sharing is
   labelled by those terms, and enriching an open item only from free, open lookups leaves it
   `clear`, so a public threat-intel rollup built from such sources publishes at a `clear` or
   `green` ceiling. `amber+strict` is held for a licensed source, should the lab add one.

   An item that carries its own label from the source (a tag, a sidecar field, a STIX marking)
   keeps it when it is **stricter** than the declaration. It may be **looser** only when the
   source also declares `honour_item_labels: true`. A declaration looser than `red`, and
   `honour_item_labels`, are human-approve fields of the review tier.
4. **Derived data takes its strictest input.** An enrichment, correlation, summary, rollup or
   model output is labelled the most restrictive label among everything that went into it,
   including a model's context. Each derived record carries its `tlp` and `derived_from` (its
   inputs' ids), so the label can be recomputed. An open item enriched from an open source stays
   open; the same item enriched with a licensed result is `amber+strict`; the fact that an
   indicator was *seen in the lab* is lab data and makes its record `red`. A label is never
   lowered automatically; the only way to label output looser than its strictest input is a
   release transform (decision 7).
5. **Storage carries the label.** Every lake table and the SIEM's event schema have a `tlp`
   field, set per row by the writer: the log pipeline sets it on each event from the source's
   declaration before the event reaches the SIEM or the lake. A writer that supplies no label is
   refused, and there is no standing table default that can loosen a row. Rows that predate the
   field are backfilled once by a recorded migration: a row whose source is recorded takes that
   source's declared label; a row whose source is not recorded takes the strictest label of any
   source feeding the table; a source whose items carried their own labels that were not stored
   is backfilled `red` unless a human records otherwise. Rows not yet backfilled, and a stored
   value that is not one of the five labels, read as `red` (decision 1).
6. **Every reader declares a TLP ceiling, and receives only data at or below it.** A reader is
   anything that shows or sends data on: a status or generated page, a public export, a
   dashboard, the publishing gate, the bus, a notification channel, an agent profile, a model
   role. The filter is applied in the shared read path (the client library, or the view the
   reader queries), not in each page, so a new page cannot forget it. A reader with no declared
   TLP ceiling is refused by validation. The effective ceiling of a request is the lower of the
   viewer's grant and the reader's ceiling. Network reachability (`public` or `lab only` on the
   links page, a public hostname, the front door) never raises a ceiling; only a grant does. In
   this ADR "ceiling" always means a TLP ceiling, never the ceiling policy.
7. **Release transforms are the only declassification.** A wider-audience product derived from
   labelled data (a health badge, a count, a redacted summary, a public rollup) is produced by a
   declared *release transform*: a named, reviewed piece of code or configuration that records
   its input label, its output label and the fields it keeps. It is an allow-list: a field it
   does not list is dropped. Its output is labelled by that declaration and still passes the
   egress content checks (decision 13); creating or changing one is human-approve. A one-off
   downgrade of a single item is a recorded human decision of the same kind.
8. **Viewer grants.** Anonymous and internet-facing access is granted `clear`; the private tier
   behind the trusted front door (the operator) is granted `red`. `amber` (a named partner
   organisation and its clients) and `amber+strict` (the lab's own organisation, with no onward
   sharing) are added per site when such an audience exists. The day-one migration lists every
   field of the existing public view and public exports against the release transform that
   keeps it `clear`; a public field with no transform is withdrawn from the public view.
9. **`green` is not public.** The publishing gate keeps `clear` as its default. An overlay that
   sets `tlp_allowed: green` must also declare the publication's audience as a community and
   name the access control that restricts it; validation refuses `green` without both.
10. **Model roles have a TLP ceiling.** A local role's ceiling is `red`. A role whose prompts
    can leave the lab (`leaves_lab` on any binding of the role or down its fallback chain, as
    `cloud_roles` reads it) has a ceiling of `clear`. The overlay may raise it to `green` only by
    recording the provider's terms (no retention, no training); `amber` and above are never
    granted to a role that leaves the lab. Raising it is human-approve. The ceiling is in
    addition to, and does not replace, `grants.cloud_models`.
11. **Model requests carry their context label.** The caller labels each model request with the
    strictest label of everything it assembled (retrieved rows, broker results, MCP tool output,
    memory). Broker action results and MCP tool outputs carry the label of what they return; an MCP
    server record declares it. Because the caller asserts that label, the gateway takes the higher
    of the request's label and the sending profile's TLP ceiling as the request's label for a role
    that leaves the lab, so a profile that may hold `amber` cannot send to a cloud role whatever
    its request claims. It refuses a request above the role's ceiling, and a request with no label
    (read as `red`), and records the refusal. The content checks of decision 13 apply to gateway
    requests as to any egress. A profile reaching a cloud model other than through the gateway is a
    defect the actors-act-via-broker check reports, not an exemption.
12. **`data_tier` is derived, not a second axis.** For an agent profile, the ceiling policy
    attests a TLP ceiling (`tlp_ceiling`, distinct from the compiled profile's existing ceiling)
    where it attests `data_tier` today: `local-only` is a ceiling above the cloud-role ceiling,
    `cloud-allowed` one at or below it. For an MCP server, the record declares the label of what
    it returns (`tlp`, decision 11): `local-only` is a label above the cloud-role ceiling,
    `cloud-allowed` one at or below it. A profile may be granted a server only when the server's
    label is at or below the profile's ceiling. Until `data_tier` is derived, validation refuses
    an entry whose `data_tier` and TLP label or ceiling disagree.
13. **Egress points are enumerated, and each verifies.** One list in docs/modules.md names every
    point where data leaves its store: the publishing gate, the public exports, the bus,
    notification channels, webhooks, backups and off-site copies, model gateway requests, and
    memory and embedding stores, generated pages committed to a repository (ADR-0018), records and
    ticket systems (ADR-0010, ADR-0020), and logs and error text that reach a notification. Each
    one applies the reader filter and the gate's content checks (TLP markers and deny-listed names;
    a marker stricter than the label wins). An egress is a capability a module can require; a
    module requiring an egress capability that is not on the list is refused by the same grant rule
    that guards publishing (`grants.publish`). The publishing gate also refuses an item whose
    sidecar claim is looser than its recorded label (decision 4). Stored detail tiers and caches
    (the activity detail tier holds prompts and tool output) take the strictest label of their
    content, `red` when unknown.

    **Lookups to external enrichment services are egress too.** Sending an observable out for
    enrichment discloses the observable, and that the lab saw it, so a sighting from the lab's own
    data is `red` and must not reach a third-party analyzer. Each external analyzer or connector
    declares the highest label it may receive (where the enrichment platform supports it, its
    per-analyzer maximum TLP), and each enrichment job is submitted with the label of the
    observable; the platform runs only the analyzers whose maximum is at or above it. A job
    submitted with no label is submitted as `red`. Analyzers that stay inside the lab keep a `red`
    maximum.
14. **Secrets are not labelled data.** Keys, passwords and tokens are never stored in the lake,
    the SIEM or any labelled store and are never shown at any ceiling; they live only in the
    secrets slot. The existing screeners (`homelabnext.agent.screen`) and leak scans
    (`tools/leak_scan.py`) enforce this; a secret found in labelled data is a defect, not a `red`
    record.

## Consequences

- Every display, export, agent profile, MCP server and model role gains a declared TLP ceiling.
  The public view keeps only what a release transform covers; the private tier is `red` and shows
  what it shows today.
- `public` / `lab only` on the links page describes network reachability and stays; it is no
  longer read as a classification.
- Source declarations become reviewable: a declaration looser than `red`, `honour_item_labels`,
  a release transform and a raised model-role ceiling all go through the human review tier.
- The lake, the SIEM's event schema and the log pipeline each gain a `tlp` field and a one-off
  backfill. Until a table is backfilled its rows read `red` and are hidden from looser readers:
  the intended failure direction.
- Rollups for wider audiences come from the same data through release transforms, not a separate
  pipeline.
- Cloud models see only `clear` by default, and never `amber` or above. Work that needs labelled
  context runs on a local role.
- A release transform is trusted: its review is the control, and the egress content checks are a
  second line, not a proof.
- The label describes sharing terms, not sensitivity in general. Data that is sensitive for other
  reasons (personal data, legal holds) still needs its own handling; this ADR does not cover it.
- **Verification.** Each rule gets a negative fixture or a criterion:
  - an unknown label reads `red`, `white` reads `clear`, `amber-strict` reads `red`;
  - a reader with no ceiling is refused;
  - a looser item label without `honour_item_labels` is clamped to the declaration;
  - a derived record takes its strictest input;
  - a writer with no label is refused, and a NULL row reads `red`;
  - a cloud role is refused an `amber` context, an unlabelled one, and a `clear`-labelled one
    from a profile whose ceiling is `amber`;
  - a role with a local primary and a `leaves_lab` fallback has the cloud ceiling;
  - a release transform that passes an unlisted field fails;
  - a profile is refused a server whose label is above its ceiling;
  - an enrichment job labelled `red` runs no external analyzer;
  - a public field without a release transform fails the public-view test;
  - `green` publishing without an audience is refused;
  - `data_tier` disagreeing with the ceiling is refused;
  - every listed egress point applies the filter;
  - no row is looser than its own source's declaration.
- **Delivery**, in this order:
  1. the label type and its validation;
  2. source declarations in module manifests and the review tier;
  3. the storage field, pipeline tagging and the backfill;
  4. reader ceilings and the shared filter, with the public-view migration and its release
     transforms;
  5. the model-role ceiling, labelled requests at the gateway and the `data_tier` link;
  6. the egress list and its checks.

## Alternatives

- **Keep the binary public / private split, and `data_tier`.** Rejected: neither can express
  "shareable with a community but not public" or "licensed, organisation only", which are exactly
  the cases where a wrong display breaches someone else's terms.
- **A home-grown scale, or extra levels beyond TLP 2.0.** Rejected: a label partners and sources do
  not recognise has to be translated at every boundary, and the lab's sources already speak TLP
  2.0. Secrets are handled by decision 14 instead of a sixth label.
- **Label by processing stage (raw is open, enriched is amber).** Rejected as a rule, though it is
  usually the outcome: enrichment is typically third-party `amber` or licensed `amber+strict`
  (decision 3's table), but an item enriched only from open sources stays open, and one carrying a
  lab sighting is `red`.
- **Default unlabelled internal data to `amber+strict`.** Rejected: `red` (named recipients only)
  is the fail-closed choice for a lab with one operator. A site with a wider internal audience can
  declare its sources `amber+strict` explicitly.
- **A `green` default for cloud model roles.** Rejected: a model provider is not a member of the
  lab's community, and TLP:GREEN does not cover handing data to a vendor that may retain it.
  `green` needs the provider's terms on record.
- **A standing per-table default label.** Rejected: one default is wrong for some source of a
  multi-source table, and a writer bug would inherit a loose label. A one-off backfill and a
  refused unlabelled write fail closed instead.
- **Filter in each page or dashboard.** Rejected: every new page would have to remember to do it.
  Filtering in the shared read path, with validation refusing a reader that declares no ceiling,
  makes the safe behaviour the only behaviour.
- **Per-column labels.** Deferred: row labels cover the cases known today, and per-column labels
  can be added later without breaking rows.
