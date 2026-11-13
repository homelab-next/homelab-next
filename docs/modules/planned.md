---
summary: 'Module manifest reference: planned core slots, the required core slots a staged lab does not serve yet, each a warning with a review date.'
summary_of: outline:sha256:523fdae3222f571f
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: planned core slots

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed); the rest of the
> selection is on [site selection](selection.md).

## Planned core slots: not served yet

A lab built in stages has required core slots that nothing serves yet: no module provides them
and no incumbent ([incumbents](selection.md#incumbents-slots-served-outside-modules)) does
either. `none` and `pass-through` are refused for a `required_in_core` slot, rightly: they say
"nothing, by decision", and a core slot is never that. Without a third answer such a lab could
never pass `hnx modules check --deploy` ("a required core slot has no provider"), so nothing it
does run could be deployed. `planned` (optional) is that answer, per slot, with what will serve
it and when the plan is next reviewed:

```yaml
planned:
  idp: {why: "an identity provider module, the next stage", review_by: "2027-01-15"}
  orchestration: {why: "the orchestrator module, after idp", review_by: "2027-03-01"}
```

Quote `review_by`: YAML reads an unquoted `2027-01-15` as a date, not the `YYYY-MM-DD` string the
schema holds it to, and the schema refuses it. `why` and `review_by` are both required; `why` is
one line of printable text (the check prints it, so a control character or a line break is
refused, as for an incumbent's `why`), and `review_by` is written in ASCII digits.

**What a planned slot does.** `hnx modules check` (and `--deploy`) no longer refuses the slot:
it prints one warning per planned slot instead, with its `why` and `review_by`
(`warning: idp: a required core slot has no provider yet (planned: ...; review by 2027-01-15)`;
under `--json`, the report's `warnings` list), and the summary line counts them. A warning does
not change the exit code. A planned slot the loader refuses (below) is a problem, never also a
warning, and the check notes each selected module that requires or prefers a planned slot.

**What it does not do.** A planned slot is **not served**. It is not in the set of selected
slots any rule reads, so:

- it satisfies nothing: a module whose hard requirement (`requires.capabilities`) is a planned
  slot is refused by name (`<module>: requires cap:<slot>, which the site plans but does not
  serve yet`); a preference falling back to it, or a dataset living in it, is unselected, as
  before;
- it is never a provider or an instance: `provider_for` refuses it ("planned, not served yet"),
  `hnx modules providers` lists it as planned, and an agent lane cannot bind to a planned
  `orchestration`;
- a `pass-through` stage whose upstream stage is planned is refused with that reason, and a swap
  whose incoming module requires a planned slot is refused by name;
- it is never an egress target (`svc:<slot>` is no service) or an upstream (a row's upstream on
  it is "not selected, nor a fallback for it").

**What the loader refuses**, each problem naming `planned.<slot>`:

- a slot that is not in the slot registry;
- a slot that is not `required_in_core` (an optional slot the site does not select is simply left
  out of `slots`);
- a slot also under `slots` (a provider, `none` or `pass-through`) or also an incumbent: one
  answer per slot;
- a `review_by` that is no calendar date (`2027-02-30` passes the schema's pattern, not this).

**Expired plans fail the deploy.** `hnx modules check --deploy` judges each `review_by` against
the date (`HNX_TODAY` when set, else the local date: `homelabnext.registry.standing.today`, the
one reader the guest `firewall_exemption.review_by` rule also uses) and refuses a plan whose date
has passed (`review_by` before today; the day itself passes): serve the slot, or review the plan
and set a new date. The plain check reads no date at all, so it stays a pure function of its
files; a malformed `HNX_TODAY` is a usage error (exit 2), never ignored. `HNX_TODAY` exists so a
test or a replay is deterministic: the overlay's deploy workflow must not set it, since a date
in the past silences the gate. `hnx modules render` reads no date either, so it is not this
gate: the deploy runs `hnx modules check --deploy` first ([apply path](apply.md#running-it-in-an-overlay)),
and only a selection that passed it is rendered.

**Not checked.** A core registry row that is its capability's primary for a planned slot means
something already serves it, so the slot is an incumbent, not a plan; the check does not compare
the plan with the registry, so declare such a slot an incumbent.

**Leaving the plan.** Serving a planned slot is one selection edit that removes it from `planned`
and adds a provider under `slots` (or an incumbent), in the same change; the overlap rule refuses
the two together. Nothing else carries over: no plan is ever a provider, so no swap or cutover
names one.
