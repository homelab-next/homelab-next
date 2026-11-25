---
group: Added
---
status hub: `poll-stackstorm` built-in `automation-shadow` (service schema 2.14): the shadow evidence of the rendered workflow pack, one item per rule's pack over a 7-day window (would-act records, quiet evaluations, failures, first and latest record), paged over the `step` executions, so promoting a StackStorm rule to live is decided on what it would have done; `modules/stackstorm` contributes it as status source `stackstorm-shadow`.
