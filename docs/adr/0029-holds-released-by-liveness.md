# ADR-0029: Holds are released by liveness; a TTL is only a backstop

- **Status:** proposed
- **Date:** 2026-10-23
- **Related:** ADR-0001, ADR-0005, ADR-0022, `conformance/protocols/orchestration.py`,
  [the orchestrator as `orchestration`](../orchestration-controller.md)

## Context

An orchestrator that admits model work holds capacity for each run: a slot, an exclusive lease, a
token or KV-cache reservation on a backend. In a typical grown lab those holds are released along
the happy path and, for everything else, by a timer. The shape of the evidence is consistent:
requests that died mid-stream (a killed client, a cancel, a controller restart) never reached the
release, so their reservations stayed until a one-hour TTL fired, and a gateway's KV pool sat
"full" for more than a day while no work ran. A reaper that returned slots for runs no longer
alive still leaked the token-weighted reservations and exclusive leases held beside them, so the
backend refused new work while idle. ADR-0022 already keeps admission out of the gateway, but the
`orchestration` contract said nothing about when a hold must end: its suite had 11 checks and
none of them looked at capacity.

## Decision

1. A hold exists only while the worker it was granted to is alive, and that worker keeps it until
   it ends: a hold that disappears while its run is still executing is a timer, not a release. A
   run in a terminal state holds nothing.
2. Holds are released on success, failure, cancel, deadline expiry, worker death and orchestrator
   restart. Each of those is an event the orchestrator observes; none of them is "a timer
   expired".
3. A TTL may exist, as a backstop for a defect in rules 1-2. It never counts as the release
   mechanism, and a hold that a TTL had to end is reported as a defect.
4. Cancelling a running run stops its worker; it ends `cancelled` within the implementation's
   cancel grace (at most 10 s), whether or not the job body cooperates, and a late result is
   discarded.
5. After a restart, no run is `running` without a live worker and holds are rebuilt from live
   workers only. A run that was executing is ended, never run a second time, because its old
   worker may still be executing; queued runs and idempotency keys survive.
6. The contract carries this additively (ADR-0001): clauses a-e in
   `conformance/protocols/orchestration.py`, the optional `capacity()` (feature `admission`), the
   `kill`/`restart` test hooks, and five MUST checks that skip without `admission`. They judge
   capacity by its effect where a limit is reported (freed slots admit new runs), not only by
   what `capacity()` says. A check that
   needs a hook the target does not declare is `untested`, never a pass.

## Consequences

- An adapter has to expose what it holds (`capacity()`), so a leak is a failing check instead of
  an idle backend nobody can explain.
- The kill and restart checks need a fault hook on the implementation. A live service without one
  is `untested` on them, which fails the capability: proving the property costs a hook.
- Every new kind of hold (a lease, a reservation, a budget) has to be tied to a worker's lifetime
  where it is created, not swept up later.

## Alternatives

- **Shorter TTLs.** They shrink the window but keep the failure: a short TTL also expires holds
  that live, slow work still needs, and a long one is the outage described above.
- **A periodic reaper as the mechanism.** It is what leaked: a reaper returns what it knows about
  and misses holds recorded elsewhere. It remains acceptable as the backstop of rule 3.
- **Leave it to the gateway.** ADR-0022 keeps admission out of the gateway, and a gateway cannot
  see a worker die; it only sees a connection close, which a killed worker may never do cleanly.
