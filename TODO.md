# Operator to-do: standing up the lab

The steps only the operator can take to stand up a lab from this repository and its private
overlay. Agents add items here and never tick them; the operator ticks or deletes them. Nothing
here names a real host, address or account: those live in the private overlay.

Items are in rough stand-up order. Each says why it needs a person.

## 1. Repository settings (GitHub settings no test can check)

- [ ] **Require `lab-ok` on `main`.** It is the one stable check over the real lab-in-a-box stack
  that CI runs on every pull request. Until it is required, a pull request can merge with the
  real stack failing.
- [ ] **Never require the `experimental` job.** It runs the tests of components listed in
  `tools/experimental.yml` and is allowed to fail. Before any experimental component is enabled
  anywhere, move its security tests back into the blocking set.
- [ ] **In the private overlay, require the `swap-gate` job** with the template's other checks. A
  check that no rule requires gates nothing (docs/modules.md, swap-gate section).
- [ ] **In the private overlay, merge the first `lab/model_roles.json` by an owner override.**
  `swap-gate` has no base table to hold the first one against, so it exits 2. Every later
  change is gated normally.

## 2. Decisions waiting on you

- [ ] **Review ADR-0037, agent memory provenance (pull request #245), then merge it or send it
  back.** Things to know before you accept it:
  - packs carry no TLP labels yet, so all memory reads as `red`;
  - retraction holds fleet-wide only once the broker's free-form `memory.write` lane is routed
    through the memory store or removed;
  - retracting only cited facts is precise but can miss facts a poisoned source steered;
    `include_exposed` is complete but can retire facts that never used the source.

  Its first implementation pull request may merge while it is proposed; the second only after
  you accept it.
- [ ] **Accept ADR-0036 (novelty baselines)** and the ADRs whose code has shipped but whose
  status still reads `proposed` (each ADR's **Status** line). Once they
  are accepted, a test can hold frozen schemas to accepted ADRs.
- [ ] **Confirm or overturn the two defaults in pull request #59 (broker-only actors).**
  - A site's `--classes` table may not class a packaged capability or tier down.
  - There is no per-record waiver for the tool-class floors.

  Both are listed in ADR-0030. Changing either is a small follow-up.

## 3. Secrets and identity (before the first deploy)

- [ ] **Put your age public key(s) in the overlay's `.sops.yaml`**, so `lab/sealed/` can be
  encrypted. Public keys only; never the private key.
- [ ] **Initialise and unseal the secrets store for the first time.** Keep the unseal shares
  offline.
- [ ] **Stand up the identity provider and the auth proxy** (ADR-0034):
  1. choose where the identity provider runs and set the overlay's `idp` row to it;
  2. put each OIDC client secret and the break-glass admin in the secrets store, one entry per
     service under `idp/clients`;
  3. import the generated `idp/realm.json`;
  4. **create the admin group the overlay's roles name (`lab-admins` unless you renamed it) and
     add yourself before the auth proxy goes live**: every gated site fails closed, with a 403
     for everyone, if the group is missing;
  5. deploy the auth proxy;
  6. give users a temporary password and enrol their one-time-password device with them in
     person (first-sign-in enrolment trusts whoever holds the password at that moment).
- [ ] **Verify sign-in live**, since none of this has run against a real identity provider yet:
  - a user with no one-time password is refused, both at the browser and on a password grant;
  - a signed-in user outside a site's groups gets 403;
  - a sign-in return link whose query contains `&` comes back intact.

## 4. Lab bring-up

- [ ] **Validate the overlay with the scope check and the private leak check** and fix it until
  both are clean (`hnx site validate`, `tools/private_leak_check.py private`, overlay CLAUDE.md).
- [ ] **Lake readers and ceilings** (ADR-0033):
  1. declare `tlp_readers` (including `analyzer:novelty`) in the overlay;
  2. render `lake-access.json` and load it into the query engine once;
  3. confirm a reader below `red` sees only rows at or below its ceiling.

  The lake starts fresh, so there is nothing to backfill. `hnx modules tlp-backfill` is only for
  a table created before it had a `tlp` column.
- [ ] **Re-record the lake parity cassette against the real engines**, after adding a query that
  reads `tlp` to `tests/lake/fixtures/queries.py`. None of the recorded queries reads the
  column yet.
- [ ] **Novelty baselines** (ADR-0036):
  - in the overlay, write the first novelty spec and the timer that runs it;
  - set `learn_days` and `min_history_days` per profile;
  - keep lake retention at least `learn_days` for every profiled table;
  - scope the analyzer's catalog credential to the `novelty_finding` table.

  Profiles stay warming, with no findings, until they hold `min_history_days` of data.
- [ ] **Host sensor trial**: build the Phage fork from a pinned commit (never its install script
  or release binaries). Run it on one canary guest in learn mode, then alert mode, and read the
  baseline difference before widening it.
