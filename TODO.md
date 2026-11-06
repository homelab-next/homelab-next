# Operator to-do: standing up the lab

The steps only the operator can take to stand up a lab from this repository and its private
overlay, in order. Agents add items here and never tick them; the operator ticks or deletes them.
Nothing here names a real host, address or account: those live in the private overlay. The full
procedure is [docs/private-overlay.md](docs/private-overlay.md), "Bootstrapping a new server".

## 1. Repository settings (GitHub settings no test can check)

- [ ] **Require `lab-ok` on `main`.** It is the one stable check over the real lab-in-a-box stack
  that CI runs on every pull request. Until it is required, a pull request can merge with the
  real stack failing.
- [ ] **Never require the `experimental` job.** It runs the tests of components listed in
  `tools/experimental.yml` and is allowed to fail. Before any experimental component is enabled
  anywhere, return it to the blocking set: delete its `tools/experimental.yml` entry and restore
  its gates and invariants in one change.
- [ ] **Create the `experimental-growth` label** (Issues, Labels). CI's `trusted-gates` job lets
  `tools/experimental.yml` grow only on a pull request carrying it (CONTRIBUTING.md, "Experimental
  and frozen components"); until it exists, no change can add to the list. Apply it yourself only:
  anyone with triage or write access can label a pull request, so the label is only as strong as
  that access. It approves only the head it is applied to: apply it on the final diff, and remove
  and re-apply it after any later push.
- [ ] **In the private overlay, require the `checks` job on `main`**, with pull requests and Code
  Owners review. It is the last job of `checks.yml` and needs every other one, `swap-gate`
  included, so it is the one check to require.
- [ ] **In the private overlay, merge the first `lab/model_roles.json` by an owner override.**
  `swap-gate` has no base table to hold the first one against, so it exits 2 and `checks` fails.
  Every later change is gated normally ([docs/modules/swap-flow.md](docs/modules/swap-flow.md),
  "The overlay's gate").

## 2. Secrets and the deploy path (before the first deploy)

- [ ] **Put your age public key in the overlay's `.sops.yaml`**, replacing the placeholders, and
  the deploy identity's public key (below). Public keys only; the deploy identity's private key
  goes only into the `production` Environment secret `SOPS_AGE_KEY`.
- [ ] **Initialise and unseal the secrets store for the first time, and create its KV version 2
  mount (`secret/`).** `hnx secrets seed` refuses a version 1 mount.
- [ ] **Seed the secrets store and revoke the root token**: `hnx secrets plan`, then `hnx secrets
  seed` with the overlay's `lab/secrets.yml` (docs/private-overlay.md, "Seeding the
  credentials"). Keep the break-glass material (unseal shares, the root-token recovery path, your
  age identity) off the lab, by hand.
- [ ] **Create the deploy identity**:
  - an AppRole that can read only the deploy's paths, with short TTLs, bound to the deploy's
    addresses;
  - a second age identity for the deploy, its recipient added to `.sops.yaml` (`sops
    updatekeys`).
- [ ] **Give the deploy a path into the lab** (`HNX_DEPLOY_PATH` is `tailscale` or `self-hosted`):
  the VPN with a federated identity (tag `tag:ci-deploy`, subject the `production` Environment), or
  an ephemeral just-in-time self-hosted runner. Never a persistent runner.
- [ ] **Create the overlay's `production` Environment**, with deployment branch `main` only.
  - Secrets: `BAO_SECRET_ID`, `SOPS_AGE_KEY`, `DEPLOY_SSH_KEY`; `ANSIBLE_VAULT_PASSWORD` only if the
    vault password is not in the secrets store.
  - Variables: `HNX_REF` (a full commit SHA), `SOPS_VERSION`, `SOPS_SHA256`, `HNX_DEPLOY_PATH`,
    `BAO_ADDR`, `BAO_ROLE_ID`, `BAO_CACERT_PEM`, `HNX_VAULT_PASSWORD_REF`, and for the VPN path
    `TS_OAUTH_CLIENT_ID` and `TS_AUDIENCE`.
- [ ] **Record host keys** in the overlay's `ansible/known_hosts`, checking each fingerprint out of
  band.
- [ ] **Run the first deploy by hand** (`deploy.yml` on `main`, from the overlay's Actions page or
  `gh workflow run deploy.yml --ref main`) and watch it.

## 3. Identity (after the first deploy)

- [ ] **Stand up the identity provider and the auth proxy** (ADR-0034):
  1. choose where the identity provider runs and set the overlay's `idp` row to it;
  2. put each OIDC client secret in the secrets store, one entry per service under `idp/clients`
     (the auth proxy's included). Put each app's break-glass local admin under its own name in
     the secrets store, never in the identity provider;
  3. import the generated `idp/realm.json`, which creates every group the overlay's roles name;
  4. **create your own user, enrol its one-time password, and add it to the admin group**
     (`lab-admins` unless you renamed it) **before the auth proxy goes live**: a signed-in user
     in none of a site's groups gets 403, so with nobody in the group every gated site refuses
     everyone;
  5. deploy the auth proxy;
  6. give other users a temporary password and enrol their one-time-password device with them in
     person (first-sign-in enrolment trusts whoever holds the password at that moment).
- [ ] **Verify sign-in live** (none of this has run against a real identity provider yet):
  - a user with no one-time password is refused at the browser, and on a password grant;
  - a signed-in user outside a site's groups gets 403;
  - a sign-in return link whose query contains `&` comes back intact.

## 4. Lab bring-up

- [ ] **Lake readers and ceilings** (ADR-0033):
  1. declare `tlp_readers` (including `analyzer:novelty`) in the overlay;
  2. render `lake-access.json` (`hnx modules render`) and load it into the query engine, and
     again after every change to `tlp_readers`;
  3. have the lake-query adapter sign each reader in to the engine as the user named by its whole
     reader id (`analyzer:novelty`, `profile:x`, ...), and each `group:` reader as the engine
     group of that name;
  4. confirm a reader below `red` sees only rows at or below its ceiling.

  The lake starts fresh, so there is nothing to backfill. `hnx modules tlp-backfill` is only for
  a table created before it had a `tlp` column.
- [ ] **Check lake parity against the lab's own query engine**, once an agent pull request has
  added a `tlp` query to `tests/lake/fixtures/queries.py` and re-recorded the cassette.
- [ ] **Novelty baselines** (ADR-0036):
  - write the first novelty spec in the overlay;
  - schedule `hnx novelty run` (the repository ships no timer for it);
  - set `learn_days` and `min_history_days` per profile;
  - keep lake retention at least `learn_days` for every profiled table;
  - scope the analyzer's catalog credential to the `novelty_finding` table.

  Profiles stay warming, with no findings, until they hold `min_history_days` of data.
- [ ] **Agent memory retraction** (ADR-0037 decision 12; only if agents run with memory):
  create `/etc/homelabnext/memory-operators.yml` (owned by root, mode 0644) listing
  `operators`, the agent runtime's and broker's users, and `deny_file`: an absolute path in a
  directory root owns and the runtime cannot write (create that directory root-owned, mode
  0755; the deny file appears there on the first retraction, root's, mode 0644). Point the
  runtime's `FileBackend(..., deny_path=)` at the same path (`memory.deny_path_from`). Keep the
  memory state file owned by the runtime user, which must not be root; run `hnx agent memory`
  via sudo.

## 5. Decisions waiting on you (not blocking stand-up)

- [ ] **Accept ADR-0036 (novelty baselines).** That ends the draft status of its novelty spec
  schema and of its amendment to ADR-0033 decision 6. Accept, too, the other ADRs whose code has
  shipped but whose **Status** line still reads `proposed`.
- [ ] **Confirm or overturn the defaults in pull request #59 (broker-only actors).** The first is
  ADR-0030 decision 1: a site's `--classes` table may not class a packaged capability or tier
  down. The second, that there is no per-record waiver for the tool-class floors, is in #59's
  "Decisions defaulted" table, which lists nine more.
