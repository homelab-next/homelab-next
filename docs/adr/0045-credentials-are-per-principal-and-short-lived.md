---
summary: Each principal holds its own credential, short-lived where it can be; every secret has an owner and rotates by a verb and a drill; standing ones expire.
summary_of: outline:sha256:862db64283ad1cbd
---
# ADR-0045: Credentials are per principal and short-lived

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0017 (the broker), ADR-0021 (the private overlay; credentials only in OpenBao),
  ADR-0022 and ADR-0038 (the LLM gateway and its keys), ADR-0026 (the orchestrator's stages),
  ADR-0028 (one source of truth), ADR-0029 (holds released by liveness), ADR-0030 (agents act only
  through the broker), ADR-0034 (single sign-on; SSH certificates); this batch: ADR-0039 (one
  primary per capability), ADR-0040 (modules are replaceable by construction), ADR-0041 (versioned
  capability contracts), ADR-0042 (tested restores, cold start and OpenBao break-glass), ADR-0043
  (the cutover ledger and its revocation records), ADR-0044 (the broker carries the vault's
  lifecycle), ADR-0046 (repository governance: agents are not the operator), ADR-0047 (agent runs
  traced, budgeted and evaluated), ADR-0048 (verification beyond one reviewer), ADR-0049 (the SOC
  data plane and the lab's checks move as modules) and the ADR-0026 amendment (placing what the
  split left unplaced); [private overlay](../private-overlay.md) ("SSH certificates", "Rotation",
  "Threat model"), [broker](../broker.md) ("Running the service"),
  [orchestration controller](../orchestration-controller.md) ("Per-agent keys"),
  [compute model](../compute-model.md) ("cloud-init and sudo"), `homelabnext/secretseed/`,
  `homelabnext/sshca.py`, `homelabnext/agent/keyring.py`, `homelabnext/registry/model.py`,
  `homelabnext/generators/llm_gateway.py`, `orchestrator/internal/gateway/secrets.go`; checklist
  F-04, F-06, F-13, F-24, M-11 to M-13 and S-05
- **Depends-on:** ADR-0021, ADR-0030, ADR-0034, ADR-0038
- **Requirements on ADR-0026:** decision 9 lands in stage 2's controller pull request, and
  decision 6's per-run credential properties bind stage 3's agent-runner ADR, which must cite them.

## Context

A credentials audit of the old lab and of this repository (read-only; names only, no value read)
found that the lab's principals are few and broad, and that the replacements this repository has
already built are not yet in force:

- **Automation identities can be shared and broad.** When unrelated jobs (agents, the
  controller, deploys) share one automation identity with standing keys and broad root, a fault
  in one is a fault in all, and containment rests on host-local software rather than on the
  kernel's separation of users. Where the old lab stands on this is overlay data (ADR-0011).
  This repository's guest model allows passwordless root as an
  explicit opt-in (`cloudinit.sudo: nopasswd`, guest schema 1.2), and nothing yet limits who may
  hold it.
- **An agent's identity is a label it sets itself.** The old vault records the filing agent as a
  configured string that plays no part in any decision, so the approval trail cannot prove which
  agent filed a proposal. The broker here already maps a caller by its kernel peer uid
  (`SO_PEERCRED`) to exactly one profile (`callers` in the broker manifest, schema 1.9), and
  refuses an asserted identity in production (`dev_identity: false`). No lab agent runs under its
  own uid yet.
- **Inference keys can be shared.** Clients that share one gateway key cannot be told apart by
  the gateway, which cannot limit one without the others. This repository's gateway spec names its
  **admin** key `secret:llm-gateway/master-key` (`examples/*/gateway.yml`), and the admin key may
  call every role at a `red` sending ceiling (ADR-0038 decision 5). If a value an old client holds
  were seeded under that name, that client would become an admin of the new gateway, past every
  per-key TLP ceiling and limit.
- **Per-agent gateway keys are half-designed.** The gateway renderer already derives one key per
  profile (the name `secret:llm-gateway/key-` plus the profile's slug, `llm_gateway.py`), but the
  runtime's home is per backend, not per agent, so [the controller doc](../orchestration-controller.md)
  leaves a **[verify]** open and settles for a key per backend first. Until that closes, the
  gateway's usage records cannot attribute a call to an agent, and per-agent budgets (ADR-0047)
  have nothing to key on.
- **The controller's API does not yet require authentication.** The frozen copy this repository
  ports has per-caller digest tokens with scopes, and they default to off. Once agents run as
  their own uids on the same host as the controller, a loopback bind is no boundary.
- **Secrets cannot be traced to an owner.** A service's `owner` names a person
  (`schemas/platform/service.json` 2.8); the schema has no field for the credentials a service
  holds, only `front_door.secret` and `status_sources[].auth.secret`. So a decommission finds a
  service's secrets only by grepping names, and a declaration of names that no role reads is
  indistinguishable from one that every role reads.
- **`hnx secrets plan` cannot see generated names.** It finds names by a literal scan for
  `secret:<name>` (`secretseed.scan`). The realm generator computes one client secret per
  `auth: idp` service plus the auth proxy (`client_secret_ref`, `builtin.py`), and the gateway
  renderer computes one key per profile. None is ever written as text, so none is planned or
  seeded.
- **One secret, two names.** Where two names must carry the same value, a rotation that reaches
  one name and not the other breaks a consumer or, worse, leaves the old value live. Nothing
  detects equal values under different names; the gateway alone refuses two of its own callers
  with one value at start (`LoadSecrets`).
- **Nothing rotates, and nothing ages.** `hnx secrets seed` is create-only (check-and-set 0);
  there is no `rotate` verb, no rotation runbook, no record of a credential's age and no drill.
  [private overlay](../private-overlay.md) says "rotate on a schedule" and sets none. Checklist
  F-06 ("every inventoried secret is within its rotate-by date") has no inventory to read and no
  rotate-by date to compare.
- **The short-lived replacements exist but are idle.** OpenBao as the SSH user CA (`hnx ssh-ca`,
  `ssh_hardening`), with deploy certificates capped at one hour and person certificates at 24 hours
  (`sshca.CAP`), is built; no site uses it yet.

What to do with the **old** credentials (revoke each one at its issuer before the old repository
is archived) is ADR-0043 decision 8's revocation ledger. This ADR is about the **new** ones: who
holds each, for how long, and how it is replaced.

## Decision

1. **A principal is one holder of one credential.** The principals are: a service (a registry
   row), an agent (a compiled profile), a person (an IdP subject), an automation (the deploy job,
   a broker handler run, a module's own process) and the site (credentials the substrate issues,
   such as the router's API key). Every credential has **exactly one holder**. A credential's
   **verifier** (the service that checks it, such as the gateway for its client keys) is recorded
   too, but checking a credential is not holding it. Two principals never hold one credential,
   and no principal holds a credential issued for another (checklist F-04: "no credential shared by
   two consumers").
   - **The token mint** is an automation principal: a broker handler (`github-token`, under
     ADR-0030) that holds the repository App's private key (ADR-0046) and nothing else. An agent
     obtains an installation token only by asking the broker for one; the handler mints it for the
     repository and permissions ADR-0046 fixes for that request, and returns it to the requesting
     run. The private key never leaves the handler's account.
   - **Lake writers** are module principals: each holds its own table-scoped credential under its
     module's namespace (ADR-0040; checklist S-05), never a catalog-wide one.
2. **The service schema names the credentials a service uses.** Service schema 2.10 (additive; the
   batch numbers its service-schema minors in the merge order ADR-0039 (2.9), this ADR, ADR-0042
   (2.11)) adds an
   optional `credentials` object with two lists of `secret:` references: `holds` (what the service
   presents, signs or decrypts with) and `verifies` (what it checks callers against, by value or
   by digest). `front_door.secret` and `status_sources[].auth.secret` count as held and need not
   be repeated. `hnx registry validate` (`registry/model.py`, beside `secret_ref_problems`)
   refuses:
   - one reference in the `holds` of two services;
   - a reference in both the `holds` and the `verifies` of one service;
   - a reference in the `verifies` of more than one service;
   - the gateway's admin key in any service's `holds` (decision 5).

   A shared MAC key is held by its signer and verified by its checker, which these rules allow
   (ADR-0047's run-token keys are this shape: held by the controller, verified by one verifier
   each).

   Agent, site, module and deploy credentials keep their existing declarations: a profile's
   gateway key is derived from the profile, the site's router keys sit in `site.yml`, a module's
   names sit under its `secret:<id>/` namespace (ADR-0040) and the deploy's own names in the spec's
   `also:` list. Together they are the **owner map**: every name has one owning principal, and
   `hnx decommission` and ADR-0043's revocation records read it instead of grepping names.
3. **`hnx secrets plan` sees every name, generated ones included, and every name has an owner.**
   - `plan` takes `--registry lab/services.yml` and `--profiles GLOB` and adds the names the
     generators compute, through the generators' own functions (`client_secret_ref` for each
     `auth: idp` service and the auth proxy; the gateway renderer's per-profile key names), never
     a copy of their naming rule (ADR-0028). Each computed name is listed with its generator as
     where it is named.
   - Each name is reported with its owner (decision 2) or as `unowned`: named in files but absent
     from the owner map, which includes a name that only a declaration nothing reads mentions.
     `plan --strict` exits 1 on an `unowned` name and on an `unclassified` name (no rule; today's
     behaviour, now fatal under `--strict`). The overlay's `checks.yml` runs `plan --strict`.
   - A test renders the example realm and the example gateway and asserts that every `secret:`
     reference in their output is in `plan`'s list; a name a generator adds without the plan
     seeing it fails that test.
4. **One credential, one name; one value, one name.** A secret has one name. Where two consumers
   must agree on one value, one holds it and the other verifies it under the same name
   (decision 2); a second name for the same value is never created. Doubled names collapse to one
   at the cutover of the service that reads them, and the dropped name goes on ADR-0043's
   revocation ledger. `hnx secrets audit --values` (decision 10) reads every value in the store,
   compares their HMAC-SHA256 under a key drawn at random for that run and held only in memory,
   and fails on two names with equal values, printing the names only. It extends to the whole
   store the rule the gateway already applies to its own callers at start. Because it reads every
   value, it runs interactively as the operator only, never in CI or on a timer.
5. **The gateway admin key is fresh and held by no client.**
   - The gateway spec renames `master_key` to `admin_key`, and the examples and the template's
     rules name it `secret:llm-gateway/admin-key`; no new gateway is deployed yet, so there is no
     alias: `master_key` is refused from the first release, and `secret:llm-gateway/master-key` is
     refused as the value of `admin_key`. The old name, and any value once seeded under it, is
     never what the new gateway reads.
   - Its rule is a generated `token` marked `broad: true` and `fresh: true`. `hnx secrets seed`
     refuses a supplied value (`--ask`, `--from-file`) for a rule marked `broad` or `fresh` (exit
     2), so the admin key can only be a value the seeder drew. Other generated rules still accept
     `--from-file` (an app restored with its existing database password, ADR-0042, is a legitimate
     import), and a value carried over from the old lab is classed `external` with a `how:` naming
     its origin. The template's comment says never to import an old gateway's key.
   - The admin key is held by no service (decision 2's refusal). It is used by the operator and by
     the deploy step that provisions keys, and by nothing that serves traffic. The Go gateway
     already refuses two callers with one value (`LoadSecrets`); a test pins that the refusal
     includes the admin key.
6. **Every gateway client has its own key, and every agent its own.**
   - A registry service whose `upstreams` include `llm-gateway` holds exactly one gateway key
     named for it (`secret:llm-gateway/key-svc-` plus the service's name; profile keys keep
     `key-` plus the slug, and the renderer refuses a profile slug that starts with `svc-`), and
     that key's `owner` in the gateway spec is that service. `hnx gen gateway render --check
     --registry` refuses a calling service with no key of its own, a key whose owner is not a
     registered service or profile, and a key two services hold. Until the controller's cutover it
     accepts a backend-home key that a standing exception covers (decision 11).
   - Per-agent keys close the controller doc's **[verify]** this way: a profile's key is delivered
     **per run**, never through a backend's home.
     - **Where the key comes from.** The deploy writes each profile's key as a host-sealed systemd
       credential (`systemd-creds encrypt`, under `/etc/credstore.encrypted/`, root-only). The run
       unit loads it with `LoadCredentialEncrypted=`, so it is plaintext only in that run's
       `$CREDENTIALS_DIRECTORY`, readable only by the run's uid and removed when the unit stops
       (ADR-0029: released on every exit).
     - **How a run starts.** The deploy renders one unit template per profile
       (`hnx-agent-<slug>@.service`: a fixed `ExecStart`, `User=` the profile's system user
       (decision 7), the profile's credential, a per-run spool directory). The controller starts a
       run only as an instance of that template (the instance name is the run id), allowed by a
       polkit rule that names those templates and the `start` and `stop` verbs and nothing else.
       The controller chooses no command and no environment; it supplies only the run's job input
       and the run tokens it issued itself (ADR-0047) through the run's spool directory.
     - The controller never reads an agent's gateway key. The agent-runner contract (ADR-0026
       decision 5, its own ADR in stage 3) requires these properties; the stage-3 ADR may choose
       another shape that keeps all of them: a key sealed at rest to the host, plaintext only to the
       run's uid for the run's life, and a launcher that cannot run an arbitrary process as an agent
       uid.
     - Whether the runtime reads its model key from where the run puts it is answered by the
       runner's conformance suite, not by a note: a check `per-run-credential` points a run at a
       fake gateway that records each call's bearer and passes only if every call carries the run's
       profile key, never another profile's and never a backend key.
   - Until the controller cuts over after stage 3 (ADR-0026's amendment), a key per backend home is
     allowed as a transitional standing exception (decision 11) that expires on the cutover date.
7. **Agents run as their own system users, through the broker.** Each compiled profile runs as one
   system user that the deploy creates from the profiles (a new `agent_users` role), a member of
   `hnx-broker-clients` and nothing else. That user has no `authorized_keys`, no sudo rule, no
   shell login and no credential beyond its own gateway key, its run's tokens and what the broker
   gives a request.
   - `hnx agent keyring check` (M-12) also refuses: a compiled profile with no `callers` entry in
     the broker manifest; two profiles with one uid or user; a production manifest with
     `dev_identity: true`.
   - The `agent_users` role's `validate` tag fails on an agent user that is in a sudo group, is
     named by a sudoers drop-in, or has an `authorized_keys` file.
   - The server observable of M-13 gains one probe per agent user: as that user, `sudo -n true` and
     an SSH login to a lab host both fail. A probe that succeeds pages.
   - The old vault's self-asserted agent label stops being an identity: the broker's peer-uid
     mapping is the only actor a record carries (ADR-0044 carries the vault's lifecycle onto it).
8. **People and the deploy sign in with short-lived certificates; standing root goes.**
   - The overlay holds `lab/ssh-ca.yml` once OpenBao is up, and the deploy signs a key it generates
     per job (deploy role: one hour, `source_addresses` bound), in the switch order
     [private overlay](../private-overlay.md) already gives. A person logs in to OpenBao through the
     IdP (Keycloak, the single IdP: ADR-0034, ADR-0039) for a certificate of at most a working day.
   - Site schema 1.7 (additive; ADR-0042's restore zone takes 1.8 after it) adds
     `access.ssh: certificates | static`. With `certificates`, `hnx guests validate` refuses a
     guest whose `cloudinit.ssh_authorized_keys` names any key but the site's one break-glass key,
     and refuses `cloudinit.sudo: nopasswd` for any account but the deploy account the CA's deploy
     role names. Once `lab/ssh-ca.yml` exists beside the site file, `guests validate` refuses a site
     without `access.ssh: certificates` unless the static-deploy-key standing exception is in force.
   - **The break-glass key** (custody: ADR-0042 decision 6) logs in to a dedicated break-glass
     account only, never the deploy account, whose sudo needs a password held offline in the same
     custody. It is a permanent standing exception (decision 11), and the F-04 server probe checks
     that it is the only `authorized_keys` entry on each host.
   - Root reach is scoped to who needs it. The deploy account keeps passwordless root, because
     configuration management needs it, but only a certificate valid for one job reaches it, and no
     person or agent logs in as it. A person's admin account accepts only the person principal.
     Nothing else holds `NOPASSWD:ALL`.
   - **A broker handler that acts on another host** gets a certificate for that run from a new
     `for: broker` signing kind in `hnx ssh-ca` (capped at 15 minutes and at the handler's
     `timeout_s`). There is one account and one OpenBao signing role per handler (`allowed_users`
     fixed to that account); handlers never share an account. The broker's OpenBao policy can sign
     only for the handlers in its manifest, and the broker's token is a broad credential (decision
     11). Each handler account's sudoers rule is rendered from the handler's manifest by a new
     `scoped_sudo` role and checked with `visudo -c` before it replaces the live file. Rendered
     rules name absolute, root-owned command paths with fixed arguments: no wildcards, no shells,
     interpreters or editors, no `SETENV`; `scoped_sudo` refuses the rest.
   - The server criterion for F-04 adds: on every host, `sudo -l -U` for every local account shows
     `(ALL) NOPASSWD: ALL` for the deploy account only, and after
     `ssh_hardening_keep_user_cert_only: true` the deploy account has no `authorized_keys` entry.
9. **The controller's API runs with authentication on.** The controller in this repository refuses
   to start with `api_auth` off, whatever it binds to, except under an explicit development switch
   on loopback that the production config renderer never sets, as the gateway refuses a
   conformance-only config outside its conformance mode (ADR-0038 decision 7). Each caller has its
   own token with its scopes (`jobs`, `read`, `admin`): the broker's job-submit handler, the status
   hub's reader, the workflow engine's dispatch, the operator. Tokens are held as SHA-256 digests,
   compared in constant time, and two callers with one token are refused at start. The profiling
   routes need `admin`.
   - The broker passes the requesting actor (its peer-uid profile) with each job it submits; the
     controller records `submitted_by` (the token's caller) and `on_behalf_of` (that actor), and a
     `jobs`-scoped read returns only runs whose `on_behalf_of` matches the actor the broker passes.
   - The orchestration conformance adapter gains an `auth` feature (no token is 401, a `read` token
     cannot drain or reload, a `jobs` token sees only its own actor's runs). The frozen private copy
     may turn its existing `api_auth` on now as a security backport (ADR-0026 decision 8), recorded
     in the stage-2 pull request.
10. **Rotation is a verb, and rotation is drilled.**
    - `hnx secrets rotate NAME --spec lab/secrets.yml` writes a new KV v2 version with check-and-set
      equal to the current version (so two concurrent rotations cannot both win), drawing the value
      for a generated rule and requiring `--ask` or `--from-file` for an external one. It refuses a
      supplied value equal to the current version. It records `rotated_at`, `rotated_by` (the
      OpenBao token's display name) and `reason` in the secret's custom metadata, updates the
      Vaultwarden copy when the spec's `vaultwarden` globs include the name, prints names only, and
      lists what must be redeployed: the holder and verifiers from the owner map (decision 2).
    - The previous version is kept until `hnx secrets rotate NAME --finish`, after the operator has
      deployed the consumers. `--finish` runs the verifier probe where the owner map names one (new
      value accepted, old refused) and refuses to destroy the old version if the probe fails, unless
      `--force` with a reason, which is recorded in the metadata. `seed` stays create-only.
    - Rules in `lab/secrets.yml` gain `max_age` (default 365 days; at most 90 days for every
      `token` and `hex` rule unless the rule sets `local_only: true` with a `why`), `broad`,
      `fresh` and `local_only`; the spec gains `exceptions` (decision 11) and `drill`. These are
      optional keys, so `secrets_version` stays 1: it is a format integer, not a schema `$id`, and
      today's loader refuses unknown keys, so an older `hnx` reading a spec that uses them fails
      loudly rather than ignoring them. A name's **rotate-by** date is its newest version's
      `created_time` plus `max_age`.
    - `hnx secrets audit --metadata --spec lab/secrets.yml` needs only list and read-metadata
      capability on the store and reports every name past its rotate-by date, every unfinished
      rotation, every name in the store that no file names (a stale secret) and every standing
      exception past its expiry or its rotate-by date (decision 11). It is what the scheduled F-06
      observable runs. `hnx secrets audit --values` is decision 4's duplicate-value comparison, run
      by the operator by hand; its result is stamped as a manual evidence note for F-04.
    - **A rotation drill** is `hnx secrets drill run` over the spec's `drill:` list (low-risk
      generated names, at least one per verifier kind: a gateway client key, an ingest token, an
      OIDC client secret). It rotates each, prints the deploy to dispatch (deploys stay dispatched
      by hand, ADR-0021 decision 5), and `hnx secrets drill verify` then runs each verifier probe,
      finishes each rotation that passes, and writes a dated drill record. F-06's server observable
      fails when the newest passing drill record is older than 90 days, as F-13 does for break-glass
      at 180.
11. **A long-lived broad credential is an invariant failure unless it is a dated or rotated
    exception.** A credential is **broad** when it can act as an administrator or on more than one
    service (the deploy key, the gateway admin key, the broker's OpenBao token, a hypervisor API
    token, a cloud access key, the AppRole `secret_id`). One that cannot be short-lived is allowed
    only as a **standing exception** in `lab/secrets.yml`, in one of two classes:
    - **transitional:** `{match, why, expires, replaced_by}`, where `expires` is at most 180 days
      after the commit that sets it (judged from git, as swap evidence is) and `replaced_by` names
      the short-lived mechanism or the decision that retires it. The first are the backend-level
      gateway keys (decision 6, until the controller's cutover), the static deploy SSH key and any
      account's standing key with `NOPASSWD:ALL` (until the certificate switch).
    - **permanent** (no short-lived option exists at the issuer): `{match, why, permanent: true}`,
      which requires the matched rules to set a `max_age` of at most 90 days and is kept in force by
      rotation, not by extension. These are the hypervisor and router API tokens, the deploy's age
      identity and cloud provider keys held by the gateway with spend limits. Offline break-glass
      material (the break-glass SSH key, the unseal shares; ADR-0042 decision 6) is permanent with a
      `max_age` of 365 days (**decided 2026-11-08, operator**), because it is exercised under F-13
      rather than used.

    `hnx secrets plan` refuses a broad rule (`broad: true`) that no exception matches, and a
    transitional exception further than 180 days from its commit. `hnx secrets audit --metadata`
    fails F-06 on a transitional exception past its date and on a permanent one past its
    rotate-by date; renewing a transitional one is a reviewed change to the overlay, never a
    default.
12. **What this ADR does not decide.**
    - Revoking the old stack's credentials at their issuers and the archive gate (ADR-0043
      decision 8).
    - The agents' repository identity (the App, its permissions, admin bypass, code-owner review:
      ADR-0046); this ADR places only the token mint (decision 1).
    - Per-agent budgets, run tracing and honeytokens (ADR-0047, which keys on decision 6's
      per-agent keys).
    - OpenBao's unseal and root-token custody and the break-glass procedure (ADR-0042), and each
      app's break-glass local admin (ADR-0034 decision 6), beyond classing them as exceptions with a
      `max_age`.
    - The IdP itself (ADR-0034; Keycloak is the single IdP and Authentik retires, ADR-0039).
    - An MCP module's own credentials, beyond the rule that each is under the module's namespace
      and has one holder (ADR-0026 decision 6, ADR-0040).
    - The agent-runner contract's full shape (its own ADR, ADR-0026 stage 3); this ADR sets only
      the credential properties it must have.

## Consequences

- F-04 and F-06 become measurable. F-04 has an owner map to read and a duplicate-value audit
  stamped as manual evidence; F-06 has a rotate-by date per name and a drill record, read by a
  metadata-only audit. Both stay `server` criteria with these observables, and their public-now
  halves (`registry validate`, `secrets plan --strict`, `agent keyring check`, `guests validate`)
  run in `make check` and in the overlay's `checks.yml`.
- A compromised agent gets its own gateway key and its broker grants, not root on every host. A
  compromised client gets its own key's roles and ceiling, not the gateway's admin.
- A compromised controller can still start runs as any agent with input it chooses, but it cannot
  read an agent's key or run an arbitrary process as an agent uid. Root on the controller's host
  can read the sealed keys; that is the ceiling of a host-sealed credential.
- The gateway's usage records name an agent per call, which per-agent budgets (ADR-0047) need.
- More principals means more to provision: one system user, one unit template and one gateway key
  per profile, one key per gateway client, one controller token per caller, one account per
  remote-host handler. The owner map and `plan` keep the list derivable rather than hand-kept.
- Rotation becomes routine work with a cost: each drill is a rotate, a hand-dispatched deploy and
  a verify. A rotation that skips `--finish` leaves the old version live; `secrets audit
  --metadata` lists unfinished rotations.
- Standing exceptions are visible: a transitional one turns F-06 red at its expiry until it is
  retired or deliberately renewed in review, and a permanent one turns it red when it is not
  rotated. That will happen, and it is the point.
- The deploy account still holds root on every host for the length of a job. That is the honest
  ceiling of configuration management; what goes is the standing key and the account's use by
  anyone but the deploy.
- The admin key rename touches every gateway example and the LiteLLM renderer's input (its own
  `master_key` setting is still rendered from the admin key while LiteLLM runs, ADR-0038
  decision 8).

### Implementation plan

Each step is one pull request in this repository unless it says otherwise; overlay steps are pull
requests the operator merges there.

1. **This ADR.** Docs only. The ADR log test, the docs index and the summaries lint pass.
2. **Gateway admin key.** `admin_key` replacing `master_key` (no alias; `master_key` and
   `secret:llm-gateway/master-key` refused), the example and template names, the `broad` and
   `fresh` rule markers with `seed` refusing a supplied value for either, and a Go test that the
   admin key is among the callers checked for equal values. Tests prove each refusal, and that a
   plain generated rule still accepts `--from-file`. This step blocks step 14.
3. **Service schema `credentials`** (2.10). Schema, the frozen previous version,
   examples and negatives (a reference held by two services; held and verified by one; verified by
   two; the admin key held). Tests prove `registry validate` refuses each negative and accepts the
   example registry with every existing `front_door`/`status_sources` secret counted as held.
4. **`secrets plan` sees generated names and owners.** `--registry`, `--profiles`, owner column,
   `--strict`. Tests prove: every reference in the rendered example realm and gateway is in the
   plan (the generated-name gap closes); an unowned or unclassified name fails `--strict`; the
   output carries no value.
5. **Spec keys: `max_age`, `broad`, `fresh`, `local_only`, `exceptions`, `drill`.** Tests prove a
   broad rule without an exception is refused, a transitional exception further than 180 days from
   its commit is refused (a fixture repository with dated commits), a permanent exception over a
   rule without a `max_age` of at most 90 days is refused, a `token` rule with `max_age` over 90 and
   no `local_only` is refused, and specs without the new keys still load.
6. **`hnx secrets rotate`.** Against the fake KV v2 server the seed tests use, tests prove: a
   rotation is a new version with check-and-set on the current one; a concurrent rotation loses;
   an external rule needs a supplied value, and one equal to the current value is refused; metadata
   is written; the Vaultwarden copy is updated when included; `--finish` destroys only the previous
   version, and refuses when the verifier probe fails unless `--force` with a reason; no value
   reaches stdout, stderr or an argument list.
7. **`hnx secrets audit --metadata | --values` and the F-04/F-06 observables.** Tests with the fake
   store prove: `--metadata` reads no value (the fake refuses a data read under its token); a name
   past rotate-by, an expired transitional exception, an unrotated permanent one and an unfinished
   rotation are each reported; `--values` reports two names with one value by name only and the
   HMAC key never leaves the process. The example invariants register gets an F-06 observable that
   calls `--metadata` and an F-04 manual evidence note for `--values`.
8. **Gateway client keys.** `key-svc-<service>` names, the `svc-` slug refusal, and
   `render --check --registry` refusing a calling service without its own key, an unregistered
   owner and a key two services hold, with backend-home keys accepted under a standing exception.
   Tests prove each refusal.
9. **Controller authentication on by default.** Lands inside ADR-0026 stage 2's controller pull
   request: refusal to start without `api_auth` outside the loopback development switch, per-caller
   digest tokens, duplicate-token refusal, profiling behind `admin`, `submitted_by` and
   `on_behalf_of`, and the conformance `auth` feature. Tests prove each status code by scope and
   that a `jobs` read for one actor omits another actor's runs.
10. **Agent users.** The `agent_users` role (argument specs, task sets, `validate`) and the
    keyring check's three refusals. Role tests prove an agent user with a sudo group, a sudoers
    mention or an `authorized_keys` file fails `validate`; keyring tests prove the refusals.
11. **Per-run agent keys.** Inside ADR-0026 stage 3's runner pull request: the sealed credentials,
    the per-profile unit templates and the polkit rule, and the `per-run-credential` conformance
    check with its mutants (a run sent the backend key; a run sent another profile's key; a key
    left after the run; a start of a unit outside the templates refused). The backend-key standing
    exception's expiry is set to the controller cutover.
12. **Site `access.ssh` and the break-glass account.** Site schema 1.7, the
    `guests validate` refusals (including a site without `access.ssh: certificates` once
    `lab/ssh-ca.yml` exists), and the break-glass account with its password-gated sudo. Tests prove
    each refusal.
13. **Scoped root for broker handlers** (when the first remote-host handler lands). `hnx ssh-ca`
    `for: broker` with its cap and one role per handler, and the `scoped_sudo` role from handler
    manifests (`visudo -c` before replace). Tests prove the cap, a rendered sudoers that names only
    a handler's absolute commands, and a refusal for each forbidden form (wildcard, shell,
    interpreter, editor, `SETENV`).
14. **Drills.** `hnx secrets drill run|verify`, the drill record, F-06's freshness rule, and a
    rotation runbook in this repository's runbook register. Lab-in-a-box tests prove a drill on a
    gateway client key leaves the old key refused (401) and the new one served.
15. **Overlay (operator-merged; blocked by step 2).** `lab/ssh-ca.yml`; `credentials` on its
    services; unread declarations removed in favour of the roles' own references; rules for its
    unclassified names; standing exceptions with their classes and dates; a fresh admin key seeded
    under `secret:llm-gateway/admin-key`, and `secret:llm-gateway/master-key` not seeded at all;
    `plan --strict` and `secrets audit --metadata` wired into its checks and its server criteria.

## Alternatives

- **Keep one automation account and harden around it** (stricter host-local guards, more
  auditing). Rejected: host-local software is per host and bypassable, so a bypass inherits
  everything the account can do; per-uid identity is enforced by the kernel and the broker already
  uses it.
- **Per-profile homes per backend for agent keys.** It works without asking the runtime anything,
  but multiplies homes by backends and leaves a plaintext key file per profile readable by the
  agent's uid between runs. A host-sealed credential is at rest only as ciphertext readable by
  root, and is plaintext only to a live run.
- **The controller hands each run its key.** Simpler, but the controller would then read every
  agent's key, and a controller compromise would be every agent's. With sealed credentials loaded
  by fixed unit templates, a controller compromise can still start runs as any agent with input it
  chooses, but it cannot read a key or run an arbitrary process as an agent uid.
- **A per-profile OpenBao identity that fetches the key at run start.** It moves the problem: the
  identity's own `secret_id` is a standing credential per profile on the same host.
- **OpenBao dynamic secrets for everything.** Ideal where the consumer supports it (database
  users, cloud roles), and a later rule may require it there. Most of the lab's consumers read a
  static value at start, and the hypervisor and router have no short-lived option, so rotation
  with an age limit is the floor this ADR sets everywhere.
- **Detect shared values by naming convention.** Names do not reveal equal values; only comparing
  values (as digests, in memory) does.
- **No expiry on standing exceptions, only a list.** A list without dates becomes wallpaper; an
  expiry, or a rotate-by date for those that cannot expire, forces a decision in review.
