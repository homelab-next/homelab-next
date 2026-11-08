---
summary: Agents act on GitHub as an App, never with the operator's token; GitHub enforces the review tiers, only the operator deploys, the deny-list scan runs itself.
summary_of: outline:sha256:721a3e2d31f4e38b
---
# ADR-0046: Repository governance: agents are not the operator

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0011 decision 3 (the three leak layers), ADR-0021 decisions 5 and 7 (the deploy
  and the pin), ADR-0026 decision 1 (CODEOWNERS owns `/orchestrator/`), ADR-0027 (the module review
  tier), ADR-0028 (one source), ADR-0030 (agents act only through the broker), ADR-0033 decision 7
  (release transforms are human-approve); this batch: ADR-0039, ADR-0040, ADR-0041 (contract
  changes are schema-tier), ADR-0042 (governance settings restore from git), ADR-0043 (the old
  lab's repository credentials are ledger rows), ADR-0044 (broker approvals are not GitHub
  approvals), ADR-0045 (the App's key is a credential with one holder), ADR-0047 (review records
  name a run), ADR-0048 (review independence and allowlist ratchets), ADR-0049 (the scan's
  liveness is a lab check); [private overlay](../private-overlay.md) ("Writers and reviews", "The
  pinned homelab-next commit", "The leak checks, both directions"),
  [trust tiers](../modules/contributes.md#trust-tiers-what-selecting-a-module-grants),
  `CONTRIBUTING.md`, `.github/CODEOWNERS`, `homelabnext/modules/review_tier.py`,
  `homelabnext/network/review_tier.py`, `tools/leak_scan.py`, `tools/private_leak_check.py`,
  `tools/check_changelog.py`, `TODO.md`
- **Depends-on:** ADR-0021
- **Amends:** ADR-0011, ADR-0021

## Context

Agents write most of this repository and all of the overlay's changes. They do it with the
operator's own GitHub token, so GitHub cannot tell an agent from the operator. The credential audit
of 2026-11-07 lists where that is relied on, and the naming and tech-debt audits of the same day
add the pin and the changelog:

- **Every agent pull request is authored as the operator.** GitHub does not let an author approve
  their own pull request, so no approval can ever come from a second party.
  `.github/CODEOWNERS` says so in its header: `main`'s ruleset requires the CI checks but no
  review, "Require review from Code Owners" cannot be turned on, and every human-approve in the
  ADRs "is given by convention until then, not enforced".
- **Admin bypass is on.** The overlay's rule "never merge a pull request" is therefore a sentence
  in an instruction file, not a control: the token an agent holds can merge, and can start
  `deploy.yml`, which runs with root on every host.
- **The tiers exist but do not bite.** `hnx modules review-tier` and `hnx site review-tier` rate
  every changed path and field `human-approve` or `owner`, and fail only when a human-approve change
  has no CODEOWNERS owner. CODEOWNERS's first line, `*`, gives every path the one owner, so the
  check is near-vacuous ([trust tiers](../modules/contributes.md#trust-tiers-what-selecting-a-module-grants)
  says this in as many words).
- **The overlay's pin proves merged, not reviewed** ([private overlay](../private-overlay.md), "The
  pinned homelab-next commit"): with bypass on and agents holding the operator's token, a commit
  on homelab-next's `main` may never have had an owner's review. And the real overlay does not use
  the pin ADR-0021 decision 7 decided: it still reads an Actions variable, which anyone holding the
  token can change outside review; the overlay has no `locks/hnx-ref` (the naming audit of the
  same day).
- **The documents disagree.** The overlay's README and its CODEOWNERS comment assume a bot account
  that does not exist; its instruction file says agents act as the operator and asks for a bot
  account "before any agent writes to this repository unattended".
- **The deny-list layer runs only where a person remembers it.** ADR-0011 decision 3's third
  layer is a pre-push scan on the maintainer's machine with a deny-list supplied at run time
  (`HNX_DENYLIST`). Agents in cloud sessions push without it. Nothing scans what reached GitHub.
- **The changelog has stopped being read.** `CHANGELOG.md` is about 515 KB in under 700 lines:
  587 top-level entries, all but the 0.1.0 section under `[Unreleased]`, and about 90 of them (91
  at the audit) over 1,500 characters each (the longest above 8,000). No release has been cut since
  0.1.0 (2026-10-15), and no version tag exists on the repository.
- **34 of the 38 ADRs before this batch are `proposed`**, many of them implemented and enforced by
  CI (the tech-debt audit of the same day). A status that never moves stops meaning anything, and
  ADR-0021's "depends on" rule cannot hold an accepted ADR to proposed foundations.

The operator's standing rule for this repository is that agents keep building and merge
homelab-next pull requests when they are green, after an agent design review and an agent security
audit; that overlay pull requests are merged only by the operator; and that no agent starts
`deploy.yml`. This ADR makes GitHub enforce that rule instead of trusting the agent that reads it.

## Decision

1. **Agents act on GitHub through one GitHub App, never through the operator's token.**
   - One App, installed on homelab-next and on the overlay only. Commits, branches, pull requests,
     comments and merges by agents are the App's (`<app>[bot]`, its GitHub noreply address).
   - Agents hold only **installation tokens**: minted for one repository, narrowed to the
     permissions of the task, valid at most one hour. The App's private key is a credential with
     one holder, the token mint (ADR-0045 decision 1); it is never in an agent's environment, home
     or files. Until the secret store holds it, the operator keeps it off every host that runs
     agents.
   - **The token mint is a broker action handler** (ADR-0030: agents act only through the broker),
     running in the lab: an agent asks the broker for `github.installation_token` naming one
     repository and a permission set no wider than decision 1's table for it; the handler signs the
     App JWT with the key, requests the installation token narrowed to that repository and those
     permissions, and returns it with its expiry. The broker records each mint (principal,
     repository, permissions, expiry, never the token). The handler also records, from its own JWT
     calls, the installation's granted permissions and repositories, which is what the governance
     check reads (decision 7). The principal kind and the key's custody are ADR-0045's.
   - **Every route that acts as the operator's account is removed from agent environments:**
     personal and OAuth tokens, `gh` logins, SSH keys and deploy keys, and hosted-session GitHub
     connectors or MCP servers authorised as the operator. `tools/github_identity.py preflight`,
     called by the pre-push hook and by the agent runtime before `git push` or `gh`, refuses a
     token whose documented prefix is a user's (`ghp_`, `github_pat_`, `gho_`, `ghu_`), accepts
     only `ghs_`, and refuses an SSH remote (git over SSH skips the credential helper). It reads the
     token from the credential helper and prints the prefix class only. **Preflight is a tripwire
     against misconfiguration, not the control:** the control is that no agent environment holds
     the operator's identity, and preflight runs inside the environment it checks.
   - The App's permissions, per repository, are fixed in `.github/review-tiers.yml` (decision 3)
     and are the whole grant:

     | Permission | homelab-next | overlay | Why |
     |---|---|---|---|
     | contents | write | write | branches and commits |
     | pull requests, issues | write | write | open, comment, record reviews |
     | workflows | write, only while decision 2's required-workflow rule holds; otherwise **none** | **none** | a branch workflow could forge a required check (decision 2) or, in the overlay, dispatch a deploy (decision 6) |
     | actions | read | read | logs; **write** would allow `workflow_dispatch` and re-runs |
     | checks, metadata, administration | read | read | the merge rule and the governance check read them |
     | secrets, variables, environments | read (names) | read (names) | the governance check; never write |

     Nothing else: no `administration: write`, no `actions: write`, no `environments: write`, no
     organisation permission.
2. **`main` is protected by rulesets kept as code, with no bypass.**
   - `.github/rulesets/main.json` and `.github/rulesets/tags.json` in this repository, and the
     templates `examples/private-overlay/.github/rulesets/{main,merge,tags}.json` for the overlay,
     are the desired state, in the GitHub REST API's own ruleset format, applied by the operator
     (`gh api -X PUT repos/<owner>/<repo>/rulesets/<id> --input ...`). They are restorable from git
     after a repository is recreated (ADR-0042).
   - **homelab-next, `main`:** a pull request is required; the required status checks are the
     ones CI already aggregates (`test-ok`, `go-ok`, `lab-ok`, `real-tools`, the gates);
     "Require review from Code Owners" on; 0 required approvals otherwise; stale approvals
     dismissed on push; force-push and deletion blocked. ("Require approval of the most recent
     reviewable push" is not used: stale-approval dismissal already ties an approval to the head,
     and it could demand an approval on every pull request.)
   - **`review-gate` (decision 4) and `agent-reviews` (decision 5) are required through an
     organisation ruleset's required-workflow rule, pinned to the file on `main`**, not as
     status-check names. A required status check is matched by name, and its source, GitHub
     Actions, is the same for every workflow, so any workflow on any branch could post a passing
     check run of that name on another pull request's head. If the plan does not offer
     required-workflow rules (to be verified when the App is created), the App gets
     `workflows: none` in homelab-next too, and CI changes are the operator's, by break-glass.
     homelab-next keeps no repository-level Actions secret (decision 7), so a branch workflow
     reaches none.
   - **homelab-next, tags `v*`:** creation, update and deletion restricted to the repository-admin
     role, so neither the App nor a workflow's `GITHUB_TOKEN` can start `release.yml`.
   - **Overlay, `main`:** a pull request and the `checks` job required, force-push and deletion
     blocked; no required review and no code-owner rule. `merge.json`, which lets only the
     repository-admin role update `main`, is the review: the operator's merge is the approval, and
     the App, which never holds that role, can never merge. (GitHub never counts an author's own
     approval, so a code-owner rule here would leave every operator-authored overlay pull request
     unmergeable, and the operator authors the workflow changes of decision 6 and the pin moves.)
     The overlay's CODEOWNERS keeps its `*` line as documentation only.
   - **Bypass actors, exactly.** `main.json` (both repositories) has none. `merge.json` and the
     `tags.json` files carry exactly one, the repository-admin role, with bypass mode
     `pull_request` in `merge.json` (a merge, never a direct push) and `always` in `tags.json`
     (the operator pushes the tag). The governance check fails on any other actor or mode.
   - **Break-glass** is an operator editing a ruleset, an action GitHub records in the ruleset's
     history. The governance check (decision 7) pages while the rulesets differ from git, so a
     bypass left on is visible within a day.
3. **The operator's review tiers have one source, and GitHub enforces them.**
   - `.github/review-tiers.yml` is the authored list (ADR-0028) of every path whose change needs
     the operator's review. CODEOWNERS is generated from it (`hnx governance codeowners`, checked
     equal in CI like the docs index), and `homelabnext.modules.review_tier.GOVERNANCE` reads it
     instead of holding its own tuple. Its first version holds today's CODEOWNERS lines and
     `GOVERNANCE` entries, and these classes:

     | Class | Paths (first version) |
     |---|---|
     | schemas | `/schemas/`, `capabilities.yml`, `examples/modules/slots.yml` (contract versions too, ADR-0041) |
     | egress | `homelabnext/tlp_egress.py`, `homelabnext/modules/egress.py` |
     | grants | `homelabnext/grants.py`, `examples/broker/` (the broker manifests), `homelabnext/agent/tool_classes.yml`, `/examples/mcp/` |
     | TLP | `homelabnext/tlp.py`, `homelabnext/registry/model_tlp.py`, `homelabnext/logpipeline/tlp_labels.py`, `homelabnext/modules/tlp_sources.py`, `homelabnext/status/release_transforms.yml`, `homelabnext/status/release.py`, `conformance/fixtures/tlp_admit_vectors.json`, `examples/model_roles.json` |
     | CODEOWNERS and the tiers | `.github/CODEOWNERS`, `.github/review-tiers.yml`, `.github/rulesets/`, both `review_tier.py` files and what `GOVERNANCE` lists; the tests that enforce coverage and the tier and governance suites (`tests/governance/`, `tests/modules/test_review_tier.py`, the review-tier tests under `tests/network/`); `/hooks/` (it installs the preflight hook) |
     | CI | `/.github/` (workflows and actions), `Makefile`, `/constraints/`, `pyproject.toml`, `setup.py`, `MANIFEST.in`, `.pre-commit-config.yaml` |
     | licences | `LICENSE`, `NOTICE`, `tools/licences.yml`, `tools/licence_check.py`, `orchestrator/go.mod`, `orchestrator/go.sum` |
     | leak gates | `/tools/` (the scanners, lints and their allowlists), `.gitleaks.toml`, `/examples/private-overlay/`, `SECURITY.md` |
     | kept wholly, as today | `/conformance/`, `/orchestrator/` (ADR-0026 decision 1) |

   - **Code-owner review is real once `*` goes.** The homelab-next CODEOWNERS drops its `*` line in
     the same change that turns the rule on (implementation step 7, after the App exists): a path
     not listed has no code owner, and GitHub requires no review for it.
   - **Tiers finer than a path** are enforced by a required check (decision 4), since GitHub can
     own only paths: the per-field module tier (`/modules/` and `/examples/modules/` leave
     CODEOWNERS for it, so a module's docs or detections are agent-mergeable and its credentials,
     egress, roles or grants are not); an ADR's `Status:` line changed to anything but `proposed`
     (status values are the operator's, `docs/adr/README.md`); and any change to an ADR whose
     Status, as of the base, is not `proposed`, except added `Amended-by:`/`Superseded-by:` lines
     and their notes, so an accepted ADR's decision text cannot be rewritten without the operator.
   - **The list only grows by review.** Removing a path or class from `review-tiers.yml` is itself
     a change to an operator-tier file. A test fails when a `GOVERNANCE` entry, a leak-gate script
     (every `tools/*` script whose `hnx-script` header has `kind: check`), or a schema is not
     covered by some line; that test is itself in the "CODEOWNERS and the tiers" class, so weakening
     it needs the operator too.
4. **`review-gate`: a required check that reads who approved.**
   `hnx governance review-gate --ci-base` runs in a new workflow `.github/workflows/review-gate.yml`
   on `pull_request` and on `pull_request_review` (`submitted`, `dismissed`), with the **base
   commit's** code, as the `trusted-gates` job runs the tiers today, and `pull-requests: read`
   only. It passes when every change it rates human-approve has an approving review that:
   - is on the pull request's head commit (`commit_id`);
   - is by a `User` who is an owner, as of the base, of the CODEOWNERS line for
     `.github/review-tiers.yml` (the governance owner), and is not the pull request's author;
   - is not dismissed.

   Its human-approve set is: the per-field module tier (`homelabnext.modules.review_tier`, whose
   "no owner in CODEOWNERS" failure becomes "no approval" for paths CODEOWNERS no longer lists); the
   two ADR rules of decision 3; **every path** of a pull request not opened by the App or by
   Dependabot (GitHub's record `user.type` and `user.login`, which no commit can set), so an outside
   contributor's pull request is never agent-mergeable; and a pull request with a commit that is
   not the App's. A commit's identity is judged by GitHub's commit record (the author and committer
   **logins** GitHub resolves, or a GitHub-verified signature on commits the App creates through
   the API), never by the git author string, which any pusher sets. The same reader checks the
   label gates: `experimental-growth` (CONTRIBUTING.md) counts only when the issue's `labeled` event
   names the governance owner and came after the head commit. It prints each path, its class and the
   approval it found, never a
   review's text. Because it runs again on each review event, a head commit can carry several
   `review-gate` runs; the newest decides (shown in step 7, since agents cannot re-run a job).
5. **The merge rule for agents, precisely.** An agent may merge a homelab-next pull request, by
   squash, through the API, when all of these hold, and at no other time:
   1. GitHub's record says the App opened it, and every commit is the App's (judged as in
      decision 4).
   2. Every required check of decision 2 passed on the head commit, `review-gate` and
      `agent-reviews` included.
   3. GitHub reports it mergeable with no code-owner review outstanding: it touches no
      operator-tier path, or the operator approved its head commit.
   4. An agent design review and an agent security audit, each by a run other than the author's
      run, are recorded on the pull request against the head commit. `agent-reviews` (a job of
      `review-gate.yml`) refuses an App-opened pull request without two App comments that start
      `hnx-review: design` and `hnx-review: security-audit` and name the head SHA, a verdict of
      `pass` and the reviewing run's id (ADR-0047). The same App writes them, so this is a record
      that the reviews happened, not proof of an independent reviewer; how independence is shown
      is ADR-0048's. ADR-0048's second-model-family review for its security-tier classes is **in
      addition to** the operator's approval wherever this ADR's tiers already require one (every
      egress, grants, TLP, CODEOWNERS-and-tiers and leak-gate path); it never replaces it, and
      ADR-0048's "ask the operator instead" fallback adds nothing on those paths.

   Nothing else is merged by an agent: not an overlay pull request (decision 2's `merge.json`
   makes that impossible), not a Dependabot or outside pull request (decision 4), and no auto-merge
   or merge queue is enabled for the App. The DCO stays the operator's certification: an App-
   authored commit in an App-opened pull request carries the operator's `Signed-off-by:` trailer,
   as agent commits do today, and the `dco` job accepts that pair (the sign-off address named as
   `dco_delegate` in `review-tiers.yml`) and nothing looser. `tools/leak_scan.py --check-authors`
   already accepts a `[bot]` noreply address.
6. **No agent can start a deploy.** Each layer holds on its own:
   - The App has no `actions: write` in the overlay, so it cannot call `workflow_dispatch` or
     re-run a job.
   - It has no `workflows` permission in the overlay, so it cannot push, on any branch, a workflow
     that dispatches with its run's `GITHUB_TOKEN`. Changes to the overlay's workflows are taken
     from the template in this repository (`examples/private-overlay/.github/`, which GitHub never
     runs here) by the operator's own pull request, as `TODO.md` §1 already does for the pin.
   - The overlay's templates declare `permissions:` per job and no job but `deploy.yml`'s holds
     `actions` or `id-token` (a template test reads every template workflow and fails otherwise);
     the overlay keeps no repository-level secrets, only the `production` Environment's, main only.
   - homelab-next has no deploy workflow, and `release.yml` starts only from a `v*` tag, which
     decision 2's tag ruleset keeps from the App.

   **Amended:** ADR-0021 decision 5's "a writer can dispatch" no longer holds for the agents'
   writer: the App is a writer that cannot dispatch, and only the operator starts a deploy.
7. **A governance check compares GitHub with git.** `hnx governance check --repo <owner>/<repo>
   --expect .github/review-tiers.yml` reads the live rulesets (with their bypass lists), the
   organisation's required-workflow rule, the CODEOWNERS file GitHub resolves, the App
   installation's permissions as the mint recorded them (decision 1), the repository's Actions
   secret and variable names and its Environments, and the pull requests merged to `main` in the
   last seven days, and fails, naming each difference, when:
   - a ruleset differs from `.github/rulesets/`, or carries a bypass actor or mode other than
     decision 2's;
   - in homelab-next, the required-workflow rule is missing while the App holds `workflows: write`;
   - the App's permissions are wider than decision 1's table;
   - a repository-level Actions secret exists;
   - in the overlay, an `HNX_REF` Actions variable exists (repository or Environment), or
     `locks/hnx-ref` is missing: the pin is the tracked file (ADR-0021 decision 7), and the
     variable's presence means something outside review can still choose what deploys;
   - a pull request merged in the look-back was merged by the App against decision 5 (its author,
     merger, tier classes and approvals are printed).

   **It runs only from the lab** (ADR-0049), nightly, for both repositories, with read-only
   installation tokens from the mint, and pages on a newly failing difference. `nightly.yml` is
   not wired to it: running it in homelab-next's Actions would need the App key, or a second App's,
   as an Actions secret in a public repository whose branches the App can push workflows to.
8. **The deny-list scan runs itself, in the overlay's private CI.**
   - The list's one copy is the overlay file `lab/sealed/denylist.txt`, SOPS-encrypted (a sealed
     path, which `tools/private_leak_check.py private` already refuses in plain text). Its
     recipients are the operator and a `leak-watch` age identity. A SOPS creation rule only chooses
     the recipients of new files, so the containment is a check: the `leak-watch` recipient appears
     on `lab/sealed/denylist.txt` only, and `tools/private_leak_check.py private` fails when any
     other sealed file or `.sops.yaml` rule lists it. A workstation copy is decrypted from it, never
     kept as a second source.
   - A template workflow, `examples/private-overlay/.github/workflows/leak-watch.yml`, runs hourly
     (or on the overlay's self-hosted runner) in the overlay, in an Environment `leak-watch`
     (deployment branch `main` only) that holds the `leak-watch` identity. A ten-minute schedule
     would be about 4,000 to 9,000 billed minutes a month in a private repository, above what the
     plan includes. It fetches every branch and pull request head of homelab-next as data, with the
     job's `GITHUB_TOKEN` to stay clear of the unauthenticated rate limit, and runs **the pinned
     `hnx`'s scanner** (`python -I hnx/tools/leak_scan.py`, the commit in `locks/hnx-ref`), never
     code from the commits under scan, with the decrypted list in `HNX_DENYLIST`:
     - `--history` over every commit reachable from the current branch and pull-request tips and
       not from the tips recorded by the last successful run (kept in the run cache; a lost cache
       scans the full history), plus the before and head SHAs of the `PushEvent`s in the
       repository's events feed for the window. Git records no push time and commit dates are the
       author's to set, so a date window would miss a backdated commit, and a commit force-pushed
       away between runs survives only in the events feed;
     - the tree of `main`;
     - `--stdin` over the titles, bodies and comments of pull requests and issues updated since the
       last successful run, release bodies and annotated tag messages, which are public text too.
   - On a hit the job fails, so GitHub notifies the operator, and opens or updates one overlay
     issue naming the commit or the pull request and the deny-list **line number** only, as the
     scanner prints it. Hits are state-diffed by commit and line, so a known hit is not re-paged
     every hour; a lost cache re-pages, which fails loud.
   - The watch's last success is a lab check (ADR-0049): no successful run for three hours pages.

   **Amended:** ADR-0011 decision 3's third layer is no longer only a pre-push check on one
   machine: it also runs on GitHub's copy, automatically, after every push. The pre-push check
   stays, because the watch finds a leak after it is public and only the pre-push check before.
9. **The changelog is short and releases are cut.**
   - An entry added under `[Unreleased]` is one line of at most 300 characters ending in a link
     (the pull request, an ADR or a doc section). `tools/check_changelog.py --base origin/main`
     judges only the lines a change adds, so existing entries do not fail anyone's pull request;
     the long text belongs in the pull request body, which the link reaches.
   - The existing long entries are rewritten to that form in one pull request, each linking the
     pull request it came from, found by the merge commit that added it.
   - `tools/check_changelog.py --cadence` (nightly) fails when the newest version section is more
     than 28 days old. It is a nightly failure with no page: there is no entry-count trigger, since
     about 25 entries a day would cross any small count every few days. This answers ADR-0041's
     open question on release cadence; its 30-day deprecation window closes by the second release
     after a deprecation. A release is an agent pull request (version in `homelabnext/_version.py`,
     the `[Unreleased]` section renamed) that the agent may merge; the tag that starts
     `release.yml` is pushed by the operator.
10. **The proposed ADRs are put to the operator.** The 34 proposed ADRs that predate this batch are
    listed below for the operator to accept, reject or leave; the batch's own 11 (0039 to 0049)
    join the list as the last group. An agent prepares a status change only on the operator's
    word, and decision 3's ADR status rule makes its merge need the operator's approval.
    Grouped by the evidence in the tree on 2026-11-07:

    | Group | ADRs | Evidence |
    |---|---|---|
    | Implemented and enforced by CI | 0001, 0002, 0003, 0004, 0005, 0006, 0007, 0008, 0011, 0012, 0013, 0017, 0019, 0021, 0024, 0025, 0027, 0032, 0036 | a CI gate or suite holds each (frozen schemas, `no_raw_endpoints`, the shared-helpers lint, `role_lint` and the role hooks, the conformance suites, the detections lint, the role table, the leak checks both ways, the status hub, the broker suite, `register_ids`, the MCP catalog gate, the telemetry store, the module loader, the summaries lint, the novelty package); 0012 decides a boundary and needs no code |
    | Built in part: check each against its own decisions first | 0009, 0010, 0014, 0015, 0016, 0018, 0020, 0023, 0029, 0030, 0035 | code exists in the packages each names; some decisions are library-only or lab-side |
    | Not ready | 0022, 0026, 0031, 0038 | 0022 and 0038 resolve together at the gateway's cutover; 0026 is mid-stage; 0031 is frozen until the core lab runs |
    | This batch, not yet built | 0039, 0040, 0041, 0042, 0043, 0044, 0045, 0046, 0047, 0048, 0049 | each is decided on its own review; acceptance means the decision, not the implementation |

11. **Out of scope.**
    - The old lab's repositories and their convention of agents pushing straight to the default
      branch with a workstation credential (the credential audit of 2026-11-07). They retire with
      the old lab; their GitHub credentials (deploy keys, tokens) are rows of ADR-0043's revocation
      ledger.
    - Commit signing (signed commits or signed release tags). Decision 1 makes authorship
      attributable by GitHub; signing can follow without changing it.
    - A second, independent reviewer identity, and fuzzing, static analysis and allowlist ratchets
      (ADR-0048).
    - The response to a deny-list hit (rewriting history, asking GitHub to purge caches, rotating a
      leaked credential): the operator's, and a credential's rotation is ADR-0045's verb.
    - Repositories other than homelab-next and the overlay.
    - The broker's approvals (ADR-0017, ADR-0044): a GitHub approval approves a change to a
      repository; a broker approval approves an action in the lab. Neither stands in for the other.

## Consequences

- "Never merge an overlay pull request" and "never start `deploy.yml`" become things the agents'
  token cannot do, rather than sentences an agent must remember, provided no agent environment
  still holds a route that acts as the operator (decision 1). The overlay's instruction file,
  README and CODEOWNERS comment are rewritten to agree with each other and with this ADR, by the
  operator's overlay pull request.
- The tiers start to bite. A pull request touching an operator-tier path waits for the operator;
  the rest merge without one, which is the operator's standing rule made exact. Throughput depends
  on how much of the work touches `/tools/`, `/orchestrator/` and `/conformance/`, kept wholly
  operator-tier in the first version. Narrowing them (for example to the gateway's TLP and key
  packages) is a later change to `review-tiers.yml`, itself operator-tier.
- A commit on homelab-next's `main` now proves merged with green checks, by the App or the
  operator, with the operator's approval wherever a tier required it. The pinned-commit doc's
  "proves merged, not reviewed" narrows to "reviewed where the tiers say so"; moving the pin is
  still an overlay pull request the operator reads and merges.
- In homelab-next, the operator can no longer merge their own change to a tier path without
  break-glass: GitHub does not count an author's approval. (The overlay has no review rule, so the
  operator's own overlay pull requests merge normally.) In practice the App authors and the
  operator approves; an operator-authored tier change is a ruleset edit that the governance check
  reports until it is undone.
- Agents lose the ability to re-run a failed CI job (no `actions: write`); a flaky job is re-run by
  a new push or by the operator.
- A leak in homelab-next is found within minutes of reaching GitHub instead of whenever a person
  next runs the scan, and the deny-list stops living in one workstation file. It is still found
  after it is public; the pre-push layer remains the one that prevents.
- Agents commit as the App. Today's convention (author the operator's handle, committer Claude) is
  replaced in this repository's agent instructions and the overlay's instruction file in step 7;
  the operator's `Signed-off-by:` trailer stays (decision 5).
- New obligations: one App and its key's custody; the rulesets kept equal to git; the governance
  check and the leak watch kept green; a release roughly monthly.
- `docs/private-overlay.md` ("Writers and reviews", "The pinned homelab-next commit", "The leak
  checks, both directions"), `docs/modules/contributes.md` ("Today the check is near-vacuous"),
  `CONTRIBUTING.md` (DCO, the label gate, changelog entries) and the CODEOWNERS header are
  rewritten with the steps below.

### Implementation plan

Each step is one pull request in this repository unless it says otherwise; overlay steps are the
operator's to merge.

1. **This ADR, the amendments and the operator's to-do.** ADR-0011 and ADR-0021 gain
   `Amended-by: ADR-0046` and their amendment notes; `TODO.md` §1 gains the stand-up items: create
   the App with decision 1's permissions and install it on the two repositories; put its key with
   the token mint; remove every route that acts as the operator's account from agent
   environments (tokens, `gh` logins, SSH and deploy keys, and hosted-session GitHub connectors and
   MCP servers authorised as the operator); verify whether the plan offers organisation
   required-workflow rules (decision 2); create the overlay's `leak-watch` Environment and identity
   and seal the deny-list (step 8); and decide the ADRs of decision 10. Applying the rulesets is
   step 7's item, not this one: applied earlier, the required checks would never report and every
   path would need the operator. *Tests:* the ADR log test (reciprocal
   amendments), the docs index and summaries checks.
2. **One source for the tiers.** `.github/review-tiers.yml`, `hnx governance codeowners`
   (generate and `--check`), `GOVERNANCE` read from it; CODEOWNERS output still begins with `*`,
   so nothing changes on GitHub yet. *Tests prove:* CODEOWNERS equals the render; every
   `GOVERNANCE` entry, every `kind: check` script under `tools/` and every schema is covered;
   removing a covered path fails; the generated file parses under GitHub's matching rules as
   `review_tier.py` reads them.
3. **`review-gate`.** The workflow and `hnx governance review-gate`, run from the base commit,
   with the module tier's "no owner" failure turned into "no approval". *Tests prove,* on recorded
   API responses: an approval on an older head is refused; the author's own approval is refused; a
   non-owner's is refused; a dismissed one is refused; an outside or Dependabot pull request needs
   approval on every path; a module docs change passes without one and a module egress change does
   not; an ADR status change to `accepted` needs one and a new `proposed` ADR does not; an edit to
   an accepted ADR's decision text needs one and an added `Amended-by:` line with its note does
   not; a commit whose git author string names the App but whose GitHub login does not is not the
   App's; a label applied before the head commit or by a non-owner does not count.
4. **`agent-reviews` and the DCO pair.** The job and the `dco` job's App rule. *Tests prove:* a
   missing or stale `hnx-review:` record fails; a `changes` verdict fails; a record by a user fails;
   an App commit signed off by anyone but `dco_delegate` fails; a user's commit with a `[bot]`
   address in a pull request the App did not open is not exempt.
5. **The credential preflight.** `github_identity.py` under `tools/` and its pre-push hook, shipped in warn
   mode until `TODO.md`'s App item is ticked, so it does not refuse every agent push before the App
   exists. *Tests prove:* each user-token prefix is refused, `ghs_` passes, an SSH remote is
   refused, a missing credential is a misconfiguration (exit 2), warn mode reports without
   refusing, and no output contains more of the token than its prefix class.
6. **Rulesets as code and the governance check.** `.github/rulesets/`, the overlay templates and
   `hnx governance check`, run from the lab (ADR-0049) with tokens from the mint;
   `docs/private-overlay.md` ("Writers and reviews") is rewritten to the overlay rulesets of
   decision 2 (the operator's merge is the review). *Tests prove,* on
   recorded API responses and a recorded mint permission record: an extra bypass actor, a wrong
   bypass mode, a missing required-workflow rule while `workflows: write` is held, a widened App
   permission, a repository secret, an `HNX_REF` variable and a missing `locks/hnx-ref` each fail
   with their own line; an exact match passes; the seven-day look-back flags an agent merge of a
   tier path without approval.
7. **Turn the rule on.** After the operator has done step 1's items and steps 3 to 6 have merged:
   CODEOWNERS drops `*` and `/modules/` lines, and its header says review is enforced; the agents'
   commit identity becomes the App's in this repository's agent instructions, and the operator's
   overlay pull request does the same in the overlay's instruction file. `TODO.md` gains the item:
   apply the rulesets (and the organisation required-workflow rule), in the same sitting as
   approving this step's CODEOWNERS change. *Proof:* the governance check passes against the live
   repository; a canary App pull request touching `.github/review-tiers.yml` shows GitHub's
   code-owner review as required, and a docs-only App pull request is mergeable with no review; a
   check run named `review-gate` posted from another branch's workflow does not satisfy the rule;
   an operator approval submitted after a failing `review-gate` run turns the required check green
   without a new push.
8. **The leak watch.** The `leak-watch.yml` template, the sealed deny-list path and its
   `.sops.yaml` rule in the overlay skeleton, and `private_leak_check.py` coverage of them; then
   the operator's overlay pull request adopting them. *Tests prove:* the template runs only the
   pinned `hnx` with `python -I`, never the scanned checkout's code; it holds no `pull_request`
   trigger; its job is in `leak-watch` with main-only deployment; it prints line numbers only; a
   planted term in a fixture repository's new commit, a backdated commit, a commit force-pushed
   away but named by a `PushEvent`, a pull request body, a release body and the tree of `main`
   each produce a hit; a known hit is not re-paged; a lost cache scans the full history;
   `private_leak_check.py private` fails when a second sealed file or `.sops.yaml` rule lists the
   `leak-watch` recipient.
9. **The changelog.** `check_changelog.py --base` and `--cadence`, then the rewrite of the long
   entries in its own pull request, then the release pull request for the next version. *Tests
   prove:* an added two-line or over-length entry fails, an unchanged long entry passes, an entry
   without a link fails, `--cadence` passes at 28 days and fails at 29 (with no page) and has no
   entry-count trigger; after the rewrite the file is under 200 KB.
10. **The operator decides decision 10's ADRs**; each accepted one is a status-line pull request
    that decision 3 routes to the operator's approval.

## Alternatives

- **A bot user with a fine-grained personal access token.** It works on any plan and is simpler to
  stand up, but the token lives up to a year, belongs to an account with a seat and a password, and
  cannot be minted per task. The App's installation tokens expire within an hour and are narrowed
  per request.
- **Keep the operator's token and harden the instruction files.** This is the status quo, and the
  audit's finding is that it is a convention: any agent that misreads or is misled by text can
  merge or deploy.
- **CODEOWNERS on every path (keep `*`) and have the operator approve everything.** This is the
  strictest, and it contradicts the operator's standing rule that agents merge green work; the
  review queue would become the bottleneck.
- **Environment required reviewers on the overlay's deploy.** They are not available for private
  repositories on Pro or Team ([private overlay](../private-overlay.md), "GitHub plans"), so the
  App's missing permissions are the control on any plan.
- **Trigger the leak watch from homelab-next on each push** (a `repository_dispatch` to the
  overlay). The public repository would have to hold a credential that can act on the private one,
  and its workflows run code from branches; a schedule in the private repository needs no such
  credential.
- **Run the leak watch with the newest homelab-next scanner.** The newest code is exactly what is
  under scan; running it with the decrypted deny-list would hand the list to any commit that
  changed the scanner.
