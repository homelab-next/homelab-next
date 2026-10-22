#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: overlay-runner-job-started
#   kind: tool
#   purpose: Refuse every job on the self-hosted deploy runner except deploy.yml dispatched by hand on main of the one private repository.
#   owner: maintainers
#   trigger: [manual]
#   inputs: "env HNX_DEPLOY_REPOSITORY (owner/repo, set by the runner host) and the job's GITHUB_REPOSITORY, GITHUB_EVENT_NAME, GITHUB_REF, GITHUB_WORKFLOW_REF"
#   outputs: one line on stderr naming why a job was refused, or one line on stdout naming the accepted workflow
#   exit:
#     "0": the job is the manual deploy from main; it may run
#     "1": any other job; the runner fails it before its first step
#
# The runner's job-started hook (docs/private-overlay.md "The self-hosted runner").  Runner labels
# do not restrict which workflow a runner accepts: any workflow in the repository, on any branch
# or pull request, can name `runs-on: [self-hosted, hnx-deploy]`.  This hook is what does.  Install
# it outside the runner's own directory, owned by root and not writable by the runner user, and
# point the runner at it from the root-owned service environment, never from the runner's .env:
#
#   install -o root -g root -m 0755 job-started.sh /usr/local/libexec/hnx-deploy/job-started.sh
#   ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/libexec/hnx-deploy/job-started.sh
#   HNX_DEPLOY_REPOSITORY=<owner>/<private-repo>
#
# A runner whose hook fails fails the job ("Set up runner"), so a misconfigured hook refuses
# everything: it fails closed.
set -euo pipefail

refuse() {
  printf 'hnx-deploy runner: refusing this job: %s\n' "$1" >&2
  exit 1
}

want="${HNX_DEPLOY_REPOSITORY:-}"
[[ "$want" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || refuse "HNX_DEPLOY_REPOSITORY (owner/repo) is not set on the runner host"
[[ "${GITHUB_REPOSITORY:-}" == "$want" ]] \
  || refuse "repository '${GITHUB_REPOSITORY:-}' is not $want"
[[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" ]] \
  || refuse "event '${GITHUB_EVENT_NAME:-}': only a manual dispatch deploys"
[[ "${GITHUB_REF:-}" == "refs/heads/main" ]] \
  || refuse "ref '${GITHUB_REF:-}': only main deploys"
[[ "${GITHUB_WORKFLOW_REF:-}" == "$want/.github/workflows/deploy.yml@refs/heads/main" ]] \
  || refuse "workflow '${GITHUB_WORKFLOW_REF:-}' is not $want/.github/workflows/deploy.yml on main"
printf 'hnx-deploy runner: accepted %s\n' "$GITHUB_WORKFLOW_REF"
