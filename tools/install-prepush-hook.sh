#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Install `make precheck` as the git pre-push hook of this clone or worktree, so nothing is pushed
# that CI's first job would refuse. A worktree shares its clone's hooks directory unless
# core.hooksPath says otherwise, so the hook is written where `git rev-parse --git-path hooks`
# points. An existing hook that is not this one is kept as pre-push.saved and run first.
# `git push --no-verify` skips the hook.
#
#   tools/install-prepush-hook.sh          install (or refresh) the hook (make prepush-hook)
#
# Environment:
#   PY   the interpreter the hook passes to make (default: python3)
#
# hnx-script:
#   id: install-prepush-hook
#   kind: tool
#   purpose: Install `make precheck` as the git pre-push hook of the clone or worktree it runs in.
#   owner: maintainers
#   trigger: [make:prepush-hook, manual]
#   inputs: PY; the clone's hooks directory (git rev-parse --git-path hooks)
#   outputs: <hooks>/pre-push (an existing foreign hook moved to pre-push.saved)
#   exit:
#     "0": installed
#     "1": not inside a git work tree
set -euo pipefail

top=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not inside a git work tree"; exit 1; }
cd "$top"
hooks=$(git rev-parse --path-format=absolute --git-path hooks)
mkdir -p "$hooks"
hook="$hooks/pre-push"
mark="# hnx: make precheck (tools/install-prepush-hook.sh)"
if [ -e "$hook" ] && ! grep -qF "$mark" "$hook"; then
  mv "$hook" "$hook.saved"
  echo "kept the existing hook as $hook.saved (it runs first)"
fi
py=${PY:-python3}
cat > "$hook" <<HOOK
#!/usr/bin/env bash
$mark
set -euo pipefail
here=\$(dirname "\$0")
if [ -x "\$here/pre-push.saved" ]; then "\$here/pre-push.saved" "\$@"; fi
cd "\$(git rev-parse --show-toplevel)"
exec make precheck PY="\${PY:-$py}"
HOOK
chmod +x "$hook"
echo "installed $hook: make precheck runs before every push (git push --no-verify skips it)"
