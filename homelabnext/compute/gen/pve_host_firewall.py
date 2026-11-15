# SPDX-License-Identifier: Apache-2.0
"""The Proxmox node's own firewall: ``nodes/<node>/host.fw`` (``_nodes.yml`` ``host_firewall``).

The ``host-firewall`` baseline control binds ``nftables_host``, which refuses to run beside
``pve-firewall``; a hypervisor therefore has no host firewall at all unless PVE's own is configured.
PVE reads a node's rules from ``/etc/pve/nodes/<node>/host.fw``.  A node that declares
``host_firewall`` gets, under ``nodes/<node>/``:

* ``host.fw``: ``[OPTIONS]`` ``enable: 1`` and the ``[RULES]`` the node lets in: SSH (22) and the
  web interface and API (8006) from ``management``, ICMP from ``icmp``, the consoles (5900-5999)
  from ``console`` and the SPICE proxy (3128) from ``spice``, each only when declared, and
  corosync (5405-5412/udp) from ``cluster.peers`` only for a node in a multi-node cluster.  The
  inbound and outbound policy of a node is the datacenter's (``policy_in`` defaults to DROP,
  ``policy_out`` to ACCEPT; ``host.fw`` has no policy option), and none of this has any effect
  while the datacenter firewall is off: the apply script refuses both cases.
* ``hnx-host-firewall.sh``: run on the node as root.  ``apply`` arms a systemd timer that restores
  the previous file, then installs ``host.fw`` and restarts ``pve-firewall``; the file stays on
  only after ``confirm`` stops the timer.  ``rollback`` and ``status`` do what they say.
* ``hnx-host-firewall-run.sh``: run from the controller.  Copies both files over, runs ``apply``,
  checks the declared management ports answer from here (the one place that proves the controller
  is not locked out), and only then runs ``confirm``.  Any failure, or the controller losing the
  node, leaves the timer to restore the previous file.

Refusals, all before a file is written: a node declaring neither a source for 22 nor one for 8006
(the lock-out guard); ``any`` or a /0 for 22, 8006, the consoles or SPICE without
``allow_any_management: true``; unknown keys; a rule twice (also after zones resolve to the same
network); a zone that does not exist.
"""

from __future__ import annotations

from homelabnext.compute.loader import HF_MANAGEMENT, hf_is_wildcard
from homelabnext.compute.model import ComputeError, Fleet
from homelabnext.generators.safe import checked

from ._text import HEADER
from .firewall_rules import _rule_lines
from .node_notify import NODE_RE

#: one hypervisor node applies this output: ``hnx guests render --node`` may narrow it to one
PER_NODE = True

#: made of the node's ``_nodes.yml`` entry, not its guests (an empty node is no hazard)
RENDERS_GUESTS = False

#: (spec key, rule name, protocol, ports): the order the rules are written in
RULES = (
    ("ssh", "pve-ssh", "tcp", "22"),
    ("web", "pve-web", "tcp", "8006"),
    ("icmp", "pve-icmp", "icmp", None),
    ("console", "pve-console", "tcp", "5900:5999"),
    ("spice", "pve-spice", "tcp", "3128"),
    ("peers", "pve-corosync", "udp", "5405:5412"),
)


def _sources(spec: dict, key: str) -> list[str]:
    if key in HF_MANAGEMENT:
        return spec.get("management", {}).get(key, [])
    if key == "peers":
        return spec.get("cluster", {}).get("peers", [])
    return spec.get(key, [])


def check_spec(node: str, spec: dict) -> None:
    """The lock-out guard and the wildcard rule, again at render time: a fleet built by hand
    skips the loader, and a refusal must come before a file does."""
    where = f"node {node!r}: host_firewall"
    unknown = set(spec) - {
        "management",
        "icmp",
        "console",
        "spice",
        "cluster",
        "allow_any_management",
        "rollback_minutes",
    }
    if unknown:
        raise ComputeError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    if not _sources(spec, "ssh") and not _sources(spec, "web"):
        raise ComputeError(
            f"{where}: no management source for ssh (22) or web (8006); the node would be "
            "unreachable once the file is on (lock-out guard)"
        )
    if any(hf_is_wildcard(x) for x in _sources(spec, "peers")):
        raise ComputeError(f"{where}: cluster.peers are the cluster's nodes, never any or /0")
    if not spec.get("allow_any_management", False):
        for key in ("ssh", "web", "console", "spice"):
            if any(hf_is_wildcard(s) for s in _sources(spec, key)):
                raise ComputeError(
                    f"{where}: {key} is open to any address; name the sources or set "
                    "allow_any_management: true"
                )


def rule_lines(fleet: Fleet, node: str, spec: dict) -> list[str]:
    """The ``[RULES]`` lines, in the fixed order of :data:`RULES`; a rule twice is refused."""
    out: list[str] = []
    seen: dict[str, str] = {}
    for key, name, proto, ports in RULES:
        for src in _sources(spec, key):
            rule = {"name": name, "proto": proto, "source": src}
            if ports:
                rule["ports"] = ports
            try:
                lines = _rule_lines(fleet, rule, "IN")
            except ComputeError as exc:
                raise ComputeError(f"node {node!r}: host_firewall.{key}: {exc}") from None
            for line in lines:
                body = line.split(" # ", 1)[0]
                if body in seen:
                    raise ComputeError(
                        f"node {node!r}: host_firewall: the rule `{body}` is written twice "
                        f"({seen[body]} and {name})"
                    )
                seen[body] = name
                out.append(line)
    return out


def host_file(fleet: Fleet, node: str, spec: dict) -> str:
    check_spec(node, spec)
    L = [
        f"# {HEADER}",
        f"# {node}: /etc/pve/nodes/{node}/host.fw.  Inbound policy and the outbound policy are the",
        "# datacenter's (cluster.fw); a node file only carries the node's own allows.",
        "[OPTIONS]",
        "enable: 1",
        "log_level_in: nolog",
        "",
        "[RULES]",
    ]
    L += rule_lines(fleet, node, spec)
    return "\n".join(L) + "\n"


def check_ports(spec: dict) -> list[int]:
    """The management ports the controller must see answer, in port order."""
    return sorted(port for key, port in HF_MANAGEMENT.items() if _sources(spec, key))


# ------------------------------------------------------------------------------- the scripts
# Placeholders are @NAME@ words so shell braces need no escaping.  Every value substituted is
# validated before it gets here (node name, whole numbers) and passed through `checked`.

NODE_SCRIPT = r"""#!/bin/sh
# @HEADER@
# Node @NODE@: install the rendered host.fw behind a timed rollback.  Run as root, on the node:
#   hnx-host-firewall.sh [apply]   arm the rollback timer, install host.fw, restart pve-firewall
#   hnx-host-firewall.sh confirm   the controller still reaches the node: stop the timer
#   hnx-host-firewall.sh rollback  restore the previous file now (the timer runs this)
#   hnx-host-firewall.sh status
# Open the node's BMC console before the first apply (docs/compute-model.md, PVE host firewall).
# Environment: HNX_HEALTH_HOOK (an executable run with the node name after the restart; non-zero
# rolls back), HNX_HEALTH_UNITS (units that must be active, default "pveproxy pvedaemon
# pve-firewall"), and for a test HNX_UNIT_DIR, HNX_PVE_NODE_DIR, HNX_PVE_CLUSTER_FW, HNX_STATE_DIR.
set -eu
umask 077
NODE="@NODE@"
MINUTES="@MINUTES@"
UNIT="hnx-hostfw-rollback-@NODE@"
NODE_DIR="${HNX_PVE_NODE_DIR:-/etc/pve/nodes/$NODE}"
CLUSTER_FW="${HNX_PVE_CLUSTER_FW:-/etc/pve/firewall/cluster.fw}"
STATE_DIR="${HNX_STATE_DIR:-/var/lib/hnx/host-firewall-$NODE}"
UNIT_DIR="${HNX_UNIT_DIR:-/etc/systemd/system}"
HEALTH_UNITS="${HNX_HEALTH_UNITS:-pveproxy pvedaemon pve-firewall}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RULES="$HERE/host.fw"
TARGET="$NODE_DIR/host.fw"
PENDING="$STATE_DIR/pending"

usage() {
  echo "usage: $0 [apply | confirm | rollback | status]" >&2
  exit 2
}

restore() {
  # the file the node had before apply, or none if it had none; then make pve-firewall read it
  if [ -f "$STATE_DIR/host.fw.prev" ]; then
    cp "$STATE_DIR/host.fw.prev" "$TARGET.hnx-new"
    mv "$TARGET.hnx-new" "$TARGET"
  elif [ -f "$STATE_DIR/host.fw.absent" ]; then
    rm -f "$TARGET"
  else
    echo "$0: no record of the previous host.fw in $STATE_DIR; nothing restored" >&2
    return 1
  fi
  if ! pve-firewall restart; then
    echo "$0: pve-firewall did not restart after the restore; the pending marker is kept" >&2
    return 1
  fi
  rm -f "$PENDING"
  systemctl disable "$UNIT-boot.service" >/dev/null 2>&1 || true
  rm -f "$UNIT_DIR/$UNIT-boot.service"
}

rollback() {
  systemctl stop "$UNIT.timer" >/dev/null 2>&1 || true
  # a confirm that won the race removed the marker: a late timer must not undo a confirmed file
  if [ ! -f "$PENDING" ]; then
    echo "no host.fw change is pending; nothing to roll back"
    return 0
  fi
  restore
  echo "host.fw of $NODE rolled back"
}

armed() {
  [ -f "$PENDING" ] || systemctl is-active --quiet "$UNIT.timer" 2>/dev/null
}

fail_back() {
  echo "$0: $1; rolling back now" >&2
  rollback || echo "$0: ROLLBACK FAILED: restore $TARGET by hand (copy in $STATE_DIR)" >&2
  exit 1
}

apply() {
  [ -r "$RULES" ] || { echo "$0: $RULES not found next to this script" >&2; exit 1; }
  grep -qx 'enable: 1' "$RULES" || { echo "$0: $RULES does not set enable: 1" >&2; exit 1; }
  [ -d "$NODE_DIR" ] || { echo "$0: $NODE_DIR is not a node directory" >&2; exit 1; }
  if armed; then
    echo "$0: a change is already pending (confirm or rollback first)" >&2
    exit 1
  fi
  # host.fw is inert while the datacenter firewall is off, and its policy is the datacenter's
  if ! awk '/^\[/ { s = $0 } s == "[OPTIONS]" && /^enable:[ \t]*1[ \t]*$/ { ok = 1 }
            END { exit !ok }' "$CLUSTER_FW" 2>/dev/null; then
    echo "$0: the datacenter firewall is off ('enable: 1' under [OPTIONS] of $CLUSTER_FW)" >&2
    exit 1
  fi
  if awk '/^\[/ { s = $0 } s == "[OPTIONS]" && /^policy_in:[ \t]*(ACCEPT|REJECT)/ { bad = 1 }
          END { exit !bad }' "$CLUSTER_FW"; then
    echo "$0: the datacenter inbound policy is not DROP ($CLUSTER_FW)" >&2
    exit 1
  fi
  mkdir -p "$STATE_DIR"
  rm -f "$STATE_DIR/host.fw.prev" "$STATE_DIR/host.fw.absent"
  if [ -f "$TARGET" ]; then
    cp -p "$TARGET" "$STATE_DIR/host.fw.prev"
  else
    : > "$STATE_DIR/host.fw.absent"
  fi
  cp "$0" "$STATE_DIR/hnx-host-firewall.sh"
  : > "$PENDING"
  # arm BEFORE the change: if the timer cannot be set, nothing has changed
  if ! systemd-run --quiet --unit="$UNIT" --on-active="${MINUTES}m" \
      --description="hnx: restore host.fw of $NODE" \
      /bin/sh "$STATE_DIR/hnx-host-firewall.sh" rollback; then
    rm -f "$PENDING"
    echo "$0: could not arm the rollback timer; host.fw not touched" >&2
    exit 1
  fi
  # the transient timer does not survive a reboot: a boot-time unit, run only while the marker
  # exists, restores the previous file then
  cat > "$UNIT_DIR/$UNIT-boot.service" <<UNITEOF
[Unit]
Description=hnx: restore host.fw of $NODE if an apply was never confirmed
ConditionPathExists=$PENDING
After=pve-cluster.service
[Service]
Type=oneshot
ExecStart=/bin/sh $STATE_DIR/hnx-host-firewall.sh rollback
[Install]
WantedBy=multi-user.target
UNITEOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable "$UNIT-boot.service" >/dev/null 2>&1 || true
  cp "$RULES" "$TARGET.hnx-new" || fail_back "could not stage the new host.fw"
  mv "$TARGET.hnx-new" "$TARGET" || fail_back "could not install the new host.fw"
  grep -qx 'enable: 1' "$TARGET" || fail_back "the installed host.fw does not set enable: 1"
  pve-firewall compile >/dev/null || fail_back "pve-firewall cannot compile the ruleset"
  pve-firewall restart || fail_back "pve-firewall did not restart"
  for u in $HEALTH_UNITS; do
    systemctl is-active --quiet "$u" || fail_back "$u is not active"
  done
  if [ -n "${HNX_HEALTH_HOOK:-}" ]; then
    "$HNX_HEALTH_HOOK" "$NODE" || fail_back "the health hook failed"
  fi
  echo "note: PVE's built-in rules also let the datacenter 'management' set (by default the node's"
  echo "own network: $(pve-firewall localnet 2>/dev/null | tr '\n' ' ')) reach 22, 8006, 5900-5999 and 3128;"
  echo "these allows are additional, and a controller inside that network passes the check regardless"
  echo "host.fw of $NODE installed.  UNCONFIRMED: it is restored in $MINUTES minute(s) unless"
  echo "the controller reaches the node and runs: $0 confirm"
}

confirm() {
  if [ ! -f "$PENDING" ]; then
    echo "$0: no change is pending (already confirmed, or rolled back)" >&2
    exit 1
  fi
  systemctl stop "$UNIT.timer" || { echo "$0: could not stop $UNIT.timer; still armed" >&2; exit 1; }
  rm -f "$PENDING"
  systemctl disable "$UNIT-boot.service" >/dev/null 2>&1 || true
  rm -f "$UNIT_DIR/$UNIT-boot.service"
  echo "host.fw of $NODE confirmed; the previous file is kept in $STATE_DIR"
}

case "${1:-apply}" in
  apply) [ "$#" -le 1 ] || usage; apply ;;
  confirm) [ "$#" -eq 1 ] || usage; confirm ;;
  rollback) [ "$#" -eq 1 ] || usage; rollback ;;
  status)
    [ "$#" -eq 1 ] || usage
    if [ -f "$PENDING" ]; then echo "pending: rollback armed ($UNIT.timer)"; else echo "idle"; fi
    systemctl list-timers "$UNIT.timer" --no-pager 2>/dev/null || true ;;
  *) usage ;;
esac
"""

RUN_SCRIPT = r"""#!/bin/sh
# @HEADER@
# Node @NODE@: apply host.fw from the controller, with the controller as the judge of whether the
# node is still reachable.  Open the node's BMC console first.
#   hnx-host-firewall-run.sh SSH_TARGET [CHECK_HOST]
# SSH_TARGET is what ssh takes (user@address; key login, passwordless sudo); CHECK_HOST is the
# address the management ports are tried at (default: SSH_TARGET's host part).  The ports tried
# are @PORTS@.  This machine's address must be among the declared sources, or the check fails and
# the file is rolled back, which is the safe way for it to fail.
# Environment: HNX_VERIFY_HOOK (a command run with CHECK_HOST after the ports answer; non-zero
# rolls back), HNX_CHECK_TRIES (default 5), HNX_CHECK_SLEEP seconds between tries (default 3),
# HNX_PORT_CHECK (default "nc -z -w 5"), and HNX_HEALTH_HOOK, passed to the node's script as a
# path ON THE NODE.
set -eu
NODE="@NODE@"
PORTS="@PORTS@"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 SSH_TARGET [CHECK_HOST]" >&2
  exit 2
fi
TARGET="$1"
CHECK_HOST="${2:-${TARGET#*@}}"
TRIES="${HNX_CHECK_TRIES:-5}"
PAUSE="${HNX_CHECK_SLEEP:-3}"
PORT_CHECK="${HNX_PORT_CHECK:-nc -z -w 5}"
REMOTE="sudo -n"
[ -z "${HNX_HEALTH_HOOK:-}" ] || REMOTE="sudo -n env HNX_HEALTH_HOOK=$HNX_HEALTH_HOOK"

remote() {
  # shellcheck disable=SC2086
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" $REMOTE sh "$DIR/hnx-host-firewall.sh" "$1"
}

ports_answer() {
  for p in $PORTS; do
    # shellcheck disable=SC2086
    $PORT_CHECK "$CHECK_HOST" "$p" || return 1
  done
}

# a private directory made by this login (mode 700): root runs the script from it, so no other
# account on the node may be able to replace it between the copy and the run
DIR="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" 'mktemp -d /var/tmp/hnx-hostfw.XXXXXX')"
case "$DIR" in /var/tmp/hnx-hostfw.??????) ;; *) echo "$0: no scratch directory on the node" >&2; exit 1 ;; esac
cleanup() {
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$TARGET" "rm -rf $DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT
scp -q "$HERE/host.fw" "$HERE/hnx-host-firewall.sh" "$TARGET:$DIR/"

case " $PORTS " in
  *" 22 "*) ;;
  *) echo "$0: this runner works over SSH and no source for port 22 is declared; copy the files and run hnx-host-firewall.sh by hand" >&2; exit 1 ;;
esac

remote apply && rc=0 || rc=$?
if [ "$rc" -eq 255 ]; then
  echo "$0: the connection dropped during apply: host.fw may be ON and unconfirmed; its timer restores the previous file within @MINUTES@ minute(s)" >&2
  exit 1
elif [ "$rc" -ne 0 ]; then
  echo "$0: apply failed on the node (it rolls itself back); host.fw is as before" >&2
  exit 1
fi

n=0
ok=0
streak=0
while [ "$n" -lt "$TRIES" ]; do
  n=$((n + 1))
  # two passes in a row, after a pause: the first look can precede the reload
  sleep "$PAUSE"
  if ports_answer; then
    streak=$((streak + 1))
    [ "$streak" -ge 2 ] && { ok=1; break; }
  else
    streak=0
  fi
done

if [ "$ok" -eq 1 ] && [ -n "${HNX_VERIFY_HOOK:-}" ]; then
  # shellcheck disable=SC2086
  $HNX_VERIFY_HOOK "$CHECK_HOST" || ok=0
fi

if [ "$ok" -ne 1 ]; then
  echo "$0: @PORTS@ did not all answer from here; restoring the previous host.fw" >&2
  if remote rollback; then
    echo "rolled back" >&2
  else
    echo "$0: could not reach the node; its timer restores the previous host.fw within" \
      "@MINUTES@ minute(s); use the BMC console if it does not" >&2
  fi
  exit 1
fi

remote confirm || { echo "$0: confirm failed; the timer may still restore the previous host.fw" >&2; exit 1; }
echo "host.fw of $NODE is on and confirmed"
"""


def _sub(text: str, **kv: str) -> str:
    for k, v in kv.items():
        text = text.replace(f"@{k}@", v)
    return text


def scripts(node: str, spec: dict) -> dict[str, str]:
    node = checked(node, "node", "shell")
    ports = " ".join(str(p) for p in check_ports(spec))
    kv = {
        "HEADER": HEADER,
        "NODE": node,
        "MINUTES": str(int(spec["rollback_minutes"])),
        "PORTS": ports,
    }
    return {
        f"nodes/{node}/hnx-host-firewall.sh": _sub(NODE_SCRIPT, **kv),
        f"nodes/{node}/hnx-host-firewall-run.sh": _sub(RUN_SCRIPT, **kv),
    }


def readme(specs: dict[str, dict]) -> str:
    L = [f"<!-- {HEADER} -->", "# Hypervisor host firewalls", ""]
    if not specs:
        L.append("No node declares `host_firewall` in `_nodes.yml`.")
        return "\n".join(L) + "\n"
    L += [
        "Each node below gets `<node>/host.fw` (PVE's `/etc/pve/nodes/<node>/host.fw`) and two",
        "scripts. With the node's BMC console open, run `<node>/hnx-host-firewall-run.sh",
        "SSH_TARGET` from the controller: it installs the file behind a timed rollback, checks the",
        "management ports from here, and only then confirms. The datacenter firewall must be on",
        "(`enable: 1` in `cluster.fw`); the inbound and outbound policy are the datacenter's.",
        "",
        "| Node | SSH (22) from | Web/API (8006) from | Other | Rollback after |",
        "|---|---|---|---|---|",
    ]

    def cell(srcs: list[str]) -> str:
        return ", ".join(f"`{checked(s, 'source', 'markdown')}`" for s in srcs) or "none"

    for node, spec in specs.items():
        other = [
            label
            for key, label in (
                ("icmp", "ICMP"),
                ("console", "5900-5999"),
                ("spice", "3128"),
                ("peers", "corosync"),
            )
            if _sources(spec, key)
        ]
        L.append(
            f"| `{checked(node, 'node', 'markdown')}` | {cell(_sources(spec, 'ssh'))} "
            f"| {cell(_sources(spec, 'web'))} | {', '.join(other) or 'none'} "
            f"| {spec['rollback_minutes']} min |"
        )
    return "\n".join(L) + "\n"


def node_files(fleet: Fleet, node: str) -> dict[str, str]:
    spec = fleet.nodes[node]["host_firewall"]
    return {f"nodes/{node}/host.fw": host_file(fleet, node, spec), **scripts(node, spec)}


def render(fleet: Fleet) -> dict[str, str]:
    specs = {n: s["host_firewall"] for n, s in sorted(fleet.nodes.items()) if "host_firewall" in s}
    for node in specs:
        if not NODE_RE.match(node):
            raise ComputeError(
                f"node {node!r}: a node with a host firewall must have a name a guest can name"
            )
    out = {"nodes/README.md": readme(specs)}
    for node in specs:
        out.update(node_files(fleet, node))
    return out
