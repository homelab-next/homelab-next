#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: lab-bind-guard
#   kind: tool
#   purpose: Refuse to publish the lab beyond loopback unless asked and every credential is changed.
#   owner: lab-in-a-box
#   trigger: [make:lab-up, make:lab-broker, script:lab-smoke]
#   inputs: LAB_BIND and the credentials (environment, .env, .env.example), then the configuration docker compose resolves from them
#   outputs: the refusal reason on stderr
#   exit:
#     "0": safe to start
#     "3": the compose configuration could not be resolved (nothing was run)
#     "4": refused
#
# Lab-in-a-box bind guard: refuse to publish the stack beyond loopback unless the operator says so
# and every credential has been changed from its .env.example placeholder.
#
#   compose/lab-in-a-box/bind_guard.sh          # exit 0 ok, 3 cannot resolve, 4 refused
#   . compose/lab-in-a-box/bind_guard.sh; lab_bind_guard   # from another bash script
#
# Why: with LAB_BIND set to a routable address the stack publishes OpenBao in dev mode (known root
# token, no TLS), the object-store admin API (known token), and Trino, NATS, the catalog and ntfy
# with no authentication at all. Docker publishes ports through its own firewall rules,
# ahead of ufw or firewalld, so a host firewall does not cover them.
#
# Two passes, and both must pass:
#
# 1. Before docker is looked at (pure bash): every line of .env.example and .env must be blank, a
#    comment or a plain KEY=value. docker compose also accepts `export KEY=v`, `KEY = v`, an
#    indented line and `KEY: v`; a guard that skipped those fell back to the .env.example default
#    (loopback) while compose published wherever the line said, so a line this pass cannot read
#    is refused, never skipped. The values are then judged the way compose interpolates them: the
#    process environment first, then .env, then .env.example.
# 2. The resolved configuration: `docker compose config` (every profile, the same --env-file
#    arguments as `make lab-up` and smoke.sh) and `config --environment` for the values. Every
#    published port must be on loopback and no service may use the host network; otherwise the
#    acknowledgement and changed credentials are required, judged on what compose resolved (a
#    placeholder is what compose resolves from .env.example alone). This is what compose will do,
#    whatever the files look like. When it cannot be resolved (no docker compose, a compose too old
#    for `config --environment` (a recent Compose v2 has it), no python3, or config fails) the
#    guard exits 3: it never passes a configuration it has not seen. `lab_bind_guard_pass1` runs
#    the first pass alone.

LAB_GUARD_DIR="${LAB_GUARD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

# strip an inline comment or the quotes from a dotenv value
_lab_env_clean() {
  local v=$1
  case "$v" in
    \"*\"*) v=${v#\"}; v=${v%%\"*} ;;
    \'*\'*) v=${v#\'}; v=${v%%\'*} ;;
    *)
      v=${v%%[[:space:]]#*}
      v=${v%"${v##*[![:space:]]}"}
      ;;
  esac
  printf '%s' "$v"
}

# FILE: status 4 (and the reason) when a line is not blank, a comment or a plain KEY=value
_lab_env_file_syntax() {
  local file=$1 line n=0
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line=${line%$'\r'}
    case "$line" in
      "" | "#"*) continue ;;
    esac
    if ! [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      echo "lab-in-a-box: refusing: $file line $n is not a plain KEY=value line; docker compose" \
        "would apply it (export, spaces around '=', indentation, 'KEY: value') but this guard" \
        "cannot judge it. Write it as KEY=value." >&2
      return 4
    fi
  done <"$file"
  return 0
}

# FILE KEY: print KEY's value from a dotenv file (last assignment wins); status 1 when absent
_lab_env_file_value() {
  local file=$1 key=$2 line val="" found=1
  [ -f "$file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in
      "$key="*) val=${line#"$key="}; found=0 ;;
    esac
  done <"$file"
  [ "$found" -eq 0 ] || return 1
  _lab_env_clean "$val"
}

# KEY: the value docker compose would interpolate
_lab_effective() {
  local key=$1
  if [ -n "${!key+x}" ]; then
    printf '%s' "${!key}"
  elif ! _lab_env_file_value "$LAB_GUARD_DIR/.env" "$key"; then
    _lab_env_file_value "$LAB_GUARD_DIR/.env.example" "$key"
  fi
}

_lab_is_loopback() {
  case "$1" in
    "" | ::1 | "[::1]") return 0 ;;
    127.*)
      local rest=${1#127.}
      case "$rest" in
        *[!0-9.]* | *..* | .* | *.) return 1 ;;
      esac
      local dots=${rest//[0-9]/}
      [ "${#dots}" -eq 2 ]
      return
      ;;
  esac
  return 1
}

lab_bind_guard() {
  lab_bind_guard_pass1 || return $?
  _lab_resolved_guard
}

# pass 1 alone (no docker): the dotenv syntax, then the values as written; 0 or 4
lab_bind_guard_pass1() {
  _lab_env_file_syntax "$LAB_GUARD_DIR/.env.example" || return 4
  _lab_env_file_syntax "$LAB_GUARD_DIR/.env" || return 4
  _lab_bind_guard_values
}

# pass 1: the values as written (see the header)
_lab_bind_guard_values() {
  local bind ack key line example_value placeholders=""
  bind=$(_lab_effective LAB_BIND)
  _lab_is_loopback "$bind" && return 0
  ack=$(_lab_effective LAB_I_UNDERSTAND_UNAUTHENTICATED)
  if [ "$ack" != "1" ]; then
    echo "lab-in-a-box: refusing LAB_BIND=$bind: the stack is unauthenticated (OpenBao in dev mode" \
      "with a known root token, an unauthenticated query engine, bus and catalog) and docker's" \
      "port publishing bypasses the host firewall. Keep LAB_BIND on loopback, or set" \
      "LAB_I_UNDERSTAND_UNAUTHENTICATED=1 and replace every credential in .env." >&2
    return 4
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    key=${line%%=*}
    case "$key" in
      LAB_PORT_* | "#"* | "") continue ;;
      *PASSWORD* | *SECRET* | *TOKEN* | *_KEY | *_KEY_*) ;;
      *) continue ;;
    esac
    example_value=$(_lab_env_clean "${line#*=}")
    if [ "$(_lab_effective "$key")" = "$example_value" ]; then
      placeholders="$placeholders $key"
    fi
  done <"$LAB_GUARD_DIR/.env.example"
  if [ -n "$placeholders" ]; then
    echo "lab-in-a-box: refusing LAB_BIND=$bind while these still equal their .env.example" \
      "placeholder:$placeholders. Set real values in compose/lab-in-a-box/.env first." >&2
    return 4
  fi
  return 0
}

# pass 2: what docker compose resolves (see the header); 0 ok, 3 cannot resolve, 4 refused
_lab_resolved_guard() {
  if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "lab-in-a-box: cannot resolve the compose configuration: docker with the compose" \
      "plugin is required; nothing was run" >&2
    return 3
  fi
  local help
  help=$(docker compose config --help 2>/dev/null)
  if [[ "$help" != *--environment* ]]; then
    echo "lab-in-a-box: cannot resolve the compose configuration: this docker compose has no" \
      "'config --environment' (a recent Compose v2 is required); nothing was run" >&2
    return 3
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "lab-in-a-box: cannot judge the resolved compose configuration: python3 is required;" \
      "nothing was run" >&2
    return 3
  fi
  python3 -I -c "$_LAB_RESOLVED_JUDGE" "$LAB_GUARD_DIR"
}

# the judge of pass 2 (Python, read with the builtin read so no external command is needed)
read -r -d '' _LAB_RESOLVED_JUDGE <<'PY' || true
import json
import os
import re
import subprocess
import sys

lab = sys.argv[1]
CANNOT, REFUSED = 3, 4
CREDENTIAL = re.compile(r"^LAB_(?!PORT_).*(PASSWORD|SECRET|TOKEN|_KEY$|_KEY_)")
OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
LOOPBACK = re.compile(r"127(\.%s){3}|::1|\[::1\]" % OCTET)


def cannot(why):
    print(f"lab-in-a-box: cannot resolve the compose configuration ({why}); nothing was run",
          file=sys.stderr)
    sys.exit(CANNOT)


def compose(env_files, *args, env=None):
    argv = ["docker", "compose"]
    for f in env_files:
        argv += ["--env-file", f]
    argv += ["-f", os.path.join(lab, "docker-compose.yml"), "--profile", "*", "config", *args]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        cannot(exc.__class__.__name__)
    if proc.returncode != 0:
        cannot((proc.stderr.strip().splitlines() or ["no output"])[-1])
    return proc.stdout


def environment(text):
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            out[key] = value
    return out


example = os.path.join(lab, ".env.example")
files = [example] + [f for f in [os.path.join(lab, ".env")] if os.path.isfile(f)]
try:
    config = json.loads(compose(files, "--format", "json"))
except ValueError:
    cannot("config printed no JSON")
if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
    cannot("no services in the resolved configuration")
effective = environment(compose(files, "--environment"))
# the placeholders: what compose resolves from .env.example alone, with no LAB_ variable around
bare = {k: v for k, v in os.environ.items() if not k.startswith("LAB_")}
placeholders = environment(compose([example], "--environment", env=bare))

exposed = []
for name, svc in sorted(config["services"].items()):
    if str(svc.get("network_mode", "")) == "host":
        exposed.append(f"{name} (network_mode: host)")
    for port in svc.get("ports") or []:
        if not isinstance(port, dict):
            exposed.append(f"{name} {port!r}")
            continue
        host_ip = str(port.get("host_ip") or "")
        if not LOOPBACK.fullmatch(host_ip):
            exposed.append(f"{name} {host_ip or '*'}:{port.get('published', '?')}")
if not exposed:
    sys.exit(0)
shown = ", ".join(exposed[:6]) + (" ..." if len(exposed) > 6 else "")
if effective.get("LAB_I_UNDERSTAND_UNAUTHENTICATED") != "1":
    print(f"lab-in-a-box: refusing: the resolved compose configuration publishes {shown} beyond"
          " loopback and LAB_I_UNDERSTAND_UNAUTHENTICATED is not 1: the stack is"
          " unauthenticated, so keep every published port on loopback.", file=sys.stderr)
    sys.exit(REFUSED)
same = sorted(k for k, v in placeholders.items() if CREDENTIAL.search(k) and effective.get(k) == v)
if same:
    print(f"lab-in-a-box: refusing: the resolved compose configuration publishes {shown} beyond"
          f" loopback while these resolve to their .env.example placeholder: {' '.join(same)}."
          " Set real values in compose/lab-in-a-box/.env first.", file=sys.stderr)
    sys.exit(REFUSED)
print(f"lab-in-a-box: WARNING: publishing {shown}; the query engine, bus, catalog and notify"
      " services have no authentication and OpenBao runs in dev mode", file=sys.stderr)
PY

# run directly (not sourced): act as a command
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  lab_bind_guard
  exit $?
fi
