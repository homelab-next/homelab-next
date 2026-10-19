#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Lab-in-a-box bind guard: refuse to publish the stack beyond loopback unless the operator says so
# and every credential has been changed from its .env.example placeholder.
#
#   compose/lab-in-a-box/bind_guard.sh          # exit 0 ok, 4 refused
#   . compose/lab-in-a-box/bind_guard.sh; lab_bind_guard   # from another bash script
#
# Why: with LAB_BIND set to a routable address the stack publishes OpenBao in dev mode (known root
# token, no TLS), the object-store admin API (known token), and Trino, NATS, the catalog, ntfy and
# OpenFGA with no authentication at all. Docker publishes ports through its own firewall rules,
# ahead of ufw or firewalld, so a host firewall does not cover them.
#
# Values are resolved the way docker compose resolves them for interpolation: the process
# environment first, then .env, then .env.example. Pure bash (no external commands), so it runs
# before anything else is checked.

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
  echo "lab-in-a-box: WARNING: publishing on $bind; the query engine, bus, catalog, notify and" \
    "authz services have no authentication and OpenBao runs in dev mode" >&2
  return 0
}

# run directly (not sourced): act as a command
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  lab_bind_guard
  exit $?
fi
