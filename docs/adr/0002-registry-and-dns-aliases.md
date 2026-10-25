---
summary: 'A service registry plus DNS capability aliases are the only source of addresses; nothing hard-codes a host.'
---
# ADR-0002: The service registry and DNS capability aliases are the only source of addresses

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0003, ADR-0004, ADR-0007, `docs/interfaces.md`

## Context

Addresses are the dominant coupling in a grown lab. The same endpoint appears as a literal in
hundreds of scripts, role defaults and unit files, so changing one port or moving one service
becomes a repository-wide sweep, and a single missed literal with an unset-environment default
silently points at the old listener.

## Decision

1. `services.yml` is the single hand-written source of service facts: host, ports, internal and
   public name, auth mode, health URL, metrics endpoint, backup membership, dependencies,
   pinned version and `impl:` (the current product).
2. Every capability gets a DNS alias `<capability>.svc.example.internal` generated from the
   registry (and an `/etc/hosts` fallback). Consumers resolve the alias; a cutover or rollback
   is a CNAME change plus regeneration.
3. Reverse-proxy sites, uptime monitors, metrics targets, backup membership, keyring rows,
   systemd `Environment=` lines and the architecture pages are generated from the registry.
4. `tools/no_raw_endpoints.py` fails CI on any default or literal that names an address or a
   raw `host:port` outside `inventory/`, `services.yml` and the address plan.
5. The registry is data plus generators plus DNS records. It is never a running service.

## Consequences

- One file to edit per swap; migrating to new hardware becomes a sequence of DNS flips.
- The DNS server becomes more load-bearing: run several resolvers and keep the hosts-file
  fallback.
- Existing literals are migrated as files are touched, with the remaining count published as an
  invariant.

## Alternatives

A runtime registry service (Consul style): a new tier-0 dependency, and most consumers would
still need a client library and a redeploy. Rejected in favour of DNS, which every language
already speaks, and in favour of keeping the registry a file.
