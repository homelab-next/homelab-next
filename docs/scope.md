---
summary: 'The scope guard writer tools call before writing about a target, so throwaway or scratch targets are skipped: policy as data, resolution then decision.'
summary_of: outline:sha256:a6271f679ee1cd0d
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Scope guard for writer tools

Tools that write a task, a note or a finding about a target (a guest, a service) must not do so for
throwaway or scratch targets; the noise buries the real work. `homelabnext.scope` is the check they
call **before** writing.

```python
guard = ScopeGuard(targets_from_fleet(fleet), ScopePolicy.from_file("scope.yml"))


@guarded(guard, target_arg="target", tool="task-writer", sink=publish_event)
def write_task(target, title): ...
```

`guard.in_scope(ref)` returns a `Decision(allow, target, canonical, code, reason)`; `guard.require(ref)`
raises `ScopeDenied`. A denied tool body never runs; the wrapper returns
`{"ok": False, "denied": {...}}` (or raises with `on_deny="raise"`) and hands the sink a
`homelabnext.scope.denied` event (`schemas/events/scope.denied.schema.json`).

## The policy is data

On the target (guest file 1.1, service registry 1.1): `scope: in | out`. In a policy mapping:

```yaml
scope_policy:
  unknown: deny             # fail closed (default); `allow` is an explicit choice
  vmid_threshold: 9000      # vmid ABOVE this is out; equal is in
  out_tags: [lab, scratch]  # any of these tags -> out
  overrides: {guest:keep-me: in}   # per canonical id; beats everything
```

Precedence, first match wins: `overrides` > the host's decision (for a service) > the target's
own `scope` > `vmid_threshold` / `out_tags` > allow. A service runs on the guest named like its
host and inherits that guest's vmid and tags. The host is decided first, so a service can only
**narrow** its host's scope: `scope: out` on a service of an in-scope host takes it out, but
`scope: in` on a service of a host that is out (by its own `scope`, the threshold, a tag or an
override) is still out. Only a policy override naming the service itself beats the host.

## Resolution first, decision second

Every reference is resolved to one canonical logical id before anything is decided: the id itself,
the guest hostname, FQDN, address, `vmid:<n>`, any registered alias, and (optionally) an
`homelabnext.ids` resolver. Case and a trailing dot are normalised, and an address is put in its
one canonical spelling: IPv6 compressed; an IPv4 address written inside IPv6 (IPv4-compatible,
IPv4-mapped, IPv4-translated, NAT64's RFC 6052 well-known prefix) as that IPv4 address; an IPv4
address in hex, octal, integer or short dotted form (what `inet_aton` accepts) as its dotted quad.
A guest's targets carry every address it has (`network.ip` and its `network.extra_addresses`). A
reference that resolves to nothing is denied (`unknown-target`); one that matches two different
targets is denied (`ambiguous-target`) even under `unknown: allow`, and so is an address in any
but its canonical spelling that resolves to nothing, as is NAT64's local-use prefix, whose IPv4
reading depends on the operator's prefix length. A different spelling of an out-of-scope target
therefore cannot slip past the guard.

Denial codes: `explicit-out`, `override-out`, `vmid-threshold`, `out-tag`, `unknown-target`,
`ambiguous-target`. Tests: `pytest tests/scope`.
