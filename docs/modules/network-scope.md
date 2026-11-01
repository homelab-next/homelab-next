---
summary: 'Module manifest reference: the site''s network scope, its parts, the strict reader and how module egress and references are judged against it.'
summary_of: outline:sha256:bbfce5b29a8c6096
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: the network scope

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## The network scope

The site's addresses live in one place: the selection's `scope:` block, in the **private** overlay
(`lab/modules.yml`; seal the file with SOPS if its WAN addresses would hurt in a leak, as
[private overlay](../private-overlay.md) describes for `lab/site.yml`). The public repository carries
only the schema, the enforcement and fictional examples in the documentation ranges (RFC 5737's
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, RFC 3849's `2001:db8::/32` and RFC 9637's <!-- no-raw-endpoint: allow documentation ranges -->
`3fff::/20`).

```yaml
scope:
  trusted:
    wan: [203.0.113.32/29]                  # the lab's own public addresses (no-raw-endpoint: allow a documentation range)
    nets: [192.0.2.0/24, "2001:db8:30::/48"]  # its internal networks (no-raw-endpoint: allow a documentation range)
    tooling: [192.0.2.240/28]               # where the operator's own tooling runs from (no-raw-endpoint: allow a documentation range)
  target: [198.51.100.0/24, 192.0.2.0/24]   # what assessment tooling may touch (no-raw-endpoint: allow a documentation range)
  exclude:
    unattended_mutation: [192.0.2.1/32]     # no unattended job changes these (no-raw-endpoint: allow a documentation range)
    offensive: [192.0.2.0/28]               # never the target of offensive tooling; [] = none (no-raw-endpoint: allow a documentation range)
```

- **Entries.** Each part is a list of IPv4 or IPv6 addresses or CIDR networks. Quote an IPv6
  entry: YAML 1.1 reads an unquoted all-digit value such as `1:20:30` as a number. The schema and
  the loader match one pattern (`ENTRY_PATTERN` in `homelabnext/modules/scope.py`, from which the
  schema's `scope` object is generated): no zone id, no whitespace, no leading zeros, no IPv4
  written inside or embedded in IPv6 (mapped, compatible, NAT64; an IPv4 target is never inside an
  IPv6 network, so such an exclusion would exclude nothing), no IPv4 host bits. The loader
  (`scope_problems`, `parse_entry`) adds what a pattern cannot say: IPv6 host bits, `/0`, any
  network touching the unspecified, loopback, link-local, multicast or reserved blocks, a network
  listed twice, and in `trusted.*` a network broader than **/8 (IPv4) or /32 (IPv6)**: trusting
  more is a blind spot, not the lab. `target` has no floor. `trusted.wan` also refuses private,
  shared (RFC 6598) and unique-local space: the internet never sees the lab as one of those, so it
  is a typo for `trusted.nets`. It reports a wrong-typed or unknown part itself, without relying on
  the schema.
- **Empty and absent.** A part is non-empty, except an exclusion: `exclude.*: []` means "nothing
  excluded". An absent part is never read as empty: a module that requires it is refused.
- **Declared reads.** A module declares the parts it reads (`requires.scope`), and
  `homelabnext.modules.scope.scope_networks(site, module, part)`, the reader a module is meant to
  call, raises `ScopeUndeclared` for any other part; an absent, empty (unless an exclusion) or
  malformed part raises `ScopeMissing`, never an empty list. The API is **cooperative**: nothing
  stops code from reading `site["scope"]` or the low-level `_part_networks` directly, or from
  passing a module dict with an edited `requires`. What enforces the declaration today is review
  of the module's code and the loader's rule that every declared part is present; there is no
  sandbox between a module and the selection. The external data collector requires `trusted.wan`,
  so sessions from the lab's own WAN are dropped instead of reported, without a list of its own.
  It does not read `trusted.tooling`: the operator's own scanners and runners seen from outside are
  recorded like any other source (a site that wants one dropped lists it under `trusted.wan`).
- **Modules that read addresses.** The manifest has no "offensive", "mutating" or "acts on"
  marker, so the loader keys the rule on what a manifest declares, and fails closed: a module that
  requires any address part (`target` or any `trusted.*` part) must also require
  `exclude.offensive`, and `exclude.unattended_mutation` too unless it is attended. A module is
  **unattended unless every contribution kind it uses is inert** (`INERT_CONTRIBUTIONS`: docs,
  detections, lake tables, status sources, notify pairs); a service, a workflow pack, an MCP
  server, an invariant, an entry point, a preflight hook, a role, shared config, a scheduler job
  and every agent (each has a calendar or a trigger) can run with no human present, and a test ties
  the classification to the `platform/module` schema so a new kind counts as executable. The
  external data collector only filters on `trusted.wan`, but the manifest cannot say so, so it
  declares both exclusions and a site may set them to `[]`. A module acts only on
  `effective_targets(site, module)`: `target` minus those exclusions, per IP version; when the
  exclusions leave nothing it raises `ScopeMissing` ("nothing left after the exclusions"), never
  an empty list, which a caller could read as "unrestricted".
- **Addresses live here.** A module config default refuses an address literal (the schema's
  pattern, a dotted quad or `::`). A selection's string-valued config value (every type but
  `integer`, `duration_s` and `boolean`) refuses a site address (`address_literals`): an IPv6, hex
  or zero-padded address; any IPv4 address with a port, a prefix length, in brackets or in a URL,
  including an `inet_aton` short form there (`http://10.1/` is the octets 10, 0, 0, 1 and <!-- no-raw-endpoint: allow inet_aton short forms -->
  `10.20.5:8080` is 10, 20, 0, 5); and a plain dotted quad or 8 to 10 digit integer only when it is private or shared
  space. Let through: a plain global dotted quad and a plain short form (they read the same as a
  version), and unspecified, loopback, link-local, multicast, reserved and documentation addresses
  (bind addresses such as `0.0.0.0` and `[::]:8080`, labels such as `cafe::beef`). **Not scanned:**
  `integer`, `duration_s` and `boolean` keys. Their value is a number by schema, and any integer of
  2^24 or more is also an IPv4 address, so scanning them would refuse ordinary sizes; a module
  that reads an address out of an integer key is a defect in that module. An **external
  endpoint** (a public resolver, an NTP server) is a hostname or a `svc:` reference, never a
  literal; it is not part of the scope.
- **The public gate.** `tools/private_leak_check.py public` places the rule by **location**, not
  by format:
  - A site scope block may sit only at `SCOPE_BLOCK_PATHS`: the example site profiles
    (`examples/modules/sites/*.yml`) and the generated selection examples and negatives
    (`schemas/platform/{examples,negative}/module_selection.*.yml`). There the file is parsed
    strictly, after a size and depth bound (larger or deeper is refused before any parser sees
    it), every entry must be a string naming a documentation network (`scope-address`), the shape
    is the selection's with `scope` at the top level only (`scope-shape`: an unknown part, a key
    twice, an anchor or alias), and a file the parse refuses fails (`scope-unparsed`).
  - Everywhere, in **every file** the scanner reads (any suffix; CRLF and CR line ends are
    normalised first), two rules run and either one fails the file (`scope-address`):
    - **the parse pass:** a file that parses as JSON, TOML or YAML (by content, whatever the
      suffix; YAML only within the size and depth bounds) has every scalar, keys included, judged
      under any key whose resolved value is `scope` in any case, at any depth. An alias-spelled key,
      `? scope` with a comment, a CRLF `[scope]` header and a flow dedented anywhere are ordinary
      mappings here;
    - **the raw rule:** the raw text under every `scope` key is tokenised. A key is `scope` in
      any case, quoted or not: `scope:`, `[scope]`, `[[scope]]`, a dotted `scope.x` key followed
      by its own `:` or `=` (an attribute access or a call such as `scope.get(` is none), an
      assignment to a Python subscript such as `site["scope"]["target"]` (never a `==`
      comparison), a comment before the colon, the Markdown spellings `` `scope`: ``, `**scope**:`, `_scope_:`
      and a table row whose first cell is `scope`, and `scope =` at a line's start (TOML, INI)
      or spaced inside a TOML inline table. A call's keyword argument (`fixture(scope="module")`)
      and an HTML or XML attribute (`<th scope="row">`) are never keys. Keys are found again after
      decoding `\x`, `\u`, `\U`, escaped line breaks and HTML character references. The rule also
      reads what does not parse: Markdown prose and fences of any indent, length or info string,
      and each cell and textual output of a Jupyter notebook, joined from its per-line strings
      (both rules run on it). What a key holds is over-read: the rest of its line, every line
      indented deeper than the key's column, a value on the first later line with content, a
      quoted scalar or flow collection opened there through its close, and for a TOML header
      everything to the next header. A key's column is its first non-blank character, so an
      indented `scope = x` holds only the lines deeper than itself. A quoted or flow value on the key's line with nothing deeper
      is exactly that value, so the rest of a minified line is another key's. A YAML alias is
      followed to its anchor's last real definition (more than 256 aliases is itself a finding),
      and a value tagged as YAML binary fails.
    - **cost:** flow closers, anchors, TOML headers and line ends are indexed in one pass and no
      line is re-read per key. `test_the_raw_rule_grows_linearly` times ten shapes (among them
      the ones earlier versions were quadratic on) at n, 4n and 16n in CPU time
      (`time.process_time`, best of five, so a busy runner's other processes do not count) and
      allows at most 8x per 4x step; a quadratic shape grows 16x.

    An address-like token is an IPv6 address, a dotted quad in any numeric spelling, an integer
    of 2^24 or more in any YAML, TOML or C spelling, and an `inet_aton` short form of two or three
    parts that cannot be a version or a decimal: a hex part or a part over 255 (`81.2.17806`,
    `0x51.0x2458e`, also `1.300` or `3.14159`), or one in an address context (a prefix length such
    as `10.20/16`, a port, after `//` or `@`). Every other short form (`1.0`, `24.04`, `0.05`,
    `1.0.3`, and a bare `10.20`) is ignored, and a reading inside 0/8 never counts. Loopback,
    unspecified and link-local addresses name no site and are let through in both families, and
    an IPv6 form inside `::/96` is judged by its embedded IPv4 address, so `::` (a Python
    `[::-1]` slice, a C++ `Foo::bar`) is in 0/8; an IPv4-compatible or mapped form of a real
    address is still refused. The price of the integer and dotted-quad rules: an epoch, a byte
    size or a `YYYYMMDD` integer of 2^24 or more, and a four-part version (`1.0.0.0`), under a
    scope key are refused too. A page may show a block's shape with documentation addresses, so a doc-only block
    outside the allowlist is not judged for shape. A case variant of an allowlisted path is
    refused (`scope-shape`).
  - **Threat model.** The gate defends against an **accidental** commit of a real address in any
    ordinary format (YAML, JSON, TOML, Markdown, CRLF line ends, escapes, integer, hex,
    zero-padded and short spellings), and fails closed on what it cannot read. A **deliberately
    obfuscating** author is out of scope for a text gate and is review's to catch. Known non-goals:
    a hostname that resolves to the address it spells (`81-2-69-142.sslip.io`, `*.nip.io`), <!-- no-raw-endpoint: allow a non-goal example -->
    percent-encoded or ideographic dots, named HTML entities, Markdown backslash escapes or
    emphasis inside a number, and numbers spelt in words. Carriers no loader in this project
    reads as a scope are non-goals too: environment variables (`SCOPE_TARGET=` in `.env` or a
    shell), a CSV or TSV column headed `scope`, INI sections such as `[scope:lab]`, XML
    `<scope>` and HCL `scope {` blocks, YAML behind `//` comments or `>` blockquotes, a Markdown
    heading or bullet `scope` with the address on a later bullet, a TOML multi-line string inside
    a Markdown fence, and a notebook output that prints a scope's value without its key.
  - Parse-only layouts and the bounds. A few layouts only the parse pass reads (a YAML key
    spelled by an alias); in a YAML file over 256 KiB, or one nested deeper than the bounds
    anywhere, the parse pass does not run, so the raw rule alone judges it.
  - Not covered either: an address that is not under a scope key (a sibling key, plain prose) is
    `tools/leak_scan.py`'s, which ignores zero-padded and integer spellings; an integer below
    2^24 (it names no host); a version-like short form outside private space; a file the scanner
    cannot read as text (binary, over 5 MB), which `leak_scan` itself fails on.
- This block is the site's **network** scope. It is not `homelabnext.scope` ([scope guard](../scope.md)),
  which keeps writer tools off scratch targets by registry id.

**Specified, not implemented**:

- **Dynamic WAN sources.** `trusted.wan` may list `{source: <name>}` instead of a network: a WAN
  from DHCP or CGNAT, or a delegated IPv6 prefix that changes. The schema accepts it so freezing the
  shape later is additive; the loader refuses it ("dynamic WAN sources are specified, not
  implemented") until a reader resolves a source.
- **A module that reads `target`.** No example module does yet; the rule above and
  `effective_targets` are ready for the first one.
- **Acting on names.** A module that acts on hostnames or `svc:` references is outside the
  network scope: the scope holds networks only, and the manifest cannot say a module acts on a
  name (nor that it only filters on a part, an `acts_on` marker), so no rule here covers it.
