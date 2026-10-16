# Security policy

## Reporting a vulnerability

Please report privately through GitHub: **Security -> Report a vulnerability** on this repository
(private security advisories). Do not open a public issue for anything that could be exploited.
Include the affected version or commit, a minimal reproduction using synthetic data, and the
impact you expect.

You will get an acknowledgement within 7 days. We aim to triage within 14 days, and we follow a
**90-day** coordinated disclosure window from the report, shorter if a fix ships sooner and longer
only by agreement.

## Supported versions

The latest minor release receives fixes. Before `1.0`, only the most recent tagged release and
`main` are supported.

## What counts as a vulnerability

- Code in `homelabnext/` or `tools/` that allows injection, path traversal, unsafe deserialisation,
  or secret exposure.
- **A conformance test that passes a non-conforming implementation.** Swaps rely on these tests, so a
  false pass is a security bug, not only a quality bug.
- A leak-scanner pattern gap that lets an address, key or token shape through (please send the shape,
  not a real secret).
- A fake or example that teaches an unsafe pattern (for example a default credential).

Not in scope: weaknesses in third-party products that the contracts merely describe; report those to
the product's own project.

## Handling secrets and data

Never include real credentials, tokens, addresses or logs in a report. If you find that the
repository itself contains a real credential or identifier, report it privately as above so it can be
rotated and removed from history before disclosure.
