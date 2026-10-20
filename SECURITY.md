# Security policy

## Reporting a vulnerability

Please report privately through GitHub: **Security -> Report a vulnerability** on this repository
(private vulnerability reporting, which creates a private security advisory). Do not open a public
issue for anything that could be exploited.

This route works only while private vulnerability reporting is enabled in the repository settings
(**Settings -> Code security -> Private vulnerability reporting**); maintainers keep it switched on.
If the button is missing, open an issue that says only "security contact requested", with no
details, and a maintainer will reply with a private channel. There is no security e-mail address.
Include the affected version or commit, a minimal reproduction using synthetic data, and the
impact you expect.

You will get an acknowledgement within 7 days. We aim to triage within 14 days, and we follow a
**90-day** coordinated disclosure window from the report, shorter if a fix ships sooner and longer
only by agreement.

## Verifying a release

Each GitHub release is built once by `.github/workflows/release.yml` and carries a
build-provenance attestation and a CycloneDX SBOM. Verify a downloaded file with
`gh attestation verify <file> --repo <owner>/<repo>`.

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

## Trusted inputs (code execution by design)

Some inputs are code, or name code, and are run with the caller's privileges. Treat them like the
source tree itself: review them, keep them in version control, and never point these options at
files someone else can write. Running what they say is the feature, not a vulnerability:

- **`--plugins-dir DIR`** (`python -m homelabnext.invariants`): every `*.py` in `DIR` is imported.
  Entry points in the `homelabnext.invariants.checks` group are imported the same way.
- **Invariant observables**: a register row's `check` (in `invariants.yml` or any register file
  passed to the runner) is a command line that the runner executes, and `--notify-cmd` is run on a
  newly red criterion.
- **Register files** in general (`examples/registers/` and your own): they hold those commands and
  feed the generators, so a register file is as trusted as a script.
- **Conformance targets**: `hnx conform run --target FILE` and a binding of
  `{"adapter": "pkg.mod:factory"}` import and run the named adapter; `--root DIR` runs the suites
  found there.
- **Repository tools**: `hnx schema-check`, the scaffold checks and `hnx custom lint` execute files
  from `tools/`, and only from a verified source checkout of this project (`homelabnext.paths`).

A bug that makes one of these run something *other* than what the trusted input names (for
example a path traversal out of `--plugins-dir`, or data from an untrusted source reaching a
command line) is in scope.

## Scope of security testing

The security testing this project describes is internal and authorized: the operator testing their
own lab (see the README's "Scope of security testing"). Nothing here is for use against systems you
do not own or are not authorized to test.

## Handling secrets and data

Never include real credentials, tokens, addresses or logs in a report. If you find that the
repository itself contains a real credential or identifier, report it privately as above so it can be
rotated and removed from history before disclosure.
