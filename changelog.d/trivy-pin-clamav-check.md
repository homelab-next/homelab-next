---
group: Fixed
---
role `trivy`: the pinned version moves to `0.76.2`; the vendor repository keeps only its newest build, so `0.76.1` no longer had an installation candidate and every new install failed. role `clamav`: a `--check` run on a host that does not have the package yet skips the freshclam service step (the unit does not exist until the real run installs it), instead of failing the check.
