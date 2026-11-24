---
group: Fixed
---
Test flake: `test_events_bus_config_is_enforced_by_the_pinned_server` read `/connz` once right after opening its unauthenticated probe connection, before the server had registered it, so the `external-tools` CI job failed about half the time. It now polls `/connz` with a 10 s bound until the probe is listed; every assertion is unchanged.
