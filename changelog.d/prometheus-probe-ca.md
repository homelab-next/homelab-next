---
group: Added
---
modules/prometheus: `prometheus_probe_ca_ref` makes the HTTP(S) probes trust a private CA beside the system roots (one bundle both probe modules name), so services on the lab's internal certificates are verified rather than refused; the probe exporter now reloads when its modules or that bundle change.
