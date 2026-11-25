---
group: Added
---
role `events_bus`: `events_bus_forward_logins`, SSH logins whose only power is a local TCP forward to the loopback-only bus (restricted key, a sshd Match block tested with `sshd -t`/`sshd -T` before it goes live, checked again by the health hook); module stackstorm: the bus forward (`stackstorm_events_forward_*`, unit `hnx-st2-events-tunnel.service`, host key pinned, the bridge ordered after it), so the event bridge can reach a bus on another host without a TLS listener.
