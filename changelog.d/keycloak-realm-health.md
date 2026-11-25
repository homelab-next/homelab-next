---
group: Fixed
---
modules/keycloak: the contributed health path is the site realm's discovery document (`/realms/:realm/...`, the realm the edge publishes), not the master realm's, which the edge refuses; a contributed `health.path` may name a site segment `:name` that the lab registry fills (registry equality compares the rest).
