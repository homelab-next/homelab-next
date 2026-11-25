---
group: Added
---
Service schema 2.15: `oidc.pkce: false` with a required `oidc.why` exempts one row's confidential client from the realm's PKCE-only rule (for a product whose OAuth2 login sends no code challenge); the realm generator refuses it on a public client, keeps the client's exact redirect URIs, and `hnx registry validate` prints a `note: pkce exemption` line for every one (ADR-0034, amendment 2026-11-25).
