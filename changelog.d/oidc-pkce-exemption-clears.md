---
group: Changed
---
The realm's PKCE exemption (`oidc.pkce: false`, schema 2.15) renders the client's `pkce.code.challenge.method` as an empty string instead of leaving the attribute out: the IdP merges client attributes on update, so an absent key kept a previous S256 requirement on a live client and the module's converge re-reported the client on every run.
