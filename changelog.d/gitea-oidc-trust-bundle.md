---
group: Changed
---
`modules/gitea`: with OpenID Connect on, the container trusts a bundle of the host's public roots and the lab CA (`tls/ca-bundle.pem`, new `gitea_system_ca_file`) instead of the lab CA alone, so an issuer behind the edge's public certificate verifies and the token exchange succeeds.
