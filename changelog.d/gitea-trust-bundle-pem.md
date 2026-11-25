---
group: Changed
---
`modules/gitea`: the OpenID Connect trust bundle (`tls/ca-bundle.pem`) separates its certificates with real line breaks; the first release wrote a literal backslash-n between the host's public roots and the lab CA, so a PEM reader lost the last public root and the lab CA.
