---
group: Added
---
`cti-pipeline`: an optional egress entry to the `web-search` slot (the collect stage's web search through the lab's metasearch service, the app's `SEARXNG_URL`); a site opts in with `grants.egress.cti-pipeline.worker: [..., svc:web-search]`. `hnx modules check` no longer requires an optional `svc:` target the site does not grant to exist in that site (it opens nothing there).
