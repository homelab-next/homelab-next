---
group: Added
---
module `context`: a `documents` source kind indexes the document store's documents in place, by tag, through its REST API (endpoint from the registry, API token from the secret store, explicit Host header and lab CA supported, bounded requests, no redirects followed). Ids are `<kind>:<source>/<doc id>-<slug>`; an unchanged document is not embedded again and a deleted or untagged one is removed. The documents are never copied into a git repository.
