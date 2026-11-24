---
group: Fixed
---
module `gitea`: git housekeeping no longer runs unbounded in the push path. The container's environment sets `gc.auto=0` (the `git gc --auto` of a receive-pack repacked a repository with 838 MiB of loose objects, an unbounded `pack-objects` that ran for hours and starved the web worker at the slice's MemoryHigh), `pack.threads=1`, `pack.windowMemory=256m` and `pack.deltaCacheSize=128m` in Gitea's `[git.config]`, and `[git.timeout] GC` 3600 s so Gitea's own scheduled repository GC can finish a large repository. Pinned by `tests/roles/test_gitea_git_limits.py`.
