---
group: Changed
---
`cti-schedule-*` packs are rendered for the real lane (`cti_schedules.LANE = "real"`, the CLI default; digests re-pinned in `workflows/deploy.yml`): they no longer send `shadow: true`, so the StackStorm rules C01-C23, still `mode: shadow`, record exactly the request the live pipeline would receive, the parity evidence a promotion needs. `--lane shadow` renders the other lane.
