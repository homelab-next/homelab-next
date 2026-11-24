---
group: Added
---
orchestration: a module job-unit set may declare `overlap: skip`: a session whose instance already has a run in progress answers `skipped` (exit 0) at once instead of waiting for the lock, so a scheduled job's next firing coalesces into the run in progress. Waiting held a controller slot while the attempt ceiling ran: hourly firings of a multi-hour job piled up, starved other agents and cut a run off mid-way when a waiter finally got the lock. The default stays `wait`.
