---
group: Fixed
---
Log pipeline module: the aggregator removes its own stale listener socket (and only that path) at every start, so a hard reset or a kill no longer leaves it crash-looping on "Address already in use" with the lake receiving nothing; a liveness timer writes `vector_pipeline_*` textfile metrics (containers, restarts, status age, rows per route) and the monitoring module gains `LogPipelineContainerDown`, `LogPipelineCrashLooping`, `LogPipelineContainerUnhealthy`, `LogPipelineStatusStale`, `LogPipelineArchiveIntakeStalled` and `LogPipelineLivenessCheckStale` rules (the stalled archive stream pages within about 17 minutes). The compose application role accepts an `entrypoint` (a list of words).
