---
group: Changed
---
module `prometheus`: `ProbeDown` reads the HTTP probe job only, so a failing LLM completion probe pages once (`LlmProbeFailed`), not a second time as `ProbeDown`.
