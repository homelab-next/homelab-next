---
group: Added
---
`modules/openwebui` concierge shim: a model entry can be a PERSONA. Beside `persona` and `context` it now takes `context_allowed` (the namespaces that model may read from the context service; entries the service-wide `openwebui_concierge_context_allowed` does not cover are refused at validation and ignored at run time, so a model narrows retrieval and never widens it), `context_top_k`, and `grounded` (when retrieval returns nothing, or the service is down, the model is told so and must not answer from memory as if it had read a source). A site adds a domain assistant (a tax or help-desk persona, say) as one more entry on a local tier, with its own scope; nothing else changes.
