---
group: Added
---
`openwebui` / core `open_webui`: optional web search through the lab's own metasearch service (`openwebui_web_search_id`, a registry row of capability `web-search`; `openwebui_web_search_result_count`, 1 to 20). Answers are made from the results' snippets: the web loader and the embedding of result pages are bypassed, so the chat container still reaches only the gateway, the identity provider and that service. Empty (the default) keeps web search off as before; the name stays reserved for extra settings.
