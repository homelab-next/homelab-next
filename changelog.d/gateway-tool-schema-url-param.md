---
group: Fixed
---
gateway: a tool definition whose JSON Schema declares a parameter named `url` or `*_url` is no longer refused as "carries a URL" on local deployments; URL keys everywhere else (messages, options, response_format, metadata) and URL values hidden in a schema's `default`/`enum`/`const`/`examples` are still refused.
