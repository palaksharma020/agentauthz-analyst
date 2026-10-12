# Model Context Protocol (MCP) Authorization: summary

Source: MCP specification, Authorization section (2025 revisions), https://modelcontextprotocol.io/specification. Summarized for this project.

- MCP servers that expose tools over HTTP act as **OAuth 2.1 resource servers**. MCP clients (agents or hosts) obtain access tokens from an authorization server.
- Clients include a **resource indicator (RFC 8707)** that names the MCP server the token is for. Servers **must validate that the token's audience is themselves** and reject tokens issued for other resources.
- **Token passthrough is forbidden.** An MCP server must not accept a token meant for another service and forward it downstream. This prevents confused-deputy attacks and preserves accountability.
- Servers publish protected resource metadata (RFC 9728) so clients can discover the authorization server.
- Least privilege: request only the scopes needed for the tool being called. Use short-lived tokens.
