# OAuth 2.0 Security Best Current Practice (RFC 9700) and Resource Indicators (RFC 8707): summary

Sources: RFC 9700 (January 2025) https://www.rfc-editor.org/rfc/rfc9700; RFC 8707 https://www.rfc-editor.org/rfc/rfc8707. Summarized for this project.

- **Audience restriction.** Access tokens should be restricted to a specific resource server, so a token leaked from one service can't be replayed at another. RFC 8707 adds the `resource` parameter for this.
- **Sender-constrained tokens.** Bind tokens to the client with mTLS (RFC 8705) or DPoP (RFC 9449) to prevent replay of stolen tokens. Single-use token IDs (jti) at sensitive endpoints detect replay.
- **Least privilege.** Tokens should carry only the privileges needed for the specific action.
- **Short lifetimes and refresh token protection.** These limit the window of misuse.
- **Mapping to this project.** A reused jti → DENY (replay). Audience mismatch → DENY (confused deputy). An over-age token → DENY.
