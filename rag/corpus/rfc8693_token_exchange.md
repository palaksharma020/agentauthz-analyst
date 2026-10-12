# OAuth 2.0 Token Exchange (RFC 8693): summary for agent delegation

Source: IETF RFC 8693 (January 2020), https://www.rfc-editor.org/rfc/rfc8693. Summarized and paraphrased for this project.

- **Purpose.** A client exchanges one security token (the subject token) for another, for example to act on behalf of a user when calling a downstream service. The grant type is `urn:ietf:params:oauth:grant-type:token-exchange`.
- **Impersonation vs delegation.** In impersonation the new token is indistinguishable from the user's own token. In delegation the token keeps the user as subject but also records who is acting. For AI agents, delegation is preferred: an audit trail must show that an agent, not the human, performed the action.
- **The `act` (actor) claim.** It identifies the acting party, for example `{"sub":"u-1","act":{"sub":"agent-7"}}`. Nested `act` claims form a chain that shows prior actors. Only the outermost actor is the current one. A token with an agent caller but no `act` claim hides the agent's involvement.
- **`may_act` claim.** It lets a subject token declare which parties are allowed to act for the subject.
- **Audience and resource.** `audience` and `resource` parameters restrict where the new token can be used.
- **Security notes.** Exchanged tokens should be narrowly scoped and short-lived. The authorization server decides which exchanges to permit.
