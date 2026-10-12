# Acme Logistics: Agent Authorization Policy v3.2

Fictional organization used for this project. Owner: Security Architecture. Applies to every AI agent that calls internal tools through MCP servers on behalf of a user.

## Section 1 Identity and delegation
Agents must present a token obtained by OAuth token exchange (RFC 8693) whose `sub` is the human user and whose `act.sub` is the registered agent ID. Tokens without an `act` claim are impersonation tokens and are rejected. The maximum delegation chain depth is 2 (user → agent → sub-agent).

## Section 2 Token lifetime
Agent access tokens live at most 15 minutes. Tokens older than 60 minutes are rejected outright. A token ID (jti) may be used only once per tool call.

## Section 3 Scopes
The scopes in an agent token must be a subset of the scopes the user delegated, and the user must hold the role that the tool requires. An agent can never do more than its user.

## Section 4 Bulk data
An agent may read at most 50 PII or financial records in one call. Above 50 records, the call is stepped up and the Data Owner must approve. customer.export is always stepped up to the Customer Privacy Officer.

## Section 5 Irreversible actions (Verify and Act)
These tools need recorded human approval before they run. Pending approval means STEP_UP, not ALLOW.
| Tool | Approver |
|---|---|
| payment.release | Finance Controller |
| email.send_external | Comms Lead |
| record.delete | Data Owner |
| iam.grant_role | IAM Change Board |
| customer.export | Customer Privacy Officer |

## Section 6 Runtime location
Agents may execute only in approved regions: US, IN, DE. A runtime region different from the agent's usual region is allowed without step-up if it is approved. Any other region requires step-up and a Security On-Call ticket.

## Section 7 Background agents
Background (long-running) agents rely on the user's last MFA. If that MFA is older than 12 hours, the next sensitive call is stepped up for user reauthentication.

## Section 8 Human logins
A login from a new country together with a new network (ASN) is stepped up to phishing-resistant MFA. A login from an IP on the threat-intel attack list is denied, and the account is flagged for a password reset.
