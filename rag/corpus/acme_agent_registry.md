# Acme Logistics: AI Agent Registry (status export)

Fictional organization used for this project. Generated from the agent registry on 2026-10-01. The IdP token cache can lag this registry by up to 24 hours, so the gateway must check this list on every agent call. A token claiming state=active does not override this list.

## Revoked or suspended agents (deny all tokens immediately)
Agent registry status. REVOKED or SUSPENDED (deny all tokens, IdP cache may lag): invoice-bot-07, returns-triage-12, slotting-optimizer-03, dock-scheduler-19.

| Agent ID | Status | Owner | Reason | Effective |
|---|---|---|---|---|
| invoice-bot-07 | REVOKED | u-2210 | Prompt-injection incident INC-4471: attempted payment.release outside delegation | 2026-09-28 |
| returns-triage-12 | REVOKED | u-3307 | Owner left the company; agent not re-homed | 2026-09-15 |
| slotting-optimizer-03 | REVOKED | u-1180 | Replaced by slotting-optimizer-04 | 2026-08-30 |
| dock-scheduler-19 | SUSPENDED | u-4412 | Under review: anomalous calls from unapproved region | 2026-09-30 |

## Active agents (sample)
| Agent ID | Type | Owner | Allowed MCP servers | Max scopes |
|---|---|---|---|---|
| inv-recon-03 | interactive | u-1042 | erp-mcp | orders:read, inventory:read |
| cust-support-03 | interactive | u-5531 | crm-mcp, mail-mcp | customers:read, email:send |
| ship-planner-05 | background | u-6181 | erp-mcp | orders:read, shipments:write |
| invoice-bot-08 | interactive | u-2210 | erp-mcp | orders:read, reports:read |
| audit-helper-11 | background | u-7001 | erp-mcp, crm-mcp | reports:read |

## Lifecycle rules
- Registering an agent requires an owner, a purpose and a maximum scope set (AL-1).
- Revocation takes effect at once in this registry. Gateways must reject tokens for revoked agents even if the token is still within its lifetime (AL-3).
- A suspended agent may be reinstated only by the Security On-Call after review.
