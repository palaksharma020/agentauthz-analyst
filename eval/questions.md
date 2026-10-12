# Evaluation questions

Ground-truth answers come from the rule engine in `data/build_dataset.py`. Regenerate with `python3 eval/make_questions.py`.

## Part A: Base vs fine-tuned (same 3 questions, no retrieval)

Asked in Colab notebook cell 6 (screenshots `03`–`05` side-by-side). In Terminal: `ollama run llama3.2:3b` vs `ollama run agentauthz`.

### Q1: Q1 human login: new country/ASN/browser at 03:00 after failures

```text
Assess this event and return the authorization decision as JSON.

EVENT:
{"event_type":"human_login","primary_credential":"valid","hour_local":3,"country":"BR","asn":"28573","browser_os":"Chrome 79.0 | Windows 10","device_type":"desktop","rtt_ms":742,"ip_reputation":"no_known_threat","history":{"prior_logins":37,"country_seen_before":false,"asn_seen_before":false,"browser_os_seen_before":false,"device_type_seen_before":true,"failed_attempts_24h":4}}
```

**Expected:** `STEP_UP` (risk 80). new country BR for this user; new network ASN 28573; new browser/OS combination; 4 failed attempts in last 24h

### Q2: Q2 agent: payment.release with no act claim and escalated scope

```text
Assess this event and return the authorization decision as JSON.

EVENT:
{"event_type":"agent_tool_call","user":{"id":"u-2210","roles":["finance_analyst"],"mfa_age_min":30},"agent":{"id":"invoice-bot-08","registered":true,"state":"active","owner":"u-2210","type":"interactive"},"token":{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","sub":"u-2210","act":null,"aud":"https://mcp.erp.example/","scopes":["orders:read","payments:write"],"age_min":5,"jti_seen_before":false},"delegated_scopes":["orders:read","reports:read"],"tool_call":{"mcp_server":"erp-mcp","tool":"payment.release","target_resource":"https://mcp.erp.example/","reversible":false,"data_sensitivity":"financial","records":1},"human_approval":"none","context":{"hour_local":10,"runtime_geo":"US","usual_geo":"US","delegation_depth":1}}
```

**Expected:** `DENY` (risk 99). token has sub=user but no act claim: impersonation, not delegation; token scopes exceed user delegation: payments:write; user role 'finance_analyst' is not entitled to payment.release; an agent cannot exceed its user; payment.release is irreversible and human approval is 'none'

### Q3: Q3 agent: external email (irreversible) with approval pending

```text
Assess this event and return the authorization decision as JSON.

EVENT:
{"event_type":"agent_tool_call","user":{"id":"u-5531","roles":["warehouse_manager"],"mfa_age_min":30},"agent":{"id":"cust-support-03","registered":true,"state":"active","owner":"u-5531","type":"interactive"},"token":{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","sub":"u-5531","act":{"sub":"cust-support-03"},"aud":"https://mcp.mail.example/","scopes":["email:send"],"age_min":5,"jti_seen_before":false},"delegated_scopes":["customers:read","email:send","orders:read"],"tool_call":{"mcp_server":"mail-mcp","tool":"email.send_external","target_resource":"https://mcp.mail.example/","reversible":false,"data_sensitivity":"internal","records":1},"human_approval":"pending","context":{"hour_local":10,"runtime_geo":"US","usual_geo":"US","delegation_depth":1}}
```

**Expected:** `STEP_UP` (risk 45). email.send_external is irreversible and human approval is 'pending'

## Part B: RAG questions (fine-tuned model + retrieved Acme policy)

In the LangFlow **Playground**, paste the whole block for each question: the question line, then `EVENT:` and the JSON (screenshots `11`–`13`). The question line steers retrieval to the right policy section.
Each question needs a fact that exists **only** in `rag/corpus/acme_*.md`. The fine-tuned model alone should get it wrong; with RAG it should be right and name the source.

| Q | FT alone (no context) | FT + RAG (Acme policy) | Fact only retrieval supplies |
|---|---|---|---|
| R1 | ALLOW | **DENY** | invoice-bot-07 is on the revoked list in `acme_agent_registry.md` |
| R2 | ALLOW | **STEP_UP** | Acme's PII limit is 50 records per call (`acme_agent_authorization_policy.md` §4) |
| R3 | STEP_UP | **ALLOW** | DE is an approved runtime region (`acme_agent_authorization_policy.md` §6) |

### R1: Is invoice-bot-07 allowed to read orders? (agent was revoked after an incident)

```text
Agent invoice-bot-07 wants to read orders. Is this agent still allowed to act?
EVENT: {"event_type":"agent_tool_call","user":{"id":"u-2210","roles":["finance_analyst"],"mfa_age_min":30},"agent":{"id":"invoice-bot-07","registered":true,"state":"active","owner":"u-2210","type":"interactive"},"token":{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","sub":"u-2210","act":{"sub":"invoice-bot-07"},"aud":"https://mcp.erp.example/","scopes":["orders:read"],"age_min":5,"jti_seen_before":false},"delegated_scopes":["orders:read","reports:read"],"tool_call":{"mcp_server":"erp-mcp","tool":"orders.read","target_resource":"https://mcp.erp.example/","reversible":true,"data_sensitivity":"internal","records":5},"human_approval":"none","context":{"hour_local":10,"runtime_geo":"US","usual_geo":"US","delegation_depth":1}}
```

**Expected with RAG:** `DENY`, sources ['acme_agent_registry.md']. agent 'invoice-bot-07' is listed as revoked in acme_agent_registry.md although the token says state=active (stale cache)

### R2: cust-support-03 looks up 80 customer PII records

```text
Agent cust-support-03 is looking up 80 customer PII records in one call. Is that within our bulk data policy?
EVENT: {"event_type":"agent_tool_call","user":{"id":"u-5531","roles":["warehouse_manager"],"mfa_age_min":30},"agent":{"id":"cust-support-03","registered":true,"state":"active","owner":"u-5531","type":"interactive"},"token":{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","sub":"u-5531","act":{"sub":"cust-support-03"},"aud":"https://mcp.crm.example/","scopes":["customers:read"],"age_min":5,"jti_seen_before":false},"delegated_scopes":["customers:read","email:send"],"tool_call":{"mcp_server":"crm-mcp","tool":"customer.lookup","target_resource":"https://mcp.crm.example/","reversible":true,"data_sensitivity":"pii","records":80},"human_approval":"none","context":{"hour_local":10,"runtime_geo":"US","usual_geo":"US","delegation_depth":1}}
```

**Expected with RAG:** `STEP_UP`, sources ['acme_agent_authorization_policy.md']. 80 pii records exceeds the 50-record agent limit in acme_agent_authorization_policy.md

### R3: ship-planner-05 runs from Germany instead of its usual US region

```text
Agent ship-planner-05 is running from region DE instead of its usual US. Is that runtime location approved?
EVENT: {"event_type":"agent_tool_call","user":{"id":"u-6181","roles":["warehouse_manager"],"mfa_age_min":30},"agent":{"id":"ship-planner-05","registered":true,"state":"active","owner":"u-6181","type":"interactive"},"token":{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","sub":"u-6181","act":{"sub":"ship-planner-05"},"aud":"https://mcp.erp.example/","scopes":["shipments:write"],"age_min":5,"jti_seen_before":false},"delegated_scopes":["orders:read","shipments:write"],"tool_call":{"mcp_server":"erp-mcp","tool":"shipment.update_eta","target_resource":"https://mcp.erp.example/","reversible":true,"data_sensitivity":"internal","records":3},"human_approval":"none","context":{"hour_local":10,"runtime_geo":"DE","usual_geo":"US","delegation_depth":1}}
```

**Expected with RAG:** `ALLOW`, sources ['acme_agent_authorization_policy.md']. runtime geo DE is an approved agent region in acme_agent_authorization_policy.md
