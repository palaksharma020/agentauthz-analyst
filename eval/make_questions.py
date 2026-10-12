#!/usr/bin/env python3
"""Regenerate eval/questions.json (base vs FT) and eval/rag_questions.json (RAG) with rule-engine answers."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "data"))
from build_dataset import TOKEN_EXCHANGE, USER_TEMPLATE, label_agent_event, label_login  # noqa: E402

# The real Acme values, as written in rag/corpus/acme_*.md (only retrieval can supply these).
ACME = {"revoked": {"invoice-bot-07", "returns-triage-12", "slotting-optimizer-03", "dock-scheduler-19"},
        "pii_limit": 50, "regions": ["DE", "IN", "US"],
        "approvers": {"payment.release": "Finance Controller", "email.send_external": "Comms Lead",
                      "record.delete": "Data Owner", "iam.grant_role": "IAM Change Board",
                      "customer.export": "Customer Privacy Officer"}}


def agent_event(uid, role, agent, tool, server, scopes, deleg, rev, sens, rec, appr, geo, usual, act=True):
    aud = f"https://mcp.{server}.example/"
    return {"event_type": "agent_tool_call",
            "user": {"id": uid, "roles": [role], "mfa_age_min": 30},
            "agent": {"id": agent, "registered": True, "state": "active", "owner": uid, "type": "interactive"},
            "token": {"grant_type": TOKEN_EXCHANGE, "sub": uid, "act": {"sub": agent} if act else None, "aud": aud,
                      "scopes": scopes, "age_min": 5, "jti_seen_before": False},
            "delegated_scopes": deleg,
            "tool_call": {"mcp_server": f"{server}-mcp", "tool": tool, "target_resource": aud, "reversible": rev,
                          "data_sensitivity": sens, "records": rec},
            "human_approval": appr,
            "context": {"hour_local": 10, "runtime_geo": geo, "usual_geo": usual, "delegation_depth": 1}}


def compact(e):
    return json.dumps(e, separators=(",", ":"))


q1 = {"event_type": "human_login", "primary_credential": "valid", "hour_local": 3, "country": "BR", "asn": "28573",
      "browser_os": "Chrome 79.0 | Windows 10", "device_type": "desktop", "rtt_ms": 742,
      "ip_reputation": "no_known_threat",
      "history": {"prior_logins": 37, "country_seen_before": False, "asn_seen_before": False,
                  "browser_os_seen_before": False, "device_type_seen_before": True, "failed_attempts_24h": 4}}
q2 = agent_event("u-2210", "finance_analyst", "invoice-bot-08", "payment.release", "erp",
                 ["orders:read", "payments:write"], ["orders:read", "reports:read"], False, "financial", 1, "none",
                 "US", "US", act=False)
q3 = agent_event("u-5531", "warehouse_manager", "cust-support-03", "email.send_external", "mail", ["email:send"],
                 ["customers:read", "email:send", "orders:read"], False, "internal", 1, "pending", "US", "US")
qs = [("Q1 human login: new country/ASN/browser at 03:00 after failures", q1, label_login(q1)),
      ("Q2 agent: payment.release with no act claim and escalated scope", q2, label_agent_event(q2)),
      ("Q3 agent: external email (irreversible) with approval pending", q3, label_agent_event(q3))]
(ROOT / "eval" / "questions.json").write_text(json.dumps(
    [{"id": f"Q{i}", "title": t, "prompt": USER_TEMPLATE.format(event=compact(e)), "expected": lab}
     for i, (t, e, lab) in enumerate(qs, 1)], indent=1))

rag = [("R1", "Is invoice-bot-07 allowed to read orders? (agent was revoked after an incident)",
        "Agent invoice-bot-07 wants to read orders. Is this agent still allowed to act?",
        agent_event("u-2210", "finance_analyst", "invoice-bot-07", "orders.read", "erp", ["orders:read"],
                    ["orders:read", "reports:read"], True, "internal", 5, "none", "US", "US")),
       ("R2", "cust-support-03 looks up 80 customer PII records",
        "Agent cust-support-03 is looking up 80 customer PII records in one call. Is that within our bulk data policy?",
        agent_event("u-5531", "warehouse_manager", "cust-support-03", "customer.lookup", "crm", ["customers:read"],
                    ["customers:read", "email:send"], True, "pii", 80, "none", "US", "US")),
       ("R3", "ship-planner-05 runs from Germany instead of its usual US region",
        "Agent ship-planner-05 is running from region DE instead of its usual US. Is that runtime location approved?",
        agent_event("u-6181", "warehouse_manager", "ship-planner-05", "shipment.update_eta", "erp",
                    ["shipments:write"], ["orders:read", "shipments:write"], True, "internal", 3, "none", "DE", "US"))]
(ROOT / "eval" / "rag_questions.json").write_text(json.dumps(
    [{"id": i, "title": t, "question": q, "event": compact(e), "chat_input": f"{q}\nEVENT: {compact(e)}",
      "expected_without_context": label_agent_event(e), "expected_with_acme_policy": label_agent_event(e, ACME)}
     for i, t, q, e in rag], indent=1))


def write_markdown():
    qs = json.loads((ROOT / "eval" / "questions.json").read_text())
    rq = json.loads((ROOT / "eval" / "rag_questions.json").read_text())
    L = ["# Evaluation questions", "",
         "Ground-truth answers come from the rule engine in `data/build_dataset.py`. Regenerate with `python3 eval/make_questions.py`.", "",
         "## Part A: Base vs fine-tuned (same 3 questions, no retrieval)", "",
         "Asked in Colab notebook cell 6 (screenshots `03`–`05` side-by-side). In Terminal: `ollama run llama3.2:3b` vs `ollama run agentauthz`.", ""]
    for q in qs:
        L += [f"### {q['id']}: {q['title']}", "", "```text", q["prompt"], "```", "",
              f"**Expected:** `{q['expected']['decision']}` (risk {q['expected']['risk']}). " + "; ".join(q["expected"]["reasons"]), ""]
    L += ["## Part B: RAG questions (fine-tuned model + retrieved Acme policy)", "",
          "In the LangFlow **Playground**, paste the whole block for each question: the question line, then `EVENT:` and the JSON "
          "(screenshots `11`–`13`). The question line steers retrieval to the right policy section.",
          "Each question needs a fact that exists **only** in `rag/corpus/acme_*.md`. The fine-tuned model alone should get it wrong; with RAG it should be right and name the source.", "",
          "| Q | FT alone (no context) | FT + RAG (Acme policy) | Fact only retrieval supplies |", "|---|---|---|---|",
          "| R1 | ALLOW | **DENY** | invoice-bot-07 is on the revoked list in `acme_agent_registry.md` |",
          "| R2 | ALLOW | **STEP_UP** | Acme's PII limit is 50 records per call (`acme_agent_authorization_policy.md` §4) |",
          "| R3 | STEP_UP | **ALLOW** | DE is an approved runtime region (`acme_agent_authorization_policy.md` §6) |", ""]
    for q in rq:
        w = q["expected_with_acme_policy"]
        L += [f"### {q['id']}: {q['title']}", "", "```text", q["chat_input"], "```", "",
              f"**Expected with RAG:** `{w['decision']}`, sources {w.get('sources')}. {w['reasons'][0]}", ""]
    (ROOT / "eval" / "questions.md").write_text("\n".join(L))


if __name__ == "__main__":
    write_markdown()
    for q in json.loads((ROOT / "eval" / "questions.json").read_text()):
        print(q["id"], q["expected"]["decision"])
    for q in json.loads((ROOT / "eval" / "rag_questions.json").read_text()):
        print(q["id"], q["expected_without_context"]["decision"], "->", q["expected_with_acme_policy"]["decision"])
