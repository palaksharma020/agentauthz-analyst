#!/usr/bin/env python3
"""Build the AgentAuthZ training set (stdlib only, Python 3.9+).

Two sources, one output schema:
  1. REAL-WORLD-DERIVED human login events from the RBA dataset (Wiefling et al.,
            33M SSO login attempts, Norway 2020-21, values synthesized by the authors
            to preserve real distributions; CC BY 4.0; zenodo.org/records/6782156).
  2. SYNTH  AI-agent delegation / MCP tool-call events from a seeded generator.

Each event is labeled by a transparent rule engine (ALLOW / STEP_UP / DENY)
that also emits the reasons and the controls it relied on. That target JSON
is what the model learns to produce.

Usage:
  python3 data/build_dataset.py --rba data/raw/rba-dataset.csv
  python3 data/build_dataset.py --synthetic-only        # no RBA file yet
"""
import argparse
import collections
import csv
import hashlib
import json
import random
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEED = 7

SYSTEM_PROMPT = (
    "You are AgentAuthZ, an identity security analyst. You receive one "
    "authentication or authorization event: either a human login or an AI agent "
    "acting on behalf of a user (OAuth token exchange / MCP tool call). "
    "Return ONLY a JSON object with keys in this order: checks (result of each "
    "security check on the event), decision (ALLOW | STEP_UP | DENY), risk (0-100), "
    "reasons (list of short strings), controls (standards or controls applied), "
    "and sources (files used) when CONTEXT is provided."
)
USER_TEMPLATE = "Assess this event and return the authorization decision as JSON.\n\nEVENT:\n{event}"

DECISIONS = ("ALLOW", "STEP_UP", "DENY")


def target_json(label):
    """Serialize with `checks` first: the model must evaluate every signal before it decides."""
    order = ["checks", "decision", "risk", "reasons", "controls", "sources"]
    return json.dumps({k: label[k] for k in order if k in label}, ensure_ascii=False)


def to_example(event, label, source):
    return {
        "source": source,
        "decision": label["decision"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_TEMPLATE.format(event=json.dumps(event, separators=(",", ":")))},
            {"role": "assistant", "content": target_json(label)},
        ],
    }


# ---------------------------------------------------------------------------
# 1. Synthetic agent-delegation events
# ---------------------------------------------------------------------------

# tool -> (required scope, reversible, data sensitivity, roles allowed to perform it)
TOOLS = {
    "orders.read":          ("orders:read",     True,  "internal",  None),
    "inventory.query":      ("inventory:read",  True,  "internal",  None),
    "report.generate":      ("reports:read",    True,  "internal",  None),
    "shipment.update_eta":  ("shipments:write", True,  "internal",  {"warehouse_manager", "admin"}),
    "customer.lookup":      ("customers:read",  True,  "pii",       {"warehouse_manager", "finance_analyst", "finance_approver", "admin"}),
    "customer.export":      ("customers:export", True, "pii",       {"admin"}),
    "email.send_external":  ("email:send",      False, "internal",  {"warehouse_manager", "finance_approver", "admin"}),
    "record.delete":        ("records:delete",  False, "internal",  {"admin"}),
    "payment.release":      ("payments:write",  False, "financial", {"finance_approver"}),
    "iam.grant_role":       ("iam:admin",       False, "internal",  {"iam_admin"}),
}
# role -> scopes the user may delegate
ROLE_SCOPES = {
    "viewer":            {"orders:read", "inventory:read", "reports:read"},
    "warehouse_manager": {"orders:read", "inventory:read", "reports:read", "shipments:write", "customers:read", "email:send"},
    "finance_analyst":   {"orders:read", "reports:read", "customers:read"},
    "finance_approver":  {"orders:read", "reports:read", "customers:read", "payments:write", "email:send"},
    "admin":             {"orders:read", "inventory:read", "reports:read", "shipments:write", "customers:read",
                          "customers:export", "email:send", "records:delete"},
    "iam_admin":         {"reports:read", "iam:admin"},
}
AGENT_NAMES = ["inv-recon", "ship-planner", "cust-support", "invoice-bot", "dock-scheduler",
               "returns-triage", "po-assistant", "audit-helper", "slotting-optimizer", "onboarding-agent"]
GEOS = ["US", "US", "US", "IN", "DE", "GB", "NL"]
RESOURCES = {"erp": "https://mcp.erp.example/", "crm": "https://mcp.crm.example/",
             "mail": "https://mcp.mail.example/", "iam": "https://mcp.iam.example/"}
TOOL_SERVER = {"orders.read": "erp", "inventory.query": "erp", "report.generate": "erp",
               "shipment.update_eta": "erp", "customer.lookup": "crm", "customer.export": "crm",
               "email.send_external": "mail", "record.delete": "erp", "payment.release": "erp",
               "iam.grant_role": "iam"}
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

C_ACT = "RFC 8693 token exchange (act claim / delegation)"
C_AUD = "RFC 8707 resource indicators + MCP authorization (audience validation)"
C_LP = "Least privilege: agent scopes <= delegated <= user entitlements"
C_LLM06 = "OWASP LLM06:2025 Excessive Agency"
C_BCP = "RFC 9700 OAuth 2.0 Security BCP (replay, token lifetime)"
C_LIFE = "Agent lifecycle: registration and revocation"
C_HITL = "Human-in-the-loop: Verify & Act for irreversible actions"
C_REAUTH = "NIST SP 800-63B reauthentication / step-up"
C_DATA = "Data sensitivity: bulk PII / financial export controls"
C_CTX = "Contextual risk: geo / time anomaly"


def clean_agent_event(rng):
    role = rng.choice(list(ROLE_SCOPES))
    allowed = sorted(ROLE_SCOPES[role])
    candidate_tools = [t for t, (s, _, _, roles) in TOOLS.items()
                       if s in ROLE_SCOPES[role] and (roles is None or role in roles)]
    tool = rng.choice(candidate_tools)
    scope, reversible, sensitivity, _ = TOOLS[tool]
    delegated = sorted(set(rng.sample(allowed, k=min(len(allowed), rng.randint(1, 3)))) | {scope})
    uid = f"u-{rng.randint(1000, 9999)}"
    aname = f"{rng.choice(AGENT_NAMES)}-{rng.randint(1, 20):02d}"
    agent_type = rng.choice(["interactive", "interactive", "background"])
    geo = rng.choice(GEOS)
    server = TOOL_SERVER[tool]
    return {
        "event_type": "agent_tool_call",
        "user": {"id": uid, "roles": [role], "mfa_age_min": rng.randint(2, 240)},
        "agent": {"id": aname, "registered": True, "state": "active", "owner": uid, "type": agent_type},
        "token": {
            "grant_type": TOKEN_EXCHANGE, "sub": uid, "act": {"sub": aname},
            "aud": RESOURCES[server], "scopes": [scope], "age_min": rng.randint(1, 15),
            "jti_seen_before": False,
        },
        "delegated_scopes": delegated,
        "tool_call": {
            "mcp_server": f"{server}-mcp", "tool": tool, "target_resource": RESOURCES[server],
            "reversible": reversible, "data_sensitivity": sensitivity,
            "records": rng.choice([1, 1, 3, 12, 40]),
        },
        "human_approval": "approved" if not reversible else "none",
        "context": {"hour_local": rng.randint(8, 18), "runtime_geo": geo, "usual_geo": geo, "delegation_depth": 1},
    }


# Fault injectors: each mutates an event toward a risky scenario.
def f_revoked(e, r): e["agent"]["state"] = r.choice(["revoked", "suspended"])
def f_unregistered(e, r): e["agent"]["registered"] = False
def f_no_act(e, r): e["token"]["act"] = None  # gateway normalizes absent claims to explicit null
def f_wrong_actor(e, r): e["token"]["act"] = {"sub": f"{r.choice(AGENT_NAMES)}-{r.randint(21, 40)}"}
def f_wrong_aud(e, r):
    other = [v for v in RESOURCES.values() if v != e["tool_call"]["target_resource"]]
    e["token"]["aud"] = r.choice(other)
def f_scope_escalation(e, r):
    extra = r.choice(["payments:write", "iam:admin", "records:delete", "customers:export"])
    e["token"]["scopes"] = sorted(set(e["token"]["scopes"]) | {extra})
def f_replay(e, r): e["token"]["jti_seen_before"] = True
def f_deep_chain(e, r): e["context"]["delegation_depth"] = r.randint(3, 5)
def f_old_token(e, r): e["token"]["age_min"] = r.randint(90, 1440)
def f_role_exceeded(e, r):
    # Agent asks for a tool the user's role cannot perform (and the scope rides along).
    role = e["user"]["roles"][0]
    bad = [t for t, (s, _, _, roles) in TOOLS.items() if roles is not None and role not in roles]
    if not bad:
        return
    tool = r.choice(bad)
    scope, rev, sens, _ = TOOLS[tool]
    server = TOOL_SERVER[tool]
    e["tool_call"].update(tool=tool, mcp_server=f"{server}-mcp", target_resource=RESOURCES[server],
                          reversible=rev, data_sensitivity=sens)
    e["token"]["aud"] = RESOURCES[server]
    e["token"]["scopes"] = [scope]
    e["delegated_scopes"] = sorted(set(e["delegated_scopes"]) | {scope})
def f_irreversible_no_hitl(e, r):
    role = e["user"]["roles"][0]
    opts = [t for t, (s, rev, _, roles) in TOOLS.items()
            if not rev and s in ROLE_SCOPES[role] and (roles is None or role in roles)]
    if not opts:
        return
    tool = r.choice(opts)
    scope, rev, sens, _ = TOOLS[tool]
    server = TOOL_SERVER[tool]
    e["tool_call"].update(tool=tool, mcp_server=f"{server}-mcp", target_resource=RESOURCES[server],
                          reversible=rev, data_sensitivity=sens)
    e["token"].update(aud=RESOURCES[server], scopes=[scope])
    e["delegated_scopes"] = sorted(set(e["delegated_scopes"]) | {scope})
    e["human_approval"] = r.choice(["none", "pending"])
def f_bulk_sensitive(e, r):
    if e["tool_call"]["data_sensitivity"] == "internal":
        role = e["user"]["roles"][0]
        if "customers:read" in ROLE_SCOPES[role]:
            e["tool_call"].update(tool="customer.lookup", mcp_server="crm-mcp",
                                  target_resource=RESOURCES["crm"], reversible=True, data_sensitivity="pii")
            e["token"].update(aud=RESOURCES["crm"], scopes=["customers:read"])
            e["delegated_scopes"] = sorted(set(e["delegated_scopes"]) | {"customers:read"})
    e["tool_call"]["records"] = r.choice([250, 800, 5000, 20000])
def f_geo(e, r):
    e["context"]["runtime_geo"] = r.choice([g for g in ["RU", "BR", "SG", "NG", "CN"]])
def f_odd_hour(e, r): e["context"]["hour_local"] = r.choice([0, 1, 2, 3, 4, 23])
def f_stale_mfa(e, r):
    e["agent"]["type"] = "background"
    e["user"]["mfa_age_min"] = r.randint(800, 10000)

DENY_FAULTS = [f_revoked, f_unregistered, f_no_act, f_wrong_actor, f_wrong_aud,
               f_scope_escalation, f_replay, f_deep_chain, f_old_token, f_role_exceeded]
STEP_FAULTS = [f_irreversible_no_hitl, f_bulk_sensitive, f_geo, f_odd_hour, f_stale_mfa]


def agent_checks(e, policy):
    """Per-signal verdicts the model writes BEFORE its decision (a compact, auditable trace)."""
    a, t, tc, ctx = e["agent"], e["token"], e["tool_call"], e["context"]
    scope_needed, _, _, roles_allowed = TOOLS[tc["tool"]]
    role = e["user"]["roles"][0]
    act = t.get("act")
    status = a["state"] if a["state"] != "active" else (
        "revoked_in_registry" if a["id"] in policy.get("revoked", ()) else "active")
    if ctx["runtime_geo"] == ctx["usual_geo"]:
        geo = "usual"
    elif ctx["runtime_geo"] in policy.get("regions", ()):
        geo = "approved_region"
    else:
        geo = "anomalous"
    limit = policy.get("pii_limit", 100)
    return {
        "agent_registered": a["registered"],
        "agent_status": status,
        "act_claim": "missing" if not act else ("ok" if act.get("sub") == a["id"] else "mismatch"),
        "audience": "ok" if t["aud"] == tc["target_resource"] else "mismatch",
        "scopes_within_delegation": set(t["scopes"]) <= set(e["delegated_scopes"]),
        "user_entitled": (roles_allowed is None or role in roles_allowed) and scope_needed in t["scopes"],
        "token_replay": t["jti_seen_before"],
        "token_age_ok": t["age_min"] <= 60,
        "chain_depth_ok": ctx["delegation_depth"] <= 2,
        "irreversible_unapproved": (not tc["reversible"]) and e["human_approval"] != "approved",
        "bulk_sensitive": tc["data_sensitivity"] in ("pii", "financial") and tc["records"] > limit,
        "geo": geo,
        "hour_ok": a["type"] != "interactive" or 6 <= ctx["hour_local"] <= 22,
        "mfa_fresh": a["type"] != "background" or e["user"]["mfa_age_min"] <= 720,
    }


def label_agent_event(e, policy=None):
    """Deterministic rule engine. Returns label dict (decision, risk, reasons, controls[, sources]).

    `policy` holds facts that only retrieved CONTEXT can supply (org registry and
    policy). When given, those facts override the generic defaults and every
    reason that relied on them cites its source file.
    """
    policy = policy or {}
    deny, step, controls, sources, notes = [], [], [], [], []

    def cite(src):
        if src not in sources:
            sources.append(src)

    def add(bucket, reason, control, weight):
        bucket.append((weight, reason))
        if control not in controls:
            controls.append(control)

    a, t, tc, ctx = e["agent"], e["token"], e["tool_call"], e["context"]
    role = e["user"]["roles"][0]
    scope_needed, _, _, roles_allowed = TOOLS[tc["tool"]]
    checks = agent_checks(e, policy)

    if not a["registered"]:
        add(deny, f"agent '{a['id']}' is not in the agent registry", C_LIFE, 40)
    if a["state"] != "active":
        add(deny, f"agent '{a['id']}' is {a['state']}; its credentials must not be honored", C_LIFE, 45)
    elif a["id"] in policy.get("revoked", ()):
        add(deny, f"agent '{a['id']}' is listed as revoked in {REGISTRY_DOC} although the token says state=active (stale cache)", C_LIFE, 45)
        cite(REGISTRY_DOC)
    if not t.get("act"):
        add(deny, "token has sub=user but no act claim: impersonation, not delegation", C_ACT, 35)
    elif t["act"].get("sub") != a["id"]:
        add(deny, f"act.sub '{t['act']['sub']}' does not match calling agent '{a['id']}'", C_ACT, 40)
    if t["aud"] != tc["target_resource"]:
        add(deny, f"token audience {t['aud']} != MCP resource {tc['target_resource']} (confused deputy / token passthrough)", C_AUD, 35)
    over = sorted(set(t["scopes"]) - set(e["delegated_scopes"]))
    if over:
        add(deny, f"token scopes exceed user delegation: {', '.join(over)}", C_LLM06, 35)
    if roles_allowed is not None and role not in roles_allowed:
        add(deny, f"user role '{role}' is not entitled to {tc['tool']}; an agent cannot exceed its user", C_LP, 35)
    elif scope_needed not in t["scopes"]:
        add(deny, f"tool {tc['tool']} requires scope {scope_needed} which the token lacks", C_LP, 30)
    if t["jti_seen_before"]:
        add(deny, "token jti already used: replay", C_BCP, 40)
    if t["age_min"] > 60:
        add(deny, f"agent token age {t['age_min']} min exceeds 60 min lifetime", C_BCP, 25)
    if ctx["delegation_depth"] > 2:
        add(deny, f"delegation chain depth {ctx['delegation_depth']} > 2", C_ACT, 25)

    if not tc["reversible"] and e["human_approval"] != "approved":
        approver = policy.get("approvers", {}).get(tc["tool"])
        if approver:
            add(step, f"{tc['tool']} is irreversible and approval is '{e['human_approval']}': route to {approver} per {POLICY_DOC}", C_HITL, 30)
            cite(POLICY_DOC)
        else:
            add(step, f"{tc['tool']} is irreversible and human approval is '{e['human_approval']}'", C_HITL, 30)
    if tc["data_sensitivity"] in ("pii", "financial"):
        limit = policy.get("pii_limit")
        if limit is None and tc["records"] > 100:
            add(step, f"bulk {tc['data_sensitivity']} access: {tc['records']} records", C_DATA, 25)
        elif limit is not None:
            cite(POLICY_DOC)
            if tc["records"] > limit:
                add(step, f"{tc['records']} {tc['data_sensitivity']} records exceeds the {limit}-record agent limit in {POLICY_DOC}", C_DATA, 25)
            else:
                notes.append(f"{tc['records']} {tc['data_sensitivity']} records is within the {limit}-record limit in {POLICY_DOC}")
    if ctx["runtime_geo"] != ctx["usual_geo"]:
        regions = policy.get("regions")
        if regions is None:
            add(step, f"agent runtime geo {ctx['runtime_geo']} differs from usual {ctx['usual_geo']}", C_CTX, 20)
        else:
            cite(POLICY_DOC)
            if ctx["runtime_geo"] in regions:
                notes.append(f"runtime geo {ctx['runtime_geo']} is an approved agent region in {POLICY_DOC}")
            else:
                add(step, f"agent runtime geo {ctx['runtime_geo']} is not an approved region ({', '.join(regions)}) in {POLICY_DOC}", C_CTX, 20)
    if a["type"] == "interactive" and not (6 <= ctx["hour_local"] <= 22):
        add(step, f"interactive agent active at {ctx['hour_local']:02d}:00 local", C_CTX, 15)
    if a["type"] == "background" and e["user"]["mfa_age_min"] > 720:
        add(step, f"background agent relying on user MFA {e['user']['mfa_age_min']} min old", C_REAUTH, 20)

    if deny:
        decision, base, items = "DENY", 60, deny + step
    elif step:
        decision, base, items = "STEP_UP", 30, step
    else:
        lab = {"checks": checks, "decision": "ALLOW", "risk": 5 + (5 if tc["data_sensitivity"] != "internal" else 0),
               "reasons": notes + ["registered active agent, valid delegated token, scopes within delegation, reversible low-risk action"],
               "controls": [C_ACT, C_LP]}
        if policy:
            lab["sources"] = sources
        return lab
    risk = min(99, base + sum(w for w, _ in items) // 2)
    if decision == "STEP_UP":
        risk = min(risk, 75)
    reasons = [r for _, r in sorted(items, key=lambda x: -x[0])][:4]
    lab = {"checks": checks, "decision": decision, "risk": risk, "reasons": reasons, "controls": controls}
    if policy:
        lab["sources"] = sources
    return lab


def gen_agent_events(n, rng):
    per = {d: n // 3 for d in DECISIONS}
    per["ALLOW"] += n - sum(per.values())
    out, counts = [], collections.Counter()
    while sum(counts.values()) < n:
        want = rng.choice([d for d in DECISIONS if counts[d] < per[d]])
        e = clean_agent_event(rng)
        if want == "DENY":
            for f in rng.sample(DENY_FAULTS, k=rng.choice([1, 1, 2, 2, 3])):
                f(e, rng)
            if rng.random() < 0.4:
                rng.choice(STEP_FAULTS)(e, rng)
        elif want == "STEP_UP":
            for f in rng.sample(STEP_FAULTS, k=rng.choice([1, 1, 2])):
                f(e, rng)
        lab = label_agent_event(e)
        if lab["decision"] != want:
            continue  # rejection sampling keeps classes balanced and labels rule-consistent
        counts[want] += 1
        out.append(to_example(e, lab, "synthetic_agent"))
    return out


# ---------------------------------------------------------------------------
# 1b. RAG-aware examples: event + retrieved CONTEXT with RANDOMIZED policy values.
#     The model learns to read and cite context, not to memorize Acme's values
#     (the real ones live only in rag/corpus/ and are retrieved at query time).
# ---------------------------------------------------------------------------

REGISTRY_DOC = "acme_agent_registry.md"
POLICY_DOC = "acme_agent_authorization_policy.md"
CTX_TEMPLATE = ("Assess this event and return the authorization decision as JSON. Use the CONTEXT "
                "(retrieved policy) when relevant and list the files you used in \"sources\".\n\n"
                "CONTEXT:\n{context}\n\nEVENT:\n{event}")
APPROVER_ROLES = ["Finance Controller", "Data Owner", "Comms Lead", "IAM Change Board", "Security On-Call",
                  "Plant Manager", "Customer Privacy Officer"]
DISTRACTORS = [
    ("rfc8693_token_exchange.md", "In token exchange the act claim identifies the acting party; nested act claims record a delegation chain."),
    ("owasp_llm06_excessive_agency.md", "Excessive agency arises from excessive functionality, permissions or autonomy granted to an LLM agent."),
    ("mcp_authorization.md", "MCP servers must validate that access tokens were issued specifically for them as the intended audience."),
    ("nist_800_63b_reauthentication.md", "Reauthentication is required periodically and after inactivity; step-up raises assurance for a sensitive action."),
    ("oauth_security_bcp_rfc9700.md", "Sender-constrained tokens and short lifetimes limit the impact of token replay."),
    ("rba_research_signals.md", "Risk-based authentication compares login features such as IP, ASN and user agent against the user's history."),
]


def _registry_snippet(revoked, rng):
    active = [f"{rng.choice(AGENT_NAMES)}-{rng.randint(1, 20):02d}" for _ in range(2)]
    if rng.random() < 0.5:
        return (f"[source: {REGISTRY_DOC}] Agent registry status. REVOKED or SUSPENDED (deny all tokens, IdP cache may lag): "
                f"{', '.join(revoked)}. ACTIVE examples: {', '.join(active)}.")
    rows = " ".join(f"| {x} | {rng.choice(['REVOKED', 'REVOKED', 'SUSPENDED'])} | u-{rng.randint(1000, 9999)} | "
                    f"{rng.choice(['incident review', 'owner left', 'replaced', 'anomalous calls'])} |" for x in revoked)
    return (f"[source: {REGISTRY_DOC}] ## Revoked or suspended agents (deny all tokens immediately) "
            f"| Agent ID | Status | Owner | Reason | |---|---|---|---| {rows}")


QUESTION_LINES = {
    "revoked": "Agent {agent} wants to call {tool}. Is this agent still allowed to act?",
    "pii": "Agent {agent} is reading {records} {sens} records in one call. Is that within our bulk data policy?",
    "region": "Agent {agent} is running from region {geo} instead of its usual {usual}. Is that runtime location approved?",
    "approver": "Agent {agent} wants to run {tool}. Who must approve it and can it proceed?",
}


def gen_context_events(n, rng):
    out, counts = [], collections.Counter()
    per = {d: n // 3 for d in DECISIONS}
    per["ALLOW"] += n - sum(per.values())
    while sum(counts.values()) < n:
        e = clean_agent_event(rng)
        kind = rng.choice(["revoked", "pii", "region", "approver"])
        policy, snippets = {}, []
        if kind == "revoked":
            revoked = [f"{rng.choice(AGENT_NAMES)}-{rng.randint(1, 20):02d}" for _ in range(rng.randint(2, 4))]
            if rng.random() < 0.5:
                revoked[rng.randrange(len(revoked))] = e["agent"]["id"]
            revoked = [x for x in revoked if x != e["agent"]["id"]] if e["agent"]["id"] not in revoked else revoked
            policy["revoked"] = set(revoked)
            snippets.append(_registry_snippet(revoked, rng))
        elif kind == "pii":
            f_bulk_sensitive(e, rng)
            limit = rng.choice([25, 50, 200, 500, 1000, 5000])
            e["tool_call"]["records"] = rng.choice([limit // 2, limit - 1, limit + 1, limit * 2, limit * 4])
            policy["pii_limit"] = limit
            snippets.append(f"[source: {POLICY_DOC}] Section 4 Bulk data. An agent may read at most {limit} PII or "
                            f"financial records in one call; above that the Data Owner must approve.")
        elif kind == "region":
            f_geo(e, rng)
            regions = sorted(set(rng.sample(["US", "IN", "DE", "GB", "NL", "SG", "BR", "RU", "CN", "NG"], k=3)) | {e["context"]["usual_geo"]})
            if rng.random() < 0.5 and e["context"]["runtime_geo"] not in regions:
                regions = sorted(set(regions) | {e["context"]["runtime_geo"]})
            policy["regions"] = regions
            snippets.append(f"[source: {POLICY_DOC}] Section 6 Runtime location. Agents may execute only in approved regions: "
                            f"{', '.join(regions)}. Other regions require step-up.")
        else:
            f_irreversible_no_hitl(e, rng)
            approver = rng.choice(APPROVER_ROLES)
            policy["approvers"] = {e["tool_call"]["tool"]: approver}
            snippets.append(f"[source: {POLICY_DOC}] Section 5 Irreversible actions. {e['tool_call']['tool']} needs "
                            f"approval from the {approver} before execution.")
        if rng.random() < 0.25:
            rng.choice(DENY_FAULTS)(e, rng)
        snippets.append("[source: {}] {}".format(*rng.choice(DISTRACTORS)))
        rng.shuffle(snippets)
        lab = label_agent_event(e, policy)
        d = lab["decision"]
        if counts[d] >= per[d] or not lab.get("sources"):
            continue
        counts[d] += 1
        ev_text = json.dumps(e, separators=(",", ":"))
        if rng.random() < 0.5:  # LangFlow chat input = question line + event
            q = QUESTION_LINES[kind].format(agent=e["agent"]["id"], tool=e["tool_call"]["tool"],
                                            records=e["tool_call"]["records"], sens=e["tool_call"]["data_sensitivity"],
                                            geo=e["context"]["runtime_geo"], usual=e["context"]["usual_geo"])
            ev_text = f"{q}\nEVENT: {ev_text}"
        content = CTX_TEMPLATE.format(context="\n".join(snippets), event=ev_text)
        out.append({"source": "synthetic_agent_rag", "decision": d, "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": content},
            {"role": "assistant", "content": target_json(lab)},
        ]})
    return out


# ---------------------------------------------------------------------------
# 2. Real RBA login events
# ---------------------------------------------------------------------------

RBA_COLS = ["Login Timestamp", "User ID", "Round-Trip Time [ms]", "Country", "ASN",
            "Browser Name and Version", "OS Name and Version", "Device Type",
            "Login Successful", "Is Attack IP", "Is Account Takeover"]
C_RBA = "Risk-based authentication (IP/ASN/country/device novelty)"
C_TI = "IP reputation / threat intelligence"
C_THROTTLE = "NIST SP 800-63B rate limiting of failed attempts"


def _true(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def _user_selected(uid, modulo):
    return int(hashlib.md5(uid.encode()).hexdigest()[:8], 16) % modulo == 0


def label_login(ev):
    score, reasons, controls = 0, [], []

    def add(w, reason, control):
        nonlocal score
        score += w
        reasons.append(reason)
        if control not in controls:
            controls.append(control)

    h = ev["history"]
    first = h["prior_logins"] == 0
    checks = {
        "ip_reputation": ev["ip_reputation"],
        "first_login": first,
        "new_country": not first and not h["country_seen_before"],
        "new_asn": not first and not h["asn_seen_before"],
        "new_browser_os": not first and not h["browser_os_seen_before"],
        "new_device_type": not first and not h["device_type_seen_before"],
        "failed_attempts_24h": h["failed_attempts_24h"],
    }
    if ev["ip_reputation"] == "known_attack_source":
        add(60, "source IP is on the known-attack list", C_TI)
    if h["prior_logins"] == 0:
        add(10, "first login seen for this account: no baseline", C_RBA)
    else:
        if not h["country_seen_before"]:
            add(25, f"new country {ev['country']} for this user", C_RBA)
        if not h["asn_seen_before"]:
            add(15, f"new network ASN {ev['asn']}", C_RBA)
        if not h["browser_os_seen_before"]:
            add(10, "new browser/OS combination", C_RBA)
        if not h["device_type_seen_before"]:
            add(10, f"new device type {ev['device_type']}", C_RBA)
    if h["failed_attempts_24h"] >= 3:
        add(15, f"{h['failed_attempts_24h']} failed attempts in last 24h", C_THROTTLE)

    # Decisions use only signals observable at login time. The dataset's ground-truth
    # account-takeover flag is NOT used for labels; it measures what the rules catch.
    if ev["ip_reputation"] == "known_attack_source":
        decision, risk = "DENY", min(99, 50 + score)
    elif score >= 35:
        decision, risk = "STEP_UP", min(80, 25 + score)
    else:
        decision, risk = "ALLOW", max(3, min(30, score))
        if not reasons:
            reasons = ["known country, network and device for this user; no recent failures"]
            controls = [C_RBA]
    return {"checks": checks, "decision": decision, "risk": risk, "reasons": reasons[:4], "controls": controls}


def sample_rba(path, n, rng, user_modulo=150):
    """Two streaming passes over the 9 GB CSV, bounded memory."""
    path = Path(path)
    print(f"[rba] pass 1: finding account-takeover users in {path} ...", file=sys.stderr)
    ato_users = set()
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        idx = {c: header.index(c) for c in RBA_COLS if c in header}
        missing = [c for c in RBA_COLS if c not in idx]
        if missing:
            sys.exit(f"RBA header missing columns: {missing}\nGot: {header}")
        i_ato, i_uid = idx["Is Account Takeover"], idx["User ID"]
        assert i_ato == len(header) - 1 and i_uid == 2, "fast path assumes the published column order"
        for k, line in enumerate(fh):
            # fast path: ATO flag is the last field; only parse candidate lines
            if line.rstrip().endswith("True"):
                row = next(csv.reader([line]))
                if _true(row[i_ato]):
                    ato_users.add(row[i_uid])
            if k % 5_000_000 == 0 and k:
                print(f"[rba]   {k:,} rows", file=sys.stderr)
    print(f"[rba] {len(ato_users)} ATO users", file=sys.stderr)

    print("[rba] pass 2: replaying history for sampled users ...", file=sys.stderr)
    hist = {}
    buckets = {d: [] for d in DECISIONS}
    seen = collections.Counter()
    cap = {"DENY": n // 3, "STEP_UP": n // 3, "ALLOW": n - 2 * (n // 3)}
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        next(fh)
        for line in fh:
            uid = line.split(",", 3)[2]  # index, timestamp, user id never contain commas
            if uid not in ato_users and not _user_selected(uid, user_modulo):
                continue
            row = next(csv.reader([line]))
            if len(row) != len(header):
                continue  # quoted newline in a user-agent string; skip the fragment
            ts_raw = row[idx["Login Timestamp"]]
            try:
                ts = datetime.fromisoformat(ts_raw[:19])
            except ValueError:
                continue
            country, asn = row[idx["Country"]], row[idx["ASN"]]
            bros = f"{row[idx['Browser Name and Version']]} | {row[idx['OS Name and Version']]}"
            dev = row[idx["Device Type"]]
            success = _true(row[idx["Login Successful"]])
            attack = _true(row[idx["Is Attack IP"]])
            is_ato = _true(row[idx["Is Account Takeover"]])
            h = hist.setdefault(uid, {"n": 0, "countries": set(), "asns": set(), "bros": set(),
                                      "devs": set(), "fails": collections.deque(maxlen=50)})
            while h["fails"] and (ts - h["fails"][0]).total_seconds() > 86400:
                h["fails"].popleft()
            if success:
                rtt = row[idx["Round-Trip Time [ms]"]]
                ev = {
                    "event_type": "human_login",
                    "primary_credential": "valid",
                    "hour_local": ts.hour,
                    "country": country,
                    "asn": asn,
                    "browser_os": bros,
                    "device_type": dev,
                    "rtt_ms": int(float(rtt)) if rtt not in ("", "nan") else None,
                    "ip_reputation": "known_attack_source" if attack else "no_known_threat",
                    "history": {
                        "prior_logins": h["n"],
                        "country_seen_before": country in h["countries"],
                        "asn_seen_before": asn in h["asns"],
                        "browser_os_seen_before": bros in h["bros"],
                        "device_type_seen_before": dev in h["devs"],
                        "failed_attempts_24h": len(h["fails"]),
                    },
                }
                lab = label_login(ev)
                d = lab["decision"]
                seen[d] += 1
                # reservoir sample per class; always keep ATO rows (rare, high value)
                b = buckets[d]
                item = (is_ato, ev, lab)
                if is_ato:
                    b.append(item)
                elif len(b) < cap[d] * 3:
                    b.append(item)
                else:
                    j = rng.randrange(seen[d])
                    if j < len(b) and not b[j][0]:
                        b[j] = item
                h["n"] += 1
                h["countries"].add(country); h["asns"].add(asn); h["bros"].add(bros); h["devs"].add(dev)
            else:
                h["fails"].append(ts)
    print(f"[rba] candidate counts by label: {dict(seen)}", file=sys.stderr)
    ato = collections.Counter(d for d in DECISIONS for x in buckets[d] if x[0])
    caught = ato["DENY"] + ato["STEP_UP"]
    print(f"[rba] ground-truth account takeovers: {sum(ato.values())}; rule labels DENY={ato['DENY']} "
          f"STEP_UP={ato['STEP_UP']} ALLOW={ato['ALLOW']} -> caught {caught}/{sum(ato.values())}", file=sys.stderr)
    out = []
    for d in DECISIONS:
        b = buckets[d]
        atos = [x for x in b if x[0]]
        rest = [x for x in b if not x[0]]
        rng.shuffle(rest)
        chosen = (atos[: cap[d] // 2] + rest)[: cap[d]]
        out += [to_example(ev, lab, "rba_login") for _, ev, lab in chosen]
    return out


def write_csv_preview(examples, path):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["source", "decision", "event_json", "target_json"])
        for ex in examples:
            ev = ex["messages"][1]["content"].split("EVENT:\n", 1)[1]
            if "CONTEXT:\n" in ex["messages"][1]["content"]:
                ev = "[with CONTEXT] " + ev
            w.writerow([ex["source"], ex["decision"], ev, ex["messages"][2]["content"]])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rba", help="path to rba-dataset.csv")
    ap.add_argument("--synthetic-only", action="store_true")
    ap.add_argument("--n-rba", type=int, default=450)
    ap.add_argument("--n-agent", type=int, default=750)
    ap.add_argument("--n-rag", type=int, default=210)
    ap.add_argument("--eval-frac", type=float, default=0.1)
    args = ap.parse_args()
    if not args.rba and not args.synthetic_only:
        ap.error("pass --rba PATH or --synthetic-only")

    rng = random.Random(SEED)
    agent = gen_agent_events(args.n_agent, rng) + gen_context_events(args.n_rag, rng)
    write_csv_preview(agent, HERE / "agent_events.csv")
    rba = []
    if args.rba:
        rba = sample_rba(args.rba, args.n_rba, rng)
        write_csv_preview(rba, HERE / "rba_sample.csv")

    # stratified split by (source, decision)
    groups = collections.defaultdict(list)
    for ex in agent + rba:
        groups[(ex["source"], ex["decision"])].append(ex)
    train, evals = [], []
    for key in sorted(groups):
        g = groups[key]
        rng.shuffle(g)
        k = max(1, round(len(g) * args.eval_frac))
        evals += g[:k]
        train += g[k:]
    rng.shuffle(train)
    rng.shuffle(evals)
    for name, rows in (("train.jsonl", train), ("eval.jsonl", evals)):
        with open(HERE / name, "w") as fh:
            for ex in rows:
                fh.write(json.dumps(ex, ensure_ascii=False) + "\n")

    def dist(rows):
        return dict(collections.Counter((r["source"], r["decision"]) for r in rows))
    print(f"train={len(train)} eval={len(evals)}")
    print("train:", dist(train))
    print("eval: ", dist(evals))


if __name__ == "__main__":
    main()
