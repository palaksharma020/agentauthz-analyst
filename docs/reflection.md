# Reflection: parametric vs contextual knowledge in a security AI

*Project: AgentAuthZ Analyst. A model that decides ALLOW / STEP_UP / DENY for human logins and AI-agent delegated tool calls.*
*All numbers come from `eval/run_compare.py` on 141 held-out events (see `eval/results/summary.txt`).*

## What fine-tuning added over the base model
The base Llama-3.2-3B already "knows" OAuth vocabulary in a general way. Given a raw token-exchange event, though, it:
- writes prose instead of a decision,
- often misses the decisive signal (a missing `act` claim, a token whose scopes exceed the user's delegation, an audience that doesn't match the MCP server),
- picks the safe-sounding but wrong answer.

Fine-tuning on 1,269 labeled events baked three things into the weights:
1. **A decision procedure.** It learned which signals dominate: revocation, impersonation, and scope escalation mean DENY; irreversibility without approval or bulk PII means STEP_UP. It also learned the precedence between them. This is pattern knowledge that doesn't change week to week.
2. **A contract.** It returns valid, machine-enforceable JSON every time, with a risk score, reasons, and the controls applied (RFC 8693, RFC 8707/MCP, OWASP LLM06, NIST 800-63B). A gateway can act on that. It can't act on a paragraph.
3. **Domain calibration on human logins.** From the RBA data it learned that a new country *plus* a new ASN warrants step-up, that a known attack IP warrants deny, and that a familiar context is fine.

Result: held-out decision accuracy went from **33% (base, which says ALLOW to nearly everything) to 96% (fine-tuned v2)**, and macro-F1 went from 0.21 to 0.96. The model is also 1.6× faster per event, because it answers in compact JSON instead of an essay.

**What it took.** My first fine-tune (v1) reached a training loss of 0.023 but only 55% held-out accuracy. It had memorized the *shape* of the answers, and the single `decision` token barely moved the loss. v2 makes the model write a `checks` object, one verdict per signal, *before* the decision, with 2.5× more agent examples. Agent accuracy went from 51% to 93%. Lesson: the training target should make the model do the reasoning you care about, not just emit the final label.

## What RAG added over the fine-tuned model alone
Weights are frozen at training time, and they hold no facts about *my* organization. The three RAG questions are designed so that the fine-tuned model alone is *confidently wrong*. Measured result: the fine-tuned model alone got **0/3**, and fine-tuned + RAG got **3/3**, each naming its source file.

| Question | FT alone | FT + RAG | Fact that exists only in retrieved docs |
|---|---|---|---|
| R1 invoice-bot-07 reads orders | ALLOW | **DENY** | The agent was revoked on 2026-09-28 (`acme_agent_registry.md`); the IdP cache still says active |
| R2 80 PII records | ALLOW | **STEP_UP** | Acme's limit is 50 records, not the generic 100 (`acme_agent_authorization_policy.md` §4) |
| R3 agent runs from DE | STEP_UP | **ALLOW** | DE is an approved region (`acme_agent_authorization_policy.md` §6) |

The most striking result: when I asked the fine-tuned model *"is that within our bulk data policy?"* without retrieval, it **invented a policy**. It said the call "exceeds the 10-record bulk data policy" and cited nothing; the real limit is 50. A fine-tuned model is fluent in the domain, which makes its hallucinations *more* convincing, not less.

RAG supplied **current, organization-specific, citable facts**: who is revoked *today*, what the thresholds are, who approves what. It also made every answer **auditable**, because the response names its source document. A trick made this reliable: 210 training rows contained a CONTEXT block with *randomized* policy values. The model learned the *skill* of reading and citing context, not the values themselves.

## When to use each

| Need | Use | Why |
|---|---|---|
| Stable reasoning patterns, output format, domain vocabulary, latency/cost on a small model | **Fine-tuning** | Changes rarely; must be fast and consistent at every call |
| Facts that change (revocations, thresholds, approvers, new CVEs or TTPs), tenant-specific policy, citations for audit | **RAG** | Update a document, not the weights; provenance for every answer |
| Hard, non-negotiable rules (revoked = deny) | **Deterministic policy engine** in front of both | An LLM should explain and triage, not be the only enforcement point. Measured: the 4-bit model once reported `act_claim: missing` yet answered STEP_UP; an escalate-only guard over its own checks raised accuracy from 96% to 99%. |

**Production security AI needs both.** Fine-tuning makes a small model a competent analyst. RAG keeps it current and accountable. Neither replaces deterministic enforcement for the rules that must never be wrong.
