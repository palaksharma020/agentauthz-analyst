# Reflection

_AgentAuthZ Analyst decides ALLOW / STEP_UP / DENY for human logins and AI-agent tool calls. Numbers come from 141 held-out events._

## Fine-tuning adds a skill (parametric knowledge)

- **Base Llama-3.2-3B: 33% accuracy.** It says ALLOW to nearly everything and misses the decisive signal, such as a missing `act` claim or a scope escalation.
- **Fine-tuned v2: 96% accuracy** (macro-F1 0.21 → 0.96). It learned a decision procedure, a machine-enforceable JSON contract, and calibration for login risk.
- **Lesson from v1 (55%):** a low training loss (0.023) only meant the model had memorized the answer _shape_. Making it write a checks trace before the decision, plus 2.5× more agent data, took agent accuracy from 51% to 93%."

## RAG adds facts (contextual knowledge)

- Weights know nothing about _my_ org. On the 3 policy questions, the fine-tuned model alone scored **0/3**; with RAG it scored **3/3**, each answer naming its source file.
- Example facts only retrieval can supply: a revoked agent, a 50-record PII limit, an approved region.
- **Without retrieval it invents policy.** It claimed a "10-record bulk data policy" with no source; the real limit is 50. Domain fluency makes hallucinations _more_ convincing.
- 210 training rows with _randomized_ policy context taught the model to read and cite context, not to memorize values.

## When to use each

| Need                                                    | Use                                                                                                                                                          |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Stable reasoning, output format, speed on a small model | Fine-tuning                                                                                                                                                  |
| Changing, org-specific, auditable facts                 | RAG                                                                                                                                                          |
| Rules that must never be wrong                          | Deterministic code in front of both. An escalate-only guard over the model's own checks fixed a 4-bit quantization slip and raised accuracy from 96% to 99%. |

**Bottom line:** fine-tuning makes the model competent, RAG keeps it current and accountable, and code enforces the hard rules.
