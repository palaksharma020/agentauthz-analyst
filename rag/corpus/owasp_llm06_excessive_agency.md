# OWASP Top 10 for LLM Applications 2025: LLM06 Excessive Agency (summary)

Source: OWASP GenAI Security Project, https://genai.owasp.org/llmrisk/llm062025-excessive-agency/. Summarized for this project.

- **Definition.** Damaging actions performed because an LLM-based agent has too much functionality, too many permissions, or too much autonomy. Typical triggers are hallucination, prompt injection, or a compromised plugin or tool.
- **Root causes.** Excessive functionality (tools the task doesn't need), excessive permissions (scopes beyond what the user or task needs), and excessive autonomy (high-impact actions without human verification).
- **Mitigations.**
  - Minimize the tools exposed to the agent.
  - Minimize permissions, and run tools in the user's security context instead of a shared privileged identity.
  - Require human approval for high-impact actions.
  - Enforce authorization in downstream systems, not in the LLM.
  - Log and monitor agent actions, and rate-limit them.
- **Mapping to this project.** Scope escalation beyond delegation → DENY. Irreversible action without approval → STEP_UP (human in the loop).
