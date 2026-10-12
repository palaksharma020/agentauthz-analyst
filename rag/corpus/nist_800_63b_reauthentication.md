# NIST SP 800-63B Digital Identity Guidelines, Authentication: relevant points (summary)

Source: NIST SP 800-63B (rev. 4 finalized 2025), https://pages.nist.gov/800-63-4/sp800-63b.html. Summarized for this project.

- **Rate limiting.** Verifiers must limit consecutive failed authentication attempts on an account to resist online guessing.
- **Reauthentication.** Sessions require periodic reauthentication, with timeouts tied to the assurance level and inactivity.
- **Risk signals.** Verifiers may use signals such as IP address, geolocation, and device characteristics to inform risk-based decisions. These signals supplement authentication factors and do not replace them.
- **Phishing resistance.** Higher assurance levels need phishing-resistant authenticators. Step-up to such an authenticator is the usual answer to a risky login.
- **Mapping to this project.** Repeated failures plus a new context → STEP_UP. Stale MFA behind a background agent → STEP_UP (reauthenticate).
