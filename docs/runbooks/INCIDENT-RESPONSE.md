# Incident response

1. Classify whether the incident affects API availability, account sessions, metadata, or client/crypto code.
2. Preserve immutable logs and deployment artifacts without collecting vault plaintext.
3. Revoke compromised service credentials or device sessions.
4. If a protocol or client compromise is suspected, stop rollout and open a security ADR.
5. Notify affected users according to the data-protection process; never claim vault compromise without evidence of key exposure.
6. Record root cause, containment, recovery, and follow-up tests.

