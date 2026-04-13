"""PySOAR Agent Platform.

Unified endpoint agent for Breach & Attack Simulation execution, Live
Response / incident containment, and Purple Team exercises.

Key properties:
- Cryptographically pinned command allowlist (agent refuses anything
  not pre-signed by PySOAR's master key).
- Capability-scoped: an agent enrolled as ``bas`` cannot be used for
  live response even by an admin, and vice versa.
- Tamper-evident command chain: every command is hash-linked to the
  previous command for that agent, so an attacker with DB access
  cannot rewrite history without invalidating every subsequent row.
- Approval workflow hooks for high-blast-radius actions.
"""
