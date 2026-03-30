"""PySOAR Threat Hunting Module

Enables structured, hypothesis-driven security investigations through:
- HuntHypothesis: Define investigation hypotheses with MITRE tactics/techniques
- HuntSession: Execute hunts and track progress
- HuntFinding: Document findings with evidence and classification
- HuntTemplate: Reusable investigation templates
- HuntNotebook: Interactive investigation notebooks
- HuntEngine: Core execution engine with query building and result analysis
"""

__all__ = [
    "models",
    "engine",
]
