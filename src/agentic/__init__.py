"""
Agentic SOC for PySOAR - a guarded LLM agent for SOC analysts and autonomous triage.

Every tool call goes through one runtime and one policy gate; destructive tools
are never executed inline but become hash-bound AgentAction proposals that an
analyst or admin approves. See docs/agentic-soc.md for the architecture,
policy order, trust model and control map.

Key components (src/agentic):
- context.py       AgentContext: org, role, mode (interactive | autonomous | approval), actor, run id
- toolspec.py      ToolSpec / ParamSpec / Effects / Tier - the typed contract every tool declares
- decisions.py     Decision, TrustState, TrustTier, PolicyEvent
- policy.py        PolicyEngine - schema, role, mode, trust, tenant refs, targets, rate, audit
- trust.py         untrusted-content boundary, injection scanner, sticky lockdown/acknowledge
- prompts.py       canonical system prompt (PROMPT_VERSION)
- runtime.py       AgentRunner - the tool loop (native-turn replay, proposals, honest failure)
- runtime_factory.py  builds provider + registry + policy + runner for endpoints and Celery
- investigator.py  AutonomousInvestigator - read-only evidence tools, submit_verdict terminal tool
- tasks.py         Celery: run_investigation (dedicated queue), admission-gated kickoff, sweeps
- engine.py        explain_reasoning and the NaturalLanguageInterface explain/suggest helpers
- transcript.py    AgentRunTranscript model (per-run evidence of what the agent was shown/did)
- models.py        SOCAgent, Investigation, ReasoningStep, AgentAction, AgentMemory, chat sessions
The tools themselves live in src/services/agent_tools.py; providers in src/llm/.
"""

__version__ = "1.0.0"

from src.agentic.models import (
    SOCAgent,
    Investigation,
    ReasoningStep,
    AgentAction,
    AgentMemory,
)

__all__ = [
    "SOCAgent",
    "Investigation",
    "ReasoningStep",
    "AgentAction",
    "AgentMemory",
]
