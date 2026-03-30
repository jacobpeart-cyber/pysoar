"""
Agentic AI SOC Analyst Module for PySOAR

This module implements autonomous multi-step investigation capabilities for the
SOC, enabling agents to conduct investigations without predefined playbooks.
Features autonomous reasoning, evidence gathering, hypothesis generation, and
action execution with human-in-the-loop controls.

Key components:
- Models: SOCAgent, Investigation, ReasoningStep, AgentAction, AgentMemory
- Engine: AgenticSOCEngine (core OODA loop), AgentMemoryManager, NLI, Orchestrator
- Tasks: Celery background jobs for investigations and memory management
- API: REST endpoints for agent management and investigation control
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
