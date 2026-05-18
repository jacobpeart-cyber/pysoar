"""Guardrails for Agentic tool execution.

Provides lightweight, auditable checks to prevent dangerous automated actions.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Optional, Tuple


class Guardrails:
    """Simple guardrail enforcement for tool invocation.

    - Rate limits tool calls per-organization
    - Blocks high-risk tools from automated execution (require approval)
    - Performs basic input sanitization
    """

    # Tools that must require human approval / manual workflow
    HIGH_RISK_TOOLS = {
        "isolate_host",
        "block_ip",
        "run_vulnerability_scan",
        "quarantine_file",
        "unquarantine_file",
    }

    def __init__(self, window_seconds: int = 60, max_calls_per_window: int = 10) -> None:
        self.window = window_seconds
        self.max_calls = max_calls_per_window
        # map (org_id, tool_name) -> [timestamps]
        self._history: Dict[Tuple[Optional[str], str], list[float]] = {}

    async def check_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Return (allowed, reason). If not allowed, reason explains why.

        This is intentionally conservative: unknown or dangerous inputs are blocked.
        """

        # Block known high-risk tools from automated invocation
        if tool_name in self.HIGH_RISK_TOOLS:
            return False, "tool_requires_human_approval"

        # Rate limiting per organization + tool
        key = (organization_id, tool_name)
        now = time.time()
        history = self._history.setdefault(key, [])
        # purge old timestamps
        cutoff = now - self.window
        while history and history[0] < cutoff:
            history.pop(0)
        if len(history) >= self.max_calls:
            return False, "rate_limited"
        history.append(now)

        # Basic sanitization: reject suspicious shell metacharacters in string args
        suspicious_pattern = re.compile(r"[;&|`$<>]{2,}|\bshutdown\b|\brm\b|\bdel\b", re.IGNORECASE)
        for k, v in (arguments or {}).items():
            if isinstance(v, str) and suspicious_pattern.search(v):
                return False, f"suspicious_input:{k}"

        # Validate common typed args: ip_address looks like an IP or CIDR
        ip_like = arguments.get("ip_address") or arguments.get("ip")
        if ip_like and isinstance(ip_like, str):
            if not re.match(r"^[0-9a-fA-F:.\/]+$", ip_like):
                return False, "invalid_ip_format"

        return True, None
