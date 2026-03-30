"""
LLM Integration for Agentic SOC

Provides abstracted LLM provider interface with support for multiple models:
- Claude (Anthropic)
- GPT-4 (OpenAI)
- Local models (Ollama, vLLM)

Includes orchestration, prompt templates, caching, and audit logging.
"""

import json
import logging
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Structured LLM response"""

    content: str
    model: str
    tokens_used: int
    cost: float
    cached: bool = False
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class ToolCall:
    """LLM tool invocation request"""

    tool_name: str
    arguments: Dict[str, Any]


class LLMProvider(ABC):
    """Abstract base class for LLM providers"""

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> LLMResponse:
        """Generate completion"""
        pass

    @abstractmethod
    async def stream(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ):
        """Generate streaming completion"""
        pass

    @abstractmethod
    async def embed(self, text: str) -> List[float]:
        """Generate embeddings"""
        pass

    @abstractmethod
    async def count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        pass


class AnthropicProvider(LLMProvider):
    """Claude (Anthropic) LLM provider"""

    # Token pricing per million tokens (as of March 2026)
    INPUT_COST = 3.00  # $3 per 1M input tokens
    OUTPUT_COST = 15.00  # $15 per 1M output tokens

    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        """
        Initialize Anthropic provider

        Args:
            api_key: Anthropic API key
            model: Model ID (default: Claude 3.5 Sonnet)
        """
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "anthropic library required: pip install anthropic"
            )

        self.client = Anthropic(api_key=api_key)
        self.model = model
        logger.info(f"Anthropic provider initialized with model: {model}")

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> LLMResponse:
        """Generate completion using Claude"""
        try:
            kwargs = {
                "model": self.model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [{"role": "user", "content": prompt}],
            }

            if system:
                kwargs["system"] = system

            if tools:
                kwargs["tools"] = tools

            response = self.client.messages.create(**kwargs)

            content = response.content[0].text
            tokens_used = response.usage.input_tokens + response.usage.output_tokens

            # Calculate cost
            input_cost = (response.usage.input_tokens / 1_000_000) * self.INPUT_COST
            output_cost = (response.usage.output_tokens / 1_000_000) * self.OUTPUT_COST
            cost = input_cost + output_cost

            logger.info(
                f"Claude completion: {tokens_used} tokens, ${cost:.4f}"
            )

            return LLMResponse(
                content=content,
                model=self.model,
                tokens_used=tokens_used,
                cost=cost,
            )
        except Exception as e:
            logger.error(f"Anthropic completion failed: {e}")
            raise

    async def stream(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ):
        """Stream completion from Claude"""
        try:
            kwargs = {
                "model": self.model,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [{"role": "user", "content": prompt}],
            }

            if system:
                kwargs["system"] = system

            with self.client.messages.stream(**kwargs) as stream:
                for text in stream.text_stream:
                    yield text
        except Exception as e:
            logger.error(f"Anthropic stream failed: {e}")
            raise

    async def embed(self, text: str) -> List[float]:
        """Generate embeddings using Anthropic"""
        # Note: Anthropic doesn't provide embeddings API directly
        # This would typically use a separate embeddings model
        raise NotImplementedError("Anthropic embeddings not yet implemented")

    async def count_tokens(self, text: str) -> int:
        """Count tokens using Anthropic's tokenizer"""
        try:
            response = self.client.messages.count_tokens(
                model=self.model,
                messages=[{"role": "user", "content": text}],
            )
            return response.input_tokens
        except Exception as e:
            logger.error(f"Token counting failed: {e}")
            # Rough estimate: ~4 chars per token
            return len(text) // 4


class OpenAIProvider(LLMProvider):
    """GPT-4 (OpenAI) LLM provider"""

    # Token pricing per 1M tokens
    INPUT_COST_GPT4 = 30.00
    OUTPUT_COST_GPT4 = 60.00

    def __init__(self, api_key: str, model: str = "gpt-4-turbo"):
        """
        Initialize OpenAI provider

        Args:
            api_key: OpenAI API key
            model: Model ID (default: GPT-4 Turbo)
        """
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("openai library required: pip install openai")

        self.client = OpenAI(api_key=api_key)
        self.model = model
        logger.info(f"OpenAI provider initialized with model: {model}")

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> LLMResponse:
        """Generate completion using GPT-4"""
        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            kwargs = {
                "model": self.model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }

            if tools:
                kwargs["tools"] = [
                    {"type": "function", "function": tool} for tool in tools
                ]

            response = self.client.chat.completions.create(**kwargs)

            content = response.choices[0].message.content
            tokens_used = response.usage.prompt_tokens + response.usage.completion_tokens

            # Calculate cost
            input_cost = (response.usage.prompt_tokens / 1_000_000) * self.INPUT_COST_GPT4
            output_cost = (response.usage.completion_tokens / 1_000_000) * self.OUTPUT_COST_GPT4
            cost = input_cost + output_cost

            logger.info(
                f"GPT-4 completion: {tokens_used} tokens, ${cost:.4f}"
            )

            return LLMResponse(
                content=content,
                model=self.model,
                tokens_used=tokens_used,
                cost=cost,
            )
        except Exception as e:
            logger.error(f"OpenAI completion failed: {e}")
            raise

    async def stream(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ):
        """Stream completion from GPT-4"""
        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                stream=True,
            )

            for chunk in response:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
        except Exception as e:
            logger.error(f"OpenAI stream failed: {e}")
            raise

    async def embed(self, text: str) -> List[float]:
        """Generate embeddings using OpenAI"""
        try:
            response = self.client.embeddings.create(
                model="text-embedding-3-small",
                input=text,
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"OpenAI embedding failed: {e}")
            raise

    async def count_tokens(self, text: str) -> int:
        """Count tokens using OpenAI"""
        try:
            import tiktoken

            encoding = tiktoken.encoding_for_model(self.model)
            return len(encoding.encode(text))
        except Exception:
            # Fallback estimate
            return len(text) // 4


class LocalProvider(LLMProvider):
    """Local LLM provider (Ollama, vLLM, etc)"""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama2",
    ):
        """
        Initialize local LLM provider

        Args:
            base_url: Base URL for local LLM API (default: Ollama)
            model: Model name
        """
        self.base_url = base_url
        self.model = model
        logger.info(f"Local LLM provider initialized: {model} at {base_url}")

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> LLMResponse:
        """Generate completion using local LLM"""
        try:
            async with httpx.AsyncClient() as client:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "temperature": temperature,
                    "num_predict": max_tokens,
                    "stream": False,
                }

                if system:
                    payload["system"] = system

                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=120.0,
                )
                response.raise_for_status()

                data = response.json()

                return LLMResponse(
                    content=data.get("response", ""),
                    model=self.model,
                    tokens_used=0,  # Local models may not track tokens
                    cost=0.0,  # Local models are free
                )
        except Exception as e:
            logger.error(f"Local LLM completion failed: {e}")
            raise

    async def stream(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ):
        """Stream completion from local LLM"""
        try:
            async with httpx.AsyncClient() as client:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "temperature": temperature,
                    "num_predict": max_tokens,
                    "stream": True,
                }

                if system:
                    payload["system"] = system

                async with client.stream(
                    "POST",
                    f"{self.base_url}/api/generate",
                    json=payload,
                ) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if line:
                            data = json.loads(line)
                            if "response" in data:
                                yield data["response"]
        except Exception as e:
            logger.error(f"Local LLM stream failed: {e}")
            raise

    async def embed(self, text: str) -> List[float]:
        """Generate embeddings using local embeddings model"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": self.model, "prompt": text},
                )
                response.raise_for_status()
                return response.json().get("embedding", [])
        except Exception as e:
            logger.error(f"Local embedding failed: {e}")
            raise

    async def count_tokens(self, text: str) -> int:
        """Count tokens (estimate for local)"""
        return len(text) // 4


class LLMOrchestrator:
    """
    Orchestrates multiple LLM providers with fallback, caching, and budgeting
    """

    def __init__(
        self,
        primary: LLMProvider,
        secondary: Optional[LLMProvider] = None,
        fallback: Optional[LLMProvider] = None,
        cache_client=None,
        max_tokens_per_day: int = 100_000,
    ):
        """
        Initialize orchestrator with provider chain

        Args:
            primary: Primary LLM provider
            secondary: Secondary fallback provider
            fallback: Last-resort local provider
            cache_client: Redis client for response caching
            max_tokens_per_day: Token budget limit per day
        """
        self.primary = primary
        self.secondary = secondary
        self.fallback = fallback
        self.cache_client = cache_client
        self.max_tokens_per_day = max_tokens_per_day
        self.tokens_used_today = 0

        logger.info("LLM Orchestrator initialized")

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        tools: Optional[List[Dict[str, Any]]] = None,
        use_cache: bool = True,
    ) -> LLMResponse:
        """
        Generate completion with fallback chain

        Tries primary → secondary → fallback
        """
        # Check cache first
        if use_cache and self.cache_client:
            cache_key = self._make_cache_key(prompt, system)
            cached = await self._get_cached_response(cache_key)
            if cached:
                logger.info("Cache hit for LLM response")
                return cached

        # Try providers in order
        for provider in [self.primary, self.secondary, self.fallback]:
            if provider is None:
                continue

            try:
                logger.debug(f"Attempting completion with {provider.__class__.__name__}")
                response = await provider.complete(
                    prompt=prompt,
                    system=system,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                )

                # Track tokens
                self.tokens_used_today += response.tokens_used
                if self.tokens_used_today > self.max_tokens_per_day:
                    logger.warning(
                        f"Token budget exceeded: {self.tokens_used_today}/{self.max_tokens_per_day}"
                    )

                # Cache successful response
                if use_cache and self.cache_client:
                    cache_key = self._make_cache_key(prompt, system)
                    await self._cache_response(cache_key, response)

                logger.info(f"Completion successful via {provider.__class__.__name__}")
                return response

            except Exception as e:
                logger.warning(
                    f"Provider {provider.__class__.__name__} failed: {e}. "
                    "Trying next provider..."
                )
                continue

        raise RuntimeError("All LLM providers exhausted")

    async def stream(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ):
        """Stream completion with fallback"""
        for provider in [self.primary, self.secondary, self.fallback]:
            if provider is None:
                continue

            try:
                logger.debug(f"Streaming with {provider.__class__.__name__}")
                async for chunk in provider.stream(
                    prompt=prompt,
                    system=system,
                    temperature=temperature,
                    max_tokens=max_tokens,
                ):
                    yield chunk
                return
            except Exception as e:
                logger.warning(
                    f"Provider {provider.__class__.__name__} stream failed: {e}"
                )
                continue

        raise RuntimeError("All LLM providers exhausted")

    # Security task prompts

    async def investigate_alert(
        self,
        alert_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate structured investigation plan from alert"""
        prompt = f"""You are a cybersecurity analyst. Analyze this alert and provide a structured investigation plan.

Alert Data:
{json.dumps(alert_data, indent=2)}

Provide a JSON response with:
- hypothesis: Initial hypothesis about what happened
- investigation_steps: List of steps to validate the hypothesis
- evidence_to_collect: Specific data points to gather
- risk_level: HIGH, MEDIUM, or LOW
- priority: 1-5 (1=lowest)
"""

        system = (
            "You are an expert cybersecurity investigator. "
            "Provide clear, actionable investigation plans. "
            "Output ONLY valid JSON with no additional text."
        )

        response = await self.complete(
            prompt=prompt,
            system=system,
            temperature=0.3,
        )

        try:
            return json.loads(response.content)
        except json.JSONDecodeError:
            logger.error("Failed to parse investigation plan JSON")
            return {"error": "Failed to parse response"}

    async def analyze_incident(
        self,
        incident_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Analyze incident for root cause and impact"""
        prompt = f"""Analyze this security incident and provide root cause analysis.

Incident Data:
{json.dumps(incident_data, indent=2)}

Provide JSON with:
- root_cause: Most likely root cause
- attack_vector: How the attack occurred
- impact_assessment: Business and technical impact
- timeline: Chronological timeline of events
- affected_systems: Systems and data compromised
- recommendations: Remediation steps
"""

        response = await self.complete(
            prompt=prompt,
            system="You are a forensic security analyst. Provide detailed technical analysis.",
            temperature=0.3,
        )

        try:
            return json.loads(response.content)
        except json.JSONDecodeError:
            return {"error": "Failed to parse response"}

    async def generate_remediation(
        self,
        finding: Dict[str, Any],
    ) -> List[str]:
        """Generate remediation steps for a security finding"""
        prompt = f"""Generate concrete remediation steps for this security finding:

{json.dumps(finding, indent=2)}

Provide a JSON array of remediation steps, each with:
- step: Action to take
- priority: CRITICAL, HIGH, MEDIUM, LOW
- effort: LOW, MEDIUM, HIGH
- expected_outcome: What should improve
"""

        response = await self.complete(
            prompt=prompt,
            temperature=0.3,
        )

        try:
            return json.loads(response.content)
        except json.JSONDecodeError:
            return []

    async def correlate_events(
        self,
        events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Correlate events into a threat narrative"""
        prompt = f"""Correlate these security events into a threat narrative:

Events:
{json.dumps(events, indent=2)}

Provide JSON with:
- narrative: Story of what happened
- threat_actor: Identified or suspected threat actor
- motivation: Likely motivation
- ttps: MITRE ATT&CK techniques used
- confidence: Confidence level (0-100)
"""

        response = await self.complete(
            prompt=prompt,
            temperature=0.3,
        )

        try:
            return json.loads(response.content)
        except json.JSONDecodeError:
            return {"error": "Failed to parse response"}

    async def explain_detection(
        self,
        rule: str,
        event: Dict[str, Any],
    ) -> str:
        """Explain detection in analyst-friendly terms"""
        prompt = f"""Explain this security detection to a non-technical manager.

Detection Rule:
{rule}

Event:
{json.dumps(event, indent=2)}

Provide a clear, business-friendly explanation of:
- What was detected
- Why it matters
- What action was taken
- What business impact this has
"""

        response = await self.complete(
            prompt=prompt,
            temperature=0.5,
        )

        return response.content

    async def threat_hunt_hypothesis(
        self,
        context: Dict[str, Any],
    ) -> List[str]:
        """Generate threat hunting hypotheses"""
        prompt = f"""Based on your knowledge of threat tactics, generate 5 threat hunting hypotheses for this context:

{json.dumps(context, indent=2)}

Provide a JSON array of hypotheses, each a clear statement of what adversaries might be doing.
"""

        response = await self.complete(
            prompt=prompt,
            temperature=0.7,
        )

        try:
            return json.loads(response.content)
        except json.JSONDecodeError:
            return []

    def _make_cache_key(self, prompt: str, system: Optional[str] = None) -> str:
        """Generate cache key from prompt and system message"""
        content = f"{system}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()

    async def _get_cached_response(
        self,
        cache_key: str,
    ) -> Optional[LLMResponse]:
        """Retrieve cached response"""
        if not self.cache_client:
            return None

        try:
            cached = self.cache_client.get(f"llm:{cache_key}")
            if cached:
                data = json.loads(cached)
                response = LLMResponse(**data)
                response.cached = True
                return response
        except Exception as e:
            logger.debug(f"Cache retrieval failed: {e}")

        return None

    async def _cache_response(
        self,
        cache_key: str,
        response: LLMResponse,
    ) -> None:
        """Cache response for future reuse"""
        if not self.cache_client:
            return

        try:
            data = {
                "content": response.content,
                "model": response.model,
                "tokens_used": response.tokens_used,
                "cost": response.cost,
                "timestamp": response.timestamp,
            }
            self.cache_client.setex(
                f"llm:{cache_key}",
                3600,  # 1 hour TTL
                json.dumps(data),
            )
        except Exception as e:
            logger.debug(f"Cache storage failed: {e}")


class LLMAuditLogger:
    """Audit log all LLM interactions"""

    def __init__(self, db_session=None):
        """Initialize with optional database session"""
        self.db = db_session

    async def log_completion(
        self,
        prompt: str,
        response: LLMResponse,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> None:
        """Log LLM completion to audit trail"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "llm_completion",
            "model": response.model,
            "tokens_used": response.tokens_used,
            "cost": response.cost,
            "user_id": user_id,
            "organization_id": organization_id,
            "prompt_length": len(prompt),
            "response_length": len(response.content),
        }

        logger.info(json.dumps(log_entry))

    async def log_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        result: Any,
        user_id: Optional[str] = None,
    ) -> None:
        """Log tool invocation by LLM"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "llm_tool_call",
            "tool": tool_name,
            "user_id": user_id,
            "success": result is not None,
        }

        logger.info(json.dumps(log_entry))
