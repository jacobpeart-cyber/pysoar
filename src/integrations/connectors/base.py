"""Base connector class for API integrations"""

import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Optional, Dict

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.core.config import settings
from src.core.exceptions import IntegrationError
from src.core.logging import get_logger

logger = get_logger(__name__)


class RateLimitTracker:
    """Track API rate limits"""

    def __init__(self):
        self.remaining: int = 0
        self.reset_at: Optional[datetime] = None
        self.limit: int = 0

    def update(self, remaining: int, reset_at: Optional[datetime] = None):
        """Update rate limit information"""
        self.remaining = remaining
        self.reset_at = reset_at or datetime.utcnow() + timedelta(minutes=1)
        if self.remaining == 0:
            logger.warning(f"Rate limit exhausted. Reset at {self.reset_at}")

    def is_exceeded(self) -> bool:
        """Check if rate limit is exceeded"""
        if self.remaining > 0:
            return False
        if self.reset_at and datetime.utcnow() < self.reset_at:
            return True
        return False

    def wait_if_needed(self):
        """Wait if rate limit exceeded"""
        if self.is_exceeded() and self.reset_at:
            wait_time = (self.reset_at - datetime.utcnow()).total_seconds()
            if wait_time > 0:
                logger.info(f"Rate limit waiting {wait_time:.1f} seconds")
                time.sleep(min(wait_time, 60))


class BaseConnector(ABC):
    """Abstract base class for API connectors"""

    name: str = "base"
    base_url: str = ""
    timeout: int = 30

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        """Initialize connector with config and credentials"""
        self.config = config
        self.credentials = credentials
        self._client: Optional[httpx.AsyncClient] = None
        self.rate_limit = RateLimitTracker()
        self._session_start = datetime.utcnow()

    @property
    def is_configured(self) -> bool:
        """Check if connector is properly configured"""
        return bool(self.credentials)

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=float(self.timeout),
                headers=self._get_headers(),
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_headers(self) -> Dict[str, str]:
        """Get default headers for requests"""
        return {
            "Accept": "application/json",
            "User-Agent": f"PySOAR/{settings.app_name}",
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Make HTTP request with retry logic and rate limiting"""
        self.rate_limit.wait_if_needed()

        client = await self.get_client()
        request_headers = {**self._get_headers(), **(headers or {})}

        try:
            start_time = time.time()
            response = await client.request(
                method=method,
                url=endpoint,
                params=params,
                json=json_data,
                headers=request_headers,
            )
            latency = time.time() - start_time

            logger.info(
                f"{self.name} API call",
                method=method,
                endpoint=endpoint,
                status=response.status_code,
                latency=f"{latency:.2f}s",
            )

            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(
                f"{self.name} API error",
                status_code=e.response.status_code,
                endpoint=endpoint,
                detail=e.response.text[:500],
            )
            raise IntegrationError(
                service=self.name,
                message=f"HTTP {e.response.status_code}",
                details={"response": e.response.text[:500]},
            )

        except httpx.RequestError as e:
            logger.error(f"{self.name} request error", error=str(e))
            raise IntegrationError(
                service=self.name,
                message="Request failed",
                details={"error": str(e)},
            )

    async def test_connection(self) -> bool:
        """Test API connectivity"""
        try:
            result = await self.health_check()
            return result.get("status") == "ok"
        except Exception as e:
            logger.error(f"{self.name} connection test failed: {e}")
            return False

    async def health_check(self) -> Dict[str, Any]:
        """Check API health and latency"""
        try:
            start_time = time.time()
            client = await self.get_client()
            response = await client.head(self.base_url, follow_redirects=True)
            latency = time.time() - start_time

            return {
                "status": "ok" if response.status_code < 400 else "degraded",
                "latency": f"{latency:.2f}s",
                "message": f"API responding with {response.status_code}",
            }

        except Exception as e:
            return {
                "status": "down",
                "latency": "0s",
                "message": str(e),
            }

    @abstractmethod
    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute a connector action"""
        pass
