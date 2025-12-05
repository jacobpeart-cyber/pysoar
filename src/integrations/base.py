"""Base class for threat intelligence integrations"""

from abc import ABC, abstractmethod
from typing import Any, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.core.config import settings
from src.core.exceptions import IntegrationError
from src.core.logging import get_logger

logger = get_logger(__name__)


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers"""

    name: str = "base"
    base_url: str = ""
    rate_limit: int = 60  # requests per minute

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def is_configured(self) -> bool:
        """Check if the provider is properly configured"""
        return bool(self.api_key)

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30.0,
                headers=self._get_headers(),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_headers(self) -> dict[str, str]:
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
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Make an HTTP request with retry logic"""
        client = await self.get_client()

        try:
            response = await client.request(
                method=method,
                url=endpoint,
                params=params,
                json=json_data,
            )
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(
                f"{self.name} API error",
                status_code=e.response.status_code,
                detail=e.response.text,
            )
            raise IntegrationError(
                service=self.name,
                message=f"HTTP {e.response.status_code}",
                details={"response": e.response.text},
            )

        except httpx.RequestError as e:
            logger.error(f"{self.name} request error", error=str(e))
            raise IntegrationError(
                service=self.name,
                message="Request failed",
                details={"error": str(e)},
            )

    @abstractmethod
    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Lookup IP address reputation"""
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Lookup domain reputation"""
        pass

    @abstractmethod
    async def lookup_hash(self, file_hash: str) -> dict[str, Any]:
        """Lookup file hash"""
        pass

    async def lookup_url(self, url: str) -> dict[str, Any]:
        """Lookup URL reputation (optional)"""
        raise NotImplementedError(f"{self.name} does not support URL lookup")

    async def lookup_email(self, email: str) -> dict[str, Any]:
        """Lookup email address (optional)"""
        raise NotImplementedError(f"{self.name} does not support email lookup")
