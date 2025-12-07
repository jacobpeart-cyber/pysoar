"""SIEM integrations for alert ingestion and log forwarding"""

import logging
from abc import abstractmethod
from datetime import datetime
from typing import Any, Optional

import httpx

from src.integrations.base import BaseIntegration

logger = logging.getLogger(__name__)


class BaseSIEMIntegration(BaseIntegration):
    """Base class for SIEM integrations"""

    @abstractmethod
    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Fetch alerts from the SIEM"""
        pass

    @abstractmethod
    async def forward_log(self, log_data: dict) -> bool:
        """Forward a log entry to the SIEM"""
        pass


class SplunkIntegration(BaseSIEMIntegration):
    """Splunk SIEM integration"""

    name = "splunk"
    display_name = "Splunk"
    description = "Integrate with Splunk for log management and SIEM"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url", "").rstrip("/")
        self.token = config.get("token", "")
        self.hec_url = config.get("hec_url", "")
        self.hec_token = config.get("hec_token", "")
        self.index = config.get("index", "main")

    async def test_connection(self) -> bool:
        """Test the Splunk connection"""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.base_url}/services/server/info",
                    headers={"Authorization": f"Bearer {self.token}"},
                    timeout=10.0,
                )
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Splunk connection test failed: {e}")
            return False

    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Fetch alerts from Splunk using saved searches or real-time search"""
        # Build SPL query
        earliest = start_time.strftime("%Y-%m-%dT%H:%M:%S") if start_time else "-24h"
        latest = end_time.strftime("%Y-%m-%dT%H:%M:%S") if end_time else "now"

        search_query = f'search index={self.index} sourcetype=alert earliest={earliest} latest={latest} | head {limit}'

        try:
            async with httpx.AsyncClient(verify=False) as client:
                # Create search job
                response = await client.post(
                    f"{self.base_url}/services/search/jobs",
                    headers={"Authorization": f"Bearer {self.token}"},
                    data={
                        "search": search_query,
                        "output_mode": "json",
                        "exec_mode": "oneshot",
                    },
                    timeout=60.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("results", [])
                else:
                    logger.error(f"Splunk search failed: {response.status_code}")
                    return []
        except Exception as e:
            logger.error(f"Failed to fetch Splunk alerts: {e}")
            return []

    async def forward_log(self, log_data: dict) -> bool:
        """Forward log to Splunk via HEC"""
        if not self.hec_url or not self.hec_token:
            logger.error("HEC URL and token required for log forwarding")
            return False

        event = {
            "event": log_data,
            "sourcetype": "pysoar",
            "index": self.index,
            "time": datetime.utcnow().timestamp(),
        }

        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    self.hec_url,
                    headers={"Authorization": f"Splunk {self.hec_token}"},
                    json=event,
                    timeout=10.0,
                )
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to forward log to Splunk: {e}")
            return False

    async def run_search(self, spl_query: str, timeout: int = 60) -> list[dict]:
        """Run a custom SPL search"""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    f"{self.base_url}/services/search/jobs",
                    headers={"Authorization": f"Bearer {self.token}"},
                    data={
                        "search": spl_query,
                        "output_mode": "json",
                        "exec_mode": "oneshot",
                    },
                    timeout=timeout,
                )

                if response.status_code == 200:
                    return response.json().get("results", [])
                return []
        except Exception as e:
            logger.error(f"Splunk search failed: {e}")
            return []


class ElasticSIEMIntegration(BaseSIEMIntegration):
    """Elasticsearch SIEM integration"""

    name = "elastic_siem"
    display_name = "Elastic SIEM"
    description = "Integrate with Elastic Security/SIEM"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url", "").rstrip("/")
        self.api_key = config.get("api_key", "")
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.index_pattern = config.get("index_pattern", "logs-*")
        self.cloud_id = config.get("cloud_id", "")

    def _get_auth_headers(self) -> dict:
        """Get authentication headers"""
        if self.api_key:
            return {"Authorization": f"ApiKey {self.api_key}"}
        return {}

    def _get_auth(self) -> Optional[tuple]:
        """Get basic auth tuple"""
        if self.username and self.password:
            return (self.username, self.password)
        return None

    async def test_connection(self) -> bool:
        """Test the Elasticsearch connection"""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.base_url}/_cluster/health",
                    headers=self._get_auth_headers(),
                    auth=self._get_auth(),
                    timeout=10.0,
                )
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Elastic SIEM connection test failed: {e}")
            return False

    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Fetch alerts from Elastic SIEM"""
        query = {
            "size": limit,
            "query": {
                "bool": {
                    "must": [{"match": {"event.kind": "alert"}}],
                    "filter": [],
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        if start_time or end_time:
            time_range = {"@timestamp": {}}
            if start_time:
                time_range["@timestamp"]["gte"] = start_time.isoformat()
            if end_time:
                time_range["@timestamp"]["lte"] = end_time.isoformat()
            query["query"]["bool"]["filter"].append({"range": time_range})

        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    f"{self.base_url}/{self.index_pattern}/_search",
                    headers=self._get_auth_headers(),
                    auth=self._get_auth(),
                    json=query,
                    timeout=30.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    return [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
                else:
                    logger.error(f"Elastic search failed: {response.status_code}")
                    return []
        except Exception as e:
            logger.error(f"Failed to fetch Elastic alerts: {e}")
            return []

    async def forward_log(self, log_data: dict) -> bool:
        """Forward log to Elasticsearch"""
        log_data["@timestamp"] = datetime.utcnow().isoformat()
        log_data["event.module"] = "pysoar"

        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    f"{self.base_url}/pysoar-logs/_doc",
                    headers=self._get_auth_headers(),
                    auth=self._get_auth(),
                    json=log_data,
                    timeout=10.0,
                )
                return response.status_code in (200, 201)
        except Exception as e:
            logger.error(f"Failed to forward log to Elastic: {e}")
            return False

    async def search(self, query: dict) -> list[dict]:
        """Run a custom Elasticsearch query"""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    f"{self.base_url}/{self.index_pattern}/_search",
                    headers=self._get_auth_headers(),
                    auth=self._get_auth(),
                    json=query,
                    timeout=30.0,
                )

                if response.status_code == 200:
                    data = response.json()
                    return [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
                return []
        except Exception as e:
            logger.error(f"Elastic search failed: {e}")
            return []


class QRadarIntegration(BaseSIEMIntegration):
    """IBM QRadar SIEM integration"""

    name = "qradar"
    display_name = "IBM QRadar"
    description = "Integrate with IBM QRadar SIEM"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("base_url", "").rstrip("/")
        self.api_key = config.get("api_key", "")

    async def test_connection(self) -> bool:
        """Test the QRadar connection"""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.base_url}/api/system/servers",
                    headers={
                        "SEC": self.api_key,
                        "Accept": "application/json",
                    },
                    timeout=10.0,
                )
                return response.status_code == 200
        except Exception as e:
            logger.error(f"QRadar connection test failed: {e}")
            return False

    async def fetch_alerts(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Fetch offenses from QRadar"""
        params = {"Range": f"items=0-{limit-1}"}

        if start_time:
            params["filter"] = f"start_time >= {int(start_time.timestamp() * 1000)}"

        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.base_url}/api/siem/offenses",
                    headers={
                        "SEC": self.api_key,
                        "Accept": "application/json",
                    },
                    params=params,
                    timeout=30.0,
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"QRadar fetch failed: {response.status_code}")
                    return []
        except Exception as e:
            logger.error(f"Failed to fetch QRadar offenses: {e}")
            return []

    async def forward_log(self, log_data: dict) -> bool:
        """QRadar typically uses syslog for log forwarding - not implemented via API"""
        logger.warning("QRadar log forwarding should use syslog")
        return False

    async def get_offense(self, offense_id: int) -> Optional[dict]:
        """Get offense details"""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(
                    f"{self.base_url}/api/siem/offenses/{offense_id}",
                    headers={
                        "SEC": self.api_key,
                        "Accept": "application/json",
                    },
                    timeout=10.0,
                )

                if response.status_code == 200:
                    return response.json()
                return None
        except Exception as e:
            logger.error(f"Failed to get QRadar offense: {e}")
            return None

    async def close_offense(self, offense_id: int, closing_reason_id: int = 1) -> bool:
        """Close a QRadar offense"""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    f"{self.base_url}/api/siem/offenses/{offense_id}",
                    headers={
                        "SEC": self.api_key,
                        "Accept": "application/json",
                    },
                    params={
                        "status": "CLOSED",
                        "closing_reason_id": closing_reason_id,
                    },
                    timeout=10.0,
                )
                return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to close QRadar offense: {e}")
            return False
