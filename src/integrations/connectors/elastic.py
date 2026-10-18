"""Elasticsearch REST API connector (Elastic Security / Elastic Stack).

Written from the Elasticsearch REST API reference (elastic.co/guide,
"REST APIs": Search API, Count API, Get API, Index API, cat indices API,
Cluster health API, and the root "info" endpoint). Not verified against a
live cluster.

``base_url`` is the Elasticsearch HTTP endpoint (``https://es.example.com:9200``).
Authentication is ``Authorization: ApiKey <api_key>`` (the base64 ``encoded``
value of an API key) or HTTP basic with a native-realm user.

A self-managed cluster usually lives on a private network: its address must
be inside the operator setting ``OUTBOUND_PRIVATE_ALLOWLIST``
(src/integrations/netguard.py), otherwise every request is refused before a
connection is made and the refusal names that setting.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
    path_segment,
)
from src.integrations.connectors.splunk import https_origin
from src.integrations.netguard import PinnedTransport

# Elasticsearch index names: lowercase, no leading _ - +, no \ / * ? " < > | space , #
# and at most 255 bytes. A '*' wildcard is accepted only by the read actions.
_INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,254}$")
_INDEX_PATTERN_RE = re.compile(r"^[a-z0-9*][a-z0-9._*-]{0,254}$")
_FIELD_RE = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_@.\-]{0,254}$")

_INDEX_READ = {"type": "string", "minLength": 1, "description": "index, data stream or alias; '*' wildcards allowed (e.g. logs-*)"}
_INDEX_WRITE = {"type": "string", "minLength": 1, "description": "index or data stream name (no wildcards)"}
_QUERY = {"type": "object", "description": "Query DSL object, e.g. {\"match\": {\"event.action\": \"logon\"}}"}


def index_name(value: Any, *, wildcard: bool) -> str:
    """An index name for a URL path; ValueError when it is not one."""
    text = str(value or "").strip()
    pattern = _INDEX_PATTERN_RE if wildcard else _INDEX_RE
    if not pattern.fullmatch(text) or text in (".", ".."):
        raise ValueError("index must be a lowercase index name" + (" (wildcards allowed)" if wildcard else " without wildcards"))
    return text


class ElasticConnector(BaseConnector):
    """Elasticsearch search, document and cluster APIs."""

    name = "elastic"
    timeout = 60

    CONFIG_FIELDS = [
        field_spec("base_url", "Elasticsearch URL", "https URL of the Elasticsearch HTTP endpoint, e.g. https://es.example.com:9200"),
        field_spec("index", "Poll index", "index pattern the SIEM poller reads (default logs-*)", required=False),
        field_spec("timestamp_field", "Poll timestamp field", "date field the SIEM poller windows on (default @timestamp)", required=False),
    ]
    CREDENTIAL_FIELDS = [
        field_spec("api_key", "API key", "Elasticsearch API key, the base64 'encoded' value (Authorization: ApiKey); or give username and password", required=False, secret=True),
        field_spec("username", "Username", "Elasticsearch user for basic authentication (when no API key is given)", required=False),
        field_spec("password", "Password", "Password of that user", required=False, secret=True),
    ]
    TEST_CALL = "GET / (cluster name and version)"
    ACTIONS = {
        "search": ActionSpec(
            "Search an index (POST /{index}/_search; Elasticsearch REST APIs, Search API).",
            object_schema({
                "index": _INDEX_READ,
                "query": _QUERY,
                "size": {"type": "integer", "minimum": 0, "maximum": 10000, "description": "hits to return (default 10)"},
                "sort": {"type": "array", "description": "sort clauses, e.g. [{\"@timestamp\": \"desc\"}]"},
                "_source": {"description": "source filtering: true, false, a field list or an includes/excludes object"},
            }, ["index"]),
            "total hits and hits (index, id, score, source)",
            idempotent=True, side_effect=False, action_type="query", display_name="Search",
        ),
        "count": ActionSpec(
            "Count matching documents (POST /{index}/_count; Elasticsearch REST APIs, Count API).",
            object_schema({"index": _INDEX_READ, "query": _QUERY}, ["index"]),
            "document count",
            idempotent=True, side_effect=False, action_type="query", display_name="Count",
        ),
        "get_document": ActionSpec(
            "Read one document (GET /{index}/_doc/{id}; Elasticsearch REST APIs, Get API).",
            object_schema({"index": _INDEX_WRITE, "id": {"type": "string", "minLength": 1, "description": "document id"}}, ["index", "id"]),
            "found, index, id, version, source",
            idempotent=True, side_effect=False, action_type="query", display_name="Get document",
        ),
        "list_indices": ActionSpec(
            "List indices (GET /_cat/indices?format=json&h=index,health,status,docs.count,store.size; "
            "Elasticsearch REST APIs, cat indices API).",
            object_schema({}),
            "indices (index, health, status, docs.count, store.size)",
            idempotent=True, side_effect=False, action_type="query", display_name="List indices",
        ),
        "cluster_health": ActionSpec(
            "Cluster health (GET /_cluster/health; Elasticsearch REST APIs, Cluster health API).",
            object_schema({}),
            "cluster name, status, node and shard counts",
            idempotent=True, side_effect=False, action_type="query", display_name="Cluster health",
        ),
        "index_document": ActionSpec(
            "Index a document with a generated id (POST /{index}/_doc; Elasticsearch REST APIs, Index API).",
            object_schema({"index": _INDEX_WRITE, "document": {"type": "object", "description": "the document body"}}, ["index", "document"]),
            "index, id, result, version",
            idempotent=False, side_effect=True, action_type="create", display_name="Index document",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(config, credentials)
        base = self.config.get("base_url")
        self.base_url = https_origin(base, "base_url") if base else ""

    # ------------------------------------------------------------------
    # Fields
    # ------------------------------------------------------------------

    @classmethod
    def missing_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        """``base_url``, plus a credential: ``api_key``, or ``username`` and ``password``."""
        missing = super().missing_fields(config, credentials)
        creds = credentials or {}

        def present(key: str) -> bool:
            return bool(str(creds.get(key) or "").strip())

        if not present("api_key"):
            if present("username") and not present("password"):
                missing.append("password")
            elif present("password") and not present("username"):
                missing.append("username")
            elif not present("username"):
                missing += ["api_key", "username", "password"]
        return missing

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:
        config = config or {}
        bad: List[str] = []
        if config.get("base_url"):
            try:
                https_origin(config["base_url"], "base_url")
            except ValueError:
                bad.append("base_url")
        if config.get("index"):
            try:
                index_name(config["index"], wildcard=True)
            except ValueError:
                bad.append("index")
        if config.get("timestamp_field") and not _FIELD_RE.fullmatch(str(config["timestamp_field"])):
            bad.append("timestamp_field")
        return bad

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            # Pinned like every connector; private_hint makes a private
            # address outside the allow-list say which setting opens it.
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=float(self.timeout),
                transport=PinnedTransport(private_hint=True),
                follow_redirects=False,
            )
        return self._client

    def _get_headers(self) -> Dict[str, str]:
        headers = super()._get_headers()
        api_key = self.credentials.get("api_key")
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        else:
            username, password = self.credentials.get("username"), self.credentials.get("password")
            if username and password:
                headers["Authorization"] = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        return headers

    def _secret_values(self) -> List[str]:
        values = super()._secret_values()
        username, password = self.credentials.get("username"), self.credentials.get("password")
        if username and password:
            values.append(base64.b64encode(f"{username}:{password}".encode()).decode())
        return values

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    async def test_connection(self) -> ConnectionTestResult:
        # REST APIs, root endpoint: GET / answers name, cluster_name and version.number
        body: Dict[str, Any] = {}

        async def _call() -> Any:
            data = await self._make_request("GET", "/")
            body["data"] = data
            return data

        def _verdict(data: Any) -> Optional[str]:
            if not isinstance(data, dict) or not data.get("cluster_name"):
                return "GET / answered without a cluster_name"
            return None

        result = await self._probe(self.TEST_CALL, _call, _verdict)
        if result.healthy:
            data = body["data"]
            version = (data.get("version") or {}).get("number") or "version unknown"
            result.detail = self.sanitize(
                f"authenticated read-only call succeeded; cluster {data.get('cluster_name')} on Elasticsearch {version}",
            )
        return result

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    async def search(
        self,
        index: str,
        query: Optional[Dict[str, Any]] = None,
        size: int = 10,
        sort: Optional[List[Any]] = None,
        _source: Any = None,
    ) -> Dict[str, Any]:
        # Search API: POST /<target>/_search
        body: Dict[str, Any] = {"size": int(size)}
        if query is not None:
            body["query"] = query
        if sort is not None:
            body["sort"] = sort
        if _source is not None:
            body["_source"] = _source
        data = await self._make_request("POST", f"/{index_name(index, wildcard=True)}/_search", json_data=body)
        hits_block = (data or {}).get("hits") or {}
        total = hits_block.get("total")
        hits = [
            {"index": h.get("_index"), "id": h.get("_id"), "score": h.get("_score"), "source": h.get("_source")}
            for h in hits_block.get("hits") or []
        ]
        return {"total": total.get("value") if isinstance(total, dict) else total, "count": len(hits), "hits": hits}

    async def count(self, index: str, query: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # Count API: POST /<target>/_count
        body = {"query": query} if query is not None else None
        data = await self._make_request("POST", f"/{index_name(index, wildcard=True)}/_count", json_data=body)
        return {"index": index, "count": (data or {}).get("count")}

    async def get_document(self, index: str, id: str) -> Dict[str, Any]:  # noqa: A002 (the API's name)
        # Get API: GET /<index>/_doc/<_id>
        data = await self._make_request("GET", f"/{index_name(index, wildcard=False)}/_doc/{path_segment(id)}")
        return {
            "found": data.get("found"),
            "index": data.get("_index"),
            "id": data.get("_id"),
            "version": data.get("_version"),
            "source": data.get("_source"),
        }

    async def list_indices(self) -> Dict[str, Any]:
        # cat indices API: GET /_cat/indices?format=json&h=...
        data = await self._make_request(
            "GET", "/_cat/indices", params={"format": "json", "h": "index,health,status,docs.count,store.size"},
        )
        indices = data if isinstance(data, list) else []
        return {"count": len(indices), "indices": indices}

    async def cluster_health(self) -> Dict[str, Any]:
        # Cluster health API: GET /_cluster/health
        data = await self._make_request("GET", "/_cluster/health")
        keys = ("cluster_name", "status", "number_of_nodes", "number_of_data_nodes", "active_shards",
                "relocating_shards", "initializing_shards", "unassigned_shards")
        return {k: data.get(k) for k in keys}

    async def index_document(self, index: str, document: Dict[str, Any]) -> Dict[str, Any]:
        # Index API: POST /<target>/_doc (generated id)
        data = await self._make_request("POST", f"/{index_name(index, wildcard=False)}/_doc", json_data=document)
        return {"index": data.get("_index"), "id": data.get("_id"), "result": data.get("result"), "version": data.get("_version")}

    # ------------------------------------------------------------------
    # SIEM poller (src/siem/cloud_poller.py)
    # ------------------------------------------------------------------

    def poll_index(self) -> str:
        return index_name(self.config.get("index") or "logs-*", wildcard=True)

    async def fetch_events(self, since: datetime, until: datetime, limit: int = 500) -> List[Dict[str, Any]]:
        """``_source`` of documents whose timestamp field is in [since, until], oldest first.

        Raises ConnectorHTTPError / IntegrationError / ValueError like an action.
        """
        ts_field = str(self.config.get("timestamp_field") or "@timestamp")
        if not _FIELD_RE.fullmatch(ts_field):
            raise ValueError("timestamp_field is not a field name")
        try:
            out = await self.search(
                self.poll_index(),
                query={"range": {ts_field: {"gte": since.isoformat(), "lte": until.isoformat()}}},
                size=limit,
                sort=[{ts_field: "asc"}],
            )
        finally:
            await self.close()
        return [h["source"] for h in out["hits"] if isinstance(h.get("source"), dict)]


__all__ = ["ElasticConnector", "index_name"]
