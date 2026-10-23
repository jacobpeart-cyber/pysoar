"""IBM QRadar SIEM REST API connector.

Written from the IBM QRadar REST API reference (API version 12.0; QRadar
"RESTful API" documentation, endpoint categories ``/siem``, ``/ariel``,
``/reference_data`` and ``/system``). Not verified against a live console.

``base_url`` is the console origin (``https://qradar.example.com``); every
endpoint lives under ``/api``. Authentication is an authorized service token
in the ``SEC`` header; every request also sends ``Version: 12.0`` (the API
version this connector was written against, as the SIEM poller sends) and
``Accept: application/json``. List endpoints are paged with the
``Range: items=<first>-<last>`` header.

A console usually lives on a private network: its address must be inside the
operator setting ``OUTBOUND_PRIVATE_ALLOWLIST`` (src/integrations/netguard.py),
otherwise every request is refused before a connection is made and the
refusal names that setting. Redirects are not followed: a 3xx answer is a
failed call.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, ClassVar, Dict, List, Optional
from urllib.parse import quote

import httpx

from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    ConnectorHTTPError,
    field_spec,
    object_schema,
    path_segment,
)
from src.integrations.connectors.splunk import https_origin
from src.integrations.netguard import PinnedTransport
from src.schemas.integrations import IntegrationConfigField

QRADAR_API_VERSION = "12.0"
_MAX_ITEMS = 1000
#: Bounded wait for an Ariel search: POST, then GET the search status every
#: ``_AQL_POLL_SECONDS`` until COMPLETED, at most ``max_wait_seconds``.
_AQL_POLL_SECONDS = 2.0
_AQL_MAX_WAIT = 300
_AQL_DONE = "COMPLETED"
_AQL_FAILED = {"CANCELED", "ERROR"}

# A reference set name in the URL path: letters, digits, space, _ . : - only
# (no slash, backslash, ?, #, % or dot-segment), at most 255 characters,
# percent-encoded as one segment.
_REFSET_RE = re.compile(r"^[A-Za-z0-9 _.:\-]{1,255}$")
_SELECT_RE = re.compile(r"^\s*select\s", re.IGNORECASE)

_OFFENSE_ID = {"type": "integer", "minimum": 0, "description": "offense id"}
_LIMIT = {"type": "integer", "minimum": 1, "maximum": _MAX_ITEMS, "description": "items to return (Range header)"}
_FIELDS = {"type": "string", "minLength": 1, "description": "comma-separated fields to return, e.g. id,description,status"}
_REFSET = {"type": "string", "minLength": 1, "description": "reference set name"}


def reference_set_segment(name: Any) -> str:
    """A reference set name as one percent-encoded path segment; ValueError when it is not one."""
    text = str(name or "").strip()
    if not _REFSET_RE.fullmatch(text) or text in (".", ".."):
        raise ValueError("reference set name may contain only letters, digits, space, _ . : -")
    return quote(text, safe="")


def check_read_only_aql(query: Any) -> str:
    """The AQL text when it is a single SELECT statement; ValueError otherwise (fail closed).

    AQL (Ariel Query Language) reads events and flows; the connector accepts
    only a statement that begins with SELECT and contains no ``;`` (one
    statement, nothing appended), so the action stays read-only whatever the
    console version accepts.
    """
    text = str(query or "").strip()
    if not text:
        raise ValueError("query_expression must not be empty")
    if not _SELECT_RE.match(text + " "):
        raise ValueError("aql_search is read-only: query_expression must be a SELECT statement")
    if ";" in text:
        raise ValueError("aql_search is read-only: query_expression must be a single SELECT statement (no ';')")
    return text


def _range(limit: int) -> Dict[str, str]:
    return {"Range": f"items=0-{int(limit) - 1}"}


class QRadarConnector(BaseConnector):
    """QRadar offenses, Ariel (AQL) searches and reference sets."""

    name = "qradar"
    timeout = 60

    CONFIG_FIELDS: ClassVar[list[IntegrationConfigField]] = [
        field_spec("base_url", "Console URL", "https origin of the QRadar console, e.g. https://qradar.example.com"),
    ]
    CREDENTIAL_FIELDS: ClassVar[list[IntegrationConfigField]] = [
        field_spec("sec_token", "SEC token", "authorized service token, sent in the SEC header", secret=True),
    ]
    TEST_CALL = "GET /api/system/about"
    ACTIONS: ClassVar[dict[str, ActionSpec]] = {
        "list_offenses": ActionSpec(
            "List offenses (GET /api/siem/offenses with filter, fields and Range; QRadar REST API reference, /siem/offenses).",
            object_schema({
                "filter": {"type": "string", "minLength": 1, "description": "QRadar filter, e.g. status=OPEN and magnitude>=5"},
                "fields": _FIELDS,
                "limit": _LIMIT,
            }),
            "offenses (id, description, status, magnitude, ...)",
            idempotent=True, side_effect=False, action_type="query", display_name="List offenses",
        ),
        "get_offense": ActionSpec(
            "Read one offense (GET /api/siem/offenses/{offense_id}; QRadar REST API reference, /siem/offenses/{offense_id}).",
            object_schema({"offense_id": _OFFENSE_ID, "fields": _FIELDS}, ["offense_id"]),
            "the offense",
            idempotent=True, side_effect=False, action_type="query", display_name="Get offense",
        ),
        "close_offense": ActionSpec(
            "Close an offense (POST /api/siem/offenses/{offense_id}?status=CLOSED&closing_reason_id=; "
            "QRadar REST API reference, /siem/offenses/{offense_id}).",
            object_schema({
                "offense_id": _OFFENSE_ID,
                "closing_reason_id": {"type": "integer", "minimum": 0, "description": "id from /siem/offense_closing_reasons"},
            }, ["offense_id", "closing_reason_id"]),
            "id, status, closing_reason_id",
            idempotent=True, side_effect=True, action_type="update", display_name="Close offense",
        ),
        "add_offense_note": ActionSpec(
            "Add a note to an offense (POST /api/siem/offenses/{offense_id}/notes?note_text=; "
            "QRadar REST API reference, /siem/offenses/{offense_id}/notes).",
            object_schema({
                "offense_id": _OFFENSE_ID,
                "note_text": {"type": "string", "minLength": 1, "description": "note text"},
            }, ["offense_id", "note_text"]),
            "note id, note_text, create_time, username",
            idempotent=False, side_effect=True, action_type="create", display_name="Add offense note",
        ),
        "assign_offense": ActionSpec(
            "Assign an offense to a QRadar user (POST /api/siem/offenses/{offense_id}?assigned_to=; "
            "QRadar REST API reference, /siem/offenses/{offense_id}).",
            object_schema({
                "offense_id": _OFFENSE_ID,
                "assigned_to": {"type": "string", "minLength": 1, "description": "QRadar user name"},
            }, ["offense_id", "assigned_to"]),
            "id, assigned_to",
            idempotent=True, side_effect=True, action_type="update", display_name="Assign offense",
        ),
        "aql_search": ActionSpec(
            "Run a read-only AQL SELECT (POST /api/ariel/searches?query_expression=, then GET "
            "/api/ariel/searches/{search_id} until COMPLETED within max_wait_seconds, then GET "
            "/api/ariel/searches/{search_id}/results with Range; QRadar REST API reference, /ariel/searches). "
            "A query that is not a single SELECT statement is refused before any request.",
            object_schema({
                "query_expression": {"type": "string", "minLength": 1, "description": "AQL, e.g. SELECT sourceip, COUNT(*) FROM events GROUP BY sourceip LAST 1 HOURS"},
                "limit": _LIMIT,
                "max_wait_seconds": {"type": "integer", "minimum": 1, "maximum": _AQL_MAX_WAIT, "description": "how long to wait for the search (default 60)"},
            }, ["query_expression"]),
            "search_id, status, count and rows (events or flows)",
            idempotent=False, side_effect=False, action_type="query", display_name="AQL search",
        ),
        "list_reference_set": ActionSpec(
            "Read a reference set and its elements (GET /api/reference_data/sets/{name}; "
            "QRadar REST API reference, /reference_data/sets/{name}).",
            object_schema({"name": _REFSET}, ["name"]),
            "name, element_type, number_of_elements, data (value, first_seen, last_seen, source)",
            idempotent=True, side_effect=False, action_type="query", display_name="List reference set",
        ),
        "add_to_reference_set": ActionSpec(
            "Add a value to a reference set (POST /api/reference_data/sets/{name}?value=; "
            "QRadar REST API reference, /reference_data/sets/{name}).",
            object_schema({
                "name": _REFSET,
                "value": {"type": "string", "minLength": 1, "description": "the value, e.g. an IP address"},
            }, ["name", "value"]),
            "name, element_type, number_of_elements",
            idempotent=True, side_effect=True, action_type="update", display_name="Add to reference set",
        ),
    }

    def __init__(self, config: Dict[str, Any], credentials: Dict[str, Any]):
        super().__init__(config, credentials)
        base = self.config.get("base_url")
        self.base_url = https_origin(base, "base_url") if base else ""

    @classmethod
    def invalid_fields(cls, config: Optional[Dict[str, Any]], credentials: Optional[Dict[str, Any]]) -> List[str]:  # noqa: ARG003 (base signature)
        config = config or {}
        if config.get("base_url"):
            try:
                https_origin(config["base_url"], "base_url")
            except ValueError:
                return ["base_url"]
        return []

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
        headers["Accept"] = "application/json"
        headers["Version"] = QRADAR_API_VERSION
        token = self.credentials.get("sec_token")
        if token:
            headers["SEC"] = str(token)
        return headers

    async def _send_once(
        self, method: str, endpoint: str, params: Optional[Dict[str, Any]], json_data: Any,
        headers: Optional[Dict[str, Any]], form_data: Optional[Dict[str, Any]], content: Optional[bytes], auth: bool,
    ) -> httpx.Response:
        response = await super()._send_once(method, endpoint, params, json_data, headers, form_data, content, auth)
        if 300 <= response.status_code < 400:
            # Redirects are not followed; a console that redirects is a failed call.
            raise ConnectorHTTPError(self.name, response.status_code, "redirect not followed")
        return response

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    async def test_connection(self) -> ConnectionTestResult:
        # /system/about: GET answers release_name, build_version and external_version.
        body: Dict[str, Any] = {}

        async def _call() -> Any:
            data = await self._make_request("GET", "/api/system/about")
            body["data"] = data
            return data

        def _verdict(data: Any) -> Optional[str]:
            if not isinstance(data, dict) or not (data.get("external_version") or data.get("release_name")):
                return "GET /api/system/about answered without a version"
            return None

        result = await self._probe(self.TEST_CALL, _call, _verdict)
        if result.healthy:
            data = body["data"]
            version = data.get("external_version") or data.get("release_name")
            result.detail = self.sanitize(f"authenticated read-only call succeeded; QRadar {version}")
        return result

    # ------------------------------------------------------------------
    # Offenses
    # ------------------------------------------------------------------

    async def list_offenses(self, filter: Optional[str] = None, fields: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:  # noqa: A002 (the API's name)
        # /siem/offenses GET: filter, fields query parameters; Range header pages.
        params = {k: v for k, v in (("filter", filter), ("fields", fields)) if v}
        data = await self._make_request("GET", "/api/siem/offenses", params=params or None, headers=_range(limit))
        offenses = data if isinstance(data, list) else []
        return {"count": len(offenses), "offenses": offenses}

    async def get_offense(self, offense_id: int, fields: Optional[str] = None) -> Dict[str, Any]:
        # /siem/offenses/{offense_id} GET
        params = {"fields": fields} if fields else None
        data = await self._make_request("GET", f"/api/siem/offenses/{path_segment(int(offense_id))}", params=params)
        return {"offense": data}

    async def close_offense(self, offense_id: int, closing_reason_id: int) -> Dict[str, Any]:
        # /siem/offenses/{offense_id} POST status=CLOSED&closing_reason_id=
        data = await self._make_request(
            "POST", f"/api/siem/offenses/{path_segment(int(offense_id))}",
            params={"status": "CLOSED", "closing_reason_id": str(int(closing_reason_id))},
        )
        return {"id": data.get("id"), "status": data.get("status"), "closing_reason_id": data.get("closing_reason_id")}

    async def add_offense_note(self, offense_id: int, note_text: str) -> Dict[str, Any]:
        # /siem/offenses/{offense_id}/notes POST note_text=
        data = await self._make_request(
            "POST", f"/api/siem/offenses/{path_segment(int(offense_id))}/notes", params={"note_text": str(note_text)},
        )
        return {k: data.get(k) for k in ("id", "note_text", "create_time", "username")}

    async def assign_offense(self, offense_id: int, assigned_to: str) -> Dict[str, Any]:
        # /siem/offenses/{offense_id} POST assigned_to=
        data = await self._make_request(
            "POST", f"/api/siem/offenses/{path_segment(int(offense_id))}", params={"assigned_to": str(assigned_to).strip()},
        )
        return {"id": data.get("id"), "assigned_to": data.get("assigned_to")}

    # ------------------------------------------------------------------
    # Ariel (AQL)
    # ------------------------------------------------------------------

    async def aql_search(self, query_expression: str, limit: int = 100, max_wait_seconds: int = 60) -> Dict[str, Any]:
        aql = check_read_only_aql(query_expression)
        # /ariel/searches POST query_expression= -> search_id, status
        created = await self._make_request("POST", "/api/ariel/searches", params={"query_expression": aql})
        if not created.get("search_id"):
            return {"error": "POST /api/ariel/searches answered without a search_id"}
        search_id = path_segment(created["search_id"])
        status = str(created.get("status") or "")
        deadline = _now() + float(max_wait_seconds)
        # /ariel/searches/{search_id} GET until COMPLETED (bounded).
        while status != _AQL_DONE:
            if status in _AQL_FAILED:
                return {"error": f"AQL search {search_id} ended {status}"}
            if _now() >= deadline:
                return {"error": f"AQL search {search_id} did not complete within {int(max_wait_seconds)}s (status {status or 'unknown'})"}
            await _sleep(_AQL_POLL_SECONDS)
            state = await self._make_request("GET", f"/api/ariel/searches/{search_id}")
            status = str(state.get("status") or "")
        # /ariel/searches/{search_id}/results GET with Range
        results = await self._make_request("GET", f"/api/ariel/searches/{search_id}/results", headers=_range(limit))
        # The results body is keyed by the queried table ("events" or "flows").
        rows: List[Any] = []
        if isinstance(results, dict):
            rows = next((results[k] for k in ("events", "flows") if isinstance(results.get(k), list)), [])
        return {"search_id": search_id, "status": status, "count": len(rows), "rows": rows}

    # ------------------------------------------------------------------
    # Reference sets
    # ------------------------------------------------------------------

    async def list_reference_set(self, name: str) -> Dict[str, Any]:
        # /reference_data/sets/{name} GET
        data = await self._make_request("GET", f"/api/reference_data/sets/{reference_set_segment(name)}")
        return {k: data.get(k) for k in ("name", "element_type", "number_of_elements", "data")}

    async def add_to_reference_set(self, name: str, value: str) -> Dict[str, Any]:
        # /reference_data/sets/{name} POST value=
        data = await self._make_request(
            "POST", f"/api/reference_data/sets/{reference_set_segment(name)}", params={"value": str(value).strip()},
        )
        return {k: data.get(k) for k in ("name", "element_type", "number_of_elements")}


def _now() -> float:
    return time.monotonic()


async def _sleep(seconds: float) -> None:
    """Isolated so tests can run the bounded AQL poll without waiting."""
    await asyncio.sleep(seconds)


__all__ = ["QRadarConnector", "check_read_only_aql", "reference_set_segment"]
